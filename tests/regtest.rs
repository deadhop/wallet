//! End to end on the regtest stack (`just up`): real bitcoind, Fulcrum and
//! relay. Each test funds fresh wallets from the stack's miner wallet,
//! sweeps them, mines a block and checks the funds arrived.
//!
//! Skipped unless DEADHOP_WALLET_REGTEST=1, because they need the stack.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bip39::Mnemonic;
use bitcoin::{Amount, Network, ScriptBuf};
use deadhop_electrum::Electrum;
use deadhop_wallet::chain::Backend;
use deadhop_wallet::config::Config;
use deadhop_wallet::keys::{Keys, EXTERNAL, INTERNAL};
use deadhop_wallet::sweep::{Outcome, Sweeper};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const RPC: &str = "127.0.0.1:18443";
const ELECTRUM: &str = "127.0.0.1:50001";
const RELAY: &str = "ws://127.0.0.1:7777";

/// The tests mine blocks, which would confirm each other's payments early:
/// they take turns.
static CHAIN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn enabled() -> bool {
    let on = std::env::var("DEADHOP_WALLET_REGTEST").is_ok_and(|v| v == "1");
    if !on {
        eprintln!("skipped: set DEADHOP_WALLET_REGTEST=1 with the regtest stack up (just up)");
    }
    on
}

/// bitcoind JSON-RPC (the dev stack's static credentials).
async fn rpc(wallet: Option<&str>, method: &str, params: Value) -> Value {
    let body = json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).to_string();
    let path = wallet.map_or("/".to_string(), |w| format!("/wallet/{w}"));
    let auth = bitcoin::base64::Engine::encode(
        &bitcoin::base64::engine::general_purpose::STANDARD,
        "deadhop:deadhop-dev-only",
    );
    let mut s = tokio::net::TcpStream::connect(RPC).await.expect("bitcoind is up");
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {RPC}\r\nAuthorization: Basic {auth}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8(raw).unwrap();
    let json_start = text.find("\r\n\r\n").unwrap() + 4;
    let v: Value = serde_json::from_str(&text[json_start..]).unwrap();
    assert!(v["error"].is_null(), "{method}: {}", v["error"]);
    v["result"].clone()
}

async fn mine(blocks: u32) {
    let to = rpc(Some("miner"), "getnewaddress", json!([])).await;
    rpc(None, "generatetoaddress", json!([blocks, to])).await;
}

async fn pay(address: &str, sat: u64) {
    let btc = format!("{}.{:08}", sat / 100_000_000, sat % 100_000_000);
    rpc(Some("miner"), "sendtoaddress", json!([address, btc])).await;
}

fn electrum() -> Electrum {
    Electrum::new(ELECTRUM, Duration::from_secs(20))
}

/// Wait until Fulcrum has the node's tip.
async fn synced() {
    let height = rpc(None, "getblockcount", json!([])).await.as_u64().unwrap() as u32;
    let e = electrum();
    for _ in 0..300 {
        if e.tip().await.is_ok_and(|t| t >= height) {
            // And its mempool view of the new block.
            tokio::time::sleep(Duration::from_millis(500)).await;
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("Fulcrum did not catch up");
}

/// Unspent value at `script`, per Fulcrum.
async fn balance(script: &ScriptBuf) -> Amount {
    let list = electrum().unspent(std::slice::from_ref(script)).await.unwrap();
    list[0].as_ref().unwrap().iter().map(|u| u.value).sum()
}

/// A fresh wallet as the offline wallet service would have made it.
fn new_wallet(dir: &Path) -> Keys {
    let mut entropy = [0u8; 32];
    getrandom::getrandom(&mut entropy).unwrap();
    let phrase = Mnemonic::from_entropy(&entropy).unwrap();
    let data = dir.join("wallet");
    std::fs::create_dir_all(&data).unwrap();
    let path = data.join("wallet.mnemonic");
    std::fs::write(&path, phrase.to_string()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let keys = Keys::from_phrase(&phrase, Network::Regtest);
    std::fs::write(dir.join("account.xpub"), format!("{}\n", keys.account_key())).unwrap();
    keys
}

fn config(dir: &Path, extra: &[(&'static str, String)]) -> Config {
    let mut m: HashMap<&'static str, String> = HashMap::from([
        ("DEADHOP_NETWORK", "regtest".to_string()),
        ("DEADHOP_ELECTRUM", ELECTRUM.to_string()),
        ("DEADHOP_DATA_DIR", dir.join("wallet").to_string_lossy().into_owned()),
        (
            "DEADHOP_XPUB_FILE",
            dir.join("account.xpub").to_string_lossy().into_owned(),
        ),
        ("DEADHOP_WALLET_STATE_DIR", dir.to_string_lossy().into_owned()),
        ("DEADHOP_WALLET_THRESHOLD_SAT", "100000".to_string()),
        ("DEADHOP_WALLET_MAX_FEE_RATE", "50".to_string()),
    ]);
    for (k, v) in extra {
        m.insert(k, v.clone());
    }
    Config::from_env(&|k| m.get(k).cloned()).unwrap()
}

fn sweeper(dir: &Path, extra: &[(&'static str, String)]) -> Sweeper {
    let cfg = config(dir, extra);
    let keys = deadhop_wallet::run::open_keys(&cfg).unwrap();
    deadhop_wallet::run::sweeper(cfg, keys).unwrap()
}

fn swept(o: Outcome) -> deadhop_wallet::state::Sweep {
    match o {
        Outcome::Swept(s) => s,
        other => panic!("expected a sweep, got {other:?}"),
    }
}

#[tokio::test]
async fn simple_send_moves_everything_to_a_fresh_address() {
    if !enabled() {
        return;
    }
    let _turn = CHAIN.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let ours = new_wallet(dir.path());
    let dest_dir = tempfile::tempdir().unwrap();
    let dest = new_wallet(dest_dir.path());
    let mut s = sweeper(dir.path(), &[("DEADHOP_WALLET_DESTINATION", dest.account_key())]);

    // Two invoices paid, far apart; one more still unconfirmed.
    pay(&ours.address(EXTERNAL, 0).to_string(), 70_000).await;
    pay(&ours.address(EXTERNAL, 30).to_string(), 40_000).await;
    std::fs::write(dir.path().join("next-index"), "31").unwrap();
    s.cfg.index_file = Some(dir.path().join("next-index"));
    synced().await;
    assert!(matches!(s.tick(1).await.unwrap(), Outcome::Below { .. }));
    mine(1).await;
    synced().await;

    let sweep = swept(s.tick(2).await.unwrap());
    assert_eq!(sweep.spent_sat, 110_000);
    mine(1).await;
    synced().await;
    assert_eq!(balance(&dest.script(EXTERNAL, 0)).await.to_sat(), sweep.moved_sat);
    assert_eq!(balance(&ours.script(EXTERNAL, 0)).await, Amount::ZERO);
    // The next sweep goes to the next address.
    assert_eq!(s.destination().unwrap().0, dest.script(EXTERNAL, 1));
    assert!(matches!(s.tick(3).await.unwrap(), Outcome::Below { .. }));
}

/// A BIP-78 receiver on 127.0.0.1 over TLS, contributing one coin of `keys`.
async fn payjoin_receiver(keys: Keys, coin: deadhop_wallet::tx::Coin) -> (u16, String, tokio::task::JoinHandle<()>) {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let cert = CertificateDer::from_pem_slice(include_bytes!("fixtures/proxy-test-cert.pem")).unwrap();
    let fp = deadhop_electrum::fingerprint_hex(cert.as_ref());
    let key = PrivateKeyDer::from_pem_slice(include_bytes!("fixtures/proxy-test-key.pem")).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.unwrap();
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        let (head, body) = loop {
            let n = tls.read(&mut buf).await.unwrap();
            raw.extend_from_slice(&buf[..n]);
            if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8(raw[..i].to_vec()).unwrap();
                let len: usize = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse().unwrap())
                    })
                    .unwrap();
                while raw.len() < i + 4 + len {
                    let n = tls.read(&mut buf).await.unwrap();
                    raw.extend_from_slice(&buf[..n]);
                }
                break (head, raw[i + 4..i + 4 + len].to_vec());
            }
        };
        let target = head
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .to_string();
        let query = target.split_once('?').map_or("", |(_, q)| q).to_string();
        struct H(HashMap<String, String>);
        impl payjoin::receive::v1::Headers for H {
            fn get_header(&self, key: &str) -> Option<&str> {
                self.0.get(&key.to_ascii_lowercase()).map(String::as_str)
            }
        }
        let headers = H(head
            .lines()
            .skip(1)
            .filter_map(|l| l.split_once(':'))
            .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
            .collect());
        let script = coin.script.clone();
        let paid_to = keys.script(EXTERNAL, 0);
        let txin = bitcoin::TxIn {
            previous_output: coin.outpoint,
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            ..Default::default()
        };
        let psbtin = bitcoin::psbt::Input {
            witness_utxo: Some(bitcoin::TxOut {
                value: coin.value,
                script_pubkey: script.clone(),
            }),
            ..Default::default()
        };
        let proposal = payjoin::receive::v1::UncheckedOriginalPayload::from_request(&body, &query, headers)
            .unwrap()
            .check_broadcast_suitability(None, |_| Ok(true))
            .unwrap()
            .check_inputs_not_owned(&mut |o| Ok(*o == coin.outpoint))
            .unwrap()
            .check_no_inputs_seen_before(&mut |_| Ok(false))
            .unwrap()
            .identify_receiver_outputs(&mut |s| Ok(s == paid_to.as_script()))
            .unwrap()
            .commit_outputs()
            .contribute_inputs(vec![payjoin::receive::InputPair::new(txin, psbtin, None).unwrap()])
            .unwrap()
            .commit_inputs()
            .apply_fee_range(
                Some(bitcoin::FeeRate::from_sat_per_vb_u32(21)),
                Some(bitcoin::FeeRate::from_sat_per_vb_u32(100)),
            )
            .unwrap()
            .finalize_proposal(|psbt| {
                let mut p = psbt.clone();
                let coins = HashMap::from([(coin.outpoint, coin.clone())]);
                let rules = deadhop_wallet::tx::Rules {
                    to: vec![paid_to.clone()],
                    min_to: Amount::ZERO,
                    max_cost: Amount::from_sat(u64::MAX / 4),
                };
                deadhop_wallet::tx::sign(&mut p, &keys, &coins, &rules, bitcoin::EcdsaSighashType::All)
                    .map_err(|e| payjoin::ImplementationError::from(e.to_string().as_str()))?;
                Ok(p)
            })
            .unwrap();
        let body = proposal.psbt().to_string();
        let reply = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        tls.write_all(reply.as_bytes()).await.unwrap();
        tls.shutdown().await.unwrap();
    });
    (port, fp, task)
}

#[tokio::test]
async fn payjoin_with_a_bip78_receiver() {
    if !enabled() {
        return;
    }
    let _turn = CHAIN.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let ours = new_wallet(dir.path());
    let recv_dir = tempfile::tempdir().unwrap();
    let receiver = new_wallet(recv_dir.path());

    // The receiver has a coin of its own to contribute.
    let theirs = receiver.script(EXTERNAL, 1);
    pay(&receiver.address(EXTERNAL, 1).to_string(), 30_000).await;
    pay(&ours.address(EXTERNAL, 0).to_string(), 150_000).await;
    mine(1).await;
    synced().await;
    let u = electrum().unspent(std::slice::from_ref(&theirs)).await.unwrap()[0]
        .clone()
        .unwrap()[0]
        .clone();
    let coin = deadhop_wallet::tx::Coin {
        outpoint: u.outpoint,
        value: u.value,
        chain: EXTERNAL,
        index: 1,
        script: theirs.clone(),
        height: u.height,
    };
    let (port, fp, task) = payjoin_receiver(receiver, coin.clone()).await;
    let pay_to = Keys::from_phrase(
        &Mnemonic::parse(
            std::fs::read_to_string(recv_dir.path().join("wallet/wallet.mnemonic"))
                .unwrap()
                .trim(),
        )
        .unwrap(),
        Network::Regtest,
    );
    let uri = payjoin::receive::v1::build_v1_pj_uri(
        &pay_to.address(EXTERNAL, 0),
        format!("https://127.0.0.1:{port}/pj").as_str(),
        payjoin::OutputSubstitution::Disabled,
    )
    .unwrap()
    .to_string();
    let uri_file = dir.path().join("payjoin.uri");
    std::fs::write(&uri_file, &uri).unwrap();

    let mut s = sweeper(
        dir.path(),
        &[
            ("DEADHOP_WALLET_MODE", "payjoin".into()),
            (
                "DEADHOP_WALLET_PAYJOIN_URI_FILE",
                uri_file.to_string_lossy().into_owned(),
            ),
            ("DEADHOP_WALLET_PAYJOIN_CERT_SHA256", fp),
        ],
    );
    let sweep = swept(s.tick(1).await.unwrap());
    task.await.unwrap();
    assert_eq!(sweep.mode, "payjoin", "{sweep:?}");
    mine(1).await;
    synced().await;
    let tx = rpc(None, "getrawtransaction", json!([sweep.txid, true])).await;
    // Both parties' coins are inputs of one transaction.
    let inputs: Vec<String> = tx["vin"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["txid"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(inputs.len(), 2, "{tx}");
    assert!(inputs.contains(&coin.outpoint.txid.to_string()));
    let got = balance(&pay_to.script(EXTERNAL, 0)).await;
    assert_eq!(got.to_sat(), sweep.moved_sat);
    assert!(
        got > Amount::from_sat(150_000),
        "the receiver's coin was added to its output: {got}"
    );
    assert_eq!(balance(&theirs).await, Amount::ZERO);

    // The same URI is never paid twice.
    pay(&ours.address(EXTERNAL, 1).to_string(), 150_000).await;
    mine(1).await;
    synced().await;
    match s.tick(2).await.unwrap() {
        Outcome::Waiting { why, .. } => assert!(why.contains("already paid"), "{why}"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn payjoin_falls_back_to_the_original_payment() {
    if !enabled() {
        return;
    }
    let _turn = CHAIN.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let ours = new_wallet(dir.path());
    let recv_dir = tempfile::tempdir().unwrap();
    let receiver = new_wallet(recv_dir.path());
    pay(&ours.address(EXTERNAL, 0).to_string(), 120_000).await;
    mine(1).await;
    synced().await;
    // Nobody listens at this endpoint.
    let uri = format!("bitcoin:{}?pj=https://127.0.0.1:1/pj", receiver.address(EXTERNAL, 0));
    let uri_file = dir.path().join("payjoin.uri");
    std::fs::write(&uri_file, &uri).unwrap();
    let mut s = sweeper(
        dir.path(),
        &[
            ("DEADHOP_WALLET_MODE", "payjoin".into()),
            (
                "DEADHOP_WALLET_PAYJOIN_URI_FILE",
                uri_file.to_string_lossy().into_owned(),
            ),
        ],
    );
    let sweep = swept(s.tick(1).await.unwrap());
    assert_eq!(sweep.mode, "payjoin-fallback");
    mine(1).await;
    synced().await;
    assert_eq!(balance(&receiver.script(EXTERNAL, 0)).await.to_sat(), sweep.moved_sat);
}

#[tokio::test]
async fn coinjoin_round_between_three_wallets() {
    if !enabled() {
        return;
    }
    let _turn = CHAIN.lock().await;
    const PEERS: usize = 3;
    // A denomination of its own, so that pools of other runs never match.
    let mut r = [0u8; 2];
    getrandom::getrandom(&mut r).unwrap();
    let denomination = 100_000 + u64::from(u16::from_le_bytes(r)) * 10;
    let mut dirs = Vec::new();
    let mut wallets = Vec::new();
    let mut dests = Vec::new();
    for _ in 0..PEERS {
        let dir = tempfile::tempdir().unwrap();
        let keys = new_wallet(dir.path());
        let dest_dir = tempfile::tempdir().unwrap();
        let dest = new_wallet(dest_dir.path());
        pay(&keys.address(EXTERNAL, 0).to_string(), denomination + 60_000).await;
        pay(&keys.address(EXTERNAL, 4).to_string(), 50_000).await;
        wallets.push(keys);
        dests.push((dest, dest_dir));
        dirs.push(dir);
    }
    mine(1).await;
    synced().await;
    let mut sweepers: Vec<Sweeper> = dirs
        .iter()
        .zip(&dests)
        .map(|(dir, (dest, _))| {
            sweeper(
                dir.path(),
                &[
                    ("DEADHOP_WALLET_MODE", "coinjoin".into()),
                    ("DEADHOP_WALLET_DESTINATION", dest.account_key()),
                    ("DEADHOP_WALLET_COINJOIN_RELAY", RELAY.into()),
                    ("DEADHOP_WALLET_COINJOIN_DENOMINATION_SAT", denomination.to_string()),
                    ("DEADHOP_WALLET_COINJOIN_PEERS", PEERS.to_string()),
                    ("DEADHOP_WALLET_COINJOIN_TIMEOUT_SECS", "180".into()),
                    ("DEADHOP_WALLET_THRESHOLD_SAT", (denomination + 1_000).to_string()),
                ],
            )
        })
        .collect();

    // First poll: each wallet consolidates into a premix coin and change.
    for s in &mut sweepers {
        let premix = swept(s.tick(1).await.unwrap());
        assert_eq!(premix.mode, "coinjoin-premix");
        assert_eq!(premix.moved_sat, denomination + 1_000);
    }
    mine(1).await;
    synced().await;

    // Second poll, all at once: one announces a pool, the others join it.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut iter = sweepers.iter_mut();
    let first = iter.next().unwrap();
    let rest: Vec<&mut Sweeper> = iter.collect();
    let creator = first.tick(now);
    let joiners = async {
        // Give the creator time to announce.
        tokio::time::sleep(Duration::from_secs(3)).await;
        futures_join(rest, now).await
    };
    let (a, others) = tokio::join!(creator, joiners);
    let mut results = vec![swept(a.unwrap())];
    results.extend(others.into_iter().map(|o| swept(o.unwrap())));
    let txids: std::collections::HashSet<_> = results.iter().map(|r| r.txid.clone()).collect();
    assert_eq!(
        txids.len(),
        1,
        "every member broadcast the same transaction: {results:?}"
    );
    mine(1).await;
    synced().await;

    let txid = results[0].txid.clone();
    let tx = rpc(None, "getrawtransaction", json!([txid, true])).await;
    assert_eq!(tx["vin"].as_array().unwrap().len(), PEERS);
    let outs = tx["vout"].as_array().unwrap();
    assert_eq!(outs.len(), PEERS);
    let values: std::collections::HashSet<_> = outs.iter().map(|o| o["value"].to_string()).collect();
    assert_eq!(values.len(), 1, "equal outputs: {tx}");
    for ((dest, _), r) in dests.iter().zip(&results) {
        assert_eq!(balance(&dest.script(EXTERNAL, 0)).await.to_sat(), r.moved_sat);
    }
    // Each wallet keeps its premix change for a later sweep.
    for w in &wallets {
        assert!(balance(&w.script(INTERNAL, 1)).await > Amount::ZERO);
    }
}

/// Poll every joiner concurrently.
async fn futures_join(sweepers: Vec<&mut Sweeper>, now: u64) -> Vec<deadhop_wallet::error::Result<Outcome>> {
    let futs = sweepers.into_iter().map(|s| s.tick(now));
    futures_util::future::join_all(futs).await
}
