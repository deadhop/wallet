//! PayJoin (BIP-78) sweeps.
//!
//! The receiver is named by a `bitcoin:` URI with a `pj=` endpoint, read
//! from `DEADHOP_WALLET_PAYJOIN_URI_FILE` before every sweep. A URI is paid
//! once: the receiver (or whoever runs it) writes a fresh one for the next
//! sweep. The wallet signs an Original transaction paying every confirmed
//! coin to the URI's address, sends it to the endpoint, checks the
//! receiver's proposal (the payjoin library's sender checks, then this
//! wallet's own rules), signs its inputs again and broadcasts. If anything
//! goes wrong after the Original is signed, the Original itself is
//! broadcast: it is an ordinary payment to the receiver, which BIP-78
//! allows the receiver to broadcast too.

use std::sync::Arc;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::sighash::EcdsaSighashType;
use bitcoin::{Amount, FeeRate, Transaction};
use payjoin::send::v1::SenderBuilder;
use payjoin::{PjUri, Uri};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::Mode;
use crate::error::{Error, Result};
use crate::state::Sweep;
use crate::sweep::{index, Sweeper};
use crate::tx::{self, Coin, Rules};

/// Longest URI accepted from the file.
const MAX_URI: usize = 2_000;
/// Largest response accepted from a receiver.
const MAX_RESPONSE: usize = 4 * 1024 * 1024;
/// How long the receiver may take to answer.
#[cfg(not(test))]
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
#[cfg(test)]
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

fn err(why: impl std::fmt::Display) -> Error {
    Error::Payjoin(why.to_string())
}

/// Parse and check a receiver URI for `network`.
pub fn parse_uri(text: &str, network: bitcoin::Network) -> Result<PjUri> {
    let text = text.trim();
    if text.len() > MAX_URI {
        return Err(err("the PayJoin URI is too long"));
    }
    let uri = Uri::try_from(text)
        .map_err(|e| err(format!("not a bitcoin: URI ({e})")))?
        .require_network(network)
        .map_err(|e| err(format!("the URI's address is for another network ({e})")))?
        .check_pj_supported()
        .map_err(|_| err("the URI has no pj= endpoint"))?;
    if uri.amount().is_some() {
        return Err(err(
            "the URI asks for an amount; a sweep pays the whole balance, so give a URI without one",
        ));
    }
    Ok(uri)
}

/// SHA-256 of a URI, as remembered once it is paid.
pub fn uri_hash(text: &str) -> String {
    sha256::Hash::hash(text.trim().as_bytes()).to_string()
}

/// POST `body` to an `https://` (or Tor `http://….onion`) endpoint and
/// return the response body. Plain http is only used for `.onion`, which a
/// proxy must reach.
pub async fn post(
    url: &str,
    content_type: &str,
    body: &[u8],
    pins: Option<Vec<[u8; 32]>>,
    proxy: Option<&deadhop::relay::ProxySpec>,
) -> Result<Vec<u8>> {
    let parsed = payjoin::Url::parse(url).map_err(|e| err(format!("bad endpoint ({e:?})")))?;
    let host = parsed.host_str();
    let host = host.trim_start_matches('[').trim_end_matches(']').to_string();
    let tls = match parsed.scheme() {
        "https" => true,
        "http" if host.ends_with(".onion") => false,
        _ => return Err(err("the endpoint must be https:// or a Tor .onion address")),
    };
    let port = parsed.port().unwrap_or(if tls { 443 } else { 80 });
    let mut target = Some(parsed.path()).filter(|p| !p.is_empty()).unwrap_or("/").to_string();
    if let Some(q) = parsed.query() {
        target.push('?');
        target.push_str(q);
    }
    let work = async {
        let stream: Box<dyn deadhop::relay::Io> = match proxy {
            Some(p) => deadhop::relay::ProxyTransport::new(p.clone())
                .tunnel(&host, port)
                .await
                .map_err(|e| err(format!("proxy: {e}")))?,
            None => {
                if !tls {
                    return Err(err("a .onion endpoint needs DEADHOP_WALLET_PROXY (Tor)"));
                }
                Box::new(TcpStream::connect((host.as_str(), port)).await.map_err(err)?)
            }
        };
        let mut stream: Box<dyn deadhop::relay::Io> = if tls {
            let config = Arc::new(deadhop::electrum::client_tls(pins));
            let name = rustls::pki_types::ServerName::try_from(host.clone()).map_err(err)?;
            Box::new(
                tokio_rustls::TlsConnector::from(config)
                    .connect(name, stream)
                    .await
                    .map_err(|e| err(format!("TLS: {e}")))?,
            )
        } else {
            stream
        };
        let head = format!(
            "POST {target} HTTP/1.1\r\nHost: {host}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(head.as_bytes()).await.map_err(err)?;
        stream.write_all(body).await.map_err(err)?;
        let mut raw = Vec::new();
        (&mut stream)
            .take(MAX_RESPONSE as u64 + 1)
            .read_to_end(&mut raw)
            .await
            .map_err(err)?;
        parse_response(&raw)
    };
    tokio::time::timeout(TIMEOUT, work)
        .await
        .unwrap_or_else(|_| Err(err("the receiver did not answer in time")))
}

/// The body of an HTTP/1.1 response (`Content-Length` or close-delimited).
fn parse_response(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() > MAX_RESPONSE {
        return Err(err("the receiver's answer is too large"));
    }
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| err("malformed HTTP response"))?;
    let head = std::str::from_utf8(&raw[..split]).map_err(|_| err("malformed HTTP response"))?;
    let body = &raw[split + 4..];
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| err("malformed HTTP response"))?;
    if head
        .lines()
        .any(|l| l.to_ascii_lowercase().starts_with("transfer-encoding:"))
    {
        return Err(err("chunked responses are not supported"));
    }
    let body = match head.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| v.trim().parse::<usize>().ok())
    }) {
        Some(Some(n)) if n <= body.len() => &body[..n],
        Some(_) => return Err(err("the receiver's answer is truncated")),
        None => body,
    };
    if status != 200 {
        let text: String = String::from_utf8_lossy(body)
            .chars()
            .take(200)
            .map(|c| if deadhop::service::is_plain_text(c) { c } else { '?' })
            .collect();
        return Err(err(format!("the receiver answered {status}: {text}")));
    }
    Ok(body.to_vec())
}

/// Sign the receiver's proposal, or say why not.
fn finish(
    s: &Sweeper,
    response: &[u8],
    ctx: payjoin::send::v1::V1Context,
    coins: &[Coin],
    original: &Transaction,
) -> Result<Transaction> {
    let mut proposal = ctx
        .process_response(response)
        .map_err(|e| err(format!("the receiver's proposal was refused: {e}")))?;
    let payee = original.output[0].script_pubkey.clone();
    let spent: Amount = coins.iter().map(|c| c.value).sum();
    let rules = Rules {
        to: vec![payee],
        // The receiver may add to its output, never take from it.
        min_to: original.output[0].value,
        // And this wallet pays no more than the Original's fee.
        max_cost: spent - original.output[0].value,
    };
    // (The payjoin library has already checked that every input of the
    // Original is still there.)
    tx::sign(&mut proposal, &s.keys, &index(coins), &rules, EcdsaSighashType::All)?;
    Ok(tx::extract(proposal))
}

/// A PayJoin sweep of `coins` at `rate` sat/vB.
pub async fn sweep(s: &mut Sweeper, coins: &[Coin], rate: f64, now: u64) -> Result<Sweep> {
    let file = s
        .cfg
        .payjoin_uri_file
        .clone()
        .ok_or_else(|| Error::Config("DEADHOP_WALLET_PAYJOIN_URI_FILE is not set".into()))?;
    let text = match std::fs::read_to_string(&file) {
        Ok(t) if !t.trim().is_empty() => t,
        _ => return Err(err(format!("waiting for a PayJoin URI in {}", file.display()))),
    };
    let hash = uri_hash(&text);
    if s.state.payjoin_used(&hash) {
        return Err(err(format!(
            "the URI in {} was already paid; waiting for a fresh one",
            file.display()
        )));
    }
    let uri = parse_uri(&text, s.cfg.network)?;
    let payee = uri.address().script_pubkey();
    let address = uri.address().to_string();

    // The Original: a complete, signed payment to the receiver.
    let refs: Vec<&Coin> = coins.iter().collect();
    let (mut original, fee) = tx::sweep(&refs, &payee, rate)?;
    let total: Amount = coins.iter().map(|c| c.value).sum();
    let rules = Rules {
        to: vec![payee.clone()],
        min_to: total - fee,
        max_cost: s.max_fee(coins.len(), &[&payee]),
    };
    tx::sign(&mut original, &s.keys, &index(coins), &rules, EcdsaSighashType::All)?;
    let original_tx = original.clone().extract_tx_unchecked_fee_rate();
    let min_rate = FeeRate::from_sat_per_vb_u32(rate.floor() as u32);
    // Cannot fail for the Original built above (one payee, no change, signed ALL).
    let builder = SenderBuilder::new(original, uri).always_disable_output_substitution();
    let sender = builder
        .build_recommended(min_rate)
        .ok()
        .ok_or(err("cannot prepare the request"))?;
    let (request, ctx) = sender.create_v1_post_request();
    // From here on the URI counts as used, whatever happens.
    s.state.use_payjoin(hash);
    let proxy = s.cfg.proxy.clone();
    let attempt = match post(
        &request.url,
        request.content_type,
        &request.body,
        s.cfg.payjoin_pins.clone(),
        proxy.as_ref(),
    )
    .await
    {
        Ok(body) => finish(s, &body, ctx, coins, &original_tx),
        Err(e) => Err(e),
    };
    let (tx, mode) = match attempt {
        Ok(tx) => (tx, Mode::Payjoin.label().to_string()),
        Err(e) => {
            tracing::warn!(error = %e, "payjoin failed, broadcasting the original payment instead");
            (original_tx, "payjoin-fallback".to_string())
        }
    };
    let txid = s.chain.broadcast(&tx).await?;
    let moved = tx
        .output
        .iter()
        .filter(|o| o.script_pubkey == payee)
        .map(|o| o.value)
        .sum::<Amount>();
    Ok(Sweep {
        at: now,
        mode,
        txid: txid.to_string(),
        spent_sat: total.to_sat(),
        moved_sat: moved.to_sat(),
        to: address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn uris_are_checked() {
        let net = bitcoin::Network::Regtest;
        let addr = crate::keys::tests::keys().address(0, 0).to_string();
        let ok = format!("bitcoin:{addr}?pj=https://example.com/pj");
        assert!(parse_uri(&format!("  {ok}\n"), net).is_ok());
        assert_eq!(uri_hash(&ok), uri_hash(&format!("{ok}\n")));
        let e = |t: &str| parse_uri(t, net).err().unwrap().to_string();
        assert!(e("hello").contains("not a bitcoin"));
        assert!(e(&format!("bitcoin:{addr}")).contains("pj="));
        assert!(e(&format!("bitcoin:{addr}?amount=1&pj=https://example.com/pj")).contains("amount"));
        assert!(e(&format!("bitcoin:{addr}?pj=http://example.com/pj")).contains("not a bitcoin"));
        assert!(e("bitcoin:bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu?pj=https://example.com/pj").contains("network"));
        assert!(e(&"x".repeat(MAX_URI + 1)).contains("too long"));
    }

    #[test]
    fn http_responses_are_parsed_strictly() {
        let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcdef";
        assert_eq!(parse_response(ok).unwrap(), b"abc");
        assert_eq!(parse_response(b"HTTP/1.1 200 OK\r\n\r\nall").unwrap(), b"all");
        let e = |r: &[u8]| parse_response(r).unwrap_err().to_string();
        assert!(e(b"HTTP/1.1 400 Bad\r\nContent-Length: 5\r\n\r\n{\"x\"}").contains("400"));
        assert!(e(b"garbage").contains("malformed"));
        assert!(e(b"HTTP/1.1 abc\r\n\r\n").contains("malformed"));
        assert!(e(b"\xff\xff\r\n\r\n").contains("malformed"));
        assert!(e(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nab").contains("truncated"));
        assert!(e(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n").contains("chunked"));
        assert!(e(&vec![b'a'; MAX_RESPONSE + 1]).contains("too large"));
    }

    /// A SOCKS5 proxy that answers every connection itself with `reply`.
    async fn socks5_that_answers(reply: &'static [u8]) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut c, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            c.read_exact(&mut greeting).await.unwrap();
            c.write_all(&[5, 0]).await.unwrap();
            let mut head = [0u8; 5];
            c.read_exact(&mut head).await.unwrap();
            let mut rest = vec![0u8; head[4] as usize + 2];
            c.read_exact(&mut rest).await.unwrap();
            c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
            // The whole request (the body is one byte), then the answer.
            let mut req = Vec::new();
            let mut buf = [0u8; 1024];
            while !req.ends_with(b"\r\n\r\nx") {
                let n = c.read(&mut buf).await.unwrap();
                req.extend_from_slice(&buf[..n]);
            }
            assert!(String::from_utf8_lossy(&req).starts_with("POST /?v=1 HTTP/1.1\r\nHost: abc.onion"));
            c.write_all(reply).await.unwrap();
            c.shutdown().await.unwrap();
        });
        port
    }

    #[tokio::test]
    async fn onion_endpoints_go_through_the_proxy() {
        let port = socks5_that_answers(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
        let proxy = deadhop::relay::parse_proxy(&format!("socks5://127.0.0.1:{port}"))
            .unwrap()
            .unwrap();
        let body = post("http://abc.onion?v=1", "text/plain", b"x", None, Some(&proxy))
            .await
            .unwrap();
        assert_eq!(body, b"ok");
        let dead = deadhop::relay::parse_proxy("socks5://127.0.0.1:1").unwrap().unwrap();
        let e = post("http://abc.onion/pj", "text/plain", b"x", None, Some(&dead))
            .await
            .unwrap_err();
        assert!(e.to_string().contains("proxy"), "{e}");
    }

    #[tokio::test]
    async fn waits_for_a_fresh_usable_uri() {
        use crate::chain::tests::FakeChain;
        use crate::keys::EXTERNAL;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("payjoin.uri");
        let k = crate::keys::tests::keys();
        let chain = FakeChain {
            tip: 100,
            relay: 1.0,
            ..FakeChain::default()
        };
        chain.fund(&k.script(EXTERNAL, 0), 200_000, Some(90));
        let (mut s, _) = crate::sweep::tests::sweeper(
            dir.path(),
            chain,
            &[
                ("DEADHOP_WALLET_MODE", "payjoin".into()),
                ("DEADHOP_WALLET_PAYJOIN_URI_FILE", file.to_string_lossy().into_owned()),
            ],
        );
        let waiting = |o: &crate::sweep::Outcome, text: &str| matches!(o, crate::sweep::Outcome::Waiting { why, .. } if why.contains(text));
        let o = s.tick(1).await.unwrap();
        assert!(waiting(&o, "waiting for a PayJoin URI"), "{o:?}");
        std::fs::write(&file, "bitcoin:nonsense").unwrap();
        let o = s.tick(2).await.unwrap();
        assert!(waiting(&o, "not a bitcoin"), "{o:?}");
        // A URI-less configuration cannot get here.
        s.cfg.payjoin_uri_file = None;
        assert!(matches!(sweep(&mut s, &[], 1.0, 3).await, Err(Error::Config(_))));
    }

    /// An HTTPS server on 127.0.0.1 (the test certificate) that answers
    /// every request with `reply`. Returns its port and certificate pin.
    async fn https_that_answers(reply: &'static [u8]) -> (u16, [u8; 32]) {
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        let cert =
            CertificateDer::from_pem_slice(include_bytes!("../../server/tests/fixtures/proxy-test-cert.pem")).unwrap();
        let pin = deadhop::electrum::parse_fingerprint(&deadhop::electrum::fingerprint_hex(cert.as_ref())).unwrap();
        let key =
            PrivateKeyDer::from_pem_slice(include_bytes!("../../server/tests/fixtures/proxy-test-key.pem")).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let mut buf = vec![0u8; 64 * 1024];
            let _ = tls.read(&mut buf).await.unwrap();
            tls.write_all(reply).await.unwrap();
            tls.shutdown().await.unwrap();
        });
        (port, pin)
    }

    #[tokio::test]
    async fn a_refused_proposal_falls_back_to_the_original() {
        crate::test_logs();
        use crate::chain::tests::FakeChain;
        use crate::keys::EXTERNAL;
        let (port, pin) = https_that_answers(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\njunk!").await;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("payjoin.uri");
        let k = crate::keys::tests::keys();
        let receiver = k.address(EXTERNAL, 77);
        std::fs::write(&file, format!("bitcoin:{receiver}?pj=https://127.0.0.1:{port}/pj")).unwrap();
        let chain = FakeChain {
            tip: 100,
            relay: 1.0,
            ..FakeChain::default()
        };
        chain.fund(&k.script(EXTERNAL, 0), 200_000, Some(90));
        let (mut s, shared) = crate::sweep::tests::sweeper(
            dir.path(),
            chain,
            &[
                ("DEADHOP_WALLET_MODE", "payjoin".into()),
                ("DEADHOP_WALLET_PAYJOIN_URI_FILE", file.to_string_lossy().into_owned()),
            ],
        );
        s.cfg.payjoin_pins = Some(vec![pin]);
        let o = s.tick(1).await.unwrap();
        assert!(
            matches!(&o, crate::sweep::Outcome::Swept(w) if w.mode == "payjoin-fallback"),
            "{o:?}"
        );
        let sent = shared.0.broadcasts.lock().unwrap()[0].clone();
        assert_eq!(sent.output[0].script_pubkey, receiver.script_pubkey());
        // The URI was used up, and that is on disk.
        assert_eq!(crate::state::State::load(dir.path()).unwrap().used_payjoin.len(), 1);
    }

    #[tokio::test]
    async fn tls_problems_and_silence_are_errors() {
        // Not TLS at all.
        let plain = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = plain.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut c, _) = plain.accept().await.unwrap();
            c.write_all(b"HTTP/1.1 400 nope\r\n\r\n").await.unwrap();
        });
        let e = post(&format!("https://127.0.0.1:{port}/pj"), "text/plain", b"", None, None)
            .await
            .unwrap_err();
        assert!(e.to_string().contains("TLS"), "{e}");
        // Connects (the kernel queues it), never answers.
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = silent.local_addr().unwrap().port();
        let e = post(&format!("https://127.0.0.1:{port}/pj"), "text/plain", b"", None, None)
            .await
            .unwrap_err();
        assert!(e.to_string().contains("in time"), "{e}");
        drop(silent);
    }

    #[tokio::test]
    async fn endpoints_must_be_private() {
        let e = |r: Result<Vec<u8>>| r.unwrap_err().to_string();
        assert!(e(post("http://example.com/pj", "text/plain", b"", None, None).await).contains("https"));
        assert!(e(post("http://abc.onion/pj", "text/plain", b"", None, None).await).contains("PROXY"));
        assert!(e(post("not a url", "text/plain", b"", None, None).await).contains("bad endpoint"));
        assert!(!e(post("https://127.0.0.1:1/pj", "text/plain", b"", None, None).await).is_empty());
    }
}
