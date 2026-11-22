//! CoinJoin sweeps, following the joinstr protocol (coinjoin over Nostr,
//! <https://docs.joinstr.xyz/protocol/>). There is no coordinator:
//!
//! 1. A pool is announced (kind 2022, signed by a fresh pool key) with a
//!    denomination, a number of peers, a fee rate, a relay and an expiry.
//! 2. Each joiner sends `join_pool` from a fresh key (NIP-04, kind 4) and
//!    receives the pool's private key in its credentials. Holding that key
//!    makes it a member; every pool message is then signed by, and encrypted
//!    to, the pool key, so members cannot tell whose message is whose.
//! 3. Each member registers one output address. Once there are as many as
//!    peers, each member signs its single input with `SIGHASH_ALL |
//!    ANYONECANPAY` against all the outputs and posts that PSBT.
//! 4. With all inputs in, every member combines them, checks the result and
//!    broadcasts it.
//!
//! A signature commits to every output, so whatever set of inputs is finally
//! combined, this wallet's output receives its amount, or the transaction is
//! invalid. Before it signs, the wallet checks (as for every signature) that
//! its coin goes to its own fresh destination address and that it loses at
//! most the joinstr cap. A round that does not complete in time is
//! abandoned and nothing is spent.
//!
//! Interoperability notes: the message flow and field names follow the
//! joinstr spec; PSBTs are version 0 (the bitcoin library has no version 2),
//! and the LSAG recovery phase is not implemented.
//!
//! Before a round, the confirmed coins are consolidated into one "premix"
//! coin of the denomination plus a small excess (joinstr takes exactly one
//! input per member, between denomination + 500 and + 5000 sat), with the
//! rest returned to the wallet's change chain.

use std::collections::{BTreeSet, HashSet};
use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::base64::{engine::general_purpose::STANDARD as B64, Engine};
use bitcoin::psbt::Psbt;
use bitcoin::sighash::EcdsaSighashType;
use bitcoin::{Address, Amount, Network, ScriptBuf, Sequence, Transaction, TxIn, TxOut};
use nostr_sdk::nips::nip04;
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::config::{CoinjoinConfig, Mode};
use crate::error::{Error, Result};
use crate::keys::INTERNAL;
use crate::state::Sweep;
use crate::sweep::{index, Sweeper};
use crate::tx::{self, Coin, Rules, DUST_SAT};

/// Pool announcement kind.
pub const KIND_POOL: u16 = 2022;
/// Least a member's input may exceed the denomination by.
pub const MIN_EXCESS_SAT: u64 = 500;
/// Most a member's input may exceed the denomination by.
pub const MAX_EXCESS_SAT: u64 = 5_000;
/// A member refuses to sign if its input minus its output is more than this.
pub const MAX_COST_SAT: u64 = 15_000;
/// The premix coin is the denomination plus this.
pub const PREMIX_EXCESS_SAT: u64 = 1_000;
/// Virtual bytes each member pays for (its input and its output).
const VBYTES_PER_PEER: f64 = 100.0;
/// How often the relay is asked for new messages.
const POLL: Duration = Duration::from_secs(2);
/// How long a joiner waits for credentials from one pool.
#[cfg(not(test))]
const CREDENTIALS_WAIT: Duration = Duration::from_secs(30);
#[cfg(test)]
const CREDENTIALS_WAIT: Duration = Duration::from_secs(3);

fn err(why: impl std::fmt::Display) -> Error {
    Error::Coinjoin(why.to_string())
}

/// A pool announcement (and, with `private_key`, its credentials).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Pool {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
    pub public_key: String,
    /// In BTC.
    pub denomination: f64,
    pub peers: u32,
    /// Unix time the pool expires.
    pub timeout: u64,
    pub relay: String,
    /// sat/vB.
    pub fee_rate: f64,
    #[serde(default)]
    pub transport: String,
    #[serde(default)]
    pub vpn_gateway: String,
}

impl Pool {
    pub fn denomination_sat(&self) -> u64 {
        (self.denomination * 100_000_000.0).round() as u64
    }

    /// Every member's output amount: the denomination less its share of the fee.
    pub fn output_sat(&self) -> u64 {
        output_sat(self.denomination_sat(), self.fee_rate)
    }

    /// Whether this wallet would take part.
    pub fn acceptable(&self, cfg: &CoinjoinConfig, max_fee_rate: f64, now: u64) -> bool {
        self.kind == "new_pool"
            && self.denomination_sat() == cfg.denomination_sat
            && self.peers == cfg.peers
            && self.relay.trim_end_matches('/') == cfg.relay.trim_end_matches('/')
            && self.timeout > now + 60
            && self.fee_rate > 0.0
            && self.fee_rate <= max_fee_rate
            && self.output_sat() >= DUST_SAT
    }
}

/// Every member's output amount for `denomination_sat` at `fee_rate`.
pub fn output_sat(denomination_sat: u64, fee_rate: f64) -> u64 {
    denomination_sat.saturating_sub((fee_rate * VBYTES_PER_PEER).ceil() as u64)
}

/// Where pool messages are posted and read: the relay, or a fake in tests.
#[async_trait]
pub trait Board: Send + Sync {
    async fn publish(&self, event: Event) -> Result<()>;
    async fn fetch(&self, filter: Filter) -> Result<Vec<Event>>;
}

#[async_trait]
impl Board for Client {
    async fn publish(&self, event: Event) -> Result<()> {
        self.send_event(&event).await.map_err(err)?;
        Ok(())
    }
    async fn fetch(&self, filter: Filter) -> Result<Vec<Event>> {
        Ok(self
            .fetch_events(filter, Duration::from_secs(10))
            .await
            .map_err(err)?
            .into_iter()
            .collect())
    }
}

/// An encrypted kind 4 message from `from` to `to`.
fn message(from: &Keys, to: &PublicKey, body: &Value) -> Result<Event> {
    let content = nip04::encrypt(from.secret_key(), to, body.to_string()).map_err(err)?;
    // Pool messages go from the pool key to itself: keep the `p` tag the
    // protocol expects, which the builder would otherwise drop.
    EventBuilder::new(Kind::EncryptedDirectMessage, content)
        .tag(Tag::public_key(*to))
        .allow_self_tagging()
        .sign_with_keys(from)
        .map_err(err)
}

/// Decrypt a kind 4 message addressed to `me`.
fn open(me: &Keys, event: &Event) -> Option<Value> {
    event.verify().ok()?;
    let text = nip04::decrypt(me.secret_key(), &event.pubkey, &event.content).ok()?;
    serde_json::from_str(&text).ok()
}

/// What a member collected from the pool so far.
#[derive(Debug, Default)]
struct Seen {
    outputs: BTreeSet<String>,
    inputs: Vec<Psbt>,
    seen_inputs: HashSet<String>,
}

/// One round in one pool.
pub struct Round<'a> {
    pub board: &'a dyn Board,
    pub pool: Pool,
    pub pool_keys: Keys,
    pub creator: bool,
    pub network: Network,
    /// When the pool was announced: every pool message is newer, whenever
    /// this member started reading.
    pub since: Timestamp,
}

/// Look for a pool to join; announce one when there is none.
pub async fn find_or_create<'a>(
    board: &'a dyn Board,
    cfg: &CoinjoinConfig,
    max_fee_rate: f64,
    rate: f64,
    now: u64,
    network: Network,
) -> Result<Round<'a>> {
    let pools = board
        .fetch(
            Filter::new()
                .kind(Kind::Custom(KIND_POOL))
                .since(Timestamp::from(now.saturating_sub(cfg.timeout_secs))),
        )
        .await?;
    let mut candidates: Vec<(Event, Pool)> = pools
        .into_iter()
        .filter(|e| e.verify().is_ok())
        .filter_map(|e| {
            let p: Pool = serde_json::from_str(&e.content).ok()?;
            (p.public_key == e.pubkey.to_hex() && p.acceptable(cfg, max_fee_rate, now)).then_some((e, p))
        })
        .collect();
    candidates.sort_by_key(|(e, _)| std::cmp::Reverse(e.created_at));
    for (event, pool) in candidates {
        if let Some(keys) = join(board, &event.pubkey, &pool).await? {
            return Ok(Round {
                board,
                pool,
                pool_keys: keys,
                creator: false,
                network,
                since: event.created_at,
            });
        }
    }
    let pool_keys = Keys::generate();
    let mut id = [0u8; 5];
    getrandom::getrandom(&mut id).expect("the operating system provides randomness");
    let pool = Pool {
        kind: "new_pool".into(),
        id: format!("{}{now}", hex::encode(id)),
        public_key: pool_keys.public_key().to_hex(),
        denomination: cfg.denomination_sat as f64 / 100_000_000.0,
        peers: cfg.peers,
        timeout: now + cfg.timeout_secs,
        relay: cfg.relay.clone(),
        fee_rate: rate.ceil(),
        transport: "tor".into(),
        vpn_gateway: String::new(),
    };
    let announcement = EventBuilder::new(
        Kind::Custom(KIND_POOL),
        serde_json::to_string(&pool).expect("plain data"),
    )
    .sign_with_keys(&pool_keys)
    .map_err(err)?;
    let since = announcement.created_at;
    board.publish(announcement).await?;
    tracing::info!(pool = %pool.id, peers = pool.peers, "announced a coinjoin pool");
    Ok(Round {
        board,
        pool,
        pool_keys,
        creator: true,
        network,
        since,
    })
}

/// Ask to join `pool`; returns its keys from the credentials.
async fn join(board: &dyn Board, pool_pk: &PublicKey, pool: &Pool) -> Result<Option<Keys>> {
    let me = Keys::generate();
    board
        .publish(message(&me, pool_pk, &json!({"type": "join_pool"}))?)
        .await?;
    let deadline = tokio::time::Instant::now() + CREDENTIALS_WAIT;
    while tokio::time::Instant::now() < deadline {
        tokio::time::sleep(POLL).await;
        let replies = board
            .fetch(Filter::new().kind(Kind::EncryptedDirectMessage).pubkey(me.public_key()))
            .await?;
        let found = replies
            .iter()
            .find_map(|r| open(&me, r).and_then(|v| credentials(&v, pool)));
        if found.is_some() {
            return Ok(found);
        }
    }
    Ok(None)
}

/// The pool keys in a credentials message, if it matches the announcement.
fn credentials(v: &Value, pool: &Pool) -> Option<Keys> {
    let sk = SecretKey::from_hex(v["private_key"].as_str()?).ok()?;
    let keys = Keys::new(sk);
    let mut announced: Value = serde_json::to_value(pool).ok()?;
    let fields = announced.as_object_mut()?;
    fields.remove("type");
    let ok = keys.public_key().to_hex() == pool.public_key
        && fields.iter().all(|(k, want)| match (&v[k], want) {
            (Value::Number(a), Value::Number(b)) => a.as_f64() == b.as_f64(),
            (a, b) => a == b,
        });
    ok.then_some(keys)
}

/// Outputs in BIP-69 order: by amount, then by script bytes.
fn bip69_outputs(mut outputs: Vec<TxOut>) -> Vec<TxOut> {
    outputs.sort_by(|a, b| {
        a.value
            .cmp(&b.value)
            .then_with(|| a.script_pubkey.as_bytes().cmp(b.script_pubkey.as_bytes()))
    });
    outputs
}

impl Round<'_> {
    fn pool_pk(&self) -> PublicKey {
        self.pool_keys.public_key()
    }

    async fn post(&self, body: Value) -> Result<()> {
        self.board
            .publish(message(&self.pool_keys, &self.pool_pk(), &body)?)
            .await
    }

    /// The outputs every member signs, from the registered addresses.
    fn outputs(&self, addresses: &BTreeSet<String>) -> Result<Vec<TxOut>> {
        let value = Amount::from_sat(self.pool.output_sat());
        let outs = addresses
            .iter()
            .map(|a| {
                let script = Address::from_str(a)
                    .ok()
                    .and_then(|a| a.require_network(self.network).ok())
                    .ok_or_else(|| err(format!("a member registered an invalid address {a}")))?
                    .script_pubkey();
                Ok(TxOut {
                    value,
                    script_pubkey: script,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(bip69_outputs(outs))
    }

    /// Answer join requests (the creator only), up to `peers - 1` members.
    async fn admit(&self, admitted: &mut HashSet<PublicKey>, since: Timestamp) -> Result<()> {
        if !self.creator || admitted.len() + 1 >= self.pool.peers as usize {
            return Ok(());
        }
        let requests = self
            .board
            .fetch(
                Filter::new()
                    .kind(Kind::EncryptedDirectMessage)
                    .pubkey(self.pool_pk())
                    .since(since),
            )
            .await?;
        for r in requests.iter().filter(|r| r.pubkey != self.pool_pk()) {
            if admitted.len() + 1 >= self.pool.peers as usize || admitted.contains(&r.pubkey) {
                continue;
            }
            if open(&self.pool_keys, r).is_some_and(|v| v["type"] == "join_pool") {
                let mut creds = serde_json::to_value(&self.pool).expect("plain data");
                creds["private_key"] = json!(self.pool_keys.secret_key().to_secret_hex());
                self.board
                    .publish(message(&Keys::generate(), &r.pubkey, &creds)?)
                    .await?;
                admitted.insert(r.pubkey);
            }
        }
        Ok(())
    }

    /// Read the pool's messages into `seen`.
    async fn collect(&self, seen: &mut Seen, since: Timestamp) -> Result<()> {
        let events = self
            .board
            .fetch(
                Filter::new()
                    .kind(Kind::EncryptedDirectMessage)
                    .author(self.pool_pk())
                    .since(since),
            )
            .await?;
        for e in &events {
            let Some(v) = open(&self.pool_keys, e) else {
                continue;
            };
            match v["type"].as_str() {
                Some("output") => {
                    if let Some(a) = v["address"].as_str() {
                        seen.outputs.insert(a.to_string());
                    }
                }
                Some("input") => {
                    let Some(text) = v["psbt"].as_str() else {
                        continue;
                    };
                    if !seen.seen_inputs.insert(text.to_string()) {
                        continue;
                    }
                    if let Some(p) = B64.decode(text).ok().and_then(|b| Psbt::deserialize(&b).ok()) {
                        seen.inputs.push(p);
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// This member's input, signed `ALL|ANYONECANPAY` over every output.
    pub fn sign_input(&self, s: &Sweeper, coin: &Coin, dest: &ScriptBuf, outputs: Vec<TxOut>) -> Result<Psbt> {
        let mut psbt = tx::build(&[coin], outputs, Sequence::ENABLE_LOCKTIME_NO_RBF);
        let out = Amount::from_sat(self.pool.output_sat());
        let rules = Rules {
            to: vec![dest.clone()],
            min_to: out,
            // joinstr's cap on what a member gives up (its input minus its output).
            max_cost: Amount::from_sat(MAX_COST_SAT),
        };
        // Exactly one of our outputs, or a member could make us pay ourselves twice.
        if psbt
            .unsigned_tx
            .output
            .iter()
            .filter(|o| &o.script_pubkey == dest)
            .count()
            != 1
        {
            return Err(err("our output is missing from the pool, or registered twice"));
        }
        let ours = index(std::slice::from_ref(coin));
        tx::sign(&mut psbt, &s.keys, &ours, &rules, EcdsaSighashType::AllPlusAnyoneCanPay).map(|_| psbt)
    }

    /// Combine the members' inputs into the final transaction.
    pub fn combine(&self, inputs: &[Psbt], outputs: &[TxOut], ours: &Coin) -> Result<Transaction> {
        let mut txins: Vec<TxIn> = Vec::new();
        let mut spent = HashSet::new();
        for p in inputs {
            let ok = p.unsigned_tx.input.len() == 1
                && p.inputs.len() == 1
                && p.unsigned_tx.output == outputs
                && p.inputs[0].final_script_witness.as_ref().is_some_and(|w| !w.is_empty());
            if !ok {
                return Err(err("a member's input does not match the pool"));
            }
            let mut txin = p.unsigned_tx.input[0].clone();
            if !spent.insert(txin.previous_output) {
                return Err(err("two members posted the same coin"));
            }
            txin.witness = p.inputs[0].final_script_witness.clone().expect("checked above");
            txin.script_sig = ScriptBuf::new();
            txins.push(txin);
        }
        if !spent.contains(&ours.outpoint) {
            return Err(err("our input is not in the final transaction"));
        }
        // BIP-69 input order: by txid (as displayed), then output index.
        txins.sort_by(|a, b| {
            a.previous_output
                .txid
                .to_string()
                .cmp(&b.previous_output.txid.to_string())
                .then(a.previous_output.vout.cmp(&b.previous_output.vout))
        });
        Ok(Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: txins,
            output: outputs.to_vec(),
        })
    }

    /// Take part until the transaction is complete or the round expires.
    pub async fn run(
        &self,
        s: &Sweeper,
        coin: &Coin,
        dest: &ScriptBuf,
        address: &str,
        deadline: u64,
    ) -> Result<Transaction> {
        // A little slack for clocks that disagree.
        let since = Timestamp::from(self.since.as_secs().saturating_sub(60));
        let mut admitted = HashSet::new();
        let mut seen = Seen::default();
        self.post(json!({"address": address, "type": "output"})).await?;
        let mut signed: Option<Vec<TxOut>> = None;
        let peers = self.pool.peers as usize;
        loop {
            if Timestamp::now().as_secs() >= deadline.min(self.pool.timeout) {
                return Err(err(format!(
                    "the round in pool {} did not complete in time ({} of {} outputs, {} of {} inputs)",
                    self.pool.id,
                    seen.outputs.len(),
                    peers,
                    seen.inputs.len(),
                    peers
                )));
            }
            self.admit(&mut admitted, since).await?;
            self.collect(&mut seen, since).await?;
            if seen.outputs.len() > peers {
                return Err(err("more outputs than peers were registered; leaving the pool"));
            }
            if signed.is_none() && seen.outputs.len() == peers {
                let outputs = self.outputs(&seen.outputs)?;
                let psbt = self.sign_input(s, coin, dest, outputs.clone())?;
                self.post(json!({"psbt": B64.encode(psbt.serialize()), "type": "input"}))
                    .await?;
                signed = Some(outputs);
            }
            if let Some(outputs) = &signed {
                let matching: Vec<Psbt> = seen
                    .inputs
                    .iter()
                    .filter(|p| &p.unsigned_tx.output == outputs)
                    .cloned()
                    .collect();
                if matching.len() >= peers {
                    return self.combine(&matching[..peers], outputs, coin);
                }
            }
            tokio::time::sleep(POLL).await;
        }
    }
}

/// Consolidate the confirmed coins into one premix coin (and change).
async fn premix(s: &mut Sweeper, cj: &CoinjoinConfig, coins: &[Coin], rate: f64, now: u64) -> Result<Sweep> {
    let total: Amount = coins.iter().map(|c| c.value).sum();
    let mix = Amount::from_sat(cj.denomination_sat + PREMIX_EXCESS_SAT);
    let mix_script = s.keys.script(INTERNAL, s.state.next_change);
    let change_script = s.keys.script(INTERNAL, s.state.next_change + 1);
    let fee2 = tx::fee(tx::vsize(coins.len(), &[&mix_script, &change_script]), rate);
    let change = total.checked_sub(mix + fee2);
    let outputs = match change {
        Some(c) if c.to_sat() >= DUST_SAT => vec![
            TxOut {
                value: mix,
                script_pubkey: mix_script.clone(),
            },
            TxOut {
                value: c,
                script_pubkey: change_script.clone(),
            },
        ],
        _ => {
            // No room for change: everything into the premix coin, if that
            // stays within what a pool accepts.
            let fee1 = tx::fee(tx::vsize(coins.len(), &[&mix_script]), rate);
            let all = total.checked_sub(fee1).unwrap_or(Amount::ZERO);
            if all < mix || all.to_sat() > cj.denomination_sat + MAX_EXCESS_SAT {
                return Err(err(format!(
                    "{total} cannot make a premix coin of {mix} plus fees; waiting for more funds"
                )));
            }
            vec![TxOut {
                value: all,
                script_pubkey: mix_script.clone(),
            }]
        }
    };
    let moved: Amount = outputs.iter().map(|o| o.value).sum();
    let refs: Vec<&Coin> = coins.iter().collect();
    let mut psbt = tx::build(&refs, outputs, Sequence::ENABLE_RBF_NO_LOCKTIME);
    let rules = Rules {
        to: vec![mix_script.clone(), change_script.clone()],
        min_to: moved,
        max_cost: s.max_fee(coins.len(), &[&mix_script, &change_script]),
    };
    tx::sign(&mut psbt, &s.keys, &index(coins), &rules, EcdsaSighashType::All)?;
    let txid = s.chain.broadcast(&tx::extract(psbt)).await?;
    let address = s.keys.address(INTERNAL, s.state.next_change).to_string();
    s.state.next_change += 2;
    Ok(Sweep {
        at: now,
        mode: "coinjoin-premix".into(),
        txid: txid.to_string(),
        spent_sat: total.to_sat(),
        moved_sat: mix.to_sat(),
        to: address,
    })
}

/// Broadcast, accepting that another member may have been first.
async fn broadcast(s: &Sweeper, tx: &Transaction) -> Result<bitcoin::Txid> {
    match s.chain.broadcast(tx).await {
        Ok(t) => Ok(t),
        Err(e) if e.to_string().contains("already") || e.to_string().contains("known") => Ok(tx.compute_txid()),
        Err(e) => Err(e),
    }
}

/// Whether `coin` can go into a pool as it is.
pub fn premix_ready(cj: &CoinjoinConfig, coin: &Coin) -> bool {
    (cj.denomination_sat + MIN_EXCESS_SAT..=cj.denomination_sat + MAX_EXCESS_SAT).contains(&coin.value.to_sat())
}

/// A CoinJoin sweep: premix if needed, then one round.
pub async fn sweep(s: &mut Sweeper, coins: &[Coin], rate: f64, now: u64) -> Result<Sweep> {
    let cj = s
        .cfg
        .coinjoin
        .clone()
        .ok_or_else(|| Error::Config("coinjoin mode needs its settings".into()))?;
    let Some(coin) = coins.iter().find(|c| premix_ready(&cj, c)).cloned() else {
        return premix(s, &cj, coins, rate, now).await;
    };
    let client = deadhop::relay::Pool::new(Keys::generate(), s.cfg.proxy.clone());
    let client = client.client().clone();
    client.add_relay(&cj.relay).await.map_err(err)?;
    client.connect().await;
    let result = round(s, client.as_ref(), &cj, &coin, rate, now).await;
    client.disconnect().await;
    result
}

/// Find or announce a pool and take part with `coin`.
pub async fn round(
    s: &mut Sweeper,
    board: &dyn Board,
    cj: &CoinjoinConfig,
    coin: &Coin,
    rate: f64,
    now: u64,
) -> Result<Sweep> {
    let round = find_or_create(board, cj, s.cfg.max_fee_rate, rate, now, s.cfg.network).await?;
    let (dest, address) = s.destination()?;
    let tx = round.run(s, coin, &dest, &address, now + cj.timeout_secs).await?;
    let txid = broadcast(s, &tx).await?;
    s.state.next_destination += 1;
    Ok(Sweep {
        at: now,
        mode: Mode::Coinjoin.label().into(),
        txid: txid.to_string(),
        spent_sat: coin.value.to_sat(),
        moved_sat: round.pool.output_sat(),
        to: address,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;

    /// An in-memory relay.
    #[derive(Default)]
    pub struct FakeBoard(pub Mutex<Vec<Event>>);

    #[async_trait]
    impl Board for FakeBoard {
        async fn publish(&self, event: Event) -> Result<()> {
            self.0.lock().unwrap().push(event);
            Ok(())
        }
        async fn fetch(&self, filter: Filter) -> Result<Vec<Event>> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .iter()
                .filter(|e| filter.match_event(e, MatchEventOptions::new()))
                .cloned()
                .collect())
        }
    }

    pub fn cfg(peers: u32) -> CoinjoinConfig {
        CoinjoinConfig {
            relay: "ws://127.0.0.1:7777".into(),
            denomination_sat: 100_000,
            peers,
            timeout_secs: 600,
        }
    }

    /// A member: its own keys and a premix coin of denomination + 1000.
    fn member(n: u8, dir: &std::path::Path) -> (Sweeper, Coin) {
        let keys = crate::keys::Keys::from_phrase(&bip39::Mnemonic::from_entropy(&[n; 32]).unwrap(), Network::Regtest);
        let mut coin = crate::tx::tests::coin(&keys, 0, 101_000, n);
        coin.chain = INTERNAL;
        coin.script = keys.script(INTERNAL, 0);
        let cfg = crate::sweep::tests::config(dir, &[]);
        let s = Sweeper::new(
            cfg,
            keys,
            Box::new(crate::chain::tests::FakeChain::default()),
            Default::default(),
        )
        .unwrap();
        (s, coin)
    }

    #[tokio::test]
    async fn three_members_build_one_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let board = FakeBoard::default();
        let c = cfg(3);
        let now = Timestamp::now().as_secs();
        let members: Vec<(Sweeper, Coin)> = (1..=3).map(|n| member(n, dir.path())).collect();
        let dests: Vec<(ScriptBuf, String)> = (0..3u32)
            .map(|i| {
                let a = members[0].0.keys.address(crate::keys::EXTERNAL, 100 + i);
                (a.script_pubkey(), a.to_string())
            })
            .collect();
        let creator = find_or_create(&board, &c, 20.0, 2.0, now, Network::Regtest)
            .await
            .unwrap();
        assert!(creator.creator);
        async fn take_part(
            round: Round<'_>,
            s: &Sweeper,
            coin: &Coin,
            dest: &(ScriptBuf, String),
            deadline: u64,
        ) -> Result<Transaction> {
            round.run(s, coin, &dest.0, &dest.1, deadline).await
        }
        async fn join_and_take_part(
            board: &FakeBoard,
            c: &CoinjoinConfig,
            now: u64,
            s: &Sweeper,
            coin: &Coin,
            dest: &(ScriptBuf, String),
        ) -> Result<Transaction> {
            let round = find_or_create(board, c, 20.0, 2.0, now, Network::Regtest).await?;
            assert!(!round.creator, "joins the announced pool");
            take_part(round, s, coin, dest, now + 120).await
        }
        let (a, b, d) = tokio::join!(
            take_part(creator, &members[0].0, &members[0].1, &dests[0], now + 120),
            join_and_take_part(&board, &c, now, &members[1].0, &members[1].1, &dests[1]),
            // The last member starts long after the others registered.
            async {
                tokio::time::sleep(Duration::from_secs(8)).await;
                join_and_take_part(&board, &c, now, &members[2].0, &members[2].1, &dests[2]).await
            },
        );
        let txs = [a.unwrap(), b.unwrap(), d.unwrap()];
        assert!(
            txs.iter().all(|t| t == &txs[0]),
            "every member built the same transaction"
        );
        let tx = &txs[0];
        assert_eq!(tx.input.len(), 3);
        assert!(tx.input.iter().all(|i| i.witness.len() == 2));
        assert_eq!(tx.output.len(), 3);
        assert!(tx.output.iter().all(|o| o.value.to_sat() == output_sat(100_000, 2.0)));
        for (dest, _) in &dests {
            assert_eq!(tx.output.iter().filter(|o| &o.script_pubkey == dest).count(), 1);
        }
        // Each signature commits to every output but only to its own input.
        let sig = &tx.input[0].witness.to_vec()[0];
        assert_eq!(*sig.last().unwrap(), 0x81);
        // A late joiner finds the pool full: the creator admitted only two.
        let late = Keys::generate();
        let pool_pk = PublicKey::from_hex(&board.0.lock().unwrap()[0].pubkey.to_hex()).unwrap();
        board
            .publish(message(&late, &pool_pk, &json!({"type": "join_pool"})).unwrap())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_round_without_enough_members_expires_without_spending() {
        let dir = tempfile::tempdir().unwrap();
        let board = FakeBoard::default();
        let now = Timestamp::now().as_secs();
        let round = find_or_create(&board, &cfg(3), 20.0, 2.0, now, Network::Regtest)
            .await
            .unwrap();
        let (s, coin) = member(1, dir.path());
        let (dest, addr) = (
            s.keys.script(crate::keys::EXTERNAL, 1),
            s.keys.address(crate::keys::EXTERNAL, 1).to_string(),
        );
        let e = round
            .run(&s, &coin, &dest, &addr, now + 1)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("did not complete in time") && e.contains("1 of 3 outputs"),
            "{e}"
        );
    }

    #[tokio::test]
    async fn hostile_pool_messages_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let board = FakeBoard::default();
        let now = Timestamp::now().as_secs();
        let round = find_or_create(&board, &cfg(2), 20.0, 2.0, now, Network::Regtest)
            .await
            .unwrap();
        let (s, coin) = member(1, dir.path());
        let dest = s.keys.script(crate::keys::EXTERNAL, 1);
        // An address for another network.
        let foreign = ["bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu".to_string()]
            .into_iter()
            .collect();
        assert!(round
            .outputs(&foreign)
            .unwrap_err()
            .to_string()
            .contains("invalid address"));
        // Our output missing.
        let other = s.keys.address(crate::keys::EXTERNAL, 9).to_string();
        let outs = round.outputs(&[other.clone()].into_iter().collect()).unwrap();
        assert!(round
            .sign_input(&s, &coin, &dest, outs)
            .unwrap_err()
            .to_string()
            .contains("missing"));
        // Inputs that do not match, are reused, or leave ours out.
        let mine = s.keys.address(crate::keys::EXTERNAL, 1).to_string();
        let outs = round.outputs(&[mine, other].into_iter().collect()).unwrap();
        let signed = round.sign_input(&s, &coin, &dest, outs.clone()).unwrap();
        let e = |inputs: &[Psbt], c: &Coin| round.combine(inputs, &outs, c).unwrap_err().to_string();
        let mut wrong = signed.clone();
        wrong.unsigned_tx.output.pop();
        assert!(e(&[signed.clone(), wrong], &coin).contains("does not match"));
        assert!(e(&[signed.clone(), signed.clone()], &coin).contains("same coin"));
        let (_, stranger) = member(2, dir.path());
        assert!(e(std::slice::from_ref(&signed), &stranger).contains("our input"));
        // Too many outputs registered: leave.
        for n in 0..3u32 {
            let a = s.keys.address(crate::keys::EXTERNAL, 20 + n).to_string();
            round.post(json!({"address": a, "type": "output"})).await.unwrap();
        }
        round
            .post(json!({"type": "input", "psbt": "not base64"}))
            .await
            .unwrap();
        round.post(json!({"type": "input"})).await.unwrap();
        round.post(json!({"type": "other"})).await.unwrap();
        let addr = s.keys.address(crate::keys::EXTERNAL, 1).to_string();
        let e = round
            .run(&s, &coin, &dest, &addr, now + 60)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("more outputs than peers"), "{e}");
    }

    #[tokio::test]
    async fn a_silent_pool_is_given_up_for_a_new_one() {
        crate::test_logs();
        let board = FakeBoard::default();
        let now = Timestamp::now().as_secs();
        // Two announced, but their creators never answer.
        let silent = find_or_create(&board, &cfg(3), 20.0, 2.0, now, Network::Regtest)
            .await
            .unwrap();
        find_or_create(&board, &cfg(3), 20.0, 2.0, now, Network::Regtest)
            .await
            .unwrap();
        // Junk on the board is ignored.
        board
            .publish(
                EventBuilder::new(Kind::Custom(KIND_POOL), "not json")
                    .sign_with_keys(&Keys::generate())
                    .unwrap(),
            )
            .await
            .unwrap();
        let mine = find_or_create(&board, &cfg(3), 20.0, 2.0, now, Network::Regtest)
            .await
            .unwrap();
        assert!(mine.creator && mine.pool.id != silent.pool.id);
    }

    #[tokio::test]
    async fn the_creator_admits_each_member_once_and_no_more() {
        let board = FakeBoard::default();
        let now = Timestamp::now().as_secs();
        let round = find_or_create(&board, &cfg(2), 20.0, 2.0, now, Network::Regtest)
            .await
            .unwrap();
        let pool_pk = round.pool_pk();
        let a = Keys::generate();
        let join = json!({"type": "join_pool"});
        board
            .publish(message(&Keys::generate(), &pool_pk, &json!({"type": "other"})).unwrap())
            .await
            .unwrap();
        board.publish(message(&a, &pool_pk, &join).unwrap()).await.unwrap();
        board.publish(message(&a, &pool_pk, &join).unwrap()).await.unwrap();
        let mut admitted = HashSet::new();
        round.admit(&mut admitted, Timestamp::from(0)).await.unwrap();
        assert_eq!(admitted.len(), 1, "one member, once, and the pool of two is full");
        board
            .publish(message(&Keys::generate(), &pool_pk, &join).unwrap())
            .await
            .unwrap();
        round.admit(&mut admitted, Timestamp::from(0)).await.unwrap();
        assert_eq!(admitted.len(), 1);
        // A full pool, re-read with the creator counted too.
        let mut more: HashSet<PublicKey> = [Keys::generate().public_key()].into();
        let r2 = Round { creator: true, ..round };
        r2.admit(&mut more, Timestamp::from(0)).await.unwrap();
        // A message under the pool key that is not readable is skipped.
        let garbage = EventBuilder::new(Kind::EncryptedDirectMessage, "garbage")
            .sign_with_keys(&r2.pool_keys)
            .unwrap();
        board.publish(garbage).await.unwrap();
        let mut seen = Seen::default();
        r2.collect(&mut seen, Timestamp::from(0)).await.unwrap();
        assert!(seen.outputs.is_empty());
    }

    #[tokio::test]
    async fn premix_makes_one_coin_of_the_right_size() {
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(3);
        let (mut s, _) = member(1, dir.path());
        s.cfg.coinjoin = Some(c.clone());
        let k = &s.keys;
        let coins = [
            crate::tx::tests::coin(k, 0, 80_000, 1),
            crate::tx::tests::coin(k, 1, 60_000, 2),
        ];
        let shared = std::sync::Arc::new(crate::chain::tests::FakeChain::default());
        s.chain = Box::new(crate::sweep::tests::Shared(shared.clone()));
        // With change.
        let p = sweep(&mut s, &coins, 2.0, 1).await.unwrap();
        assert_eq!((p.mode.as_str(), p.moved_sat), ("coinjoin-premix", 101_000));
        assert_eq!(shared.broadcasts.lock().unwrap()[0].output.len(), 2);
        assert_eq!(s.state.next_change, 2);
        // Without room for change, everything goes into the premix coin.
        let snug = [
            crate::tx::tests::coin(&s.keys, 0, 50_000, 3),
            crate::tx::tests::coin(&s.keys, 1, 51_400, 4),
        ];
        sweep(&mut s, &snug, 2.0, 1).await.unwrap();
        assert_eq!(shared.broadcasts.lock().unwrap()[1].output.len(), 1);
        // Too little for a premix coin.
        let few = [crate::tx::tests::coin(&s.keys, 0, 90_000, 5)];
        let e = sweep(&mut s, &few, 2.0, 1).await.unwrap_err().to_string();
        assert!(e.contains("cannot make a premix coin"), "{e}");
        // No settings: a configuration error.
        s.cfg.coinjoin = None;
        assert!(matches!(sweep(&mut s, &coins, 2.0, 1).await, Err(Error::Config(_))));
    }

    #[tokio::test]
    async fn another_member_broadcasting_first_is_fine() {
        let dir = tempfile::tempdir().unwrap();
        let (mut s, _) = member(1, dir.path());
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        for (msg, ok) in [
            ("txn-already-known", true),
            ("transaction already in block chain", true),
            ("bad-txns", false),
        ] {
            s.chain = Box::new(crate::chain::tests::FakeChain {
                refuse_with: Some(msg.into()),
                ..Default::default()
            });
            assert_eq!(broadcast(&s, &tx).await.is_ok(), ok, "{msg}");
        }
    }

    #[test]
    fn amounts_and_acceptable_pools() {
        assert_eq!(output_sat(100_000, 2.0), 99_800);
        assert_eq!(output_sat(100_000, 1.5), 99_850);
        let c = cfg(3);
        let pool = Pool {
            kind: "new_pool".into(),
            id: "x".into(),
            public_key: Keys::generate().public_key().to_hex(),
            denomination: 0.001,
            peers: 3,
            timeout: 10_000,
            relay: "ws://127.0.0.1:7777/".into(),
            fee_rate: 2.0,
            transport: "tor".into(),
            vpn_gateway: String::new(),
        };
        assert!(pool.acceptable(&c, 20.0, 1_000));
        assert!(!pool.acceptable(&c, 1.0, 1_000), "fee above our cap");
        assert!(!pool.acceptable(&c, 20.0, 9_990), "about to expire");
        assert!(!Pool {
            peers: 4,
            ..pool.clone()
        }
        .acceptable(&c, 20.0, 1_000));
        assert!(!Pool {
            denomination: 0.002,
            ..pool.clone()
        }
        .acceptable(&c, 20.0, 1_000));
        assert!(!Pool {
            relay: "wss://elsewhere".into(),
            ..pool.clone()
        }
        .acceptable(&c, 20.0, 1_000));
        assert!(!Pool {
            kind: "other".into(),
            ..pool
        }
        .acceptable(&c, 20.0, 1_000));
    }

    #[test]
    fn credentials_must_match_the_announcement() {
        let keys = Keys::generate();
        let pool = Pool {
            kind: "new_pool".into(),
            id: "abc".into(),
            public_key: keys.public_key().to_hex(),
            denomination: 0.001,
            peers: 3,
            timeout: 10_000,
            relay: "ws://r".into(),
            fee_rate: 2.0,
            transport: "tor".into(),
            vpn_gateway: String::new(),
        };
        let mut creds = serde_json::to_value(&pool).unwrap();
        creds["private_key"] = json!(keys.secret_key().to_secret_hex());
        assert!(credentials(&creds, &pool).is_some());
        let mut wrong = creds.clone();
        wrong["peers"] = json!(2);
        assert!(credentials(&wrong, &pool).is_none());
        let mut other = creds.clone();
        other["private_key"] = json!(Keys::generate().secret_key().to_secret_hex());
        assert!(credentials(&other, &pool).is_none());
        assert!(credentials(&json!({}), &pool).is_none());
    }
}
