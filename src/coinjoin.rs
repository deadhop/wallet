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
const CREDENTIALS_WAIT: Duration = Duration::from_secs(30);

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
            (p.public_key == e.pubkey.to_hex() && p.acceptable(cfg, max_fee_rate, now))
                .then_some((e, p))
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
    board.publish(announcement).await?;
    tracing::info!(
        "announced coinjoin pool {} for {} peers",
        pool.id,
        pool.peers
    );
    Ok(Round {
        board,
        pool,
        pool_keys,
        creator: true,
        network,
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
            .fetch(
                Filter::new()
                    .kind(Kind::EncryptedDirectMessage)
                    .pubkey(me.public_key()),
            )
            .await?;
        for r in &replies {
            if let Some(keys) = open(&me, r).and_then(|v| credentials(&v, pool)) {
                return Ok(Some(keys));
            }
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
                    if let Some(p) = B64
                        .decode(text)
                        .ok()
                        .and_then(|b| Psbt::deserialize(&b).ok())
                    {
                        seen.inputs.push(p);
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// This member's input, signed `ALL|ANYONECANPAY` over every output.
    pub fn sign_input(
        &self,
        s: &Sweeper,
        coin: &Coin,
        dest: &ScriptBuf,
        outputs: Vec<TxOut>,
    ) -> Result<Psbt> {
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
            return Err(err(
                "our output is missing from the pool, or registered twice",
            ));
        }
        tx::sign(
            &mut psbt,
            &s.keys,
            &index(std::slice::from_ref(coin)),
            &rules,
            EcdsaSighashType::AllPlusAnyoneCanPay,
        )?;
        Ok(psbt)
    }

    /// Combine the members' inputs into the final transaction.
    pub fn combine(&self, inputs: &[Psbt], outputs: &[TxOut], ours: &Coin) -> Result<Transaction> {
        let mut txins: Vec<TxIn> = Vec::new();
        let mut spent = HashSet::new();
        for p in inputs {
            let ok = p.unsigned_tx.input.len() == 1
                && p.inputs.len() == 1
                && p.unsigned_tx.output == outputs
                && p.inputs[0]
                    .final_script_witness
                    .as_ref()
                    .is_some_and(|w| !w.is_empty());
            if !ok {
                return Err(err("a member's input does not match the pool"));
            }
            let mut txin = p.unsigned_tx.input[0].clone();
            if !spent.insert(txin.previous_output) {
                return Err(err("two members posted the same coin"));
            }
            txin.witness = p.inputs[0]
                .final_script_witness
                .clone()
                .expect("checked above");
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
        let since = Timestamp::from(Timestamp::now().as_secs().saturating_sub(5));
        let mut admitted = HashSet::new();
        let mut seen = Seen::default();
        self.post(json!({"address": address, "type": "output"}))
            .await?;
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
                return Err(err(
                    "more outputs than peers were registered; leaving the pool",
                ));
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
async fn premix(
    s: &mut Sweeper,
    cj: &CoinjoinConfig,
    coins: &[Coin],
    rate: f64,
    now: u64,
) -> Result<Sweep> {
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
    tx::sign(
        &mut psbt,
        &s.keys,
        &index(coins),
        &rules,
        EcdsaSighashType::All,
    )?;
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
        Err(e) if e.to_string().contains("already") || e.to_string().contains("known") => {
            Ok(tx.compute_txid())
        }
        Err(e) => Err(e),
    }
}

/// A CoinJoin sweep: premix if needed, then one round.
pub async fn sweep(s: &mut Sweeper, coins: &[Coin], rate: f64, now: u64) -> Result<Option<Sweep>> {
    let cj = s
        .cfg
        .coinjoin
        .clone()
        .ok_or_else(|| Error::Config("coinjoin mode needs its settings".into()))?;
    let range = cj.denomination_sat + MIN_EXCESS_SAT..=cj.denomination_sat + MAX_EXCESS_SAT;
    let Some(coin) = coins
        .iter()
        .find(|c| range.contains(&c.value.to_sat()))
        .cloned()
    else {
        return premix(s, &cj, coins, rate, now).await.map(Some);
    };
    let client = deadhop::relay::Pool::new(Keys::generate(), s.cfg.proxy.clone());
    let client = client.client().clone();
    client.add_relay(&cj.relay).await.map_err(err)?;
    client.connect().await;
    let result = round(s, client.as_ref(), &cj, &coin, rate, now).await;
    client.disconnect().await;
    result.map(Some)
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
    let tx = round
        .run(s, coin, &dest, &address, now + cj.timeout_secs)
        .await?;
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
