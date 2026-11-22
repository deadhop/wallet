//! What the wallet asks of its Electrum server: unspent coins, fee rates and
//! broadcasting. Built on the payment service's hardened client (size-capped
//! lines, per-call byte budgets, pinned TLS, genesis check on connect). Every
//! reply is checked before it is used.

use std::str::FromStr;

use async_trait::async_trait;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, Txid};
use deadhop::electrum::{Electrum, MAX_LINE_BYTES};
use deadhop::wallet::scripthash;
use serde_json::{json, Value};

use crate::error::{Error, Result};

/// Scripts asked about per round trip.
const BATCH: usize = 100;
/// Bytes read for one round trip, all replies together.
const BUDGET: u64 = 16 * 1024 * 1024;
/// Most unspent outputs accepted for one script. Anyone can send dust to an
/// address; past this the script is skipped and logged rather than swept.
pub const MAX_UNSPENT: usize = 200;

/// One unspent output, as the server reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unspent {
    pub outpoint: OutPoint,
    pub value: Amount,
    /// Block height, or `None` while unconfirmed.
    pub height: Option<u32>,
}

/// The chain operations the wallet needs. Implemented by [`Electrum`].
#[async_trait]
pub trait Backend: Send + Sync {
    /// Best block height.
    async fn tip(&self) -> Result<u32>;
    /// Unspent outputs of each script, in request order. A script whose list
    /// is too long reports an error without hiding the others.
    async fn unspent(
        &self,
        scripts: &[ScriptBuf],
    ) -> Result<Vec<std::result::Result<Vec<Unspent>, String>>>;
    /// Whether each script has ever been used (has any history).
    async fn used(&self, scripts: &[ScriptBuf]) -> Result<Vec<bool>>;
    /// Fee rate (sat/vB) for confirmation within `blocks`, if the server has one.
    async fn fee_rate(&self, blocks: u16) -> Result<Option<f64>>;
    /// The server's minimum relay fee rate in sat/vB.
    async fn relay_fee(&self) -> Result<f64>;
    /// Broadcast; returns the txid the server accepted.
    async fn broadcast(&self, tx: &Transaction) -> Result<Txid>;
}

fn bad(what: &str) -> Error {
    Error::Chain(format!("malformed reply: {what}"))
}

/// BTC/kvB (as Electrum reports it) to sat/vB.
fn btc_per_kvb(v: f64) -> f64 {
    v * 100_000_000.0 / 1000.0
}

fn parse_unspent(reply: &Value) -> Result<std::result::Result<Vec<Unspent>, String>> {
    let list = reply.as_array().ok_or_else(|| bad("listunspent"))?;
    if list.len() > MAX_UNSPENT {
        return Ok(Err(format!("more than {MAX_UNSPENT} unspent outputs")));
    }
    let mut out = Vec::with_capacity(list.len());
    for u in list {
        let txid = u["tx_hash"]
            .as_str()
            .and_then(|t| Txid::from_str(t).ok())
            .ok_or_else(|| bad("tx_hash"))?;
        let vout = u["tx_pos"]
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| bad("tx_pos"))?;
        let value = u["value"].as_u64().ok_or_else(|| bad("value"))?;
        let value = Amount::from_sat(value);
        if value > Amount::MAX_MONEY {
            return Err(bad("value"));
        }
        let height = u["height"].as_i64().ok_or_else(|| bad("height"))?;
        out.push(Unspent {
            outpoint: OutPoint { txid, vout },
            value,
            height: u32::try_from(height).ok().filter(|h| *h > 0),
        });
    }
    Ok(Ok(out))
}

#[async_trait]
impl Backend for Electrum {
    async fn tip(&self) -> Result<u32> {
        let mut budget = MAX_LINE_BYTES;
        let r = self
            .batch(
                &[("blockchain.headers.subscribe", json!([]))],
                MAX_LINE_BYTES,
                &mut budget,
            )
            .await?;
        r[0]["height"]
            .as_u64()
            .and_then(|h| u32::try_from(h).ok())
            .ok_or_else(|| bad("tip height"))
    }

    async fn unspent(
        &self,
        scripts: &[ScriptBuf],
    ) -> Result<Vec<std::result::Result<Vec<Unspent>, String>>> {
        let mut out = Vec::with_capacity(scripts.len());
        for chunk in scripts.chunks(BATCH) {
            let reqs: Vec<(&str, Value)> = chunk
                .iter()
                .map(|s| ("blockchain.scripthash.listunspent", json!([scripthash(s)])))
                .collect();
            let mut budget = BUDGET;
            for r in self.batch(&reqs, MAX_LINE_BYTES, &mut budget).await? {
                out.push(parse_unspent(&r)?);
            }
        }
        Ok(out)
    }

    async fn used(&self, scripts: &[ScriptBuf]) -> Result<Vec<bool>> {
        let mut out = Vec::with_capacity(scripts.len());
        for chunk in scripts.chunks(BATCH) {
            let reqs: Vec<(&str, Value)> = chunk
                .iter()
                .map(|s| ("blockchain.scripthash.get_history", json!([scripthash(s)])))
                .collect();
            let mut budget = BUDGET;
            for r in self.batch(&reqs, MAX_LINE_BYTES, &mut budget).await? {
                out.push(!r.as_array().ok_or_else(|| bad("history"))?.is_empty());
            }
        }
        Ok(out)
    }

    async fn fee_rate(&self, blocks: u16) -> Result<Option<f64>> {
        let mut budget = MAX_LINE_BYTES;
        let r = self
            .batch(
                &[("blockchain.estimatefee", json!([blocks]))],
                MAX_LINE_BYTES,
                &mut budget,
            )
            .await?;
        let v = r[0].as_f64().ok_or_else(|| bad("estimatefee"))?;
        // -1 means the server has no estimate.
        Ok((v > 0.0).then(|| btc_per_kvb(v)))
    }

    async fn relay_fee(&self) -> Result<f64> {
        let mut budget = MAX_LINE_BYTES;
        let r = self
            .batch(
                &[("blockchain.relayfee", json!([]))],
                MAX_LINE_BYTES,
                &mut budget,
            )
            .await?;
        let v = r[0]
            .as_f64()
            .filter(|v| *v >= 0.0)
            .ok_or_else(|| bad("relayfee"))?;
        Ok(btc_per_kvb(v))
    }

    async fn broadcast(&self, tx: &Transaction) -> Result<Txid> {
        let mut budget = MAX_LINE_BYTES;
        let r = self
            .batch(
                &[(
                    "blockchain.transaction.broadcast",
                    json!([serialize_hex(tx)]),
                )],
                MAX_LINE_BYTES,
                &mut budget,
            )
            .await?;
        let txid = tx.compute_txid();
        match r[0].as_str().and_then(|t| Txid::from_str(t).ok()) {
            Some(t) if t == txid => Ok(txid),
            _ => Err(Error::Chain(
                "the server answered the broadcast with another txid".into(),
            )),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory chain for unit tests.
    #[derive(Default)]
    pub struct FakeChain {
        pub tip: u32,
        pub utxos: Mutex<HashMap<ScriptBuf, Vec<Unspent>>>,
        pub history: Mutex<std::collections::HashSet<ScriptBuf>>,
        pub fee: Option<f64>,
        pub relay: f64,
        pub broadcasts: Mutex<Vec<Transaction>>,
        pub refuse_broadcast: bool,
    }

    impl FakeChain {
        pub fn fund(&self, script: &ScriptBuf, sat: u64, height: Option<u32>) -> OutPoint {
            let mut u = self.utxos.lock().unwrap();
            let list = u.entry(script.clone()).or_default();
            let mut txid = [0u8; 32];
            txid[..8].copy_from_slice(&(list.len() as u64 + sat).to_le_bytes());
            txid[8..16].copy_from_slice(&script.as_bytes()[2..10]);
            let outpoint = OutPoint {
                txid: bitcoin::hashes::Hash::from_byte_array(txid),
                vout: 1,
            };
            list.push(Unspent {
                outpoint,
                value: Amount::from_sat(sat),
                height,
            });
            self.history.lock().unwrap().insert(script.clone());
            outpoint
        }
    }

    #[async_trait]
    impl Backend for FakeChain {
        async fn tip(&self) -> Result<u32> {
            Ok(self.tip)
        }
        async fn unspent(
            &self,
            scripts: &[ScriptBuf],
        ) -> Result<Vec<std::result::Result<Vec<Unspent>, String>>> {
            let u = self.utxos.lock().unwrap();
            Ok(scripts
                .iter()
                .map(|s| Ok(u.get(s).cloned().unwrap_or_default()))
                .collect())
        }
        async fn used(&self, scripts: &[ScriptBuf]) -> Result<Vec<bool>> {
            let h = self.history.lock().unwrap();
            Ok(scripts.iter().map(|s| h.contains(s)).collect())
        }
        async fn fee_rate(&self, _blocks: u16) -> Result<Option<f64>> {
            Ok(self.fee)
        }
        async fn relay_fee(&self) -> Result<f64> {
            Ok(self.relay)
        }
        async fn broadcast(&self, tx: &Transaction) -> Result<Txid> {
            if self.refuse_broadcast {
                return Err(Error::Chain("rejected".into()));
            }
            self.broadcasts.lock().unwrap().push(tx.clone());
            Ok(tx.compute_txid())
        }
    }

    #[test]
    fn unspent_replies_are_checked() {
        let t = "aa".repeat(32);
        let good = json!([{"tx_hash": t, "tx_pos": 1, "value": 5000, "height": 0},
                          {"tx_hash": t, "tx_pos": 2, "value": 6000, "height": 7}]);
        let list = parse_unspent(&good).unwrap().unwrap();
        assert_eq!(list[0].height, None);
        assert_eq!(list[1].height, Some(7));
        assert_eq!(list[1].value, Amount::from_sat(6000));
        let many = Value::Array(vec![good[0].clone(); MAX_UNSPENT + 1]);
        assert!(parse_unspent(&many).unwrap().is_err());
        for broken in [
            json!({}),
            json!([{"tx_hash": "zz", "tx_pos": 1, "value": 1, "height": 1}]),
            json!([{"tx_hash": t, "tx_pos": -1, "value": 1, "height": 1}]),
            json!([{"tx_hash": t, "tx_pos": 1, "value": "1", "height": 1}]),
            json!([{"tx_hash": t, "tx_pos": 1, "value": 2_100_000_000_000_001u64, "height": 1}]),
            json!([{"tx_hash": t, "tx_pos": 1, "value": 1, "height": "1"}]),
        ] {
            assert!(parse_unspent(&broken).is_err(), "{broken}");
        }
        assert!((btc_per_kvb(0.00001) - 1.0).abs() < 1e-9);
    }
}
