//! One poll of the wallet: find the coins, and once the confirmed balance
//! reaches the threshold move it out by the configured mode.

use bitcoin::sighash::EcdsaSighashType;
use bitcoin::{Amount, ScriptBuf};
use deadhop_common::wallet::Wallet as Watch;

use std::str::FromStr;

use bitcoin::{Address, Txid};

use crate::chain::{Backend, TxStatus};
use crate::config::{Config, Mode};
use crate::error::{Error, Result};
use crate::keys::Keys;
use crate::scan::{confirmed, read_index, scan};
use crate::state::{Confirmation, State, Sweep};
use crate::tx::{self, Coin, Coins, Rules};

/// What a poll did.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// Below the threshold: nothing to do.
    Below { confirmed: Amount, unconfirmed: Amount },
    /// Due, but not now (fees above the cap, no fresh PayJoin URI, no peers...).
    Waiting { confirmed: Amount, why: String },
    /// Moved out.
    Swept(Sweep),
}

/// How long a sweep may be unknown to the server before it is abandoned:
/// long enough that a server still catching up on its mempool is not
/// mistaken for a dropped transaction.
pub const ABANDON_AFTER_SECS: u64 = 3_600;

pub struct Sweeper {
    pub cfg: Config,
    pub keys: Keys,
    pub chain: Box<dyn Backend>,
    pub state: State,
    destination: Option<Watch>,
}

/// Most inputs in one transaction: about 30,000 vbytes, well inside the
/// standard size limit. The rest is swept by the next poll.
pub const MAX_INPUTS: usize = 400;

/// The coins worth spending at `rate`, largest first, at most [`MAX_INPUTS`].
/// A coin worth less than the fee of its own input would only lose money.
pub fn spendable(mut coins: Vec<Coin>, rate: f64) -> Vec<Coin> {
    let input_fee = tx::fee(tx::P2WPKH_INPUT_WEIGHT.div_ceil(4), rate);
    coins.retain(|c| c.value > input_fee);
    coins.sort_by_key(|c| std::cmp::Reverse(c.value));
    coins.truncate(MAX_INPUTS);
    coins
}

/// Coins by outpoint, for the signer.
pub fn index(coins: &[Coin]) -> Coins {
    coins.iter().map(|c| (c.outpoint, c.clone())).collect()
}

impl Sweeper {
    pub fn new(cfg: Config, keys: Keys, chain: Box<dyn Backend>, state: State) -> Result<Self> {
        let destination = match &cfg.destination {
            Some(d) => {
                let w = Watch::new(d, cfg.network)?;
                if w.account_id() == Watch::new(&keys.account_key(), cfg.network)?.account_id() {
                    return Err(Error::Config(
                        "DEADHOP_WALLET_DESTINATION is this wallet itself: name another wallet".into(),
                    ));
                }
                Some(w)
            }
            None => None,
        };
        Ok(Sweeper {
            cfg,
            keys,
            chain,
            state,
            destination,
        })
    }

    /// The next fresh destination script and its address.
    pub fn destination(&self) -> Result<(ScriptBuf, String)> {
        let w = self
            .destination
            .as_ref()
            .ok_or_else(|| Error::Config("DEADHOP_WALLET_DESTINATION is not set".into()))?;
        let a = w.address(self.state.next_destination)?;
        Ok((a.script_pubkey(), a.to_string()))
    }

    /// Fee rate to pay now, in sat/vB: the server's estimate for the target,
    /// never below its relay minimum. `None` when that is above the cap.
    pub async fn fee_rate(&self) -> Result<Option<f64>> {
        let relay = self.chain.relay_fee().await?.max(1.0);
        let rate = self
            .chain
            .fee_rate(self.cfg.fee_target_blocks)
            .await?
            .unwrap_or(relay)
            .max(relay);
        Ok((rate <= self.cfg.max_fee_rate).then_some(rate))
    }

    pub fn save(&self) -> Result<()> {
        self.state.save(&self.cfg.state_dir)
    }

    /// The most a transaction of this shape may cost at the fee cap.
    pub fn max_fee(&self, inputs: usize, outputs: &[&ScriptBuf]) -> Amount {
        tx::fee(tx::vsize(inputs, outputs), self.cfg.max_fee_rate)
    }

    /// Check every sweep not yet settled against the chain: mined ones are
    /// confirmed, and one the server has not known for
    /// [`ABANDON_AFTER_SECS`] is abandoned (its coins are still ours and the
    /// scan finds them again). Saved when anything changed.
    pub async fn reconcile(&mut self, now: u64) -> Result<()> {
        let mut changed = false;
        for i in 0..self.state.sweeps.len() {
            let sweep = &self.state.sweeps[i];
            if sweep.confirmation.settled() {
                continue;
            }
            let (Ok(txid), Some(script)) = (
                Txid::from_str(&sweep.txid),
                Address::from_str(&sweep.to)
                    .ok()
                    .map(|a| a.assume_checked().script_pubkey()),
            ) else {
                continue;
            };
            let next = match self.chain.tx_status(txid, &script).await? {
                TxStatus::Confirmed(height) => Confirmation::Confirmed { height },
                TxStatus::Missing if now >= sweep.at.saturating_add(ABANDON_AFTER_SECS) => {
                    tracing::warn!(%txid, "a sweep was never mined and is gone from the server: its coins did not move");
                    Confirmation::Abandoned
                }
                TxStatus::Mempool | TxStatus::Missing => continue,
            };
            self.state.sweeps[i].confirmation = next;
            changed = true;
        }
        if changed {
            self.save()?;
        }
        Ok(())
    }

    /// One poll.
    pub async fn tick(&mut self, now: u64) -> Result<Outcome> {
        self.reconcile(now).await?;
        let found = scan(
            self.chain.as_ref(),
            &self.keys,
            read_index(self.cfg.index_file.as_deref(), self.cfg.max_index_hint),
            self.state.next_change,
            self.cfg.gap,
        )
        .await?;
        if !found.skipped.is_empty() {
            let skipped = found.skipped.join("; ");
            tracing::warn!(%skipped, "addresses skipped");
        }
        // Change addresses found in use (e.g. after restoring the state file)
        // are never handed out again.
        self.state.next_change = self.state.next_change.max(found.used_internal);
        let tip = self.chain.tip().await?;
        let (ready, pending): (Vec<Coin>, Vec<Coin>) = found
            .coins
            .into_iter()
            .partition(|c| confirmed(c, tip, self.cfg.min_confirmations));
        let balance: Amount = ready.iter().map(|c| c.value).sum();
        let unconfirmed: Amount = pending.iter().map(|c| c.value).sum();
        // A confirmed premix coin is due whatever the balance: the premix fee
        // may have left the rest just under the threshold.
        let premixed = self
            .cfg
            .coinjoin
            .as_ref()
            .is_some_and(|cj| ready.iter().any(|c| crate::coinjoin::premix_ready(cj, c)));
        if balance.to_sat() < self.cfg.threshold_sat && !premixed {
            return Ok(Outcome::Below {
                confirmed: balance,
                unconfirmed,
            });
        }
        let Some(rate) = self.fee_rate().await? else {
            return Ok(Outcome::Waiting {
                confirmed: balance,
                why: format!("fees are above the cap of {} sat/vB", self.cfg.max_fee_rate),
            });
        };
        let ready = spendable(ready, rate);
        let done = match self.cfg.mode {
            Mode::Send => self.send(&ready, rate, now).await,
            Mode::Payjoin => crate::payjoin::sweep(self, &ready, rate, now).await,
            Mode::Coinjoin => crate::coinjoin::sweep(self, &ready, rate, now).await,
        };
        // Saved whatever happened: a failed attempt can still have used up a
        // PayJoin URI or a change address.
        if let Ok(sweep) = &done {
            self.state.record(sweep.clone());
        }
        self.save()?;
        match done {
            Ok(sweep) => Ok(Outcome::Swept(sweep)),
            Err(e @ (Error::Payjoin(_) | Error::Coinjoin(_))) => Ok(Outcome::Waiting {
                confirmed: balance,
                why: e.to_string(),
            }),
            Err(e) => Err(e),
        }
    }

    /// Simple send: every confirmed coin to the next destination address.
    pub async fn send(&mut self, coins: &[Coin], rate: f64, now: u64) -> Result<Sweep> {
        let (dest, address) = self.destination()?;
        let refs: Vec<&Coin> = coins.iter().collect();
        let (mut psbt, fee) = tx::sweep(&refs, &dest, rate)?;
        let total: Amount = coins.iter().map(|c| c.value).sum();
        let rules = Rules {
            to: vec![dest.clone()],
            min_to: total - fee,
            max_cost: self.max_fee(coins.len(), &[&dest]),
        };
        tx::sign(&mut psbt, &self.keys, &index(coins), &rules, EcdsaSighashType::All)?;
        let tx = tx::extract(psbt);
        let txid = self.chain.broadcast(&tx).await?;
        self.state.next_destination += 1;
        Ok(Sweep {
            at: now,
            mode: Mode::Send.label().into(),
            txid: txid.to_string(),
            spent_sat: total.to_sat(),
            moved_sat: (total - fee).to_sat(),
            to: address,
            confirmation: crate::state::Confirmation::Unconfirmed,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::chain::tests::FakeChain;
    use crate::keys::tests::keys;
    use crate::keys::EXTERNAL;
    use std::collections::HashMap;
    use std::sync::Arc;

    pub fn other_account() -> String {
        Keys::from_phrase(
            &bip39::Mnemonic::from_entropy(&[7u8; 32]).unwrap(),
            bitcoin::Network::Regtest,
        )
        .account_key()
    }

    pub fn config(dir: &std::path::Path, extra: &[(&'static str, String)]) -> Config {
        let mut m: HashMap<&'static str, String> = HashMap::from([
            ("DEADHOP_NETWORK", "regtest".into()),
            ("DEADHOP_ELECTRUM", "127.0.0.1:1".into()),
            ("DEADHOP_WALLET_DESTINATION", other_account()),
            ("DEADHOP_WALLET_THRESHOLD_SAT", "100000".into()),
            ("DEADHOP_WALLET_STATE_DIR", dir.to_string_lossy().into_owned()),
        ]);
        for (k, v) in extra {
            m.insert(k, v.clone());
        }
        Config::from_env(&|k| m.get(k).cloned()).unwrap()
    }

    /// A chain the test keeps a handle on after the sweeper takes it.
    #[derive(Clone)]
    pub struct Shared(pub Arc<FakeChain>);

    #[async_trait::async_trait]
    impl Backend for Shared {
        async fn tip(&self) -> Result<u32> {
            self.0.tip().await
        }
        async fn unspent(
            &self,
            s: &[ScriptBuf],
        ) -> Result<Vec<std::result::Result<Vec<crate::chain::Unspent>, String>>> {
            self.0.unspent(s).await
        }
        async fn used(&self, s: &[ScriptBuf]) -> Result<Vec<bool>> {
            self.0.used(s).await
        }
        async fn fee_rate(&self, b: u16) -> Result<Option<f64>> {
            self.0.fee_rate(b).await
        }
        async fn relay_fee(&self) -> Result<f64> {
            self.0.relay_fee().await
        }
        async fn broadcast(&self, tx: &bitcoin::Transaction) -> Result<bitcoin::Txid> {
            self.0.broadcast(tx).await
        }
        async fn has_transaction(&self, txid: bitcoin::Txid) -> Result<bool> {
            self.0.has_transaction(txid).await
        }
        async fn tx_status(&self, txid: bitcoin::Txid, script: &ScriptBuf) -> Result<TxStatus> {
            self.0.tx_status(txid, script).await
        }
    }

    pub fn sweeper(dir: &std::path::Path, chain: FakeChain, extra: &[(&'static str, String)]) -> (Sweeper, Shared) {
        let shared = Shared(Arc::new(chain));
        let s = Sweeper::new(config(dir, extra), keys(), Box::new(shared.clone()), State::default()).unwrap();
        (s, shared)
    }

    #[tokio::test]
    async fn sweeps_once_the_confirmed_balance_reaches_the_threshold() {
        crate::test_logs();
        let dir = tempfile::tempdir().unwrap();
        let k = keys();
        let chain = FakeChain {
            tip: 100,
            relay: 1.0,
            ..FakeChain::default()
        };
        chain.fund(&k.script(EXTERNAL, 0), 60_000, Some(100));
        chain.fund(&k.script(EXTERNAL, 1), 70_000, None);
        let (mut s, shared) = sweeper(dir.path(), chain, &[]);
        let below = Outcome::Below {
            confirmed: Amount::from_sat(60_000),
            unconfirmed: Amount::from_sat(70_000),
        };
        assert_eq!(s.tick(1).await.unwrap(), below);
        shared.0.fund(&k.script(EXTERNAL, 2), 50_000, Some(99));
        // A dusted address is skipped (and logged); the rest is still swept.
        shared.0.poisoned.lock().unwrap().insert(k.script(EXTERNAL, 1));
        let Outcome::Swept(sweep) = s.tick(2).await.unwrap() else { panic!("not swept") };
        assert_eq!(sweep.spent_sat, 110_000);
        assert_eq!(sweep.mode, "send");
        let sent = shared.0.broadcasts.lock().unwrap()[0].clone();
        assert_eq!(sent.input.len(), 2);
        assert_eq!(sent.output.len(), 1);
        assert_eq!(sent.output[0].value.to_sat(), sweep.moved_sat);
        assert!(shared.has_transaction(sent.compute_txid()).await.unwrap());
        // A fresh destination address next time, and the state is on disk.
        assert_eq!(s.state.next_destination, 1);
        assert_eq!(State::load(dir.path()).unwrap().sweeps.len(), 1);
        let first = Watch::new(&other_account(), bitcoin::Network::Regtest)
            .unwrap()
            .address(0)
            .unwrap();
        assert_eq!(sent.output[0].script_pubkey, first.script_pubkey());
        assert_ne!(s.destination().unwrap().1, first.to_string());
    }

    #[tokio::test]
    async fn sweeps_are_confirmed_or_abandoned_by_what_the_chain_says() {
        let dir = tempfile::tempdir().unwrap();
        let k = keys();
        let chain = FakeChain {
            tip: 100,
            relay: 1.0,
            ..FakeChain::default()
        };
        chain.fund(&k.script(EXTERNAL, 0), 200_000, Some(90));
        let (mut s, shared) = sweeper(dir.path(), chain, &[]);
        let Outcome::Swept(first) = s.tick(10).await.unwrap() else { panic!("not swept") };
        assert_eq!(first.confirmation, Confirmation::Unconfirmed);
        let txid = Txid::from_str(&first.txid).unwrap();
        // In the mempool: still unconfirmed, however long it waits.
        s.reconcile(10 + 2 * ABANDON_AFTER_SECS).await.unwrap();
        assert_eq!(s.state.sweeps[0].confirmation, Confirmation::Unconfirmed);
        // Mined: confirmed, on disk too, and never asked about again.
        shared.0.status.lock().unwrap().insert(txid, TxStatus::Confirmed(101));
        s.reconcile(20).await.unwrap();
        let mined = Confirmation::Confirmed { height: 101 };
        assert_eq!(State::load(dir.path()).unwrap().sweeps[0].confirmation, mined);
        shared.0.status.lock().unwrap().insert(txid, TxStatus::Missing);
        s.reconcile(20 + 2 * ABANDON_AFTER_SECS).await.unwrap();
        assert_eq!(s.state.sweeps[0].confirmation, mined);

        // Dropped without being mined: unconfirmed for a while, then abandoned.
        let mut dropped = first.clone();
        dropped.txid = "ab".repeat(32);
        dropped.at = 1_000;
        dropped.confirmation = Confirmation::Unconfirmed;
        s.state.record(dropped);
        s.reconcile(1_000 + ABANDON_AFTER_SECS - 1).await.unwrap();
        assert_eq!(s.state.sweeps[1].confirmation, Confirmation::Unconfirmed);
        s.reconcile(1_000 + ABANDON_AFTER_SECS).await.unwrap();
        assert_eq!(
            State::load(dir.path()).unwrap().sweeps[1].confirmation,
            Confirmation::Abandoned
        );
        // An entry that names no transaction or address is left as it is.
        let mut odd = first.clone();
        odd.txid = "t".into();
        odd.confirmation = Confirmation::Unconfirmed;
        s.state.record(odd);
        s.reconcile(1_000_000).await.unwrap();
        assert_eq!(s.state.sweeps[2].confirmation, Confirmation::Unconfirmed);
    }

    #[tokio::test]
    async fn waits_while_fees_are_above_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let k = keys();
        let chain = FakeChain {
            tip: 100,
            relay: 1.0,
            fee: Some(50.0),
            ..FakeChain::default()
        };
        chain.fund(&k.script(EXTERNAL, 0), 200_000, Some(90));
        let (mut s, shared) = sweeper(dir.path(), chain, &[]);
        let out = s.tick(1).await.unwrap();
        assert!(
            matches!(&out, Outcome::Waiting { why, .. } if why.contains("cap")),
            "{out:?}"
        );
        assert!(shared.0.broadcasts.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_refused_broadcast_burns_no_address() {
        let dir = tempfile::tempdir().unwrap();
        let k = keys();
        let chain = FakeChain {
            tip: 100,
            relay: 1.0,
            refuse_broadcast: true,
            ..FakeChain::default()
        };
        chain.fund(&k.script(EXTERNAL, 0), 200_000, Some(90));
        let (mut s, _) = sweeper(dir.path(), chain, &[]);
        assert!(s.tick(1).await.is_err());
        assert_eq!(s.state.next_destination, 0);
    }

    #[test]
    fn dust_is_left_and_inputs_are_capped() {
        let k = keys();
        let coins: Vec<Coin> = (0..(MAX_INPUTS as u32 + 10))
            .map(|i| crate::tx::tests::coin(&k, i, 1_000 + u64::from(i), (i % 250) as u8))
            .chain([crate::tx::tests::coin(&k, 0, 50, 251)])
            .collect();
        let picked = spendable(coins, 2.0);
        assert_eq!(picked.len(), MAX_INPUTS);
        assert!(
            picked.iter().all(|c| c.value.to_sat() >= 1_010),
            "the largest, and never the dust"
        );
    }

    #[test]
    fn sweeping_to_itself_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config(dir.path(), &[("DEADHOP_WALLET_DESTINATION", keys().account_key())]);
        let e = Sweeper::new(cfg, keys(), Box::new(FakeChain::default()), State::default())
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains("itself"), "{e}");
        let mut cfg = config(dir.path(), &[]);
        cfg.destination = None;
        let s = Sweeper::new(cfg, keys(), Box::new(FakeChain::default()), State::default()).unwrap();
        assert!(s.destination().is_err());
    }
}
