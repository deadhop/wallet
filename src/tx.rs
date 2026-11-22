//! Building, checking and signing transactions.
//!
//! Every signature goes through [`sign`], and [`sign`] first runs
//! [`check`]: whatever built the transaction (this wallet, a PayJoin
//! receiver, CoinJoin peers), the wallet signs only if it spends its own
//! coins to the approved scripts and loses no more than the allowed cost.

use std::collections::HashMap;

use bitcoin::absolute::LockTime;
use bitcoin::ecdsa::Signature;
use bitcoin::hashes::Hash;
use bitcoin::psbt::{Input, Psbt};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

use crate::error::{Error, Result};
use crate::keys::Keys;

/// One coin this wallet can spend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coin {
    pub outpoint: OutPoint,
    pub value: Amount,
    /// Derivation of its key: `<account>/chain/index`.
    pub chain: u32,
    pub index: u32,
    pub script: ScriptBuf,
    pub height: Option<u32>,
}

/// Coins by outpoint.
pub type Coins = HashMap<OutPoint, Coin>;

/// Weight of a P2WPKH input, with the largest (73-byte) signature.
pub const P2WPKH_INPUT_WEIGHT: u64 = 41 * 4 + (1 + 1 + 73 + 1 + 33);
/// Weight of the version, locktime, counts and the segwit marker.
const TX_OVERHEAD_WEIGHT: u64 = (4 + 4 + 1 + 1) * 4 + 2;

/// Outputs below this are not relayed (dust) for any standard script.
pub const DUST_SAT: u64 = 546;

fn output_weight(script: &ScriptBuf) -> u64 {
    (8 + 1 + script.len() as u64) * 4
}

/// Virtual size of a transaction with `inputs` P2WPKH inputs and `outputs`.
pub fn vsize(inputs: usize, outputs: &[&ScriptBuf]) -> u64 {
    let w = TX_OVERHEAD_WEIGHT
        + inputs as u64 * P2WPKH_INPUT_WEIGHT
        + outputs.iter().map(|s| output_weight(s)).sum::<u64>();
    w.div_ceil(4)
}

/// Fee for `vbytes` at `rate` sat/vB, rounded up.
pub fn fee(vbytes: u64, rate: f64) -> Amount {
    Amount::from_sat((vbytes as f64 * rate).ceil() as u64)
}

fn input_for(coin: &Coin) -> Input {
    Input {
        witness_utxo: Some(TxOut {
            value: coin.value,
            script_pubkey: coin.script.clone(),
        }),
        ..Input::default()
    }
}

/// An unsigned PSBT spending `coins` to `outputs` (in that order).
pub fn build(coins: &[&Coin], outputs: Vec<TxOut>, sequence: Sequence) -> Psbt {
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: coins
            .iter()
            .map(|c| TxIn {
                previous_output: c.outpoint,
                sequence,
                ..TxIn::default()
            })
            .collect(),
        output: outputs,
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).expect("a transaction without scripts or witnesses");
    for (slot, c) in psbt.inputs.iter_mut().zip(coins) {
        *slot = input_for(c);
    }
    psbt
}

/// Every coin to one output at `dest`, the fee taken from it.
pub fn sweep(coins: &[&Coin], dest: &ScriptBuf, rate: f64) -> Result<(Psbt, Amount)> {
    if coins.is_empty() {
        return Err(Error::Policy("nothing to spend".into()));
    }
    let total: Amount = coins.iter().map(|c| c.value).sum();
    let fee = fee(vsize(coins.len(), &[dest]), rate);
    let out = total
        .checked_sub(fee)
        .filter(|v| v.to_sat() >= DUST_SAT)
        .ok_or_else(|| Error::Policy(format!("{total} does not cover the fee of {fee}")))?;
    let psbt = build(
        coins,
        vec![TxOut {
            value: out,
            script_pubkey: dest.clone(),
        }],
        Sequence::ENABLE_RBF_NO_LOCKTIME,
    );
    Ok((psbt, fee))
}

/// What a transaction must satisfy before this wallet signs any of it.
#[derive(Debug, Clone)]
pub struct Rules {
    /// Scripts the wallet's money may go to: the destination and, for
    /// CoinJoin premixes, the wallet's own change.
    pub to: Vec<ScriptBuf>,
    /// At least this much must reach `to`.
    pub min_to: Amount,
    /// The wallet may lose at most this much: its inputs minus what reaches `to`.
    pub max_cost: Amount,
}

/// Check `psbt` against `rules` for the inputs of `ours` it spends.
pub fn check(psbt: &Psbt, ours: &Coins, rules: &Rules) -> Result<()> {
    let refuse = |why: String| Err(Error::Policy(why));
    let tx = &psbt.unsigned_tx;
    if tx.input.len() != psbt.inputs.len() || tx.output.len() != psbt.outputs.len() {
        return refuse("the PSBT does not match its transaction".into());
    }
    let mut seen = std::collections::HashSet::new();
    let mut spent = Amount::ZERO;
    for (txin, input) in tx.input.iter().zip(&psbt.inputs) {
        if !seen.insert(txin.previous_output) {
            return refuse("an input is spent twice".into());
        }
        let Some(coin) = ours.get(&txin.previous_output) else {
            continue;
        };
        // Segwit signatures commit to the value, so a lie here could only
        // make the signature invalid; refuse it anyway, it means a bug or a
        // hostile counterparty.
        let expected = TxOut {
            value: coin.value,
            script_pubkey: coin.script.clone(),
        };
        if input.witness_utxo.as_ref() != Some(&expected) {
            return refuse(format!("input {} does not describe our coin", txin.previous_output));
        }
        spent += coin.value;
    }
    if spent == Amount::ZERO {
        return refuse("the transaction spends none of our coins".into());
    }
    let to: Amount = tx
        .output
        .iter()
        .filter(|o| rules.to.contains(&o.script_pubkey))
        .map(|o| o.value)
        .sum();
    if to < rules.min_to {
        return refuse(format!("only {to} reaches the destination, {} expected", rules.min_to));
    }
    let cost = spent.checked_sub(to).unwrap_or(Amount::ZERO);
    if cost > rules.max_cost {
        return refuse(format!(
            "it would cost {cost}, more than the allowed {}",
            rules.max_cost
        ));
    }
    Ok(())
}

/// Check, then sign and finalize every input of `psbt` spending one of `ours`.
/// Returns how many inputs were signed.
pub fn sign(psbt: &mut Psbt, keys: &Keys, ours: &Coins, rules: &Rules, sighash: EcdsaSighashType) -> Result<usize> {
    check(psbt, ours, rules)?;
    let mut cache = SighashCache::new(psbt.unsigned_tx.clone());
    let mut signed = 0;
    for (i, txin) in psbt.unsigned_tx.input.iter().enumerate() {
        let Some(coin) = ours.get(&txin.previous_output) else {
            continue;
        };
        // Cannot fail: the index is in range and the coin is P2WPKH.
        let hash = cache
            .p2wpkh_signature_hash(i, &coin.script, coin.value, sighash)
            .ok()
            .ok_or(Error::Policy(format!("cannot sign input {i}")))?;
        let key = keys.private(coin.chain, coin.index);
        let msg = bitcoin::secp256k1::Message::from_digest(hash.to_byte_array());
        let sig = Signature {
            signature: keys.secp().sign_ecdsa(&msg, &key.inner),
            sighash_type: sighash,
        };
        let input = &mut psbt.inputs[i];
        input.final_script_witness = Some(Witness::p2wpkh(&sig, &keys.public(coin.chain, coin.index).0));
        input.final_script_sig = Some(ScriptBuf::new());
        input.partial_sigs.clear();
        input.sighash_type = Some(sighash.into());
        input.bip32_derivation.clear();
        signed += 1;
    }
    Ok(signed)
}

/// The finished transaction. Fee limits were enforced by [`check`].
pub fn extract(psbt: Psbt) -> Transaction {
    psbt.extract_tx_unchecked_fee_rate()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::keys::tests::keys;
    use crate::keys::{EXTERNAL, INTERNAL};
    use bitcoin::Txid;

    pub fn coin(keys: &Keys, index: u32, sat: u64, n: u8) -> Coin {
        Coin {
            outpoint: OutPoint {
                txid: Txid::from_byte_array([n; 32]),
                vout: u32::from(n),
            },
            value: Amount::from_sat(sat),
            chain: EXTERNAL,
            index,
            script: keys.script(EXTERNAL, index),
            height: Some(10),
        }
    }

    pub fn by_outpoint(coins: &[Coin]) -> Coins {
        coins.iter().map(|c| (c.outpoint, c.clone())).collect()
    }

    #[test]
    fn sizes_match_a_real_signed_transaction() {
        let k = keys();
        let coins = [coin(&k, 0, 50_000, 1), coin(&k, 1, 70_000, 2)];
        let dest = k.script(INTERNAL, 9);
        let refs: Vec<&Coin> = coins.iter().collect();
        let (mut psbt, fee) = sweep(&refs, &dest, 2.0).unwrap();
        assert_eq!(fee.to_sat(), 2 * vsize(2, &[&dest]));
        let ours = by_outpoint(&coins);
        let rules = Rules {
            to: vec![dest.clone()],
            min_to: Amount::from_sat(120_000) - fee,
            max_cost: fee,
        };
        assert_eq!(sign(&mut psbt, &k, &ours, &rules, EcdsaSighashType::All).unwrap(), 2);
        let tx = extract(psbt);
        // The estimate allows the largest signature, so it is never below the real size.
        let real = tx.vsize() as u64;
        assert!(real <= vsize(2, &[&dest]) && real + 2 >= vsize(2, &[&dest]), "{real}");
        assert_eq!(tx.output[0].value, Amount::from_sat(120_000) - fee);
        assert!(tx.input.iter().all(|i| i.sequence == Sequence::ENABLE_RBF_NO_LOCKTIME));
    }

    #[test]
    fn sweeps_that_cannot_pay_their_fee_are_refused() {
        let k = keys();
        let dest = k.script(INTERNAL, 0);
        assert!(sweep(&[], &dest, 1.0).is_err());
        let c = coin(&k, 0, 600, 1);
        let e = sweep(&[&c], &dest, 1.0).unwrap_err().to_string();
        assert!(e.contains("does not cover"), "{e}");
        assert!(sweep(&[&coin(&k, 0, 700, 1)], &dest, 1.0).is_ok());
    }

    #[test]
    fn the_policy_is_checked_before_anything_is_signed() {
        let k = keys();
        let coins = [coin(&k, 0, 50_000, 1)];
        let ours = by_outpoint(&coins);
        let dest = k.script(INTERNAL, 0);
        let thief = k.script(INTERNAL, 99);
        let refs: Vec<&Coin> = coins.iter().collect();
        let rules = |min: u64, cost: u64| Rules {
            to: vec![dest.clone()],
            min_to: Amount::from_sat(min),
            max_cost: Amount::from_sat(cost),
        };
        let err = |psbt: &mut Psbt, r: &Rules| sign(psbt, &k, &ours, r, EcdsaSighashType::All).unwrap_err().to_string();

        // Paying someone else.
        let (mut p, _) = sweep(&refs, &thief, 1.0).unwrap();
        assert!(err(&mut p, &rules(1, 1000)).contains("reaches the destination"));
        assert!(p.inputs[0].final_script_witness.is_none());
        // Too expensive.
        let (mut p, fee) = sweep(&refs, &dest, 50.0).unwrap();
        assert!(err(&mut p, &rules(1, fee.to_sat() - 1)).contains("cost"));
        // Lying about our coin.
        let (mut p, _) = sweep(&refs, &dest, 1.0).unwrap();
        p.inputs[0].witness_utxo.as_mut().unwrap().value = Amount::from_sat(1);
        assert!(err(&mut p, &rules(1, 1000)).contains("does not describe"));
        // Not ours at all.
        let (mut p, _) = sweep(&refs, &dest, 1.0).unwrap();
        assert!(sign(&mut p, &k, &Coins::new(), &rules(1, 1000), EcdsaSighashType::All)
            .unwrap_err()
            .to_string()
            .contains("none of our coins"));
        // Malformed.
        let (mut p, _) = sweep(&refs, &dest, 1.0).unwrap();
        p.inputs.push(Input::default());
        assert!(err(&mut p, &rules(1, 1000)).contains("does not match"));
        let (mut p, _) = sweep(&refs, &dest, 1.0).unwrap();
        p.unsigned_tx.input.push(p.unsigned_tx.input[0].clone());
        p.inputs.push(p.inputs[0].clone());
        assert!(err(&mut p, &rules(1, 1000)).contains("twice"));
        // Someone else's input is left alone.
        let (mut p, _) = sweep(&refs, &dest, 1.0).unwrap();
        let other = coin(&k, 5, 1000, 9);
        p.unsigned_tx.input.push(TxIn {
            previous_output: other.outpoint,
            ..TxIn::default()
        });
        p.inputs.push(input_for(&other));
        assert_eq!(
            sign(&mut p, &k, &ours, &rules(1, 1000), EcdsaSighashType::All).unwrap(),
            1
        );
        assert!(p.inputs[1].final_script_witness.is_none());
    }
}
