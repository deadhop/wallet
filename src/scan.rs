//! Finding the wallet's coins.
//!
//! The payment service gives every invoice its own receive address, and most
//! invoices are never paid, so used addresses are sparse: a plain gap-limit
//! scan would stop early and miss funds. The payment service therefore
//! writes its address high-water mark to a file (`DEADHOP_INDEX_FILE`), and
//! the scan always covers every index below it, plus a gap beyond the
//! highest used one.

use std::path::Path;

use crate::chain::Backend;
use crate::error::Result;
use crate::keys::{Keys, EXTERNAL, INTERNAL};
use crate::tx::Coin;

/// Default for the highest index taken from the payment service's file
/// (`DEADHOP_WALLET_MAX_INDEX_HINT`). That file comes from the
/// internet-facing service, so a value beyond any real use is not believed
/// in full: at this cap a poll asks about at most 2000 batches of addresses.
pub const MAX_INDEX_HINT: u32 = 1_000_000;
/// Addresses asked about per round trip of the scan.
const SCAN_CHUNK: u32 = 1_000;

/// The payment service's next unused index, or 0 when it has not said,
/// never more than `cap`. A value past the cap is clamped and logged: a
/// runaway index file should be seen, not silently believed or ignored.
pub fn read_index(file: Option<&Path>, cap: u32) -> u32 {
    let hint = file
        .and_then(|f| std::fs::read_to_string(f).ok())
        .and_then(|t| t.trim().parse::<u64>().ok())
        .unwrap_or(0);
    if hint > u64::from(cap) {
        tracing::warn!(
            hint,
            cap,
            "the payment service's index file is past DEADHOP_WALLET_MAX_INDEX_HINT; scanning up to the cap"
        );
        return cap;
    }
    hint as u32
}

/// Result of a scan.
#[derive(Debug, Default)]
pub struct Found {
    pub coins: Vec<Coin>,
    /// Scripts that could not be read (e.g. dusted past the limit).
    pub skipped: Vec<String>,
    /// Highest used index + 1 per chain.
    pub used_external: u32,
    pub used_internal: u32,
}

/// Indices of `chain` from 0, at least `floor` of them, extended until `gap`
/// unused ones follow the last used. Returns the used indices.
async fn used_indices(chain: &dyn Backend, keys: &Keys, branch: u32, floor: u32, gap: u32) -> Result<Vec<u32>> {
    let mut used = Vec::new();
    let mut scanned = 0u32;
    let mut until = floor.saturating_add(gap);
    while scanned < until {
        let range: Vec<u32> = (scanned..until.min(scanned.saturating_add(SCAN_CHUNK))).collect();
        let scripts: Vec<_> = range.iter().map(|i| keys.script(branch, *i)).collect();
        for (i, u) in range.iter().zip(chain.used(&scripts).await?) {
            if u {
                used.push(*i);
                until = until.max(i.saturating_add(1).saturating_add(gap));
            }
        }
        scanned = range.last().map_or(until, |l| l + 1);
    }
    Ok(used)
}

/// Every unspent coin of the wallet.
pub async fn scan(
    chain: &dyn Backend,
    keys: &Keys,
    external_floor: u32,
    internal_floor: u32,
    gap: u32,
) -> Result<Found> {
    let mut found = Found::default();
    for (branch, floor) in [(EXTERNAL, external_floor), (INTERNAL, internal_floor)] {
        let used = used_indices(chain, keys, branch, floor, gap).await?;
        let high = used.last().map_or(0, |i| i + 1);
        if branch == EXTERNAL {
            found.used_external = high;
        } else {
            found.used_internal = high;
        }
        let scripts: Vec<_> = used.iter().map(|i| keys.script(branch, *i)).collect();
        for ((index, script), list) in used.iter().zip(&scripts).zip(chain.unspent(&scripts).await?) {
            match list {
                Ok(list) => found.coins.extend(list.into_iter().map(|u| Coin {
                    outpoint: u.outpoint,
                    value: u.value,
                    chain: branch,
                    index: *index,
                    script: script.clone(),
                    height: u.height,
                })),
                Err(why) => found.skipped.push(format!("{}: {why}", keys.address(branch, *index))),
            }
        }
    }
    Ok(found)
}

/// Whether a coin has at least `min` confirmations at `tip`.
pub fn confirmed(coin: &Coin, tip: u32, min: u32) -> bool {
    coin.height
        .is_some_and(|h| tip.saturating_sub(h).saturating_add(1) >= min)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::tests::FakeChain;
    use crate::keys::tests::keys;

    #[tokio::test]
    async fn sparse_addresses_below_the_high_water_mark_are_found() {
        let k = keys();
        let chain = FakeChain::default();
        // Paid far apart, beyond any gap from each other.
        chain.fund(&k.script(EXTERNAL, 3), 1_000, Some(1));
        chain.fund(&k.script(EXTERNAL, 400), 2_000, Some(1));
        chain.fund(&k.script(INTERNAL, 2), 3_000, None);
        let without_hint = scan(&chain, &k, 0, 0, 20).await.unwrap();
        assert_eq!(without_hint.coins.len(), 2);
        let found = scan(&chain, &k, 401, 0, 20).await.unwrap();
        assert_eq!(found.coins.len(), 3);
        assert_eq!((found.used_external, found.used_internal), (401, 3));
        assert!(found.coins.iter().any(|c| c.index == 400 && c.chain == EXTERNAL));
        // A used address past the hint extends the scan by another gap.
        chain.fund(&k.script(EXTERNAL, 415), 1, Some(1));
        chain.fund(&k.script(EXTERNAL, 430), 1, Some(1));
        assert_eq!(scan(&chain, &k, 401, 0, 20).await.unwrap().coins.len(), 5);
        // A dusted address is skipped and named, the rest still found.
        chain.poisoned.lock().unwrap().insert(k.script(EXTERNAL, 3));
        let found = scan(&chain, &k, 401, 0, 20).await.unwrap();
        assert_eq!(found.coins.len(), 4);
        assert!(found.skipped[0].contains(&k.address(EXTERNAL, 3).to_string()));
    }

    #[test]
    fn index_file_and_confirmations() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("next-index");
        assert_eq!(read_index(None, MAX_INDEX_HINT), 0);
        assert_eq!(read_index(Some(&f), MAX_INDEX_HINT), 0);
        std::fs::write(&f, "42\n").unwrap();
        assert_eq!(read_index(Some(&f), MAX_INDEX_HINT), 42);
        std::fs::write(&f, "x").unwrap();
        assert_eq!(read_index(Some(&f), MAX_INDEX_HINT), 0);
        // A hostile or runaway file is clamped to the cap, even past u32.
        std::fs::write(&f, "4000000000").unwrap();
        assert_eq!(read_index(Some(&f), MAX_INDEX_HINT), MAX_INDEX_HINT);
        std::fs::write(&f, "99999999999999").unwrap();
        assert_eq!(read_index(Some(&f), MAX_INDEX_HINT), MAX_INDEX_HINT);
        std::fs::write(&f, "5000").unwrap();
        assert_eq!(read_index(Some(&f), 1_000), 1_000);
        assert_eq!(read_index(Some(&f), 5_000), 5_000);

        let k = keys();
        let mut c = crate::tx::tests::coin(&k, 0, 1, 1);
        c.height = Some(100);
        assert!(confirmed(&c, 100, 1) && !confirmed(&c, 100, 2) && confirmed(&c, 101, 2));
        c.height = None;
        assert!(!confirmed(&c, 100, 1));
    }
}
