//! What the wallet remembers between runs, in one JSON file replaced
//! atomically: which destination and change addresses it has used, which
//! PayJoin URIs it has already paid, and its recent sweeps.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const STATE_FILE: &str = "sweeper.json";
/// Sweeps kept in the history.
pub const HISTORY: usize = 100;
/// PayJoin URIs remembered as used.
pub const USED_URIS: usize = 1_000;

/// One completed sweep.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sweep {
    pub at: u64,
    pub mode: String,
    pub txid: String,
    /// Satoshis of ours that the transaction spent.
    pub spent_sat: u64,
    /// Satoshis that reached the destination.
    pub moved_sat: u64,
    pub to: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// Next unused index of the destination account.
    pub next_destination: u32,
    /// Next unused index of this wallet's change chain.
    pub next_change: u32,
    /// SHA-256 of every PayJoin URI already paid (a URI is used once).
    pub used_payjoin: Vec<String>,
    pub sweeps: Vec<Sweep>,
}

impl State {
    pub fn path(dir: &Path) -> PathBuf {
        dir.join(STATE_FILE)
    }

    pub fn load(dir: &Path) -> Result<State> {
        match std::fs::read_to_string(Self::path(dir)) {
            Ok(text) => serde_json::from_str(&text)
                .map_err(|e| Error::Config(format!("{} is damaged: {e}", Self::path(dir).display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Write the file atomically (temporary file, sync, rename).
    pub fn save(&self, dir: &Path) -> Result<()> {
        use std::io::Write;
        let path = Self::path(dir);
        let tmp = path.with_extension("tmp");
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(serde_json::to_string_pretty(self).expect("plain data").as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    pub fn record(&mut self, sweep: Sweep) {
        self.sweeps.push(sweep);
        let extra = self.sweeps.len().saturating_sub(HISTORY);
        self.sweeps.drain(..extra);
    }

    pub fn payjoin_used(&self, uri_hash: &str) -> bool {
        self.used_payjoin.iter().any(|h| h == uri_hash)
    }

    pub fn use_payjoin(&mut self, uri_hash: String) {
        self.used_payjoin.push(uri_hash);
        let extra = self.used_payjoin.len().saturating_sub(USED_URIS);
        self.used_payjoin.drain(..extra);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sweep(n: u64) -> Sweep {
        Sweep {
            at: n,
            mode: "send".into(),
            txid: format!("{n}"),
            spent_sat: n,
            moved_sat: n,
            to: "x".into(),
        }
    }

    #[test]
    fn survives_a_restart_and_stays_bounded() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(State::load(dir.path()).unwrap(), State::default());
        let mut s = State::default();
        for n in 0..(HISTORY as u64 + 5) {
            s.record(sweep(n));
        }
        for n in 0..(USED_URIS + 2) {
            s.use_payjoin(format!("{n}"));
        }
        assert_eq!(s.sweeps.len(), HISTORY);
        assert_eq!(s.sweeps[0].at, 5);
        assert!(s.payjoin_used(&format!("{}", USED_URIS + 1)) && !s.payjoin_used("0"));
        s.next_destination = 3;
        s.save(dir.path()).unwrap();
        assert_eq!(State::load(dir.path()).unwrap(), s);

        std::fs::write(State::path(dir.path()), "{").unwrap();
        assert!(State::load(dir.path()).unwrap_err().to_string().contains("damaged"));
        let not_a_dir = dir.path().join(STATE_FILE).join("x");
        assert!(State::load(&not_a_dir).is_err());
        assert!(s.save(&not_a_dir).is_err());
    }
}
