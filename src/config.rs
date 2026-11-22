//! Configuration, from the environment only. Nothing that decides where money
//! goes can be changed remotely: the destination, mode, threshold and fee cap
//! are set on the host.

use std::path::PathBuf;

use bitcoin::Network;
use deadhop::config::{parse_electrum, parse_network};
use deadhop::electrum::{parse_fingerprint, Security};
use deadhop::relay::{parse_proxy, ProxySpec};
use deadhop::wallet::Wallet as Watch;

use crate::error::{Error, Result};

/// How the balance leaves the wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// One transaction: every coin to a fresh destination address.
    Send,
    /// BIP-78 PayJoin with a receiver named by a payment URI.
    Payjoin,
    /// A joinstr CoinJoin round over Nostr, then the mixed coin to a fresh
    /// destination address.
    Coinjoin,
}

impl Mode {
    pub fn label(self) -> &'static str {
        match self {
            Mode::Send => "send",
            Mode::Payjoin => "payjoin",
            Mode::Coinjoin => "coinjoin",
        }
    }
}

/// CoinJoin settings.
#[derive(Debug, Clone)]
pub struct CoinjoinConfig {
    /// The one relay every message of a pool goes through.
    pub relay: String,
    /// Satoshis each participant puts in.
    pub denomination_sat: u64,
    /// Participants per round, this wallet included.
    pub peers: u32,
    /// Seconds a round may take before it is abandoned.
    pub timeout_secs: u64,
}

/// Everything the wallet reads at start.
pub struct Config {
    pub network: Network,
    /// Holds the recovery phrase; only read.
    pub data_dir: PathBuf,
    /// The account key the payment service watches; must match the phrase.
    pub xpub_file: PathBuf,
    /// Where this process keeps its own state.
    pub state_dir: PathBuf,
    /// Highest address index the payment service has handed out, if it says.
    pub index_file: Option<PathBuf>,
    pub electrum: String,
    pub electrum_security: Security,
    pub mode: Mode,
    /// Account key of the wallet funds are moved to, a fresh address each time.
    /// `None` means hold: never sweep (and never connect).
    pub destination: Option<String>,
    pub threshold_sat: u64,
    pub max_fee_rate: f64,
    pub fee_target_blocks: u16,
    pub min_confirmations: u32,
    pub poll_secs: u64,
    pub gap: u32,
    pub payjoin_uri_file: Option<PathBuf>,
    pub payjoin_pins: Option<Vec<[u8; 32]>>,
    /// Proxy for PayJoin requests and CoinJoin relay traffic.
    pub proxy: Option<ProxySpec>,
    pub coinjoin: Option<CoinjoinConfig>,
}

/// Bounds on the numeric settings.
pub mod bounds {
    pub const THRESHOLD_SAT: (u64, u64) = (10_000, 2_100_000_000_000_000);
    pub const MAX_FEE_RATE: (u64, u64) = (1, 1_000);
    pub const FEE_TARGET: (u64, u64) = (1, 1_008);
    pub const MIN_CONFIRMATIONS: (u64, u64) = (1, 100);
    pub const POLL_SECS: (u64, u64) = (10, 86_400);
    pub const GAP: (u64, u64) = (1, 10_000);
    pub const DENOMINATION_SAT: (u64, u64) = (10_000, 2_100_000_000_000_000);
    pub const PEERS: (u64, u64) = (2, 100);
    pub const TIMEOUT_SECS: (u64, u64) = (60, 86_400);
}

impl Config {
    pub fn from_env(lookup: &dyn Fn(&str) -> Option<String>) -> Result<Config> {
        let get = |k: &str| {
            lookup(k)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let num = |k: &str, default: u64, (lo, hi): (u64, u64)| -> Result<u64> {
            let Some(v) = get(k) else { return Ok(default) };
            v.parse::<u64>()
                .ok()
                .filter(|n| (lo..=hi).contains(n))
                .ok_or_else(|| {
                    Error::Config(format!("{k} must be a whole number from {lo} to {hi}"))
                })
        };
        let network = parse_network(&get("DEADHOP_NETWORK").unwrap_or("bitcoin".into()))?;
        let data_dir = PathBuf::from(get("DEADHOP_DATA_DIR").unwrap_or("data".into()));
        let xpub_file =
            get("DEADHOP_XPUB_FILE").map_or(data_dir.join("account.xpub"), PathBuf::from);
        let state_dir = get("DEADHOP_WALLET_STATE_DIR").map_or(data_dir.clone(), PathBuf::from);
        if get("DEADHOP_XPUB").is_some() {
            return Err(Error::Config(
                "DEADHOP_XPUB is set: the keys of that wallet are not on this host, so there is nothing \
                 here to sweep. Sweep from the wallet that holds them."
                    .into(),
            ));
        }

        let mode = match get("DEADHOP_WALLET_MODE").as_deref() {
            None | Some("send") => Mode::Send,
            Some("payjoin") => Mode::Payjoin,
            Some("coinjoin") => Mode::Coinjoin,
            Some(other) => {
                return Err(Error::Config(format!(
                    "DEADHOP_WALLET_MODE '{other}' must be send, payjoin or coinjoin"
                )))
            }
        };
        let destination = get("DEADHOP_WALLET_DESTINATION");
        if let Some(d) = &destination {
            Watch::new(d, network).map_err(|_| {
                Error::Config(
                    "DEADHOP_WALLET_DESTINATION must be the account key (xpub/zpub, or tpub/vpub off mainnet) \
                     of the wallet to move funds to"
                        .into(),
                )
            })?;
        }
        let payjoin_uri_file = get("DEADHOP_WALLET_PAYJOIN_URI_FILE").map(PathBuf::from);
        let electrum = get("DEADHOP_ELECTRUM");
        let sweeping =
            destination.is_some() || (mode == Mode::Payjoin && payjoin_uri_file.is_some());
        let (electrum, electrum_security) = match (electrum, sweeping) {
            (Some(e), _) => parse_electrum(&e, get("DEADHOP_ELECTRUM_CERT_SHA256").as_deref())?,
            (None, false) => (String::new(), Security::Plain),
            (None, true) => {
                return Err(Error::Config(
                    "DEADHOP_ELECTRUM is required to sweep".into(),
                ))
            }
        };
        match mode {
            Mode::Payjoin if payjoin_uri_file.is_none() && destination.is_some() => {
                return Err(Error::Config(
                    "payjoin mode needs DEADHOP_WALLET_PAYJOIN_URI_FILE: a file holding the receiver's bitcoin: \
                     URI with a pj= endpoint"
                        .into(),
                ))
            }
            Mode::Send | Mode::Coinjoin if payjoin_uri_file.is_some() => {
                return Err(Error::Config(
                    "DEADHOP_WALLET_PAYJOIN_URI_FILE is only used with DEADHOP_WALLET_MODE=payjoin".into(),
                ))
            }
            _ => {}
        }
        let payjoin_pins = match get("DEADHOP_WALLET_PAYJOIN_CERT_SHA256") {
            None => None,
            Some(list) => Some(
                list.split(',')
                    .map(|p| {
                        parse_fingerprint(p).ok_or_else(|| {
                            Error::Config(format!("'{}' is not a SHA-256 fingerprint", p.trim()))
                        })
                    })
                    .collect::<Result<Vec<_>>>()?,
            ),
        };
        let proxy = match get("DEADHOP_WALLET_PROXY") {
            None => None,
            Some(p) => {
                parse_proxy(&p).map_err(|e| Error::Config(format!("DEADHOP_WALLET_PROXY: {e}")))?
            }
        };
        let coinjoin = if mode == Mode::Coinjoin {
            let relay = get("DEADHOP_WALLET_COINJOIN_RELAY").ok_or_else(|| {
                Error::Config("coinjoin mode needs DEADHOP_WALLET_COINJOIN_RELAY".into())
            })?;
            if !(relay.starts_with("wss://") || relay.starts_with("ws://")) {
                return Err(Error::Config(
                    "DEADHOP_WALLET_COINJOIN_RELAY must be a ws:// or wss:// url".into(),
                ));
            }
            Some(CoinjoinConfig {
                relay,
                denomination_sat: num(
                    "DEADHOP_WALLET_COINJOIN_DENOMINATION_SAT",
                    1_000_000,
                    bounds::DENOMINATION_SAT,
                )?,
                peers: num("DEADHOP_WALLET_COINJOIN_PEERS", 5, bounds::PEERS)? as u32,
                timeout_secs: num(
                    "DEADHOP_WALLET_COINJOIN_TIMEOUT_SECS",
                    1_800,
                    bounds::TIMEOUT_SECS,
                )?,
            })
        } else {
            None
        };
        let threshold_sat = num(
            "DEADHOP_WALLET_THRESHOLD_SAT",
            1_000_000,
            bounds::THRESHOLD_SAT,
        )?;
        if let Some(cj) = &coinjoin {
            if threshold_sat < cj.denomination_sat + crate::coinjoin::MIN_EXCESS_SAT {
                return Err(Error::Config(format!(
                    "DEADHOP_WALLET_THRESHOLD_SAT must be at least the denomination plus {} sat",
                    crate::coinjoin::MIN_EXCESS_SAT
                )));
            }
        }
        Ok(Config {
            network,
            data_dir,
            xpub_file,
            state_dir,
            index_file: get("DEADHOP_INDEX_FILE").map(PathBuf::from),
            electrum,
            electrum_security,
            mode,
            destination,
            threshold_sat,
            max_fee_rate: num("DEADHOP_WALLET_MAX_FEE_RATE", 20, bounds::MAX_FEE_RATE)? as f64,
            fee_target_blocks: num("DEADHOP_WALLET_FEE_TARGET_BLOCKS", 6, bounds::FEE_TARGET)?
                as u16,
            min_confirmations: num(
                "DEADHOP_WALLET_MIN_CONFIRMATIONS",
                1,
                bounds::MIN_CONFIRMATIONS,
            )? as u32,
            poll_secs: num("DEADHOP_WALLET_POLL_SECS", 300, bounds::POLL_SECS)?,
            gap: num("DEADHOP_WALLET_GAP", 50, bounds::GAP)? as u32,
            payjoin_uri_file,
            payjoin_pins,
            proxy,
            coinjoin,
        })
    }

    /// Whether this configuration ever moves funds.
    pub fn sweeps(&self) -> bool {
        match self.mode {
            Mode::Payjoin => self.payjoin_uri_file.is_some(),
            _ => self.destination.is_some(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A valid regtest account key of another wallet.
    fn tpub() -> String {
        crate::keys::Keys::from_phrase(
            &bip39::Mnemonic::from_entropy(&[7u8; 32]).unwrap(),
            Network::Regtest,
        )
        .account_key()
    }

    fn env(pairs: &[(&'static str, &str)]) -> HashMap<&'static str, String> {
        pairs.iter().map(|(k, v)| (*k, v.to_string())).collect()
    }

    fn load(m: &HashMap<&'static str, String>) -> Result<Config> {
        Config::from_env(&|k| m.get(k).cloned())
    }

    fn err(pairs: &[(&'static str, &str)]) -> String {
        load(&env(pairs)).err().expect("an error").to_string()
    }

    #[test]
    fn holding_needs_nothing() {
        let c = load(&env(&[])).unwrap();
        assert_eq!(c.mode, Mode::Send);
        assert!(!c.sweeps());
        assert_eq!(c.state_dir, PathBuf::from("data"));
        assert_eq!(c.xpub_file, PathBuf::from("data/account.xpub"));
        assert_eq!(
            (c.threshold_sat, c.max_fee_rate, c.poll_secs, c.gap),
            (1_000_000, 20.0, 300, 50)
        );
        assert!(c.index_file.is_none() && c.proxy.is_none() && c.payjoin_pins.is_none());
        assert_eq!(Mode::Coinjoin.label(), "coinjoin");
    }

    #[test]
    fn a_simple_send() {
        let c = load(&env(&[
            ("DEADHOP_NETWORK", "regtest"),
            ("DEADHOP_ELECTRUM", "127.0.0.1:50001"),
            ("DEADHOP_WALLET_DESTINATION", &tpub()),
            ("DEADHOP_WALLET_THRESHOLD_SAT", "20000"),
            ("DEADHOP_WALLET_STATE_DIR", "/state"),
            ("DEADHOP_INDEX_FILE", "/scan/next-index"),
            ("DEADHOP_WALLET_PROXY", "socks5://127.0.0.1:9050"),
        ]))
        .unwrap();
        assert!(c.sweeps());
        assert_eq!(c.mode.label(), "send");
        assert_eq!(c.threshold_sat, 20_000);
        assert_eq!(c.state_dir, PathBuf::from("/state"));
        assert!(c.index_file.is_some() && c.proxy.is_some());
    }

    #[test]
    fn payjoin_and_coinjoin() {
        let c = load(&env(&[
            ("DEADHOP_NETWORK", "regtest"),
            ("DEADHOP_ELECTRUM", "127.0.0.1:50001"),
            ("DEADHOP_WALLET_MODE", "payjoin"),
            ("DEADHOP_WALLET_PAYJOIN_URI_FILE", "/pj/uri"),
            ("DEADHOP_WALLET_PAYJOIN_CERT_SHA256", &"ab".repeat(32)),
        ]))
        .unwrap();
        assert!(c.sweeps() && c.destination.is_none() && c.payjoin_pins.unwrap().len() == 1);

        let c = load(&env(&[
            ("DEADHOP_NETWORK", "regtest"),
            ("DEADHOP_ELECTRUM", "127.0.0.1:50001"),
            ("DEADHOP_WALLET_MODE", "coinjoin"),
            ("DEADHOP_WALLET_DESTINATION", &tpub()),
            ("DEADHOP_WALLET_COINJOIN_RELAY", "ws://127.0.0.1:7777"),
            ("DEADHOP_WALLET_COINJOIN_DENOMINATION_SAT", "100000"),
            ("DEADHOP_WALLET_COINJOIN_PEERS", "3"),
            ("DEADHOP_WALLET_THRESHOLD_SAT", "200000"),
        ]))
        .unwrap();
        let cj = c.coinjoin.unwrap();
        assert_eq!(
            (cj.denomination_sat, cj.peers, cj.timeout_secs),
            (100_000, 3, 1_800)
        );
    }

    #[test]
    fn mistakes_are_named() {
        let base = [
            ("DEADHOP_NETWORK", "regtest"),
            ("DEADHOP_ELECTRUM", "127.0.0.1:50001"),
        ];
        let with = |extra: &[(&'static str, &str)]| {
            let mut v = base.to_vec();
            v.extend_from_slice(extra);
            err(&v)
        };
        assert!(err(&[("DEADHOP_XPUB", &tpub())]).contains("not on this host"));
        assert!(with(&[("DEADHOP_WALLET_MODE", "lightning")]).contains("send, payjoin or coinjoin"));
        assert!(with(&[("DEADHOP_WALLET_DESTINATION", "bc1q")]).contains("account key"));
        assert!(err(&[
            ("DEADHOP_NETWORK", "regtest"),
            ("DEADHOP_WALLET_DESTINATION", &tpub())
        ])
        .contains("ELECTRUM"));
        assert!(with(&[
            ("DEADHOP_WALLET_MODE", "payjoin"),
            ("DEADHOP_WALLET_DESTINATION", &tpub())
        ])
        .contains("PAYJOIN_URI_FILE"));
        assert!(with(&[("DEADHOP_WALLET_PAYJOIN_URI_FILE", "/x")]).contains("only used"));
        assert!(with(&[("DEADHOP_WALLET_PAYJOIN_CERT_SHA256", "zz")]).contains("fingerprint"));
        assert!(with(&[("DEADHOP_WALLET_PROXY", "ftp://x")]).contains("DEADHOP_WALLET_PROXY"));
        assert!(with(&[("DEADHOP_WALLET_THRESHOLD_SAT", "5")]).contains("from 10000"));
        assert!(with(&[("DEADHOP_WALLET_MAX_FEE_RATE", "x")]).contains("whole number"));
        let dest = tpub();
        let cj = |extra: &[(&'static str, &str)]| {
            let mut v = vec![
                ("DEADHOP_WALLET_MODE", "coinjoin"),
                ("DEADHOP_WALLET_DESTINATION", dest.as_str()),
            ];
            v.extend_from_slice(extra);
            with(&v)
        };
        assert!(cj(&[]).contains("COINJOIN_RELAY"));
        assert!(cj(&[("DEADHOP_WALLET_COINJOIN_RELAY", "http://x")]).contains("ws://"));
        assert!(cj(&[
            ("DEADHOP_WALLET_COINJOIN_RELAY", "ws://x"),
            ("DEADHOP_WALLET_THRESHOLD_SAT", "20000")
        ])
        .contains("denomination"));
        assert!(err(&[("DEADHOP_NETWORK", "moon")]).contains("moon"));
    }
}
