//! The process: `deadhop-wallet [run|once|status]`.

use std::future::Future;
use std::process::ExitCode;
use std::time::Duration;

use deadhop::electrum::Electrum;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::keys::Keys;
use crate::state::State;
use crate::sweep::{Outcome, Sweeper};

const USAGE: &str = "usage: deadhop-wallet [run|once|status]\n\
  run     hold the funds, and sweep them once the confirmed balance reaches the threshold (default)\n\
  once    one poll, then exit\n\
  status  print the recent sweeps";

/// How long one Electrum request may take.
const ELECTRUM_TIMEOUT: Duration = Duration::from_secs(30);

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Open the keys and check them against the key the payment service watches.
pub fn open_keys(cfg: &Config) -> Result<Keys> {
    let keys = Keys::load(&cfg.data_dir, cfg.network)?;
    let published = std::fs::read_to_string(&cfg.xpub_file).map_err(|e| {
        Error::Config(format!(
            "{} (the account key the payment service watches): {e}",
            cfg.xpub_file.display()
        ))
    })?;
    keys.check_published(&published)?;
    Ok(keys)
}

/// The sweeper for `cfg`, with its Electrum connection (made lazily).
pub fn sweeper(cfg: Config, keys: Keys) -> Result<Sweeper> {
    let genesis = bitcoin::constants::genesis_block(cfg.network).block_hash().to_string();
    let chain = Electrum::new(cfg.electrum.clone(), ELECTRUM_TIMEOUT)
        .with_security(cfg.electrum_security.clone())
        .expect_genesis(genesis);
    let state = State::load(&cfg.state_dir)?;
    Sweeper::new(cfg, keys, Box::new(chain), state)
}

/// Describe a poll's outcome in one line.
pub fn describe(o: &Outcome) -> String {
    match o {
        Outcome::Below { confirmed, unconfirmed } => {
            format!("holding {confirmed} confirmed and {unconfirmed} unconfirmed, below the threshold")
        }
        Outcome::Waiting { confirmed, why } => {
            format!("due with {confirmed} confirmed, but waiting: {why}")
        }
        Outcome::Swept(s) => format!(
            "{}: moved {} sat of {} to {} in {}",
            s.mode, s.moved_sat, s.spent_sat, s.to, s.txid
        ),
    }
}

/// Poll until `shutdown`.
pub async fn run(mut s: Sweeper, shutdown: impl Future<Output = ()>) {
    tokio::pin!(shutdown);
    loop {
        match s.tick(now()).await {
            Ok(o) => {
                let line = describe(&o);
                tracing::info!("{line}");
            }
            Err(e) => tracing::warn!("poll failed: {e}"),
        }
        tokio::select! {
            _ = &mut shutdown => return,
            _ = tokio::time::sleep(Duration::from_secs(s.cfg.poll_secs)) => {}
        }
    }
}

async fn main(args: &[String], cfg: Config, shutdown: impl Future<Output = ()>) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("status") => {
            let state = State::load(&cfg.state_dir)?;
            if state.sweeps.is_empty() {
                println!("no sweeps yet");
            }
            for s in &state.sweeps {
                println!(
                    "{} {} moved {} of {} sat to {} in {}",
                    s.at, s.mode, s.moved_sat, s.spent_sat, s.to, s.txid
                );
            }
            Ok(())
        }
        None | Some("run") | Some("once") if cfg.own_xpub => {
            tracing::info!(
                "DEADHOP_XPUB is set: that wallet's keys are not on this host, so there is nothing here to hold \
                 or sweep. Sweep from the wallet that holds them."
            );
            if args.first().map(String::as_str) != Some("once") {
                shutdown.await;
            }
            Ok(())
        }
        None | Some("run") | Some("once") => {
            let keys = open_keys(&cfg)?;
            if !cfg.sweeps() {
                let key = keys.account_key();
                tracing::info!(
                    "holding the funds of {key}: no destination is set, so nothing is swept and no connection is made"
                );
                if args.first().map(String::as_str) != Some("once") {
                    shutdown.await;
                }
                return Ok(());
            }
            let (mode, threshold) = (cfg.mode.label(), cfg.threshold_sat);
            tracing::info!("sweeping by {mode} once {threshold} sat are confirmed");
            let mut s = sweeper(cfg, keys)?;
            if args.first().map(String::as_str) == Some("once") {
                let o = s.tick(now()).await?;
                println!("{}", describe(&o));
                return Ok(());
            }
            run(s, shutdown).await;
            Ok(())
        }
        Some(_) => Err(Error::Config(USAGE.into())),
    }
}

/// Entry point shared by the binary and the tests.
pub async fn command(
    args: &[String],
    lookup: impl Fn(&str) -> Option<String>,
    shutdown: impl Future<Output = ()>,
) -> ExitCode {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            lookup("DEADHOP_LOG")
                .filter(|v| !v.trim().is_empty())
                .unwrap_or("warn,deadhop_wallet=info,deadhop=info".into()),
        ))
        .with_writer(std::io::stderr)
        .try_init();
    let outcome = match Config::from_env(&lookup) {
        Ok(cfg) => main(args, cfg, shutdown).await,
        Err(e) => Err(e),
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("deadhop-wallet: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::tests::{keys, PHRASE};
    use std::collections::HashMap;
    use std::os::unix::fs::PermissionsExt;

    /// A data directory as the offline wallet service leaves it.
    fn wallet_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let phrase = dir.path().join(deadhop::keyholder::PHRASE_FILE);
        std::fs::write(&phrase, PHRASE).unwrap();
        std::fs::set_permissions(&phrase, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(dir.path().join("account.xpub"), keys().account_key()).unwrap();
        dir
    }

    fn vars(dir: &std::path::Path, extra: &[(&'static str, String)]) -> HashMap<&'static str, String> {
        let mut m = HashMap::from([
            ("DEADHOP_NETWORK", "regtest".to_string()),
            ("DEADHOP_DATA_DIR", dir.to_string_lossy().into_owned()),
            ("DEADHOP_LOG", "deadhop_wallet=debug".to_string()),
        ]);
        m.extend(extra.iter().cloned());
        m
    }

    async fn cmd(args: &[&str], m: &HashMap<&'static str, String>) -> ExitCode {
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        command(&args, |k| m.get(k).cloned(), async {}).await
    }

    #[tokio::test]
    async fn holds_without_a_destination_and_says_so() {
        let dir = wallet_dir();
        let m = vars(dir.path(), &[]);
        assert_eq!(cmd(&["once"], &m).await, ExitCode::SUCCESS);
        assert_eq!(cmd(&[], &m).await, ExitCode::SUCCESS, "returns once shut down");
        assert_eq!(cmd(&["status"], &m).await, ExitCode::SUCCESS);
        assert_eq!(cmd(&["nonsense"], &m).await, ExitCode::FAILURE);
        let own = vars(dir.path(), &[("DEADHOP_XPUB", keys().account_key())]);
        assert_eq!(cmd(&["once"], &own).await, ExitCode::SUCCESS);
        assert_eq!(cmd(&["run"], &own).await, ExitCode::SUCCESS);
        let bad = vars(dir.path(), &[("DEADHOP_WALLET_MODE", "x".into())]);
        assert_eq!(cmd(&["once"], &bad).await, ExitCode::FAILURE);
    }

    #[tokio::test]
    async fn refuses_a_phrase_that_is_not_the_watched_wallet() {
        let dir = wallet_dir();
        let m = vars(dir.path(), &[]);
        std::fs::write(dir.path().join("account.xpub"), crate::sweep::tests::other_account()).unwrap();
        assert_eq!(cmd(&["once"], &m).await, ExitCode::FAILURE);
        let gone = Config::from_env(&|k| {
            if k == "DEADHOP_XPUB_FILE" {
                Some("/nonexistent/account.xpub".into())
            } else {
                m.get(k).cloned()
            }
        })
        .unwrap();
        assert!(open_keys(&gone).err().unwrap().to_string().contains("watches"));
    }

    #[tokio::test]
    async fn one_poll_against_a_server() {
        let dir = wallet_dir();
        let electrum = crate::chain::tests::fake_electrum(HashMap::from([
            (
                "blockchain.headers.subscribe",
                serde_json::json!({"height": 0, "hex": ""}),
            ),
            ("blockchain.scripthash.get_history", serde_json::json!([])),
            ("blockchain.scripthash.listunspent", serde_json::json!([])),
        ]))
        .await;
        let regtest = crate::chain::tests::fake_electrum(HashMap::from([
            ("blockchain.headers.subscribe", serde_json::json!({"height": 0, "hex": ""})),
            ("blockchain.scripthash.get_history", serde_json::json!([])),
            ("blockchain.scripthash.listunspent", serde_json::json!([])),
            (
                "server.features",
                serde_json::json!({"genesis_hash": bitcoin::constants::genesis_block(bitcoin::Network::Regtest).block_hash().to_string()}),
            ),
        ]))
        .await;
        let on_regtest = vars(
            dir.path(),
            &[
                ("DEADHOP_ELECTRUM", regtest),
                ("DEADHOP_WALLET_DESTINATION", crate::sweep::tests::other_account()),
            ],
        );
        assert_eq!(cmd(&["once"], &on_regtest).await, ExitCode::SUCCESS);
        let m = vars(
            dir.path(),
            &[
                ("DEADHOP_ELECTRUM", electrum),
                ("DEADHOP_WALLET_DESTINATION", crate::sweep::tests::other_account()),
            ],
        );
        // The fake has no genesis to check: once refuses it, plainly.
        assert_eq!(cmd(&["once"], &m).await, ExitCode::FAILURE);
        // Against the same server without the genesis check, one poll holds.
        let cfg = Config::from_env(&|k| m.get(k).cloned()).unwrap();
        let chain = deadhop::electrum::Electrum::new(cfg.electrum.clone(), Duration::from_secs(5));
        let mut s = Sweeper::new(cfg, keys(), Box::new(chain), State::default()).unwrap();
        assert!(matches!(s.tick(1).await.unwrap(), Outcome::Below { .. }));
        let stop = tokio::time::sleep(Duration::from_millis(200));
        run(s, stop).await;
    }

    #[tokio::test]
    async fn polls_until_shut_down_and_reports_sweeps() {
        let dir = wallet_dir();
        // An Electrum server that is not there: polls fail and are retried.
        let m = vars(
            dir.path(),
            &[
                ("DEADHOP_ELECTRUM", "127.0.0.1:1".into()),
                ("DEADHOP_WALLET_DESTINATION", crate::sweep::tests::other_account()),
                ("DEADHOP_WALLET_POLL_SECS", "10".into()),
            ],
        );
        assert_eq!(cmd(&["once"], &m).await, ExitCode::FAILURE);
        assert_eq!(cmd(&["run"], &m).await, ExitCode::SUCCESS);

        let cfg = Config::from_env(&|k| m.get(k).cloned()).unwrap();
        let s = sweeper(
            cfg,
            open_keys(&Config::from_env(&|k| m.get(k).cloned()).unwrap()).unwrap(),
        )
        .unwrap();
        let stop = tokio::time::sleep(Duration::from_millis(50));
        run(s, stop).await;

        let mut state = State::default();
        state.record(crate::state::Sweep {
            at: 1,
            mode: "send".into(),
            txid: "t".into(),
            spent_sat: 2,
            moved_sat: 1,
            to: "a".into(),
        });
        state.save(dir.path()).unwrap();
        assert_eq!(cmd(&["status"], &m).await, ExitCode::SUCCESS);
        std::fs::write(dir.path().join(crate::state::STATE_FILE), "{").unwrap();
        assert_eq!(cmd(&["status"], &m).await, ExitCode::FAILURE);

        let d = |o: Outcome| describe(&o);
        assert!(d(Outcome::Below {
            confirmed: bitcoin::Amount::ONE_SAT,
            unconfirmed: bitcoin::Amount::ZERO
        })
        .contains("below"));
        assert!(d(Outcome::Waiting {
            confirmed: bitcoin::Amount::ONE_SAT,
            why: "fees".into()
        })
        .contains("fees"));
        assert!(d(Outcome::Swept(state.sweeps[0].clone())).contains("moved 1 sat"));
    }
}
