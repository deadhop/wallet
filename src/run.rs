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
    let genesis = bitcoin::constants::genesis_block(cfg.network)
        .block_hash()
        .to_string();
    let chain = Electrum::new(cfg.electrum.clone(), ELECTRUM_TIMEOUT)
        .with_security(cfg.electrum_security.clone())
        .expect_genesis(genesis);
    let state = State::load(&cfg.state_dir)?;
    Sweeper::new(cfg, keys, Box::new(chain), state)
}

/// Describe a poll's outcome in one line.
pub fn describe(o: &Outcome) -> String {
    match o {
        Outcome::Below {
            confirmed,
            unconfirmed,
        } => {
            format!(
                "holding {confirmed} confirmed and {unconfirmed} unconfirmed, below the threshold"
            )
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
            Ok(o) => tracing::info!("{}", describe(&o)),
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
        None | Some("run") | Some("once") => {
            let keys = open_keys(&cfg)?;
            if !cfg.sweeps() {
                tracing::info!(
                    "holding the funds of {}: no destination is set, so nothing is swept and no connection is made",
                    keys.account_key()
                );
                if args.first().map(String::as_str) != Some("once") {
                    shutdown.await;
                }
                return Ok(());
            }
            tracing::info!(
                "sweeping by {} once {} sat are confirmed",
                cfg.mode.label(),
                cfg.threshold_sat
            );
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
                .unwrap_or_else(|| "warn,deadhop_wallet=info,deadhop=info".into()),
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
