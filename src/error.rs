//! Errors of the sweeping wallet.

/// Why a step failed. `Config` stops the process; everything else is retried
/// on the next poll.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("configuration: {0}")]
    Config(String),
    #[error("chain: {0}")]
    Chain(String),
    /// A transaction this wallet was asked to sign broke its spending policy.
    #[error("refused to sign: {0}")]
    Policy(String),
    #[error("payjoin: {0}")]
    Payjoin(String),
    #[error("coinjoin: {0}")]
    Coinjoin(String),
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<deadhop_common::error::Error> for Error {
    fn from(e: deadhop_common::error::Error) -> Self {
        match e {
            deadhop_common::error::Error::Config(m) => Error::Config(m),
            deadhop_common::error::Error::Io(e) => Error::Io(e),
            other => Error::Chain(other.to_string()),
        }
    }
}

impl From<deadhop_electrum::error::Error> for Error {
    fn from(e: deadhop_electrum::error::Error) -> Self {
        match e {
            deadhop_electrum::error::Error::Config(m) => Error::Config(m),
            other => Error::Chain(other.to_string()),
        }
    }
}

impl From<deadhop_net::error::Error> for Error {
    fn from(e: deadhop_net::error::Error) -> Self {
        Error::Config(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn library_errors_keep_their_kind() {
        let c: Error = deadhop_common::error::Error::Config("x".into()).into();
        assert!(matches!(c, Error::Config(m) if m == "x"));
        let io: Error = deadhop_common::error::Error::Io(std::io::Error::other("disk")).into();
        assert!(matches!(io, Error::Io(_)));
        let ch: Error = deadhop_common::error::Error::Chain("down".into()).into();
        assert!(matches!(ch, Error::Chain(m) if m.contains("down")));
        let ec: Error = deadhop_electrum::error::Error::Config("y".into()).into();
        assert!(matches!(ec, Error::Config(m) if m == "y"));
        let eb: Error = deadhop_electrum::error::Error::Chain("gone".into()).into();
        assert!(matches!(eb, Error::Chain(m) if m.contains("gone")));
        let p: Error = deadhop_net::error::Error::InvalidParams("bad".into()).into();
        assert!(matches!(p, Error::Config(m) if m.contains("bad")));
    }
}
