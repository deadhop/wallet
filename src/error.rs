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

impl From<deadhop::error::Error> for Error {
    fn from(e: deadhop::error::Error) -> Self {
        match e {
            deadhop::error::Error::Config(m) => Error::Config(m),
            deadhop::error::Error::Io(e) => Error::Io(e),
            other => Error::Chain(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn library_errors_keep_their_kind() {
        let c: Error = deadhop::error::Error::Config("x".into()).into();
        assert!(matches!(c, Error::Config(m) if m == "x"));
        let io: Error = deadhop::error::Error::Io(std::io::Error::other("disk")).into();
        assert!(matches!(io, Error::Io(_)));
        let ch: Error = deadhop::error::Error::Chain("down".into()).into();
        assert!(matches!(ch, Error::Chain(m) if m.contains("down")));
    }
}
