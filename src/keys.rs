//! Spending keys of the wallet the payment service watches.
//!
//! The recovery phrase is the one the offline wallet service (`deadhop wallet
//! serve`) generated. This process only ever reads it: it never creates a
//! phrase, so a missing or moved file can never turn into a new, empty wallet
//! whose address the payment service does not watch.

use std::path::Path;
use std::str::FromStr;

use bip39::Mnemonic;
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv, Xpub};
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::{Address, CompressedPublicKey, Network, PrivateKey, ScriptBuf};
use deadhop_common::files::read_private;
use deadhop_common::wallet::{account_path, encode_account, Wallet};
use deadhop_common::PHRASE_FILE;

use crate::error::{Error, Result};

/// Receive chain: the payment service hands these out, one per invoice.
pub const EXTERNAL: u32 = 0;
/// Change chain: only this wallet uses it (for CoinJoin premix change).
pub const INTERNAL: u32 = 1;

/// The BIP-84 account's private key.
pub struct Keys {
    secp: Secp256k1<All>,
    account: Xpriv,
    network: Network,
}

impl Keys {
    /// Keys of a recovery phrase (no passphrase), BIP-84 account 0.
    pub fn from_phrase(phrase: &Mnemonic, network: Network) -> Self {
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(network, &phrase.to_seed("")).expect("a 64-byte seed is a valid master key");
        let path = DerivationPath::from_str(account_path(network)).expect("constant path");
        let account = master
            .derive_priv(&secp, &path)
            .expect("hardened derivation from a valid key");
        Keys { secp, account, network }
    }

    /// Read the phrase in `dir`. Never creates one.
    pub fn load(dir: &Path, network: Network) -> Result<Self> {
        let path = dir.join(PHRASE_FILE);
        let text = read_private(&path)?.ok_or_else(|| {
            Error::Config(format!(
                "{} does not exist. This wallet never creates a phrase: start the offline wallet service \
                 (deadhop wallet serve) first, and give this process its data directory",
                path.display()
            ))
        })?;
        let phrase = Mnemonic::parse(text.trim())
            .map_err(|_| Error::Config(format!("{} does not contain a BIP-39 recovery phrase", path.display())))?;
        Ok(Self::from_phrase(&phrase, network))
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// The account public key, encoded the way the wallet service publishes it.
    pub fn account_key(&self) -> String {
        encode_account(&Xpub::from_priv(&self.secp, &self.account))
    }

    /// Refuse to run against a payment service watching another wallet.
    pub fn check_published(&self, published: &str) -> Result<()> {
        let published = published.trim();
        let ours = Wallet::new(&self.account_key(), self.network)?.account_id();
        let theirs = Wallet::new(published, self.network)
            .map_err(|_| Error::Config("the published account key is not a valid key for this network".into()))?
            .account_id();
        if ours != theirs {
            return Err(Error::Config(
                "the recovery phrase does not belong to the account key the payment service watches".into(),
            ));
        }
        Ok(())
    }

    /// Private key at `<account>/chain/index`.
    pub fn private(&self, chain: u32, index: u32) -> PrivateKey {
        let child = self
            .account
            .derive_priv(
                &self.secp,
                &[ChildNumber::Normal { index: chain }, ChildNumber::Normal { index }],
            )
            .expect("non-hardened derivation from a valid key");
        child.to_priv()
    }

    /// Public key at `<account>/chain/index`.
    pub fn public(&self, chain: u32, index: u32) -> CompressedPublicKey {
        CompressedPublicKey::from_private_key(&self.secp, &self.private(chain, index))
            .expect("derived keys are compressed")
    }

    /// P2WPKH script at `<account>/chain/index`.
    pub fn script(&self, chain: u32, index: u32) -> ScriptBuf {
        ScriptBuf::new_p2wpkh(&self.public(chain, index).wpubkey_hash())
    }

    /// P2WPKH address at `<account>/chain/index`.
    pub fn address(&self, chain: u32, index: u32) -> Address {
        Address::p2wpkh(&self.public(chain, index), self.network)
    }

    pub fn secp(&self) -> &Secp256k1<All> {
        &self.secp
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use deadhop_common::wallet::account_from_phrase;
    use std::os::unix::fs::PermissionsExt;

    pub const PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    pub fn keys() -> Keys {
        Keys::from_phrase(&Mnemonic::parse(PHRASE).unwrap(), Network::Regtest)
    }

    #[test]
    fn same_account_as_the_offline_wallet_service() {
        let phrase = Mnemonic::parse(PHRASE).unwrap();
        for network in [Network::Bitcoin, Network::Regtest] {
            let k = Keys::from_phrase(&phrase, network);
            assert_eq!(k.account_key(), encode_account(&account_from_phrase(&phrase, network)));
            let w = Wallet::new(&k.account_key(), network).unwrap();
            assert_eq!(w.address(3).unwrap(), k.address(EXTERNAL, 3));
            assert_eq!(k.network(), network);
        }
        // BIP-84 test vector: first receive address of this phrase.
        let k = Keys::from_phrase(&phrase, Network::Bitcoin);
        assert_eq!(
            k.address(EXTERNAL, 0).to_string(),
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
        assert_eq!(k.script(INTERNAL, 0), k.address(INTERNAL, 0).script_pubkey());
    }

    #[test]
    fn the_published_key_must_match() {
        let k = keys();
        k.check_published(&format!("{}\n", k.account_key())).unwrap();
        let other = Keys::from_phrase(&Mnemonic::from_entropy(&[7u8; 32]).unwrap(), Network::Regtest);
        let e = k.check_published(&other.account_key()).unwrap_err().to_string();
        assert!(e.contains("does not belong"), "{e}");
        let e = k.check_published("nonsense").unwrap_err().to_string();
        assert!(e.contains("not a valid key"), "{e}");
    }

    #[test]
    fn loads_but_never_creates_a_phrase() {
        let dir = tempfile::tempdir().unwrap();
        let e = Keys::load(dir.path(), Network::Regtest).err().unwrap().to_string();
        assert!(e.contains("never creates"), "{e}");
        assert!(!dir.path().join(PHRASE_FILE).exists());

        let path = dir.path().join(PHRASE_FILE);
        std::fs::write(&path, "not words").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let e = Keys::load(dir.path(), Network::Regtest).err().unwrap().to_string();
        assert!(e.contains("BIP-39"), "{e}");

        std::fs::write(&path, format!("{PHRASE}\n")).unwrap();
        let k = Keys::load(dir.path(), Network::Regtest).unwrap();
        assert_eq!(k.account_key(), keys().account_key());

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Keys::load(dir.path(), Network::Regtest).is_err());
    }
}
