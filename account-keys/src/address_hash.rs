//! A newtype representing a standard hash of a MobileCoin public address.
//! This is used in certain memos, as a compact representation of the address.

use crate::account_keys::PublicAddress;
use core::convert::TryInto;
use mc_crypto_digestible::{Digestible, MerlinTranscript};
use subtle::{Choice, ConstantTimeEq};

/// Represents a "standard" public address hash created using merlin,
/// used in memos as a compact representation of a MobileCoin public address.
/// This hash is collision resistant.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct AddressHash([u8; 16]);

impl From<[u8; 16]> for AddressHash {
    fn from(src: [u8; 16]) -> Self {
        Self(src)
    }
}

impl From<AddressHash> for [u8; 16] {
    fn from(src: AddressHash) -> [u8; 16] {
        src.0
    }
}

impl AsRef<[u8; 16]> for AddressHash {
    fn as_ref(&self) -> &[u8; 16] {
        &self.0
    }
}

impl From<&PublicAddress> for AddressHash {
    fn from(src: &PublicAddress) -> Self {
        let digest = src.digest32::<MerlinTranscript>(b"mc-address");
        Self(digest[0..16].try_into().expect("arithmetic error"))
    }
}

impl ConstantTimeEq for AddressHash {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}
