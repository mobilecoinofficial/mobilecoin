// Copyright 2018-2021 The MobileCoin Foundation

//! This module contains code related to reading/writing mnemonic-based accounts
//! (either as protobuf or JSON strings) and converting them into AccountKey
//! data structures.

use bip39::{Language, Mnemonic};
use displaydoc::Display;
use mc_account_keys::AccountKey;
use mc_account_keys_slip10::{Error as Slip10Error, Slip10KeyGenerator};
use prost::Message;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

/// An enumeration of errors which can occur when converting an
/// [`UncheckedMnemonicAccount`] to an
/// [`AccountKey`](mc_account_keys::AccountKey).
#[derive(Clone, Debug, Display, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Error {
    /// No mnemonic was provided
    NoMnemonic,
    /// The mnemonic was invalid: {0}
    InvalidMnemonic(String),
    /// No account index was provided
    NoAccountIndex,
    /// Could not derive account key from SLIP-0010 key: {0}
    KeyDerivation(Slip10Error),
}

impl From<Slip10Error> for Error {
    fn from(src: Slip10Error) -> Error {
        Error::KeyDerivation(src)
    }
}

/// A serialized mnemonic-based account key
#[derive(Clone, Eq, Hash, Ord, PartialOrd, PartialEq, Serialize, Deserialize, Message)]
pub struct UncheckedMnemonicAccount {
    /// The mnemonic string representation of the entropy
    #[prost(string, optional, tag = "1")]
    pub mnemonic: Option<String>,
    /// The account index the mnemonic is intended to work with
    #[prost(uint32, optional, tag = "2")]
    pub account_index: Option<u32>,
    /// The Fog URL for this account, if any.
    #[prost(string, optional, tag = "3")]
    pub fog_report_url: Option<String>,
    /// The Fog Report ID string
    #[prost(string, optional, tag = "4")]
    pub fog_report_id: Option<String>,
    /// The Fog Authority subjectPublicKeyInfo
    #[prost(bytes, optional, tag = "5")]
    pub fog_authority_spki: Option<Vec<u8>>,
}

impl TryFrom<UncheckedMnemonicAccount> for AccountKey {
    type Error = Error;

    fn try_from(src: UncheckedMnemonicAccount) -> Result<AccountKey, Self::Error> {
        let mnemonic = Mnemonic::from_phrase(
            src.mnemonic.ok_or(Error::NoMnemonic)?.as_str(),
            Language::English,
        )
        .map_err(|e| Error::InvalidMnemonic(format!("{}", e)))?;
        let slip10 = mnemonic.derive_slip10_key(src.account_index.ok_or(Error::NoAccountIndex)?);
        Ok(slip10.try_into_account_key(
            src.fog_report_url.unwrap_or_default().as_str(),
            src.fog_report_id.unwrap_or_default().as_str(),
            src.fog_authority_spki.unwrap_or_default().as_slice(),
        )?)
    }
}
