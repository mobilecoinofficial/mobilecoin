// Copyright (c) 2018-2021 The MobileCoin Foundation

//! This module contains the error type which methods of the `keyfile` crate can
//! generate.

use crate::mnemonic_acct::Error as MnemonicAccountError;
use displaydoc::Display;
use mc_account_keys::Error as AccountKeyError;
use mc_account_keys_slip10::Error as Slip10Error;
use prost::{DecodeError, EncodeError};
use serde_json::Error as JsonError;
use std::io::Error as IoError;

/// There was an error while working with key files.
#[derive(Clone, Debug, Display, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Error {
    /// Account error: {0}
    AccountKey(AccountKeyError),
    /// Protobuf encoding error: {0}
    Encode(String),
    /// Protobuf decoding error: {0}
    Decode(String),
    /// IO error: {0}
    Io(String),
    /// JSON error: {0}
    Json(String),
    /// Mnemonic account error: {0}
    MnemonicAccount(MnemonicAccountError),
    /// The entropy provided was not the correct size for BIP-39
    MnemonicSize,
    /// Key derivation error: {0}
    KeyDerivation(Slip10Error),
    /// Fog details are all or nothing, some were missing
    MissingFogDetails,
}

impl From<AccountKeyError> for Error {
    fn from(src: AccountKeyError) -> Error {
        Error::AccountKey(src)
    }
}

impl From<DecodeError> for Error {
    fn from(src: DecodeError) -> Error {
        Error::Decode(format!("{}", src))
    }
}

impl From<EncodeError> for Error {
    fn from(src: EncodeError) -> Error {
        Error::Encode(format!("{}", src))
    }
}

impl From<IoError> for Error {
    fn from(src: IoError) -> Error {
        Error::Io(format!("{}", src))
    }
}

impl From<JsonError> for Error {
    fn from(src: JsonError) -> Error {
        Error::Json(format!("{}", src))
    }
}

impl From<MnemonicAccountError> for Error {
    fn from(src: MnemonicAccountError) -> Error {
        Error::MnemonicAccount(src)
    }
}

impl From<Slip10Error> for Error {
    fn from(src: Slip10Error) -> Error {
        Error::KeyDerivation(src)
    }
}
