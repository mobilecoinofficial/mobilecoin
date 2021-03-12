// Copyright (c) 2018-2021 The MobileCoin Foundation

use mc_transaction_core::ring_signature::Error as RingSigError;
use std::{
    error::Error,
    fmt::{self, Formatter},
};

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum ConversionError {
    NarrowingCastError,
    ArrayCastError,
    KeyCastError,
    Key(mc_crypto_keys::KeyError),
    FeeMismatch,
    IndexOutOfBounds,
    ObjectMissing,
    InvalidSignature,
    InvalidContents,
    Other,
}

// This is needed for some code to compile, due to TryFrom being derived from From
impl From<core::convert::Infallible> for ConversionError {
    fn from(_src: core::convert::Infallible) -> Self {
        unreachable!();
    }
}

impl From<core::array::TryFromSliceError> for ConversionError {
    fn from(_: core::array::TryFromSliceError) -> Self {
        Self::ArrayCastError
    }
}

impl From<RingSigError> for ConversionError {
    fn from(src: RingSigError) -> Self {
        match src {
            RingSigError::LengthMismatch(_, _) => Self::ArrayCastError,
            _ => Self::KeyCastError,
        }
    }
}

impl From<mc_transaction_core::ConvertError> for ConversionError {
    fn from(_src: mc_transaction_core::ConvertError) -> Self {
        Self::ArrayCastError
    }
}

impl From<mc_crypto_keys::KeyError> for ConversionError {
    fn from(src: mc_crypto_keys::KeyError) -> Self {
        Self::Key(src)
    }
}

impl From<mc_account_keys::Error> for ConversionError {
    fn from(_src: mc_account_keys::Error) -> Self {
        Self::InvalidContents
    }
}

impl Error for ConversionError {}

impl fmt::Display for ConversionError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "ConversionError")
    }
}
