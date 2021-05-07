// Copyright (c) 2018-2021 The MobileCoin Foundation

use displaydoc::Display;
use mc_fog_report_validation::FogPubkeyError;
use mc_transaction_core::{ring_signature, ring_signature::Error, AmountError};

/// An error that can occur when using the TransactionBuilder
#[derive(Debug, Display)]
pub enum TxBuilderError {
    /// Ring Signature construction failed
    RingSignatureFailed,

    /// Range proof construction failed
    RangeProofFailed,

    /// Serialization failed: {0}
    SerializationFailed(mc_util_serial::encode::Error),

    /// Serialization failed: {0}
    EncodingFailed(prost::EncodeError),

    /// Bad Amount: {0}
    BadAmount(AmountError),

    /// Ring has incorrect size
    InvalidRingSize,

    /// Input credentials: Ring contained invalid curve point
    RingInvalidCurvePoint,

    /// No inputs
    NoInputs,

    /// Fog public key error: {0}
    FogPublicKey(FogPubkeyError),

    /// Key error: {0}
    KeyError(mc_crypto_keys::KeyError),
}

impl From<mc_util_serial::encode::Error> for TxBuilderError {
    fn from(x: mc_util_serial::encode::Error) -> Self {
        TxBuilderError::SerializationFailed(x)
    }
}

impl From<prost::EncodeError> for TxBuilderError {
    fn from(x: prost::EncodeError) -> Self {
        TxBuilderError::EncodingFailed(x)
    }
}

impl From<AmountError> for TxBuilderError {
    fn from(x: AmountError) -> Self {
        TxBuilderError::BadAmount(x)
    }
}

impl From<mc_crypto_keys::KeyError> for TxBuilderError {
    fn from(e: mc_crypto_keys::KeyError) -> Self {
        TxBuilderError::KeyError(e)
    }
}

impl From<ring_signature::Error> for TxBuilderError {
    fn from(_: Error) -> Self {
        TxBuilderError::RingSignatureFailed
    }
}

impl From<FogPubkeyError> for TxBuilderError {
    fn from(src: FogPubkeyError) -> Self {
        TxBuilderError::FogPublicKey(src)
    }
}
