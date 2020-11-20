// Copyright (c) 2018-2020 MobileCoin Inc.

//! Conversions between "API types" and "domain/persistence types".
//!
//! gRPC and Protobuf provide a reduced selection of types, and so there are some differences between
//! values stored in the ledger and values transmitted over the API. This module provides conversions
//! between "equivalent" types, such as `mc_consensus_api::consensus_common::ProposeTxResult` and
//! `mc_transaction_core::validation::TransactionValidationError`.

use crate::consensus_common::ProposeTxResult;
use mc_transaction_core::{ring_signature, validation::TransactionValidationError};
use std::convert::{From, TryInto};

/// Convert TransactionValidationError --> ProposeTxResult.
impl From<TransactionValidationError> for ProposeTxResult {
    fn from(src: TransactionValidationError) -> Self {
        match src {
            TransactionValidationError::InputsProofsLengthMismatch => {
                Self::InputsProofsLengthMismatch
            }
            TransactionValidationError::NoInputs => Self::NoInputs,
            TransactionValidationError::TooManyInputs => Self::TooManyInputs,
            TransactionValidationError::InsufficientInputSignatures => {
                Self::InsufficientInputSignatures
            }
            TransactionValidationError::InvalidInputSignature => Self::InvalidInputSignature,
            TransactionValidationError::InvalidTransactionSignature(_e) => {
                Self::InvalidTransactionSignature
            }
            TransactionValidationError::InvalidRangeProof => Self::InvalidRangeProof,
            TransactionValidationError::InsufficientRingSize => Self::InsufficientRingSize,
            TransactionValidationError::TombstoneBlockExceeded => Self::TombstoneBlockExceeded,
            TransactionValidationError::TombstoneBlockTooFar => Self::TombstoneBlockTooFar,
            TransactionValidationError::NoOutputs => Self::NoOutputs,
            TransactionValidationError::TooManyOutputs => Self::TooManyOutputs,
            TransactionValidationError::ExcessiveRingSize => Self::ExcessiveRingSize,
            TransactionValidationError::DuplicateRingElements => Self::DuplicateRingElements,
            TransactionValidationError::UnsortedRingElements => Self::UnsortedRingElements,
            TransactionValidationError::UnequalRingSizes => Self::UnequalRingSizes,
            TransactionValidationError::UnsortedKeyImages => Self::UnsortedKeyImages,
            TransactionValidationError::ContainsSpentKeyImage => Self::ContainsSpentKeyImage,
            TransactionValidationError::DuplicateKeyImages => Self::DuplicateKeyImages,
            TransactionValidationError::DuplicateOutputPublicKey => Self::DuplicateOutputPublicKey,
            TransactionValidationError::ContainsExistingOutputPublicKey => {
                Self::ContainsExistingOutputPublicKey
            }
            TransactionValidationError::MissingTxOutMembershipProof => {
                Self::MissingTxOutMembershipProof
            }
            TransactionValidationError::InvalidTxOutMembershipProof => {
                Self::InvalidTxOutMembershipProof
            }
            TransactionValidationError::InvalidRistrettoPublicKey => {
                Self::InvalidRistrettoPublicKey
            }
            TransactionValidationError::InvalidLedgerContext => Self::InvalidLedgerContext,
            TransactionValidationError::Ledger(_) => Self::Ledger,
            TransactionValidationError::MembershipProofValidationError => {
                Self::MembershipProofValidationError
            }
            TransactionValidationError::TxFeeError => Self::TxFeeError,
            TransactionValidationError::KeyError => Self::KeyError,
            TransactionValidationError::UnsortedInputs => Self::UnsortedInputs,
            TransactionValidationError::UnsortedOutputs => Self::UnsortedOutputs,
        }
    }
}

/// Convert ProposeTxResult --> TransactionValidationError.
impl TryInto<TransactionValidationError> for ProposeTxResult {
    type Error = &'static str;

    fn try_into(self) -> Result<TransactionValidationError, Self::Error> {
        match self {
            Self::Ok => Err("Ok value cannot be convererted into TransactionValidationError"),
            Self::InputsProofsLengthMismatch => {
                Ok(TransactionValidationError::InputsProofsLengthMismatch)
            }
            Self::NoInputs => Ok(TransactionValidationError::NoInputs),
            Self::TooManyInputs => Ok(TransactionValidationError::TooManyInputs),
            Self::InsufficientInputSignatures => {
                Ok(TransactionValidationError::InsufficientInputSignatures)
            }
            Self::InvalidInputSignature => Ok(TransactionValidationError::InvalidInputSignature),
            Self::InvalidTransactionSignature => {
                Ok(TransactionValidationError::InvalidTransactionSignature(
                    ring_signature::Error::InvalidSignature,
                ))
            }
            Self::InvalidRangeProof => Ok(TransactionValidationError::InvalidRangeProof),
            Self::InsufficientRingSize => Ok(TransactionValidationError::InsufficientRingSize),
            Self::TombstoneBlockExceeded => Ok(TransactionValidationError::TombstoneBlockExceeded),
            Self::TombstoneBlockTooFar => Ok(TransactionValidationError::TombstoneBlockTooFar),
            Self::NoOutputs => Ok(TransactionValidationError::NoOutputs),
            Self::TooManyOutputs => Ok(TransactionValidationError::TooManyOutputs),
            Self::ExcessiveRingSize => Ok(TransactionValidationError::ExcessiveRingSize),
            Self::DuplicateRingElements => Ok(TransactionValidationError::DuplicateRingElements),
            Self::UnsortedRingElements => Ok(TransactionValidationError::UnsortedRingElements),
            Self::UnequalRingSizes => Ok(TransactionValidationError::UnequalRingSizes),
            Self::UnsortedKeyImages => Ok(TransactionValidationError::UnsortedKeyImages),
            Self::ContainsSpentKeyImage => Ok(TransactionValidationError::ContainsSpentKeyImage),
            Self::DuplicateKeyImages => Ok(TransactionValidationError::DuplicateKeyImages),
            Self::DuplicateOutputPublicKey => {
                Ok(TransactionValidationError::DuplicateOutputPublicKey)
            }
            Self::ContainsExistingOutputPublicKey => {
                Ok(TransactionValidationError::ContainsExistingOutputPublicKey)
            }
            Self::MissingTxOutMembershipProof => {
                Ok(TransactionValidationError::MissingTxOutMembershipProof)
            }
            Self::InvalidTxOutMembershipProof => {
                Ok(TransactionValidationError::InvalidTxOutMembershipProof)
            }
            Self::InvalidRistrettoPublicKey => {
                Ok(TransactionValidationError::InvalidRistrettoPublicKey)
            }
            Self::InvalidLedgerContext => Ok(TransactionValidationError::InvalidLedgerContext),
            Self::Ledger => Ok(TransactionValidationError::Ledger(String::default())),
            Self::MembershipProofValidationError => {
                Ok(TransactionValidationError::MembershipProofValidationError)
            }
            Self::TxFeeError => Ok(TransactionValidationError::TxFeeError),
            Self::KeyError => Ok(TransactionValidationError::KeyError),
            Self::UnsortedInputs => Ok(TransactionValidationError::UnsortedInputs),
            Self::UnsortedOutputs => Ok(TransactionValidationError::UnsortedOutputs),
        }
    }
}

#[cfg(test)]
mod conversion_tests {}
