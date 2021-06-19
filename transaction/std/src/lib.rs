// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Utilities for creating MobileCoin transactions, intended for client-side
//! use and not intended to be used inside of enclaves.

#![deny(missing_docs)]

mod error;
mod input_credentials;
mod memo;
mod transaction_builder;

pub use error::TxBuilderError;
pub use input_credentials::InputCredentials;
pub use memo::{
    AuthenticatedSenderMemo, DestinationMemo, DestinationMemoError, MemoDecodingError, MemoType,
    SenderMemoCredential, UnusedMemo,
};
pub use transaction_builder::TransactionBuilder;
