// Copyright (c) 2018-2021 The MobileCoin Foundation

#![no_std]
// #![deny(missing_docs)]

extern crate alloc;

#[cfg(test)]
#[macro_use]
extern crate std;

#[macro_use]
extern crate lazy_static;

use crate::onetime_keys::create_shared_secret;
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};

mod amount;
mod blockchain;
pub mod constants;
mod domain_separators;
pub mod encrypted_fog_hint;
pub mod fog_hint;
pub mod membership_proofs;
mod memo;
pub mod onetime_keys;
pub mod range_proofs;
pub mod ring_signature;
pub mod tx;
pub mod validation;

#[cfg(test)]
pub mod proptest_fixtures;

pub use amount::{get_value_mask, Amount, AmountError, Commitment, CompressedCommitment};
pub use blockchain::*;
pub use memo::{LengthError, MemoPayload};

/// Get the shared secret for a transaction output.
///
/// # Arguments
/// * `view_key` - The recipient's private View key.
/// * `tx_public_key` - The public key of the transaction.
pub fn get_tx_out_shared_secret(
    view_key: &RistrettoPrivate,
    tx_public_key: &RistrettoPublic,
) -> RistrettoPublic {
    create_shared_secret(tx_public_key, view_key)
}
