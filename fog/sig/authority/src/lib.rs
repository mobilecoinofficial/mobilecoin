// Copyright 2018-2021 The MobileCoin Foundation

#![no_std]
#![warn(missing_docs)]
#![warn(unsafe_code)]
#![feature(external_doc)]
#![doc(include = "../README.md")]

extern crate alloc;

mod ristretto;

use core::fmt::{Debug, Display};
use signature::Signature;

/// Retrieve the canonical signing context byte string.
///
/// This is intended to be used by crate-remote implementations of the
/// signature who want a "standard"
pub fn context() -> &'static [u8] {
    b"Fog authority signature"
}

/// A trait used to monkey-patch authority signatures onto existing private-key
/// types.
pub trait Signer {
    /// The signature output type
    type Sig: Signature;
    /// The error type
    type Error: Debug + Display;

    /// Sign the raw bytes of a subjectPublicKeyInfo for a fog authority
    fn sign_authority(&self, spki_bytes: &[u8]) -> Result<Self::Sig, Self::Error>;
}

/// A trait used to monkey patch authority signature verification onto existing
/// public key types.
pub trait Verifier {
    /// The signature type to be verified
    type Sig: Signature;
    /// The error type if a signature could not be verified
    type Error: Debug + Display;

    /// Verify a signature over the raw subjectPublicKeyInfo bytes.
    fn verify_authority(&self, spki_bytes: &[u8], sig: &Self::Sig) -> Result<(), Self::Error>;
}
