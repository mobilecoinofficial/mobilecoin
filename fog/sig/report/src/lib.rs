// Copyright 2018-2021 The MobileCoin Foundation

#![no_std]
#![warn(missing_docs)]
#![warn(unsafe_code)]
#![feature(external_doc)]
#![doc(include = "../README.md")]

mod ed25519;

use core::fmt::{Debug, Display};
use mc_fog_types::Report;
use signature::Signature;

/// Retrieve the domain separator used to sign a report server response
pub fn context() -> &'static [u8] {
    b"Fog ingest reports"
}

/// A trait which private keyholders can implement to allow them to sign a
/// list of IAS verification reports with appropriate domain separators.
pub trait Signer {
    /// The signature output type
    type Sig: Signature + Clone;
    /// A printable error type
    type Error: Debug + Display;

    /// Sign a list of IAS verification report.
    fn sign_reports(&self, reports: &[Report]) -> Result<Self::Sig, Self::Error>;
}

/// A trait which public keys can implement to allow them to verify a signature
/// over a list of IAS verification reports with appropriate domain separators.
pub trait Verifier {
    /// The signature output type
    type Sig: Signature + Clone;
    /// The printable error type
    type Error: Debug + Display;

    /// Verify the provided signature is valid for the object over the reports.
    fn verify_reports(&self, reports: &[Report], sig: &Self::Sig) -> Result<(), Self::Error>;
}
