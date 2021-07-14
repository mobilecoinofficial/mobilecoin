// Copyright 2018-2021 The MobileCoin Foundation

#![warn(missing_docs)]
#![deny(unsafe_code)]
#![feature(external_doc)]
#![doc(include = "../README.md")]

mod public_address;

use core::fmt::{Debug, Display};
use displaydoc::Display;
use mc_crypto_keys::KeyError;
use mc_crypto_x509_utils::ChainError;
use mc_fog_sig_authority::Verifier as AuthorityVerifier;
use mc_fog_types::ReportResponse;
use signature::Error as SignatureError;

/// An eneumeration of errors which can occur when verifying a signature set.
#[derive(Debug, Display)]
pub enum Error<A: Debug + Display, R: Debug + Display> {
    /// The public address does not have a fog authority signature
    NoSignature,
    /// There was an error parsing the signature
    SignatureParse(SignatureError),
    /// There as an error verifying the authority signature: {0}
    Authority(A),
    /// There was an error parsing or verifying the chain: {0}
    Chain(ChainError),
    /// There was an error parsing a public key: {0}
    Pubkey(KeyError),
    /// There was an error verifying the report signature: {0}
    Report(R),
}

impl<A: Debug + Display, R: Debug + Display> From<SignatureError> for Error<A, R> {
    fn from(src: SignatureError) -> Self {
        Error::SignatureParse(src)
    }
}

impl<A: Debug + Display, R: Debug + Display> From<ChainError> for Error<A, R> {
    fn from(src: ChainError) -> Self {
        Error::Chain(src)
    }
}

/// A trait which will verify the fog authority signature, the certificate
/// chain, and the signature over the report list.
pub trait Verifier: AuthorityVerifier {
    /// The type of errors which will be returned when the verifier cannot
    /// verify the leaf certificate signature over the reports.
    type ReportSigError: Debug + Display;

    /// Verify the signature and data bundled in the report server response
    fn verify_fog_sig(
        &self,
        report_response: &ReportResponse,
    ) -> Result<(), Error<<Self as AuthorityVerifier>::Error, Self::ReportSigError>>;
}
