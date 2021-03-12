// Copyright 2018-2021 The MobileCoin Foundation

//! This crate provides new traits to provide the following functionality:
//!
//!  1. Allow a recipient to sign a Fog Authority (subjectPublicKeyInfo)
//!  1. Allow the fog report server to sign a list of responses.
//!  1. Allow a sender to verify and extract the ingest key from a user's
//!     PublicAddress and a ReportResponse object(s).
//!
//! # Fog Authority Signatures
//!
//! Fog authority signatures are created by the owner of an account, in order to
//! delegate transaction monitoring to an enclave using the on-chain fog
//! accounts hints. In order to accomplish this, the user signs the DER-encoded
//! bytes of a `subjectPublicKeyInfo` X509 structure from the root certificate
//! of their fog operator.
//!
//! The operator, in turn, creates one or more intermediate certificates, which
//! in turn issue Ed25519 signing certificates to a report server.
//!
//! # Fog Report Signatures
//!
//! A fog report server uses the signing key and certificate provided by the fog
//! operator in order to cryptographically sign a list of IAS verification
//! report structures created by ingest nodes. This resulting data (chain,
//! signature, and reports) is then returned from the fog report server to a
//! senders when they want to send coins to the destination account owner.
//!
//! # Sender Verification
//!
//! The sender must verify the user's signature over the root certificate, the
//! certificate chain to the report server, and the report server's signature
//! over the report list, in order to determine which
//! [`VerificationReport`](mc_attest_core::VerificationReport) belongs
//! to the destination fog ingest enclave.
//!
//! At this point, the sender has verified that the account owner has delegated
//! transaction monitoring authority to a given ingest enclave.
//!
//! # Future Work
//!
//! The most basic missing functionality here is support for RSA leaf
//! certificates. This, in turn, will end up blocking on a nice rust
//! implementation of the RSA algorithm.
//!
//! Additionally, it would be nice for this crate to function in an enclave in
//! order to support enclaves for clients and report servers.

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
    /// There was an error verifying the authority signature: {0}
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
