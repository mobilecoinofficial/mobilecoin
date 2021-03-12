// Copyright 2018-2021 The MobileCoin Foundation

//! This module provides the implementation of the all-in-one verifier for
//! public addresses.

use crate::{Error, Verifier};
use core::convert::TryInto;
use mc_account_keys::PublicAddress;
use mc_crypto_keys::Ed25519Signature;
use mc_crypto_x509_utils::{
    PublicKeyType, X509CertificateChain, X509CertificateIter, X509KeyExtrator,
};
use mc_fog_sig_authority::Verifier as AuthorityVerifier;
use mc_fog_sig_report::Verifier as ReportVerifier;
use mc_fog_types::ReportResponse;
use signature::{Error as SignatureError, Signature};
use x509_signature::X509Certificate;

impl Verifier for PublicAddress {
    type ReportSigError = SignatureError;

    fn verify_fog_sig(
        &self,
        report_response: &ReportResponse,
    ) -> Result<(), Error<<Self as AuthorityVerifier>::Error, Self::ReportSigError>> {
        // Vec<Vec<u8>> -> Vec<&[u8]>
        // Vec<&[u8]> -> Vec<X509Certificate>
        let certs = X509CertificateIter::from(
            report_response
                .chain
                .iter()
                .map(|der| der.as_slice())
                .collect::<Vec<&[u8]>>(),
        )
        .collect::<Vec<X509Certificate>>();

        // Get the authority signature
        let authority_sig = self
            .fog_authority_sig()
            .ok_or(Error::NoSignature)?
            .try_into()?;

        // Verify the chain and signature over the resulting authority
        self.verify_authority(
            &certs.verified_root()?.subject_public_key_info().spki(),
            &authority_sig,
        )
        .map_err(Error::Authority)?;

        // Verify the signature over the reports matches the leaf cert in the chain
        match certs.leaf()?.mc_public_key().map_err(Error::Pubkey)? {
            PublicKeyType::Ed25519(pubkey) => {
                let sig = Ed25519Signature::from_bytes(&report_response.signature)
                    .map_err(Error::SignatureParse)?;
                pubkey
                    .verify_reports(report_response.reports.as_slice(), &sig)
                    .map_err(Error::Report)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_account_keys::{AccountKey, RootIdentity};
    use mc_attest_core::VerificationReport;
    use mc_crypto_keys::Ed25519Pair;
    use mc_crypto_x509_utils::X509CertificateIterable;
    use mc_fog_sig_report::Signer;
    use mc_fog_types::Report;
    use rand_core::SeedableRng;
    use rand_hc::Hc128Rng;
    use std::convert::TryFrom;

    /// Setup a functional fog authority scheme.
    ///
    /// - Load an X509 cert chain
    /// - Generate a new random account with fog support
    /// - Sign the chain authority
    /// - Return the public address and the chain as a vector of DER bytestrings
    fn setup() -> (PublicAddress, Vec<Vec<u8>>, Ed25519Pair) {
        // load, parse, and verify the x509 test vector
        let (pem_chain, keypair) = mc_crypto_x509_test_vectors::ok_rsa_chain_25519_leaf();
        let der_chain = pem::parse_many(pem_chain);
        let x509_chain = der_chain.iter_x509().collect::<Vec<X509Certificate>>();

        let mut csprng = Hc128Rng::seed_from_u64(0);
        let root_identity = RootIdentity::random_with_fog(
            &mut csprng,
            "fog://fog.unittest.mobilecoin.foundation",
            "1",
            x509_chain
                .verified_root()
                .expect("Could not verify test chain")
                .subject_public_key_info()
                .spki(),
        )
        .expect("Could not construct root identity with fog details");
        let account_key = AccountKey::try_from(&root_identity)
            .expect("Could not create AccountKey from root identity with fog details");
        let public_address = account_key.default_subaddress();

        (
            public_address,
            der_chain
                .into_iter()
                .map(|p| p.contents)
                .collect::<Vec<Vec<u8>>>(),
            keypair,
        )
    }

    /// Test a correctly produced signature
    #[test]
    fn success() {
        let (public_address, chain, keypair) = setup();

        let reports = vec![Report {
            fog_report_id: "1".to_owned(),
            report: VerificationReport::default(),
            pubkey_expiry: 100,
        }];

        let signature = keypair
            .sign_reports(&reports)
            .expect("Could not sign reports")
            .as_ref()
            .to_vec();

        let report_response = ReportResponse {
            reports,
            chain,
            signature,
        };

        public_address
            .verify_fog_sig(&report_response)
            .expect("Correct ReportResponse did not pass");
    }

    /// Test a scenario where the chain has been removed.
    #[test]
    fn empty_chain() {
        let (public_address, _chain, keypair) = setup();

        let reports = vec![Report {
            fog_report_id: "1".to_owned(),
            report: VerificationReport::default(),
            pubkey_expiry: 100,
        }];

        let signature = keypair
            .sign_reports(&reports)
            .expect("Could not sign reports")
            .as_ref()
            .to_vec();

        let report_response = ReportResponse {
            reports,
            chain: Vec::default(),
            signature,
        };

        public_address
            .verify_fog_sig(&report_response)
            .expect_err("Bad ReportResponse with empty chain accepted");
    }
}
