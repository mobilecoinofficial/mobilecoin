// Copyright (c) 2018-2021 The MobileCoin Foundation

//! In cryptography, several private keys can be derived from a single source of
//! entropy using a strong KDF (key derivation function).
//! This is sound, so long as the input-key-material to the KDF itself has
//! at least enough entropy as the length of any one of the derived keys.
//!
//! The RootIdentity object contains 32 bytes of "root entropy", used with HKDF
//! to produce the other MobileCoin private keys. This is useful because an
//! AccountKey derived this way can be represented with a smaller amount of
//! information.
//!
//! The other (fog-related) fields of RootIdentity are analogous to AccountKey.

use crate::{
    account_keys::AccountKey,
    check_fog_key_fields,
    error::{Error, Result},
};
use alloc::{borrow::ToOwned, string::String, vec::Vec};
use core::{
    convert::{From, TryFrom},
    hash::Hash,
    result::Result as StdResult,
};
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use mc_crypto_hashes::Blake2b256;
use mc_crypto_keys::RistrettoPrivate;
use mc_util_from_random::FromRandom;
use mc_util_repr_bytes::{
    derive_prost_message_from_repr_bytes, derive_repr_bytes_from_as_ref_and_try_from, typenum::U32,
    LengthMismatch,
};
use prost::Message;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// A secret value used as input key material to derive private keys.
#[derive(Clone, Default, Debug, PartialEq, Eq, Hash, Zeroize)]
#[zeroize(drop)]
pub struct RootEntropy {
    /// 32 bytes of input key material.
    /// Should be e.g. RDRAND, /dev/random/, or from properly seeded CSPRNG.
    pub bytes: [u8; 32],
}

impl AsRef<[u8]> for RootEntropy {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..]
    }
}

impl From<&[u8; 32]> for RootEntropy {
    fn from(src: &[u8; 32]) -> Self {
        Self { bytes: *src }
    }
}

impl TryFrom<&[u8]> for RootEntropy {
    type Error = LengthMismatch;

    fn try_from(src: &[u8]) -> StdResult<RootEntropy, LengthMismatch> {
        if src.len() == 32 {
            let mut result = Self { bytes: [0u8; 32] };
            result.bytes.copy_from_slice(src);
            Ok(result)
        } else {
            Err(LengthMismatch {
                expected: 32,
                found: src.len(),
            })
        }
    }
}

impl FromRandom for RootEntropy {
    fn from_random<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        let mut result = Self { bytes: [0u8; 32] };
        rng.fill_bytes(&mut result.bytes);
        result
    }
}

derive_repr_bytes_from_as_ref_and_try_from!(RootEntropy, U32);
derive_prost_message_from_repr_bytes!(RootEntropy);

/// A RootIdentity contains 32 bytes of root entropy (for deriving private keys
/// using a KDF), together with any fog data for the account.
#[derive(Clone, PartialEq, Eq, Hash, Message)]
pub struct RootIdentity {
    /// Root entropy used to derive a user's private keys.
    #[prost(message, required, tag = 1)]
    pub root_entropy: RootEntropy,
    /// Fog report url
    #[prost(string, tag = 2)]
    pub fog_report_url: String,
    /// Fog report id
    #[prost(string, tag = 3)]
    pub fog_report_id: String,
    /// Fog authority subjectPublicKeyInfo
    #[prost(bytes, tag = 4)]
    pub fog_authority_spki: Vec<u8>,
}

impl RootIdentity {
    /// Generate a random root identity with a specific fog_report_url
    /// configured
    pub fn random_with_fog<T: RngCore + CryptoRng>(
        rng: &mut T,
        fog_report_url: &str,
        fog_report_id: &str,
        fog_authority_spki: &[u8],
    ) -> Result<Self> {
        let mut result = Self::from_random(rng);

        if !fog_report_url.is_empty() {
            check_fog_key_fields(fog_report_url, fog_report_id, fog_authority_spki)?;

            result.fog_report_url = fog_report_url.to_owned();
            result.fog_report_id = fog_report_id.to_owned();
            result.fog_authority_spki = fog_authority_spki.to_owned();
        }

        Ok(result)
    }
}

// Make RootIdentity from RootEntropy by defaulting all fog-related fields.
impl From<&RootEntropy> for RootIdentity {
    fn from(src: &RootEntropy) -> Self {
        Self {
            root_entropy: src.clone(),
            fog_report_url: Default::default(),
            fog_report_id: Default::default(),
            fog_authority_spki: Default::default(),
        }
    }
}

/// Generate a random root identity without fog configured
impl FromRandom for RootIdentity {
    fn from_random<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        Self::from(&RootEntropy::from_random(rng))
    }
}

/// Derive an AccountKey from RootIdentity
impl TryFrom<&RootIdentity> for AccountKey {
    type Error = Error;

    fn try_from(src: &RootIdentity) -> Result<Self> {
        let spend_private_key = RistrettoPrivate::from(root_identity_hkdf_helper(
            src.root_entropy.as_ref(),
            b"spend",
        ));
        let view_private_key = RistrettoPrivate::from(root_identity_hkdf_helper(
            src.root_entropy.as_ref(),
            b"view",
        ));
        if src.fog_report_url.is_empty() {
            Ok(AccountKey::new(&spend_private_key, &view_private_key))
        } else {
            AccountKey::new_with_fog(
                &spend_private_key,
                &view_private_key,
                &src.fog_report_url,
                src.fog_report_id.clone(),
                &src.fog_authority_spki,
            )
        }
    }
}

/// Construct fogless RootIdentity from [u8;32]
impl From<&[u8; 32]> for RootIdentity {
    fn from(src: &[u8; 32]) -> Self {
        Self::from(&RootEntropy::from(src))
    }
}

// Helper function for using hkdf to derive a key
fn root_identity_hkdf_helper(ikm: &[u8], info: &[u8]) -> Scalar {
    let mut result = [0u8; 32];
    let (_, hk) = Hkdf::<Blake2b256>::extract(None, ikm);

    // expand cannot fail because 32 bytes is a valid keylength for blake2b/256
    hk.expand(info, &mut result)
        .expect("buffer size arithmetic is wrong");

    // Now we reduce the result modulo group order. Cryptonote functions using
    // the `scalar_from_bytes` macro require this because the macro uses
    // `Scalar::from_canonical_bytes` rather than `Scalar::from_bits` or
    // `Scalar::from_bytes_mod_order`. It will returns an error if we don't make
    // the representation canonical
    Scalar::from_bytes_mod_order(result)
}

#[cfg(test)]
mod testing {
    use super::*;
    use alloc::boxed::Box;
    use datatest::data;
    use mc_test_vectors_account_keys::*;
    use mc_util_test_vector::TestVector;

    // Protobuf deserialization should recover a serialized RootIdentity.
    #[test]
    fn prost_roundtrip_root_identity() {
        mc_util_test_helper::run_with_several_seeds(|mut rng| {
            let root_id = RootIdentity::from_random(&mut rng);
            let ser = mc_util_serial::encode(&root_id);
            let result: RootIdentity = mc_util_serial::decode(&ser).unwrap();
            assert_eq!(root_id, result);

            let der_bytes = pem::parse(mc_crypto_x509_test_vectors::ok_rsa_head())
                .expect("Could not parse RSA test vector as PEM")
                .contents;
            let fog_authority_spki = x509_signature::parse_certificate(&der_bytes)
                .expect("Could not parse X509 certificate from DER")
                .subject_public_key_info()
                .spki();

            let root_id = RootIdentity::random_with_fog(
                &mut rng,
                "fog://fog.unittest.mobilecoin.com",
                "1",
                fog_authority_spki,
            )
            .expect("Could not construct root identity with fog data");
            let ser = mc_util_serial::encode(&root_id);
            let result: RootIdentity = mc_util_serial::decode(&ser).unwrap();
            assert_eq!(root_id, result);
        })
    }

    #[data(AcctPrivKeysFromRootEntropy::from_jsonl("../test-vectors/vectors"))]
    #[test]
    fn acct_priv_keys_from_root_entropy(case: AcctPrivKeysFromRootEntropy) {
        let account_key = AccountKey::try_from(&RootIdentity::from(&case.root_entropy))
            .expect("Could not create account key from root identity");
        assert_eq!(
            account_key.view_private_key().to_bytes(),
            case.view_private_key
        );
        assert_eq!(
            account_key.spend_private_key().to_bytes(),
            case.spend_private_key
        );
    }
}
