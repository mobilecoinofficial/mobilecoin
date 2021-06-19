// Copyright (c) 2018-2021 The MobileCoin Foundation

//! MobileCoin account keys.
//!
//! MobileCoin accounts give users fine-grained controls for sharing their
//! address with senders and third-party services. Each account is defined
//! by a pair of private keys (a,b) that are used for identifying owned
//! outputs and spending them, respectively. Instead of sharing the public
//! keys (A,B) directly with senders, users generate and share "subaddresses"
//! (C_i, D_i) that are derived from the private keys (a,b) and an index i.
//! We refer to (C_0, D_0)* as the "default subaddress" for account (a,b).

#![allow(non_snake_case)]

use crate::{domain_separators::SUBADDRESS_DOMAIN_TAG, view_key::ViewKey};
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use blake2::{Blake2b, Digest};
use core::{
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
};
use curve25519_dalek::scalar::Scalar;
use mc_crypto_digestible::Digestible;
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_fog_sig_authority::{Signer as AuthoritySigner, Verifier as AuthorityVerifier};
use mc_util_from_random::FromRandom;
use prost::Message;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// An account's "default address" is its zero^th subaddress.
pub const DEFAULT_SUBADDRESS_INDEX: u64 = 0;

/// An account's "change address" is its 1st subaddress.
pub const CHANGE_SUBADDRESS_INDEX: u64 = 1;

/// A MobileCoin user's public subaddress.
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Message, Clone, Digestible)]
pub struct PublicAddress {
    /// The user's public subaddress view key 'C'.
    #[prost(message, required, tag = "1")]
    view_public_key: RistrettoPublic,

    /// The user's public subaddress spend key `D`.
    #[prost(message, required, tag = "2")]
    spend_public_key: RistrettoPublic,

    /// This is the URL to talk to the fog report server.
    /// Empty if no fog for this public address, should be parseable as
    /// mc_util_uri::FogUri.
    #[prost(string, tag = "3")]
    fog_report_url: String,

    /// The fog report server potentially returns multiple reports when queried.
    /// This id string indicates which of the reports to use.
    ///
    /// Empty if no fog for this public address.
    #[prost(string, tag = "4")]
    fog_report_id: String,

    /// A signature with the user's spend_private_key over the fog authority's
    /// subjectPublicKeyInfo.
    ///
    /// Empty if no fog for this public address, must be parseable as a
    /// [`SchnorrkelSignature`].
    #[prost(bytes, tag = "5")]
    fog_authority_sig: Vec<u8>,
}

impl fmt::Display for PublicAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "MOB")?;
        for byte in self
            .spend_public_key
            .to_bytes()
            .iter()
            .chain(self.view_public_key().to_bytes().iter())
        {
            write!(f, "{:02X}", byte)?;
        }
        if !self.fog_report_url.is_empty() {
            write!(f, ":'{}'", self.fog_report_url)?;
        }
        if !self.fog_report_id.is_empty() {
            write!(f, "#{}", self.fog_report_id)?;
        }
        Ok(())
    }
}

impl PublicAddress {
    /// Create a new public address from CryptoNote key pair (with no account
    /// service)
    ///
    /// # Arguments
    /// `spend_public_key` - The user's public subaddress spend key `D`,
    /// `view_public_key` - The user's public subaddress view key  `C`,
    #[inline]
    pub fn new(spend_public_key: &RistrettoPublic, view_public_key: &RistrettoPublic) -> Self {
        Self {
            view_public_key: *view_public_key,
            spend_public_key: *spend_public_key,
            fog_report_url: Default::default(),
            fog_report_id: Default::default(),
            fog_authority_sig: Default::default(),
        }
    }

    /// Create a new public address with specific public keys and account
    /// service name and authority sig.
    ///
    /// # Arguments
    /// `spend_public_key` - The user's public subaddress spend key `D`,
    /// `view_public_key` - The user's public subaddress view key `C`,
    /// `fog_report_url` - User's fog report server url
    /// `fog_report_id` - The id labelling the report to use, from among the
    /// several reports which might be served by the fog report server.
    /// `fog_authority_sig` - A signature over the fog authority fingerprint
    /// using the subaddress_spend_private_key
    #[inline]
    pub fn new_with_fog(
        spend_public_key: &RistrettoPublic,
        view_public_key: &RistrettoPublic,
        fog_report_url: impl ToString,
        fog_report_id: String,
        fog_authority_sig: impl AsRef<[u8]>,
    ) -> Self {
        Self {
            view_public_key: *view_public_key,
            spend_public_key: *spend_public_key,
            fog_report_url: fog_report_url.to_string(),
            fog_report_id,
            fog_authority_sig: fog_authority_sig.as_ref().to_vec(),
        }
    }

    /// Get the public subaddress view key.
    pub fn view_public_key(&self) -> &RistrettoPublic {
        &self.view_public_key
    }

    /// Get the public subaddress spend key.
    pub fn spend_public_key(&self) -> &RistrettoPublic {
        &self.spend_public_key
    }

    /// Get the optional fog report url (if it exists / is not empty).
    pub fn fog_report_url(&self) -> Option<&str> {
        if self.fog_report_url.is_empty() {
            None
        } else {
            Some(&self.fog_report_url)
        }
    }

    /// Get the optional fog authority sig (if it exists / is not empty).
    pub fn fog_authority_sig(&self) -> Option<&[u8]> {
        if self.fog_authority_sig.is_empty() {
            None
        } else {
            Some(&self.fog_authority_sig)
        }
    }

    /// Get the optional fog report key (if it exists / is not empty).
    pub fn fog_report_id(&self) -> Option<&str> {
        if self.fog_report_id.is_empty() {
            None
        } else {
            Some(&self.fog_report_id)
        }
    }
}

impl AuthorityVerifier for PublicAddress {
    type Sig = <RistrettoPublic as AuthorityVerifier>::Sig;
    type Error = <RistrettoPublic as AuthorityVerifier>::Error;

    fn verify_authority(&self, spki_bytes: &[u8], sig: &Self::Sig) -> Result<(), Self::Error> {
        self.view_public_key.verify_authority(spki_bytes, sig)
    }
}

/// Complete AccountKey, containing the pair of secret keys, which can be used
/// for spending, and optionally some fog-related info,
/// can be used for spending. This should only ever be present in client code.
#[derive(Clone, Message, Zeroize)]
#[zeroize(drop)]
pub struct AccountKey {
    /// Private key 'a' used for view-key matching.
    #[prost(message, required, tag = "1")]
    view_private_key: RistrettoPrivate,

    /// Private key `b` used for spending.
    #[prost(message, required, tag = "2")]
    spend_private_key: RistrettoPrivate,

    /// Fog Report server url (if user has Fog service), empty string otherwise
    #[prost(string, tag = "3")]
    fog_report_url: String,

    /// Fog Report Key (if user has Fog service), empty otherwise
    /// The key labelling the report to use, from among the several reports
    /// which might be served by the fog report server.
    #[prost(string, tag = "4")]
    fog_report_id: String,

    /// Fog Authority Key Fingerprint (if user has Fog service), empty otherwise
    #[prost(bytes, tag = "5")]
    fog_authority_spki: Vec<u8>,
}

// Note: Hash, Ord is implemented in terms of default_subaddress() because
// we don't want comparisons to leak private key details over side-channels.
impl Hash for AccountKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.default_subaddress().hash(state)
    }
}

impl Eq for AccountKey {}

impl PartialEq for AccountKey {
    fn eq(&self, other: &Self) -> bool {
        self.default_subaddress().eq(&other.default_subaddress())
    }
}

impl PartialOrd for AccountKey {
    fn partial_cmp(&self, other: &AccountKey) -> Option<Ordering> {
        self.default_subaddress()
            .partial_cmp(&other.default_subaddress())
    }
}

impl Ord for AccountKey {
    fn cmp(&self, other: &AccountKey) -> Ordering {
        self.default_subaddress().cmp(&other.default_subaddress())
    }
}

impl AccountKey {
    /// A user's AccountKey, without a fog service.
    ///
    /// # Arguments
    /// * `spend_private_key` - The user's private spend key `b`.
    /// * `view_private_key` - The user's private view key `a`.
    #[inline]
    pub fn new(spend_private_key: &RistrettoPrivate, view_private_key: &RistrettoPrivate) -> Self {
        Self {
            spend_private_key: *spend_private_key,
            view_private_key: *view_private_key,
            fog_report_url: Default::default(),
            fog_report_id: Default::default(),
            fog_authority_spki: Default::default(),
        }
    }

    /// A user's AccountKey, with an fog service.
    ///
    /// # Arguments
    /// * `spend_private_key` - The user's private spend key `b`.
    /// * `view_private_key` - The user's private view key `a`.
    /// * `fog_report_url` - Url of fog report service
    /// * `fog_report_id` - The id labelling the report to use, from among the
    ///   several reports which might be served by the fog report server.
    /// * `fog_authority` - The DER-encoded subjectPublicKeyInfo of the fog
    ///   authority, which will be signed by the user when constructing the
    ///   public address.
    pub fn new_with_fog(
        spend_private_key: &RistrettoPrivate,
        view_private_key: &RistrettoPrivate,
        fog_report_url: impl ToString,
        fog_report_id: String,
        fog_authority_spki: impl AsRef<[u8]>,
    ) -> Self {
        Self {
            spend_private_key: *spend_private_key,
            view_private_key: *view_private_key,
            fog_report_url: fog_report_url.to_string(),
            fog_report_id,
            fog_authority_spki: fog_authority_spki.as_ref().to_vec(),
        }
    }

    /// Get the view private key.
    pub fn view_private_key(&self) -> &RistrettoPrivate {
        &self.view_private_key
    }

    /// Get the spend private key.
    pub fn spend_private_key(&self) -> &RistrettoPrivate {
        &self.spend_private_key
    }

    /// Access the fog url (if it exists).
    pub fn fog_report_url(&self) -> Option<&str> {
        if self.fog_report_url.is_empty() {
            None
        } else {
            Some(&self.fog_report_url)
        }
    }

    /// Access the fog authority subject public key info.
    pub fn fog_authority_spki(&self) -> Option<&[u8]> {
        if self.fog_authority_spki.is_empty() {
            None
        } else {
            Some(&self.fog_authority_spki)
        }
    }

    /// Access the fog report key (if it exists).
    pub fn fog_report_id(&self) -> Option<&str> {
        if self.fog_report_id.is_empty() {
            None
        } else {
            Some(&self.fog_report_id)
        }
    }

    /// Returns the default subaddress view key (a, D).
    pub fn view_key(&self) -> ViewKey {
        ViewKey {
            spend_public_key: self.default_subaddress().spend_public_key,
            view_private_key: self.view_private_key,
        }
    }

    /// Create an account key with random secret keys, and no fog service
    /// (intended for tests).
    pub fn random<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        Self::new(
            &RistrettoPrivate::from_random(rng),
            &RistrettoPrivate::from_random(rng),
        )
    }

    /// Create an account key with random secret keys, and the fog service
    /// url "fog://example.com"
    /// (intended for tests).
    pub fn random_with_fog<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        Self::new_with_fog(
            &RistrettoPrivate::from_random(rng),
            &RistrettoPrivate::from_random(rng),
            "fog://example.com".to_string(),
            Default::default(),
            <Vec<u8>>::default(),
        )
    }

    /// Get the account's default subaddress.
    #[inline]
    pub fn default_subaddress(&self) -> PublicAddress {
        self.subaddress(DEFAULT_SUBADDRESS_INDEX)
    }

    /// Get the account's change subaddress.
    #[inline]
    pub fn change_subaddress(&self) -> PublicAddress {
        self.subaddress(CHANGE_SUBADDRESS_INDEX)
    }

    /// Get the account's i^th subaddress.
    pub fn subaddress(&self, index: u64) -> PublicAddress {
        let view_public_key = {
            let subaddress_view_private = self.subaddress_view_private(index);
            RistrettoPublic::from(&subaddress_view_private)
        };

        let spend_public_key = {
            let subaddress_spend_private = self.subaddress_spend_private(index);
            RistrettoPublic::from(&subaddress_spend_private)
        };

        let fog_authority_sig = if !self.fog_report_url.is_empty() {
            let sig = self
                .subaddress_view_private(index)
                .sign_authority(&self.fog_authority_spki)
                .expect("Could not sign authority bytes with view-key private address");
            let sig_bytes: &[u8] = sig.as_ref();
            sig_bytes.to_vec()
        } else {
            Vec::default()
        };

        PublicAddress {
            view_public_key,
            spend_public_key,
            fog_report_url: self.fog_report_url.clone(),
            fog_report_id: self.fog_report_id.clone(),
            fog_authority_sig,
        }
    }

    /// The private spend key for the default subaddress.
    pub fn default_subaddress_spend_private(&self) -> RistrettoPrivate {
        self.subaddress_spend_private(DEFAULT_SUBADDRESS_INDEX)
    }

    /// The private spend key for the i^th subaddress.
    pub fn subaddress_spend_private(&self, index: u64) -> RistrettoPrivate {
        let a: &Scalar = self.view_private_key.as_ref();

        // `Hs(a || n)`
        let Hs: Scalar = {
            let n = Scalar::from(index);
            let mut digest = Blake2b::new();
            digest.update(SUBADDRESS_DOMAIN_TAG);
            digest.update(a.as_bytes());
            digest.update(n.as_bytes());
            Scalar::from_hash::<Blake2b>(digest)
        };

        let b: &Scalar = self.spend_private_key.as_ref();
        RistrettoPrivate::from(Hs + b)
    }

    /// The private view key for the default subaddress.
    pub fn default_subaddress_view_private(&self) -> RistrettoPrivate {
        self.subaddress_view_private(DEFAULT_SUBADDRESS_INDEX)
    }

    /// The private view key for the i^th subaddress.
    pub fn subaddress_view_private(&self, index: u64) -> RistrettoPrivate {
        let a: &Scalar = self.view_private_key.as_ref();

        // `Hs(a || n)`
        let Hs: Scalar = {
            let n = Scalar::from(index);
            let mut digest = Blake2b::new();
            digest.update(SUBADDRESS_DOMAIN_TAG);
            digest.update(a.as_bytes());
            digest.update(n.as_bytes());
            Scalar::from_hash::<Blake2b>(digest)
        };

        let b: &Scalar = self.spend_private_key.as_ref();
        let c = a * (Hs + b);
        RistrettoPrivate::from(c)
    }
}

#[cfg(test)]
mod account_key_tests {
    use super::*;
    use alloc::boxed::Box;
    use core::convert::TryFrom;
    use datatest::data;
    use mc_crypto_keys::RistrettoSignature;
    use mc_test_vectors_account_keys::*;
    use mc_util_test_vector::TestVector;
    use rand::prelude::StdRng;
    use rand_core::SeedableRng;

    // Helper method to verify the signature of a public address
    fn verify_signature(subaddress: &PublicAddress, spki: &[u8]) {
        let signature = RistrettoSignature::try_from(
            subaddress
                .fog_authority_sig()
                .expect("Subaddress does not contain fog authority sig"),
        )
        .expect("Could not construct signature from fog authority sig bytes");
        assert!(subaddress
            .view_public_key
            .verify_authority(spki, &signature)
            .is_ok());
    }

    #[test]
    // Deserializing should recover a serialized a PublicAddress.
    fn mc_util_serial_prost_roundtrip_public_address() {
        mc_util_test_helper::run_with_several_seeds(|mut rng| {
            {
                let acct = AccountKey::random(&mut rng);
                let ser = mc_util_serial::encode(&acct.default_subaddress());
                let result: PublicAddress = mc_util_serial::decode(&ser).unwrap();
                assert_eq!(acct.default_subaddress(), result);
            }
            {
                let acct = AccountKey::random_with_fog(&mut rng);
                let ser = mc_util_serial::encode(&acct.default_subaddress());
                let result: PublicAddress = mc_util_serial::decode(&ser).unwrap();
                assert_eq!(acct.default_subaddress(), result);
            }
        });
    }

    #[test]
    // Subaddress private keys should agree with subaddress public keys.
    fn test_subadress_private_keys_agree_with_subaddress_public_keys() {
        let mut rng: StdRng = SeedableRng::from_seed([91u8; 32]);
        let view_private = RistrettoPrivate::from_random(&mut rng);
        let spend_private = RistrettoPrivate::from_random(&mut rng);

        let account_key = AccountKey::new(&spend_private, &view_private);

        let index = rng.next_u64();
        let subaddress = account_key.subaddress(index);

        let subaddress_view_private = account_key.subaddress_view_private(index);
        let subaddress_spend_private = account_key.subaddress_spend_private(index);

        let expected_subaddress_view_public = RistrettoPublic::from(&subaddress_view_private);
        let expected_subaddress_spend_public = RistrettoPublic::from(&subaddress_spend_private);

        assert_eq!(expected_subaddress_view_public, subaddress.view_public_key);
        assert_eq!(
            expected_subaddress_spend_public,
            subaddress.spend_public_key
        );
    }

    #[data(DefaultSubaddrKeysFromAcctPrivKeys::from_jsonl("../test-vectors/vectors"))]
    #[test]
    fn default_subaddr_keys_from_acct_priv_keys(case: DefaultSubaddrKeysFromAcctPrivKeys) {
        let spend_private_key = RistrettoPrivate::try_from(&case.spend_private_key).unwrap();
        let view_private_key = RistrettoPrivate::try_from(&case.view_private_key).unwrap();
        let account_key = AccountKey::new(&spend_private_key, &view_private_key);
        let public_address = account_key.default_subaddress();
        assert_eq!(
            account_key.default_subaddress_view_private().to_bytes(),
            case.subaddress_view_private_key
        );
        assert_eq!(
            account_key.default_subaddress_spend_private().to_bytes(),
            case.subaddress_spend_private_key
        );
        assert_eq!(
            public_address.view_public_key().to_bytes(),
            case.subaddress_view_public_key
        );

        assert_eq!(
            public_address.spend_public_key().to_bytes(),
            case.subaddress_spend_public_key
        );
    }

    #[data(SubaddrKeysFromAcctPrivKeys::from_jsonl("../test-vectors/vectors"))]
    #[test]
    fn subaddr_keys_from_acct_priv_keys(case: SubaddrKeysFromAcctPrivKeys) {
        let spend_private_key = RistrettoPrivate::try_from(&case.spend_private_key).unwrap();
        let view_private_key = RistrettoPrivate::try_from(&case.view_private_key).unwrap();
        let account_key = AccountKey::new(&spend_private_key, &view_private_key);
        let public_address = account_key.subaddress(case.subaddress_index);
        assert_eq!(
            account_key
                .subaddress_view_private(case.subaddress_index)
                .to_bytes(),
            case.subaddress_view_private_key
        );
        assert_eq!(
            account_key
                .subaddress_spend_private(case.subaddress_index)
                .to_bytes(),
            case.subaddress_spend_private_key
        );
        assert_eq!(
            public_address.view_public_key().to_bytes(),
            case.subaddress_view_public_key
        );
        assert_eq!(
            public_address.spend_public_key().to_bytes(),
            case.subaddress_spend_public_key
        );
    }

    #[test]
    // Subaddress fog authority signature should verify
    fn test_fog_authority_signature() {
        let mut rng: StdRng = SeedableRng::from_seed([42u8; 32]);
        let view_private = RistrettoPrivate::from_random(&mut rng);
        let spend_private = RistrettoPrivate::from_random(&mut rng);
        let fog_url = "fog://example.com";
        let mut fog_authority_spki = [0u8; 32];
        rng.fill_bytes(&mut fog_authority_spki);
        let fog_report_key = String::from("");

        let account_key = AccountKey::new_with_fog(
            &spend_private,
            &view_private,
            fog_url,
            fog_report_key,
            fog_authority_spki,
        );

        let index = rng.next_u64();
        let subaddress = account_key.subaddress(index);

        // Note: The fog_authority_fingerprint is published, so it is known by the
        // verifier.
        verify_signature(&subaddress, &fog_authority_spki);
    }
}
