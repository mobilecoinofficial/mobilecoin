//! Tests that prost-versions of structures round-trip with the versions generated from external.proto

use mc_account_keys::{AccountKey, PublicAddress, RootIdentity, ViewKey};
use mc_api::external;
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_util_from_random::FromRandom;
use mc_util_test_helper::{run_with_several_seeds, CryptoRng, RngCore};
use prost::Message as ProstMessage;
use protobuf::Message as ProtobufMessage;
use std::convert::TryFrom;

// Take a prost type and try to roundtrip it through a protobuf type
fn round_trip_message<SRC: ProstMessage + Eq + Default, DEST: ProtobufMessage>(prost_val: &SRC) {
    let prost_bytes = mc_util_serial::encode(prost_val);

    let dest_val =
        DEST::parse_from_bytes(&prost_bytes).expect("Parsing protobuf from prost bytes failed");

    let protobuf_bytes = dest_val
        .write_to_bytes()
        .expect("Writing protobuf to bytes failed");

    let final_val: SRC =
        mc_util_serial::decode(&protobuf_bytes).expect("Parsing prost from protobuf bytes failed");

    assert_eq!(*prost_val, final_val);
}

// Generate some example root identities
fn root_identity_examples<T: RngCore + CryptoRng>(rng: &mut T) -> Vec<RootIdentity> {
    let der_bytes = pem::parse(mc_crypto_x509_test_vectors::ok_rsa_head())
        .expect("Could not parse RSA test vector as PEM")
        .contents;
    let fog_authority_spki = x509_signature::parse_certificate(&der_bytes)
        .expect("Could not parse X509 certificate from DER")
        .subject_public_key_info()
        .spki();

    vec![
        RootIdentity::from_random(rng),
        RootIdentity::random_with_fog(
            rng,
            "fog://fog.unittest.mobilecoin.com",
            "",
            fog_authority_spki,
        )
        .expect("Could not construct root identity with fog data"),
        RootIdentity::random_with_fog(
            rng,
            "fog://fog.unittest.mobilecoin.com",
            "1",
            fog_authority_spki,
        )
        .expect("Could not construct root identity with fog data"),
    ]
}

// Test that RootIdentity roundtrips through .proto structure
#[test]
fn root_identity_round_trip() {
    run_with_several_seeds(|mut rng| {
        for example in root_identity_examples(&mut rng).iter() {
            round_trip_message::<RootIdentity, external::RootIdentity>(example);
        }
    })
}

// Test that AccountKey roundtrips through .proto structure
#[test]
fn account_key_round_trip() {
    run_with_several_seeds(|mut rng| {
        for example in root_identity_examples(&mut rng).iter() {
            round_trip_message::<AccountKey, external::AccountKey>(
                &AccountKey::try_from(example)
                    .expect("Could not create AccountKey from RootIdentity example"),
            );
        }
    })
}

// Test that PublicAddress roundtrips through .proto structure
#[test]
fn public_address_round_trip() {
    run_with_several_seeds(|mut rng| {
        for example in root_identity_examples(&mut rng).iter() {
            round_trip_message::<PublicAddress, external::PublicAddress>(
                &AccountKey::try_from(example)
                    .expect("Could not create AccountKey from RootIdentity example")
                    .default_subaddress(),
            );
        }
    })
}

// Test that ViewKey roundtrips through .proto structure
#[test]
fn view_key_round_trip() {
    run_with_several_seeds(|mut rng| {
        let vk = ViewKey::new(
            RistrettoPrivate::from_random(&mut rng),
            RistrettoPublic::from_random(&mut rng),
        );
        round_trip_message::<ViewKey, external::ViewKey>(&vk);
    })
}
