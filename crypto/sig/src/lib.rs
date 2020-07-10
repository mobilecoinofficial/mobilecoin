#![no_std]

//! Simplified API for using Schnorrkel in a deterministic manner, with simple
//! ristretto key pairs, where the public key is a RistretoPoint and the private key is a Scalar.
//!
//! mc-crypto-keys crate provides wrappers RistrettoPublic and RistrettoPrivate around these
//! and implements many handy traits for performing high-level cryptography operations,
//! and this crate provides a way to create signatures that is compatible with these key pairs.

use digest::Input;
use mc_crypto_hashes::Blake2b256;
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use rand_core::SeedableRng;
use rand_hc::Hc128Rng as FixedRng;
use schnorrkel::{signing_context, SecretKey};
pub use schnorrkel::{Signature, SignatureError};

/// Create a deterministic Schnorrkel signature
///
/// Arguments:
/// * context_tag: Domain separation tag for the signatures
/// * private_key: The RistrettoPrivate key used to sign the message
/// * message: The message that is signed
///
/// Returns:
/// * A 64-byte Schnorrkel Signature object which can be converted to and from bytes using its API.
pub fn sign(context_tag: &[u8], private_key: &RistrettoPrivate, message: &[u8]) -> Signature {
    // Nonce is hash( private_key || message )
    let mut hasher = Blake2b256::new();
    hasher.input(private_key.to_bytes());
    hasher.input(message);
    let nonce = hasher.result();

    // Construct a Schnorrkel SecretKey object from private_key and our nonce value
    let mut secret_bytes = [0u8; 64];
    secret_bytes[0..32].copy_from_slice(&private_key.to_bytes());
    secret_bytes[32..64].copy_from_slice(&nonce);
    let secret_key = SecretKey::from_bytes(&secret_bytes).unwrap();
    let keypair = secret_key.to_keypair();

    // Context provides domain separation for signature
    let ctx = signing_context(context_tag);
    // NOTE: The fog_authority_sig is deterministic due to using the above hash as the rng seed
    let mut csprng: FixedRng = SeedableRng::from_seed(nonce.into());
    keypair.sign_rng(ctx.bytes(message), &mut csprng)
}

/// Verify a Schnorrkel signature
///
/// Note that this should work correctly even with Schnorrkel signatures not generated by the sign function
/// above, because the details of the nonce generation don't affect whether the signature passes verification.
/// The signing context bytes will matter though, if the other party is using a special signing context then
/// we must provide the same signing context bytes.
///
/// Arguments:
/// * context_tag: Domain separation tag for the signatures.
/// * public_key: Public key to check the signature against.
/// * message: The message that is signed.
/// * signature: The signature object to verify.
///
/// Returns:
/// * Ok if the signature checks out, SignatureError otherwise.
pub fn verify(
    context_tag: &[u8],
    public_key: &RistrettoPublic,
    message: &[u8],
    signature: &Signature,
) -> Result<(), SignatureError> {
    let ctx = signing_context(context_tag);
    let pubkey = schnorrkel::PublicKey::from_point(*public_key.as_ref());
    pubkey.verify(ctx.bytes(message), signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_util_from_random::FromRandom;
    use mc_util_test_helper::run_with_several_seeds;

    // Expected successes
    #[test]
    fn expected_success() {
        run_with_several_seeds(|mut rng| {
            let seckey = RistrettoPrivate::from_random(&mut rng);
            let pubkey = RistrettoPublic::from(&seckey);

            let sig = sign(b"test", &seckey, b"foobar");
            verify(b"test", &pubkey, b"foobar", &sig).expect("unexpected failure");
        })
    }
    // Expected failure when key is different
    #[test]
    fn expected_failure_bad_keys() {
        run_with_several_seeds(|mut rng| {
            let seckey = RistrettoPrivate::from_random(&mut rng);
            let seckey2 = RistrettoPrivate::from_random(&mut rng);
            let pubkey = RistrettoPublic::from(&seckey);

            let sig = sign(b"test", &seckey2, b"foobar");
            let result = verify(b"test", &pubkey, b"foobar", &sig);
            assert!(!result.is_ok());
        })
    }
    // Expected failure when message is different
    #[test]
    fn expected_failure_bad_message() {
        run_with_several_seeds(|mut rng| {
            let seckey = RistrettoPrivate::from_random(&mut rng);
            let pubkey = RistrettoPublic::from(&seckey);

            let sig = sign(b"test", &seckey, b"foobar");
            let result = verify(b"test", &pubkey, b"foobarbaz", &sig);
            assert!(!result.is_ok());
        })
    }

    // Expected failure when context is different
    #[test]
    fn expected_failure_bad_context() {
        run_with_several_seeds(|mut rng| {
            let seckey = RistrettoPrivate::from_random(&mut rng);
            let pubkey = RistrettoPublic::from(&seckey);

            let sig = sign(b"test", &seckey, b"foobar");
            let result = verify(b"prod", &pubkey, b"foobar", &sig);
            assert!(!result.is_ok());
        })
    }
}
