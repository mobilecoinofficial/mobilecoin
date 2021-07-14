// Copyright (c) 2018-2021 The MobileCoin Foundation

use alloc::vec::Vec;
use blake2::digest::Update;
use core::{convert::TryFrom, fmt};

use mc_account_keys::PublicAddress;
use mc_common::Hash;
use mc_crypto_digestible::{Digestible, MerlinTranscript};
use mc_crypto_hashes::Blake2b256;
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPrivate, RistrettoPublic};
use mc_util_repr_bytes::{
    derive_prost_message_from_repr_bytes, typenum::U32, GenericArray, ReprBytes,
};
use prost::Message;
use serde::{Deserialize, Serialize};

use crate::{
    amount::{Amount, AmountError},
    domain_separators::TXOUT_CONFIRMATION_NUMBER_DOMAIN_TAG,
    encrypted_fog_hint::EncryptedFogHint,
    get_tx_out_shared_secret,
    membership_proofs::Range,
    onetime_keys::{create_onetime_public_key, create_shared_secret, create_tx_public_key},
    ring_signature::{KeyImage, SignatureRctBulletproofs},
    CompressedCommitment,
};

/// Transaction hash length, in bytes.
pub const TX_HASH_LEN: usize = 32;

#[derive(
    Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Digestible,
)]
/// Hash of a Tx.
pub struct TxHash(pub [u8; TX_HASH_LEN]);

impl TxHash {
    #[inline]
    /// Copies `self` to a new Vec.
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    #[inline]
    /// A reference to the underlying byte array.
    pub fn as_bytes(&self) -> &[u8; TX_HASH_LEN] {
        &self.0
    }
}

impl core::ops::Deref for TxHash {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&[u8; TX_HASH_LEN]> for TxHash {
    #[inline]
    fn from(a: &[u8; TX_HASH_LEN]) -> Self {
        Self(*a)
    }
}

impl From<[u8; TX_HASH_LEN]> for TxHash {
    #[inline]
    fn from(a: [u8; TX_HASH_LEN]) -> Self {
        Self(a)
    }
}

impl<'bytes> TryFrom<&'bytes [u8]> for TxHash {
    type Error = ();

    #[inline]
    fn try_from(src: &[u8]) -> Result<Self, <Self as TryFrom<&'bytes [u8]>>::Error> {
        if src.len() != TX_HASH_LEN {
            return Err(());
        }
        let mut bytes = [0u8; TX_HASH_LEN];
        bytes.copy_from_slice(src);
        Ok(Self::from(bytes))
    }
}

impl fmt::Display for TxHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex_fmt::HexFmt(&self.0[0..6]))
    }
}

impl fmt::Debug for TxHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Tx#{}", self)
    }
}

/// A CryptoNote-style transaction.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Message, Digestible)]
pub struct Tx {
    /// The transaction contents.
    #[prost(message, required, tag = "1")]
    pub prefix: TxPrefix,

    /// The transaction signature.
    #[prost(message, required, tag = "2")]
    pub signature: SignatureRctBulletproofs,
}

impl fmt::Display for Tx {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.tx_hash())
    }
}

impl Tx {
    /// Compute a 32-byte hash from all of the contents of a Tx
    pub fn tx_hash(&self) -> TxHash {
        TxHash::from(self.digest32::<MerlinTranscript>(b"mobilecoin-tx"))
    }

    /// Key images "spent" by this transaction.
    pub fn key_images(&self) -> Vec<KeyImage> {
        self.signature.key_images()
    }

    /// Get the highest index of each membership proof referenced by the
    /// transaction.
    pub fn get_membership_proof_highest_indices(&self) -> Vec<u64> {
        self.prefix.get_membership_proof_highest_indices()
    }

    /// Output public keys contained in this transaction.
    pub fn output_public_keys(&self) -> Vec<CompressedRistrettoPublic> {
        self.prefix
            .outputs
            .iter()
            .map(|tx_out| tx_out.public_key)
            .collect()
    }
}

/// TxPrefix is the Tx struct without the signature.  It is used to
/// calculate the prefix hash for signing and verifying.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize, Message, Digestible)]
pub struct TxPrefix {
    /// List of inputs to the transaction.
    #[prost(message, repeated, tag = "1")]
    pub inputs: Vec<TxIn>,

    /// List of outputs from the transaction.
    #[prost(message, repeated, tag = "2")]
    pub outputs: Vec<TxOut>,

    /// Fee paid to the foundation for this transaction
    #[prost(uint64, tag = "3")]
    pub fee: u64,

    /// The block index at which this transaction is no longer valid.
    #[prost(uint64, tag = "4")]
    pub tombstone_block: u64,
}

impl TxPrefix {
    /// Create a new TxPrefix.
    ///
    /// # Arguments:
    /// * `inputs` - Inputs spent by the transaction.
    /// * `outputs` - Outputs created by the transaction.
    /// * `fee` - Transaction fee.
    /// * `tombstone_block` - The block index at which this transaction is no
    ///   longer valid.
    pub fn new(inputs: Vec<TxIn>, outputs: Vec<TxOut>, fee: u64, tombstone_block: u64) -> TxPrefix {
        TxPrefix {
            inputs,
            outputs,
            fee,
            tombstone_block,
        }
    }

    /// Blake2b256 hash of `self`.
    pub fn hash(&self) -> TxHash {
        TxHash::from(self.digest32::<MerlinTranscript>(b"mobilecoin-tx-prefix"))
    }

    /// Return the `highest_index` for each tx_out membership proof in this
    /// transaction.
    pub fn get_membership_proof_highest_indices(&self) -> Vec<u64> {
        self.inputs
            .iter()
            .flat_map(|tx_in| {
                let indices: Vec<u64> = tx_in
                    .proofs
                    .iter()
                    .map(|tx_out_membership_proof| tx_out_membership_proof.highest_index)
                    .collect();
                indices
            })
            .collect()
    }

    /// Get all output commitments.
    pub fn output_commitments(&self) -> Vec<CompressedCommitment> {
        self.outputs
            .iter()
            .map(|output| output.amount.commitment)
            .collect()
    }
}

/// An "input" to a transaction.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize, Message, Digestible)]
pub struct TxIn {
    /// A "ring" of outputs containing the single output that is being spent.
    /// It would be nice to use [TxOut; RING_SIZE] here, but Prost only works
    /// with Vec.
    #[prost(message, repeated, tag = "1")]
    pub ring: Vec<TxOut>,

    /// Proof that each TxOut in `ring` is in the ledger.
    /// It would be nice to use [TxOutMembershipProof; RING_SIZE] here, but
    /// Prost only works with Vec.
    #[prost(message, repeated, tag = "2")]
    pub proofs: Vec<TxOutMembershipProof>,
}

/// An output created by a transaction.
#[derive(Clone, Deserialize, Eq, Hash, PartialEq, Serialize, Message, Digestible)]
pub struct TxOut {
    /// The amount being sent.
    #[prost(message, required, tag = "1")]
    pub amount: Amount,

    /// The one-time public address of this output.
    #[prost(message, required, tag = "2")]
    pub target_key: CompressedRistrettoPublic,

    /// The per output tx public key
    #[prost(message, required, tag = "3")]
    pub public_key: CompressedRistrettoPublic,

    /// The encrypted account hint for the account server.
    #[prost(message, required, tag = "4")]
    pub e_fog_hint: EncryptedFogHint,
}

impl TxOut {
    /// Creates a TxOut that sends `value` to `recipient`.
    ///
    /// # Arguments
    /// * `value` - Value of the output.
    /// * `recipient` - Recipient's address.
    /// * `tx_private_key` - The transaction's private key
    /// * `hint` - Encrypted Fog hint.
    pub fn new(
        value: u64,
        recipient: &PublicAddress,
        tx_private_key: &RistrettoPrivate,
        hint: EncryptedFogHint,
    ) -> Result<Self, AmountError> {
        let target_key = create_onetime_public_key(tx_private_key, recipient).into();
        let public_key = create_tx_public_key(tx_private_key, recipient.spend_public_key()).into();

        let amount = {
            let shared_secret = create_shared_secret(recipient.view_public_key(), tx_private_key);
            Amount::new(value, &shared_secret)
        }?;

        Ok(TxOut {
            amount,
            target_key,
            public_key,
            e_fog_hint: hint,
        })
    }

    /// Blake2B256 hash of his TxOut.
    pub fn hash(&self) -> Hash {
        self.digest32::<MerlinTranscript>(b"mobilecoin-txout")
    }
}

/// A Merkle proof-of-membership for the TxOut at the given index contains a set
/// of hashes: it includes each hash between the leaf and the root, as well as
/// each "other" child hash. It is assumed that the proof accompanies the leaf
/// TxOut, so its leaf hash may be computed as part of checking the proof.
///
/// In total, the TxOut, its index, and the set of non-leaf hashes are
/// sufficient to re-compute the root hash, which completes the
/// proof-of-membership verification.
///
/// # References
/// * [How Log Proofs Work](http://www.certificate-transparency.org/log-proofs-work)
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize, Message, Digestible)]
pub struct TxOutMembershipProof {
    /// Index of the TxOut that this proof refers to.
    #[prost(uint64, tag = "1")]
    pub index: u64,

    /// Index of the last TxOut at the time the proof was created.
    #[prost(uint64, tag = "2")]
    pub highest_index: u64,

    /// All hashes needed to recompute the root hash.
    /// These elements must be listed in the order in which they should be
    /// combined for the proof to be valid.
    #[prost(message, repeated, tag = "3")]
    pub elements: Vec<TxOutMembershipElement>,
}

impl TxOutMembershipProof {
    /// Create a Merkle proof-of-membership for a given TxOut.
    ///
    /// # Arguments
    /// * `index` - The index of the TxOut.
    /// * `highest_index` - The index of the last TxOut in the ledger,
    ///   indicating the size of the tree that the proof refers to.
    /// * `elements` - The tx out membership elements, containing ranges
    ///   referring to subtrees in the tree, and hashes. These must be provided
    ///   in the order in which they should be combined to validate the proof.
    pub fn new(index: u64, highest_index: u64, elements: Vec<TxOutMembershipElement>) -> Self {
        Self {
            index,
            highest_index,
            elements,
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialOrd, Ord, PartialEq, Serialize, Message, Digestible)]
/// An element of a TxOut membership proof, denoting an internal hash node in a
/// Merkle tree.
pub struct TxOutMembershipElement {
    /// The range of leaf nodes "under" this internal hash.
    #[prost(message, required, tag = "1")]
    pub range: Range,

    #[prost(message, required, tag = "2")]
    /// The internal hash value.
    pub hash: TxOutMembershipHash,
}

impl TxOutMembershipElement {
    pub fn new(range: Range, hash: [u8; 32]) -> Self {
        Self {
            range,
            hash: hash.into(),
        }
    }
}

#[derive(
    Clone, Deserialize, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Debug, Digestible,
)]
#[digestible(transparent)]
/// A hash in a TxOut membership proof.
pub struct TxOutMembershipHash(pub [u8; 32]);

impl TxOutMembershipHash {
    /// Copies self into a new Vec.
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl core::convert::AsRef<[u8; 32]> for TxOutMembershipHash {
    #[inline]
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::convert::From<&[u8; 32]> for TxOutMembershipHash {
    #[inline]
    fn from(src: &[u8; 32]) -> Self {
        Self(*src)
    }
}

impl core::convert::From<[u8; 32]> for TxOutMembershipHash {
    #[inline]
    fn from(src: [u8; 32]) -> Self {
        Self(src)
    }
}

impl ReprBytes for TxOutMembershipHash {
    type Error = &'static str;
    type Size = U32;
    fn from_bytes(src: &GenericArray<u8, U32>) -> Result<Self, &'static str> {
        Ok(Self((*src).into()))
    }
    fn to_bytes(&self) -> GenericArray<u8, U32> {
        self.0.into()
    }
}

derive_prost_message_from_repr_bytes!(TxOutMembershipHash);

/// A hash of the shared secret used to confirm tx was sent
#[derive(
    Clone, Deserialize, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Debug, Digestible,
)]
pub struct TxOutConfirmationNumber([u8; 32]);

impl TxOutConfirmationNumber {
    /// Copies self into a new Vec.
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn validate(
        &self,
        tx_pubkey: &RistrettoPublic,
        view_private_key: &RistrettoPrivate,
    ) -> bool {
        let shared_secret = get_tx_out_shared_secret(view_private_key, tx_pubkey);
        let calculated_confirmation = TxOutConfirmationNumber::from(&shared_secret);
        calculated_confirmation == *self
    }
}

impl core::convert::AsRef<[u8; 32]> for TxOutConfirmationNumber {
    #[inline]
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::convert::From<&[u8; 32]> for TxOutConfirmationNumber {
    #[inline]
    fn from(src: &[u8; 32]) -> Self {
        Self(*src)
    }
}

impl core::convert::From<[u8; 32]> for TxOutConfirmationNumber {
    #[inline]
    fn from(src: [u8; 32]) -> Self {
        Self(src)
    }
}

impl core::convert::From<&RistrettoPublic> for TxOutConfirmationNumber {
    fn from(shared_secret: &RistrettoPublic) -> Self {
        let mut hasher = Blake2b256::new();
        hasher.update(&TXOUT_CONFIRMATION_NUMBER_DOMAIN_TAG);
        hasher.update(shared_secret.to_bytes());

        let result: [u8; 32] = hasher.result().into();
        Self(result)
    }
}

impl ReprBytes for TxOutConfirmationNumber {
    type Error = &'static str;
    type Size = U32;
    fn from_bytes(src: &GenericArray<u8, U32>) -> Result<Self, &'static str> {
        Ok(Self((*src).into()))
    }
    fn to_bytes(&self) -> GenericArray<u8, U32> {
        self.0.into()
    }
}

derive_prost_message_from_repr_bytes!(TxOutConfirmationNumber);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        constants::MINIMUM_FEE,
        encrypted_fog_hint::{EncryptedFogHint, ENCRYPTED_FOG_HINT_LEN},
        ring_signature::SignatureRctBulletproofs,
        Amount,
    };
    use alloc::vec::Vec;
    use mc_crypto_keys::RistrettoPublic;
    use mc_util_from_random::FromRandom;
    use prost::Message;
    use rand::{rngs::StdRng, SeedableRng};
    use rand_core::{CryptoRng, RngCore};

    /// Creates a vector of TxOuts.
    ///
    /// # Arguments
    /// * `size` - Number of elements in the vector.
    /// * `rng` - Randomness.
    ///
    /// Returns outputs
    fn get_outputs<RNG: CryptoRng + RngCore>(size: usize, rng: &mut RNG) -> Vec<TxOut> {
        let mut outs: Vec<TxOut> = Vec::new();

        // Create ring_size - 1 mixins.
        for _i in 0..size {
            let shared_secret = RistrettoPublic::from_random(rng);
            let target_key = RistrettoPublic::from_random(rng).into();
            let public_key = RistrettoPublic::from_random(rng).into();
            let amount = Amount::new(23u64, &shared_secret).unwrap();
            let tx_out = TxOut {
                amount,
                target_key,
                public_key,
                e_fog_hint: EncryptedFogHint::from(&[1u8; ENCRYPTED_FOG_HINT_LEN]),
            };
            outs.push(tx_out);
        }
        outs
    }

    /// Creates a vector of TxOutMembershipElements.
    ///
    /// # Arguments
    /// * `size` - Number of elements in the vector.
    /// * `rng` - Randomness.
    ///
    /// Returns elements
    fn get_elements<RNG: CryptoRng + RngCore>(
        size: usize,
        rng: &mut RNG,
    ) -> Vec<TxOutMembershipElement> {
        let mut elements: Vec<TxOutMembershipElement> = Vec::new();
        for _i in 0..size {
            let mut membership_hash = [0u8; 32];
            rng.fill_bytes(&mut membership_hash);

            let range = Range {
                from: 0,
                to: rng.next_u64(),
            };

            let element = TxOutMembershipElement {
                range,
                hash: TxOutMembershipHash(membership_hash),
            };
            elements.push(element);
        }
        elements
    }

    /// Creates a vector of TxIns.
    ///
    /// # Arguments
    /// * `size` - Number of elements in the vector.
    /// * `rng` - Randomness.
    ///
    /// Returns inputs
    fn get_inputs<RNG: CryptoRng + RngCore>(
        size: usize,
        num_proofs_per_input: usize,
        rng: &mut RNG,
    ) -> Vec<TxIn> {
        let mut inputs: Vec<TxIn> = Vec::new();
        for _i in 0..size {
            let ring = get_outputs(11, rng);
            let proofs: Vec<TxOutMembershipProof> = ring
                .iter()
                .map(|_tx_out| {
                    let elements = get_elements(num_proofs_per_input, rng);
                    TxOutMembershipProof {
                        index: 0,
                        highest_index: 64,
                        elements,
                    }
                })
                .collect();

            let tx_in = TxIn { ring, proofs };
            inputs.push(tx_in);
        }
        inputs
    }

    #[test]
    // `serialize_tx` should create a Tx, encode/decode it, and compare
    fn test_serialize_tx() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let tx_out = {
            let shared_secret = RistrettoPublic::from_random(&mut rng);
            let target_key = RistrettoPublic::from_random(&mut rng).into();
            let public_key = RistrettoPublic::from_random(&mut rng).into();
            let amount = Amount::new(23u64, &shared_secret).unwrap();
            TxOut {
                amount,
                target_key,
                public_key,
                e_fog_hint: EncryptedFogHint::from(&[1u8; ENCRYPTED_FOG_HINT_LEN]),
            }
        };

        // TxOut = decode(encode(TxOut))
        let mut buf = Vec::new();
        tx_out.encode(&mut buf).expect("failed to serialize TxOut");
        assert_eq!(tx_out, TxOut::decode(&buf[..]).unwrap());

        let tx_in = TxIn {
            ring: vec![tx_out.clone()],
            proofs: vec![],
        };

        // TxIn = decode(encode(TxIn))
        let mut buf = Vec::new();
        tx_in.encode(&mut buf).expect("failed to serialize TxIn");
        assert_eq!(tx_in, TxIn::decode(&buf[..]).unwrap());

        let prefix = TxPrefix {
            inputs: vec![tx_in],
            outputs: vec![tx_out],
            fee: MINIMUM_FEE,
            tombstone_block: 23,
        };

        let mut buf = Vec::new();
        prefix
            .encode(&mut buf)
            .expect("failed to serialize into slice");

        assert_eq!(prefix, TxPrefix::decode(&buf[..]).unwrap());

        // TODO: use a meaningful signature.
        let signature = SignatureRctBulletproofs::default();

        let tx = Tx { prefix, signature };

        let mut buf = Vec::new();
        tx.encode(&mut buf).expect("failed to serialize into slice");
        let recovered_tx: Tx = Tx::decode(&buf[..]).unwrap();
        assert_eq!(tx, recovered_tx);
    }

    #[test]
    fn test_tx_prefix_hash() {
        let mut rng: StdRng = SeedableRng::from_seed([32u8; 32]);
        let outputs = get_outputs(3, &mut rng);

        let inputs = get_inputs(2, 4, &mut rng);
        let prefix = TxPrefix::new(inputs.clone(), outputs.clone(), MINIMUM_FEE, 100);
        let prefix_hash = prefix.hash();

        // Verify that the prefix with the same contents produces the same hash
        let prefix1 = TxPrefix::new(inputs.clone(), outputs.clone(), MINIMUM_FEE, 100);
        let prefix_hash1 = prefix1.hash();
        assert_eq!(prefix_hash, prefix_hash1);

        // Now let's construct a different set of membership elements in the proof with everything else the same
        let mut inputs2: Vec<TxIn> = Vec::new();
        for input in inputs {
            let mut proofs: Vec<TxOutMembershipProof> = Vec::new();
            for proof in input.proofs {
                let elements = get_elements(4, &mut rng);
                proofs.push(TxOutMembershipProof {
                    index: proof.index,
                    highest_index: proof.highest_index,
                    elements,
                });
            }
            inputs2.push(TxIn {
                ring: input.ring.clone(),
                proofs,
            });
        }
        let prefix2 = TxPrefix::new(inputs2, outputs, MINIMUM_FEE, 100);
        let prefix_hash2 = prefix2.hash();

        assert_ne!(prefix_hash, prefix_hash2);
    }
}
