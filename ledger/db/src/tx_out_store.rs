// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Data access abstraction for TxOuts stored in the ledger.
//!
//! Maintains a Merkle Tree of TxOuts. The tree can be thought of as full, with
//! missing values replaced with a sentinel Nil value,
//! .
//!                               H(A..H)
//!                       ------------------------
//!                      /                        \
//!              H(A..D)                        H(E..H)
//!             /       \                     /         \
//!     H(A..B)         H(C..D)         H(E..F)          H(Nil)
//!    /      \         /     \        /      \          /     \
//!  H(A)    H(B)    H(C)    H(D)   H(E)     H(Nil)   H(Nil)   H(Nil)
//!   |       |       |       |      |         |        |        |
//!   A       B       C       D      E        Nil      Nil      Nil
//!
//! As depicted above, this file refers to nodes by the range of leaf indices
//! below them. Distinct hash functions are used for leaf values, Nil, and
//! internal hashes in order to avoid second-preimage attacks.
//!
//! # References
//! * [Attacking Merkle Trees with a Second Preimage Attack](https://flawed.net.nz/2018/02/21/attacking-merkle-trees-with-a-second-preimage-attack/)

use crate::{key_bytes_to_u64, u64_to_key_bytes, Error};
use lmdb::{Database, DatabaseFlags, Environment, RwTransaction, Transaction, WriteFlags};
use mc_common::Hash;
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_transaction_core::{
    membership_proofs::*,
    tx::{TxOut, TxOutMembershipElement, TxOutMembershipProof},
};
use mc_util_serial::{decode, encode};

// LMDB Database names.
pub const COUNTS_DB_NAME: &str = "tx_out_store:counts";
pub const TX_OUT_INDEX_BY_HASH_DB_NAME: &str = "tx_out_store:tx_out_index_by_hash";
pub const TX_OUT_INDEX_BY_PUBLIC_KEY_DB_NAME: &str = "tx_out_store:tx_out_index_by_public_key";
pub const TX_OUT_BY_INDEX_DB_NAME: &str = "tx_out_store:tx_out_by_index";
pub const MERKLE_HASH_BY_RANGE_DB_NAME: &str = "tx_out_store:merkle_hash_by_range";

// Keys used by the `counts` database.
pub const NUM_TX_OUTS_KEY: &str = "num_tx_outs";

#[derive(Clone)]
pub struct TxOutStore {
    /// Aggregate counts
    /// * `NUM_TX_OUTS_KEY` --> Number (u64) of TxOuts in the ledger.
    counts: Database,

    /// TxOut by index. `key_bytes_to_u64(index) -> encode(&tx_out)`
    tx_out_by_index: Database,

    /// `tx_out.hash() -> u64_to_key_bytes(index)`
    tx_out_index_by_hash: Database,

    /// `tx_out.public_key -> u64_to_key_bytes(index)`
    tx_out_index_by_public_key: Database,

    /// Merkle hashes of subtrees. Range -> Merkle Hash of subtree containing
    /// TxOuts with indices in `[range.from, range.to]`. range.to_key_bytes
    /// --> [u8; 32]
    merkle_hashes: Database,
}

impl TxOutStore {
    #[cfg(feature = "migration_support")]
    pub fn get_tx_out_index_by_public_key_database(&self) -> Database {
        self.tx_out_index_by_public_key
    }

    /// Opens an existing TxOutStore.
    pub fn new(env: &Environment) -> Result<Self, Error> {
        Ok(TxOutStore {
            counts: env.open_db(Some(COUNTS_DB_NAME))?,
            tx_out_index_by_hash: env.open_db(Some(TX_OUT_INDEX_BY_HASH_DB_NAME))?,
            tx_out_index_by_public_key: env.open_db(Some(TX_OUT_INDEX_BY_PUBLIC_KEY_DB_NAME))?,
            tx_out_by_index: env.open_db(Some(TX_OUT_BY_INDEX_DB_NAME))?,
            merkle_hashes: env.open_db(Some(MERKLE_HASH_BY_RANGE_DB_NAME))?,
        })
    }

    // Creates a fresh TxOutStore on disk.
    pub fn create(env: &Environment) -> Result<(), Error> {
        let counts = env.create_db(Some(COUNTS_DB_NAME), DatabaseFlags::empty())?;
        env.create_db(Some(TX_OUT_INDEX_BY_HASH_DB_NAME), DatabaseFlags::empty())?;
        env.create_db(
            Some(TX_OUT_INDEX_BY_PUBLIC_KEY_DB_NAME),
            DatabaseFlags::empty(),
        )?;
        env.create_db(Some(TX_OUT_BY_INDEX_DB_NAME), DatabaseFlags::empty())?;
        env.create_db(Some(MERKLE_HASH_BY_RANGE_DB_NAME), DatabaseFlags::empty())?;

        let mut db_transaction = env.begin_rw_txn()?;

        db_transaction.put(
            counts,
            &NUM_TX_OUTS_KEY,
            &u64_to_key_bytes(0),
            WriteFlags::empty(),
        )?;

        db_transaction.commit()?;
        Ok(())
    }

    /// Appends a TxOut to the end of the collection.
    /// Returns the index of the TxOut in the ledger, or an Error.
    pub fn push(&self, tx_out: &TxOut, db_transaction: &mut RwTransaction) -> Result<u64, Error> {
        let num_tx_outs: u64 =
            key_bytes_to_u64(&db_transaction.get(self.counts, &NUM_TX_OUTS_KEY)?);
        let index: u64 = num_tx_outs;

        db_transaction.put(
            self.counts,
            &NUM_TX_OUTS_KEY,
            &u64_to_key_bytes(num_tx_outs + 1_u64),
            WriteFlags::empty(),
        )?;

        db_transaction.put(
            self.tx_out_index_by_hash,
            &tx_out.hash(),
            &u64_to_key_bytes(index),
            WriteFlags::NO_OVERWRITE,
        )?;

        db_transaction.put(
            self.tx_out_index_by_public_key,
            &tx_out.public_key,
            &u64_to_key_bytes(index),
            WriteFlags::NO_OVERWRITE,
        )?;

        let tx_out_bytes: Vec<u8> = encode(tx_out);

        db_transaction.put(
            self.tx_out_by_index,
            &u64_to_key_bytes(index),
            &tx_out_bytes,
            WriteFlags::NO_OVERWRITE,
        )?;

        self.update_merkle_hashes(index, db_transaction)?;

        Ok(index)
    }

    /// Get the total number of TxOuts in the ledger.
    pub fn num_tx_outs<T: Transaction>(&self, db_transaction: &T) -> Result<u64, Error> {
        Ok(key_bytes_to_u64(
            &db_transaction.get(self.counts, &NUM_TX_OUTS_KEY)?,
        ))
    }

    /// Returns the index of the TxOut with the given hash.
    pub fn get_tx_out_index_by_hash<T: Transaction>(
        &self,
        tx_out_hash: &Hash,
        db_transaction: &T,
    ) -> Result<u64, Error> {
        let index_bytes = db_transaction.get(self.tx_out_index_by_hash, tx_out_hash)?;
        Ok(key_bytes_to_u64(index_bytes))
    }

    /// Returns the index of the TxOut with the public key.
    pub fn get_tx_out_index_by_public_key<T: Transaction>(
        &self,
        tx_out_public_key: &CompressedRistrettoPublic,
        db_transaction: &T,
    ) -> Result<u64, Error> {
        let index_bytes = db_transaction.get(self.tx_out_index_by_public_key, tx_out_public_key)?;
        Ok(key_bytes_to_u64(index_bytes))
    }

    /// Gets a TxOut by its index in the ledger.
    pub fn get_tx_out_by_index<T: Transaction>(
        &self,
        index: u64,
        db_transaction: &T,
    ) -> Result<TxOut, Error> {
        let tx_out_bytes = db_transaction.get(self.tx_out_by_index, &u64_to_key_bytes(index))?;
        let tx_out: TxOut = decode(tx_out_bytes)?;
        Ok(tx_out)
    }

    /// Get the root hash of the Merkle Tree
    pub fn get_root_merkle_hash<T: Transaction>(
        &self,
        db_transaction: &T,
    ) -> Result<[u8; 32], Error> {
        let num_tx_outs = self.num_tx_outs(db_transaction)?;

        if num_tx_outs == 0 {
            return Ok(*NIL_HASH);
        }

        if let Some(num_leaves_full_tree) = num_tx_outs.checked_next_power_of_two() {
            let range = Range::new(0, num_leaves_full_tree - 1)?;
            let root_hash = self.get_merkle_hash(&range, db_transaction)?;
            Ok(root_hash)
        } else {
            // Overflow.
            Err(Error::CapacityExceeded)
        }
    }

    /// Writes the Merkle hash value for a node spanning the given range.
    fn write_merkle_hash(
        &self,
        range: &Range,
        hash: &[u8; 32],
        db_transaction: &mut RwTransaction,
    ) -> Result<(), Error> {
        db_transaction.put(
            self.merkle_hashes,
            &range_to_key_bytes(range),
            hash,
            WriteFlags::empty(),
        )?;
        Ok(())
    }

    /// Gets the Merkle hash value for a node spanning the given range.
    fn get_merkle_hash<T: Transaction>(
        &self,
        range: &Range,
        db_transaction: &T,
    ) -> Result<[u8; 32], Error> {
        let mut merkle_hash = [0u8; 32];

        let bytes = db_transaction.get(self.merkle_hashes, &range_to_key_bytes(range))?;
        if bytes.len() == merkle_hash.len() {
            merkle_hash.copy_from_slice(bytes);
            Ok(merkle_hash)
        } else {
            // Failed to decode the Merkle hash.
            Err(Error::Deserialization)
        }
    }

    /// Update Merkle Hashes to include the TxOut with the given index.
    ///
    /// # Arguments
    /// * `index` - The index of a TxOut that has not yet been included in the
    ///   Merkle Tree.
    /// * `db_transaction` - an LMDB transaction.
    ///
    /// Returns (the new Merkle root hash?) or an Error.
    fn update_merkle_hashes(
        &self,
        index: u64,
        db_transaction: &mut RwTransaction,
    ) -> Result<(), Error> {
        let num_tx_outs = self.num_tx_outs(db_transaction)?;
        if index >= num_tx_outs {
            return Err(Error::IndexOutOfBounds(index));
        }

        let ranges = containing_ranges(index, num_tx_outs)?;

        for (low, high) in ranges {
            if low == high {
                // Leaf.
                let tx_out = self.get_tx_out_by_index(index, db_transaction)?;
                let hash = hash_leaf(&tx_out);
                let range = Range::new(low, low)?;
                self.write_merkle_hash(&range, &hash, db_transaction)?;
            } else {
                // Internal node.
                let mid: u64 = (low + high) / 2;

                // Left child.
                let left_child_hash = {
                    let left_child_range = Range::new(low, mid)?;
                    self.get_merkle_hash(&left_child_range, db_transaction)?
                };

                // Right child.
                let right_child_hash = if mid + 1 >= num_tx_outs {
                    // The right subtree contains no TxOuts, so use the nil hash.
                    *NIL_HASH
                } else {
                    // The right subtree contains some TxOuts, so look up the child's hash.
                    let right_child_range = Range::new(mid + 1, high)?;
                    self.get_merkle_hash(&right_child_range, db_transaction)?
                };

                // This node.
                let hash = hash_nodes(&left_child_hash, &right_child_hash);
                let range = Range::new(low, high)?;
                self.write_merkle_hash(&range, &hash, db_transaction)?;
            }
        }

        Ok(())
    }

    /// Merkle proof-of-membership for TxOut with the given index.
    pub fn get_merkle_proof_of_membership<T: Transaction>(
        &self,
        index: u64,
        db_transaction: &T,
    ) -> Result<TxOutMembershipProof, Error> {
        let num_tx_outs = self.num_tx_outs(db_transaction)?;
        if index >= num_tx_outs {
            return Err(Error::IndexOutOfBounds(index));
        }

        // These pairs correspond to the ranges we will use for the proof elements
        // The first element always corresponds to the index
        let mut ranges_for_proof = vec![(index, index)];

        // Compute every internal range in the binary tree that contains
        // our node, in increasing order.
        // Then, break it in half, and talk the half that doesn't contain our index.
        // We have to skip the first one because that's our (index, index) element
        // which we already added.
        for (low, high) in containing_ranges(index, num_tx_outs)?.iter().skip(1) {
            let mid: u64 = (low + high) / 2;
            if index <= mid {
                // "other" child in the higher half-range.
                ranges_for_proof.push((mid + 1, *high));
            } else {
                // "other" child in the lower half-range.
                ranges_for_proof.push((*low, mid));
            }
        }

        // Scan over the ranges_for_proof and get hashes from the database corresponding
        // to these
        let mut elements = Vec::<TxOutMembershipElement>::default();
        for (low, high) in ranges_for_proof.iter().cloned() {
            let range = Range::new(low, high)?;
            let hash = if low >= num_tx_outs {
                // Supply the nil hash if the range contains no data.
                // Note: Nil hashes could probably be omitted as an optimization if validation
                // knows that it must supply them for any range where `low >= num_tx_outs`.
                *NIL_HASH
            } else {
                self.get_merkle_hash(&range, db_transaction)?
            };
            elements.push(TxOutMembershipElement {
                range,
                hash: hash.into(),
            });
        }

        let result = TxOutMembershipProof::new(index, num_tx_outs - 1, elements);
        debug_assert!(
            mc_transaction_core::membership_proofs::compute_implied_merkle_root(&result).is_ok(),
            "Freshly created membership proof was invalid"
        );
        Ok(result)
    }
}

/// Converts this Range to bytes for use as an LMDB key.
fn range_to_key_bytes(range: &Range) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&range.from.to_be_bytes());
    bytes[8..16].copy_from_slice(&range.to.to_be_bytes());
    bytes
}

/// The enclosing ranges of the given leaf index.
///
/// # Arguments
/// * `index` - A leaf index (zero-indexed).
/// * `num_leaves` - The number of leaves in the tree.
///
/// # Returns
/// Enclosing ranges for the leaf index in a full binary tree. The ranges are in
/// order from smallest to largest.
pub fn containing_ranges(index: u64, num_leaves: u64) -> Result<Vec<(u64, u64)>, Error> {
    if index >= num_leaves {
        return Err(Error::IndexOutOfBounds(index));
    }

    if let Some(num_leaves_full_tree) = num_leaves.checked_next_power_of_two() {
        // The depth of a full binary tree large enough to contain num_leaves.
        let depth: u32 = 64 - (num_leaves_full_tree as u64).leading_zeros() - 1;
        let ranges: Vec<(u64, u64)> = (0..=depth).map(|d| containing_range(index, d)).collect();
        Ok(ranges)
    } else {
        // Overflow.
        Err(Error::CapacityExceeded)
    }
}

/// In a binary tree whose leaves are labelled 0,1,..., this returns the leaves
/// in a subtree of a given depth that contains the given leaf index.
///
/// # Arguments
/// * `index` - A leaf index (zero-indexed).
/// * `depth` - The depth of the subtree containing the leaf. Denotes a range of
///   size 2^depth.
fn containing_range(index: u64, depth: u32) -> (u64, u64) {
    // The low end of the range is found by setting the lowest `depth` bits to
    // zeros, and the high end of the range is found by setting the lowest
    // `depth` bits to ones.

    // A mask containing 1s in the lowest `depth` bits.
    // For example, (1 << 4) - 1 = (10000) - 1 = 01111
    let mask: u64 = (1u64 << depth) - 1;

    // Set the lowest `depth` bits to 0.
    let low: u64 = index & !mask;

    // Set the lowest `depth` bits to 1.
    let high: u64 = index | mask;

    (low, high)
}

#[cfg(test)]
mod membership_proof_tests {
    use super::{
        tx_out_store_tests::{get_tx_outs, init_tx_out_store},
        *,
    };
    use lmdb::Transaction;
    use mc_transaction_core::tx::{TxOutMembershipElement, TxOutMembershipHash};

    #[test]
    // A valid proof-of-membership for the only TxOut in a set.
    fn test_is_valid_singleton() {
        let tx_outs = get_tx_outs(1);
        let tx_out = tx_outs.get(0).unwrap();
        let hash = hash_leaf(&tx_out);
        let elems = vec![TxOutMembershipElement {
            range: Range::new(0, 0).unwrap(),
            hash: hash.into(),
        }];
        let proof = TxOutMembershipProof::new(0, 0, elems);

        assert!(is_membership_proof_valid(&tx_out, &proof, &hash).unwrap());
    }

    #[test]
    // `is_valid` should return true for the proofs used by the `TxOutStore` unit
    // tests.
    fn test_is_valid_for_non_trivial_proof() {
        let (tx_out_store, env) = init_tx_out_store();
        let num_tx_outs: u32 = 6;
        let tx_outs = get_tx_outs(num_tx_outs);
        {
            // Populate the tx_out_store.
            let mut rw_transaction = env.begin_rw_txn().unwrap();
            for tx_out in &tx_outs {
                tx_out_store.push(tx_out, &mut rw_transaction).unwrap();
            }
            rw_transaction.commit().unwrap();
        }

        let db_transaction = env.begin_ro_txn().unwrap();
        let known_root_hash = tx_out_store.get_root_merkle_hash(&db_transaction).unwrap();

        let proof_of_five = tx_out_store
            .get_merkle_proof_of_membership(5, &db_transaction)
            .unwrap();

        assert!(is_membership_proof_valid(
            &tx_outs.get(5).unwrap(),
            &proof_of_five,
            &known_root_hash
        )
        .unwrap());

        let proof_of_three = tx_out_store
            .get_merkle_proof_of_membership(3, &db_transaction)
            .unwrap();

        assert!(is_membership_proof_valid(
            &tx_outs.get(3).unwrap(),
            &proof_of_three,
            &known_root_hash
        )
        .unwrap());
    }

    #[test]
    // `is_valid` should return an Error for a proof with the wrong `index`.
    fn test_is_valid_wrong_index() {
        let (tx_out_store, env) = init_tx_out_store();
        let num_tx_outs: u32 = 6;
        let tx_outs = get_tx_outs(num_tx_outs);
        {
            // Populate the tx_out_store.
            let mut rw_transaction = env.begin_rw_txn().unwrap();
            for tx_out in &tx_outs {
                tx_out_store.push(tx_out, &mut rw_transaction).unwrap();
            }
            rw_transaction.commit().unwrap();
        }

        let db_transaction = env.begin_ro_txn().unwrap();
        let known_root_hash = tx_out_store.get_root_merkle_hash(&db_transaction).unwrap();

        {
            let mut proof = tx_out_store
                .get_merkle_proof_of_membership(5, &db_transaction)
                .unwrap();

            // Tamper with proof after it is constructed. This bypasses checks in
            // TxOutMembershipProof::new().
            proof.index = 3;
            assert_eq!(
                Err(
                    mc_transaction_core::membership_proofs::MembershipProofError::MissingLeafHash(
                        3
                    )
                ),
                is_membership_proof_valid(&tx_outs.get(5).unwrap(), &proof, &known_root_hash)
            );
        }

        {
            let mut proof = tx_out_store
                .get_merkle_proof_of_membership(5, &db_transaction)
                .unwrap();

            // Tamper with proof after it is constructed. This bypasses checks in
            // TxOutMembershipProof::new().
            proof.index = 6;
            assert_eq!(
                Err(MembershipProofError::HighestIndexMismatch),
                is_membership_proof_valid(&tx_outs.get(5).unwrap(), &proof, &known_root_hash)
            );
        }
    }

    #[test]
    // `is_valid` should return false for a proof with an implausible
    // `highest_index` value.
    //
    // `highest_index` exists to indicate when the proof was created so that the
    // verifier can look up the correct root hash at that point in time. Other
    // than indicating what (historic) root hash compare against, it is not
    // required during validation. However, `is_valid` will reject a proof if
    // its `highest_index` value is obviously incompatible with the `index` or the
    // root range.
    fn test_is_valid_wrong_num_tx_outs() {
        // The number of ranges/hashes is a function of the number of tx_outs.
        // highest_index determines which hashes are the nil hash.

        let (tx_out_store, env) = init_tx_out_store();
        let num_tx_outs: u32 = 8;
        let tx_outs = get_tx_outs(num_tx_outs);
        {
            // Populate the tx_out_store.
            let mut rw_transaction = env.begin_rw_txn().unwrap();
            for tx_out in &tx_outs {
                tx_out_store.push(tx_out, &mut rw_transaction).unwrap();
            }
            rw_transaction.commit().unwrap();
        }

        let db_transaction = env.begin_ro_txn().unwrap();
        let known_root_hash = tx_out_store.get_root_merkle_hash(&db_transaction).unwrap();

        {
            let mut proof = tx_out_store
                .get_merkle_proof_of_membership(5, &db_transaction)
                .unwrap();

            // Tamper with proof after it is constructed. This bypasses checks in
            // TxOutMembershipProof::new(). `num_tx_outs` is less than the index
            // of the `TxOut` referenced by the proof.
            proof.highest_index = 2;
            assert_eq!(
                Err(MembershipProofError::HighestIndexMismatch),
                is_membership_proof_valid(&tx_outs.get(5).unwrap(), &proof, &known_root_hash)
            );
        }

        {
            let mut proof = tx_out_store
                .get_merkle_proof_of_membership(5, &db_transaction)
                .unwrap();

            // Tamper with proof after it is constructed. This bypasses checks in
            // TxOutMembershipProof::new(). `num_tx_outs` is too large, implying
            // that the proof would need to include hashes for the ranges [8,15]
            // and [0,15].
            proof.highest_index = 8;
            assert_eq!(
                Err(MembershipProofError::HighestIndexMismatch),
                is_membership_proof_valid(&tx_outs.get(5).unwrap(), &proof, &known_root_hash)
            );
        }
    }

    #[test]
    // `is_valid` should return false if any required hash is incorrect.
    fn test_is_valid_incorrect_required_hash() {
        let (tx_out_store, env) = init_tx_out_store();
        let num_tx_outs: u32 = 8;
        let tx_outs = get_tx_outs(num_tx_outs);
        {
            // Populate the tx_out_store.
            let mut rw_transaction = env.begin_rw_txn().unwrap();
            for tx_out in &tx_outs {
                tx_out_store.push(tx_out, &mut rw_transaction).unwrap();
            }
            rw_transaction.commit().unwrap();
        }

        let db_transaction = env.begin_ro_txn().unwrap();
        let known_root_hash = tx_out_store.get_root_merkle_hash(&db_transaction).unwrap();

        {
            let mut proof = tx_out_store
                .get_merkle_proof_of_membership(5, &db_transaction)
                .unwrap();

            // Tamper with proof after it is constructed. This bypasses checks in
            // TxOutMembershipProof::new().
            proof.elements[3] = TxOutMembershipElement {
                range: Range::new(6, 7).unwrap(),
                hash: TxOutMembershipHash::from([7u8; 32]),
            };
            assert_eq!(
                Err(MembershipProofError::UnexpectedMembershipElement(3)),
                is_membership_proof_valid(&tx_outs.get(5).unwrap(), &proof, &known_root_hash)
            );
        }
    }

    #[test]
    #[ignore]
    // `is_valid` should return false if the proof includes non-required hashes.
    fn test_is_valid_too_many_hashes() {
        // Including additional hashes doesn't necessarily make the proof incorrect, but
        // we still might want to reject it because its funky and larger than
        // necessary.
        unimplemented!()
    }

    #[test]
    // `is_valid` should return false if it does not include a required hash.
    fn test_is_valid_too_few_hashes() {
        let (tx_out_store, env) = init_tx_out_store();
        let num_tx_outs: u32 = 6;
        let tx_outs = get_tx_outs(num_tx_outs);
        {
            // Populate the tx_out_store.
            let mut rw_transaction = env.begin_rw_txn().unwrap();
            for tx_out in &tx_outs {
                tx_out_store.push(tx_out, &mut rw_transaction).unwrap();
            }
            rw_transaction.commit().unwrap();
        }

        let db_transaction = env.begin_ro_txn().unwrap();
        let known_root_hash = tx_out_store.get_root_merkle_hash(&db_transaction).unwrap();

        let proof = tx_out_store
            .get_merkle_proof_of_membership(5, &db_transaction)
            .unwrap();

        assert!(
            is_membership_proof_valid(&tx_outs.get(5).unwrap(), &proof, &known_root_hash).unwrap()
        );

        let mut proof1 = proof.clone();
        proof1.elements.remove(0);

        assert_eq!(
            Err(MembershipProofError::MissingLeafHash(5)),
            is_membership_proof_valid(&tx_outs.get(5).unwrap(), &proof1, &known_root_hash)
        );

        let mut proof2 = proof.clone();
        proof2.elements.remove(1);

        assert_eq!(
            Err(MembershipProofError::UnexpectedMembershipElement(2)),
            is_membership_proof_valid(&tx_outs.get(5).unwrap(), &proof2, &known_root_hash)
        );
    }

    // "Rederiving" should produce the same proof if the TxOut it references is the
    // last TxOut.
    #[test]
    fn test_derive_proof_at_index_trivial() {
        let (tx_out_store, env) = init_tx_out_store();
        let num_tx_outs: u32 = 6;
        let tx_outs = get_tx_outs(num_tx_outs);
        {
            // Populate the tx_out_store.
            let mut rw_transaction = env.begin_rw_txn().unwrap();
            for tx_out in &tx_outs {
                tx_out_store.push(tx_out, &mut rw_transaction).unwrap();
            }
            rw_transaction.commit().unwrap();
        }

        let db_transaction = env.begin_ro_txn().unwrap();
        let known_root_hash = tx_out_store.get_root_merkle_hash(&db_transaction).unwrap();

        // This is a proof of the last TxOut added to the store.
        let proof = tx_out_store
            .get_merkle_proof_of_membership(5, &db_transaction)
            .unwrap();

        let rederived_proof = derive_proof_at_index(&proof).unwrap();
        // The rederived proof must be a valid proof.
        assert!(is_membership_proof_valid(
            &tx_outs.get(5).unwrap(),
            &rederived_proof,
            &known_root_hash
        )
        .unwrap());

        // The rederived proof must equal the original proof.
        assert_eq!(proof, rederived_proof);
    }

    #[test]
    // A "rederived" proof for a TxOut should equal the proof-of-membership for that
    // TxOut when it was the most recently added member.
    fn test_derive_proof_at_index() {
        let (tx_out_store, env) = init_tx_out_store();
        let mut tx_outs = get_tx_outs(100);
        let more_tx_outs = tx_outs.split_off(17);

        {
            // Populate the tx_out_store with the first set of TxOuts.
            let mut rw_transaction = env.begin_rw_txn().unwrap();
            assert_eq!(tx_outs.len(), 17);
            for tx_out in &tx_outs {
                tx_out_store.push(tx_out, &mut rw_transaction).unwrap();
            }
            rw_transaction.commit().unwrap();
        }

        let db_transaction = env.begin_ro_txn().unwrap();
        let known_root_hash = tx_out_store.get_root_merkle_hash(&db_transaction).unwrap();

        // Proof-of-membership for TxOut 16, when it is the most recently-added member.
        let proof_of_16 = tx_out_store
            .get_merkle_proof_of_membership(16, &db_transaction)
            .unwrap();

        {
            // Populate the tx_out_store with the rest of the TxOuts.
            assert_eq!(more_tx_outs.len(), 83);
            let mut rw_transaction = env.begin_rw_txn().unwrap();
            for tx_out in &more_tx_outs {
                tx_out_store.push(tx_out, &mut rw_transaction).unwrap();
            }
            rw_transaction.commit().unwrap();
        }

        // Proof-of-membership for TxOut 16, when the store contains 100 TxOuts
        let proof_of_16_at_100 = tx_out_store
            .get_merkle_proof_of_membership(16, &db_transaction)
            .unwrap();

        let rederived_proof = derive_proof_at_index(&proof_of_16_at_100).unwrap();

        // The rederived proof must equal the original proof.
        assert_eq!(proof_of_16.index, rederived_proof.index);
        assert_eq!(proof_of_16.highest_index, rederived_proof.highest_index);
        assert_eq!(proof_of_16.elements, rederived_proof.elements);
        assert_eq!(proof_of_16, rederived_proof);

        // The rederived proof must be a valid proof.
        assert!(is_membership_proof_valid(
            &tx_outs.get(16).unwrap(),
            &rederived_proof,
            &known_root_hash
        )
        .unwrap());
    }
}

#[cfg(test)]
pub mod tx_out_store_tests {
    use super::{containing_range, containing_ranges, TxOutStore};
    use crate::Error;
    use lmdb::{Environment, RoTransaction, RwTransaction, Transaction};
    use mc_account_keys::AccountKey;
    use mc_common::Hash;
    use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPrivate, RistrettoPublic};
    use mc_transaction_core::{
        encrypted_fog_hint::{EncryptedFogHint, ENCRYPTED_FOG_HINT_LEN},
        membership_proofs::{hash_leaf, hash_nodes, Range, NIL_HASH},
        onetime_keys::*,
        tx::TxOut,
        Amount, MemoPayload,
    };
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};
    use std::path::Path;
    use tempdir::TempDir;

    fn get_env() -> Environment {
        let temp_dir = TempDir::new("test").unwrap();
        let path = temp_dir.path().to_str().unwrap().to_string();
        Environment::new()
            .set_max_dbs(10)
            .set_map_size(1_099_511_627_776)
            .open(Path::new(&path))
            .unwrap()
    }

    pub fn init_tx_out_store() -> (TxOutStore, Environment) {
        let env = get_env();
        TxOutStore::create(&env).unwrap();
        let tx_out_store: TxOutStore = TxOutStore::new(&env).unwrap();
        (tx_out_store, env)
    }

    /// Creates a number of TxOuts.
    ///
    /// All TxOuts are created as part of the same transaction, with the same
    /// recipient.
    pub fn get_tx_outs(num_tx_outs: u32) -> Vec<TxOut> {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut tx_outs: Vec<TxOut> = Vec::new();
        let recipient_account = AccountKey::random(&mut rng);
        let value: u64 = 100;

        for _i in 0..num_tx_outs {
            let tx_private_key = RistrettoPrivate::from_random(&mut rng);
            let target_key =
                create_onetime_public_key(&tx_private_key, &recipient_account.default_subaddress());
            let public_key = create_tx_public_key(
                &tx_private_key,
                recipient_account.default_subaddress().spend_public_key(),
            );
            let shared_secret: RistrettoPublic = create_shared_secret(&target_key, &tx_private_key);
            let amount = Amount::new(value, &shared_secret).unwrap();
            let tx_out = TxOut {
                amount,
                target_key: target_key.into(),
                public_key: public_key.into(),
                e_fog_hint: EncryptedFogHint::new(&[7u8; ENCRYPTED_FOG_HINT_LEN]),
                e_memo: MemoPayload::default()
                    .encrypt(&shared_secret)
                    .as_slice()
                    .to_vec(),
            };
            tx_outs.push(tx_out);
        }
        tx_outs
    }

    #[test]
    // An empty `TxOutStore` should return the correct values or Errors.
    fn test_initial_tx_out_store() {
        let (tx_out_store, env) = init_tx_out_store();
        let db_transaction: RoTransaction = env.begin_ro_txn().unwrap();
        assert_eq!(0, tx_out_store.num_tx_outs(&db_transaction).unwrap());
    }

    #[test]
    // `get_tx_out_index_by_hash` should return the correct index, or
    // Error::NotFound.
    fn test_get_tx_out_index_by_hash() {
        let (tx_out_store, env) = init_tx_out_store();
        let tx_outs = get_tx_outs(111);

        {
            // Push a number of TxOuts to the store.
            let mut rw_transaction: RwTransaction = env.begin_rw_txn().unwrap();
            for tx_out in &tx_outs {
                tx_out_store.push(tx_out, &mut rw_transaction).unwrap();
            }
            rw_transaction.commit().unwrap();
        }

        let ro_transaction: RoTransaction = env.begin_ro_txn().unwrap();
        assert_eq!(
            tx_outs.len() as u64,
            tx_out_store.num_tx_outs(&ro_transaction).unwrap()
        );

        // `get_tx_out_by_index_by_hash` should return the correct index when given a
        // recognized hash.
        for (index, tx_out) in tx_outs.iter().enumerate() {
            assert_eq!(
                index as u64,
                tx_out_store
                    .get_tx_out_index_by_hash(&tx_out.hash(), &ro_transaction)
                    .unwrap()
            );
        }

        // `get_tx_out_index_by_hash` should return `Error::NotFound` for an
        // unrecognized hash.
        let unrecognized_hash: Hash = [0u8; 32];
        match tx_out_store.get_tx_out_index_by_hash(&unrecognized_hash, &ro_transaction) {
            Ok(index) => panic!("Returned index {:?} for unrecognized hash.", index),
            Err(Error::NotFound) => {
                // This is expected.
            }
            Err(e) => panic!("Unexpected Error {:?}", e),
        }
    }

    #[test]
    // `get_tx_out_index_by_public_key` should return the correct index, or
    // Error::NotFound.
    fn test_get_tx_out_index_by_public_key() {
        let (tx_out_store, env) = init_tx_out_store();
        let tx_outs = get_tx_outs(111);

        {
            // Push a number of TxOuts to the store.
            let mut rw_transaction: RwTransaction = env.begin_rw_txn().unwrap();
            for tx_out in &tx_outs {
                tx_out_store.push(tx_out, &mut rw_transaction).unwrap();
            }
            rw_transaction.commit().unwrap();
        }

        let ro_transaction: RoTransaction = env.begin_ro_txn().unwrap();
        assert_eq!(
            tx_outs.len() as u64,
            tx_out_store.num_tx_outs(&ro_transaction).unwrap()
        );

        // `get_tx_out_by_index_by_hash` should return the correct index when given a
        // recognized hash.
        for (index, tx_out) in tx_outs.iter().enumerate() {
            assert_eq!(
                index as u64,
                tx_out_store
                    .get_tx_out_index_by_public_key(&tx_out.public_key, &ro_transaction)
                    .unwrap()
            );
        }

        // `get_tx_out_index_by_public_key` should return `Error::NotFound` for an
        // unrecognized hash.
        let unrecognized_public_key = CompressedRistrettoPublic::from(&[0; 32]);
        match tx_out_store.get_tx_out_index_by_public_key(&unrecognized_public_key, &ro_transaction)
        {
            Ok(index) => panic!("Returned index {:?} for unrecognized public key.", index),
            Err(Error::NotFound) => {
                // This is expected.
            }
            Err(e) => panic!("Unexpected Error {:?}", e),
        }
    }

    #[test]
    // `get_tx_out_by_index` should return the correct TxOut, or Error::NotFound.
    fn test_get_tx_out_by_index() {
        let (tx_out_store, env) = init_tx_out_store();
        let tx_outs = get_tx_outs(111);

        {
            // Push a number of TxOuts to the store.
            let mut rw_transaction: RwTransaction = env.begin_rw_txn().unwrap();
            for tx_out in &tx_outs {
                tx_out_store.push(tx_out, &mut rw_transaction).unwrap();
            }
            rw_transaction.commit().unwrap();
        }

        let ro_transaction: RoTransaction = env.begin_ro_txn().unwrap();
        assert_eq!(
            tx_outs.len() as u64,
            tx_out_store.num_tx_outs(&ro_transaction).unwrap()
        );

        // `get_tx_out_by_index` should return the correct TxOut if the index is in the
        // ledger.
        for (index, tx_out) in tx_outs.iter().enumerate() {
            assert_eq!(
                *tx_out,
                tx_out_store
                    .get_tx_out_by_index(index as u64, &ro_transaction)
                    .unwrap()
            );
        }

        // `get_tx_out_by_index` should return `Error::NotFound` for out-of-bound
        // indices
        for index in tx_outs.len()..tx_outs.len() + 100 {
            match tx_out_store.get_tx_out_by_index(index as u64, &ro_transaction) {
                Ok(_tx_out) => panic!("Returned a TxOut for a nonexistent index."),
                Err(Error::NotFound) => {
                    // This is expected.
                }
                Err(e) => panic!("Unexpected Error {:?}", e),
            }
        }
        ro_transaction.commit().unwrap();
    }

    #[test]
    // Pushing a duplicate TxOut should fail.
    fn test_push_duplicate_txout_fails() {
        let (tx_out_store, env) = init_tx_out_store();
        let tx_outs = get_tx_outs(10);

        {
            // Push a number of TxOuts to the store.
            let mut rw_transaction: RwTransaction = env.begin_rw_txn().unwrap();
            for tx_out in &tx_outs {
                tx_out_store.push(tx_out, &mut rw_transaction).unwrap();
            }
            rw_transaction.commit().unwrap();
        }

        let mut rw_transaction: RwTransaction = env.begin_rw_txn().unwrap();
        match tx_out_store.push(&tx_outs[0], &mut rw_transaction) {
            Err(Error::LmdbError(lmdb::Error::KeyExist)) => {}
            Ok(_) => panic!("unexpected success"),
            Err(_) => panic!("unexpected error"),
        };
    }

    #[test]
    // Pushing a TxOut with a duplicate public key should fail.
    fn test_push_duplicate_public_key_fails() {
        let (tx_out_store, env) = init_tx_out_store();
        let mut tx_outs = get_tx_outs(10);

        {
            // Push a number of TxOuts to the store.
            let mut rw_transaction: RwTransaction = env.begin_rw_txn().unwrap();
            for tx_out in &tx_outs[1..] {
                tx_out_store.push(tx_out, &mut rw_transaction).unwrap();
            }
            rw_transaction.commit().unwrap();
        }

        tx_outs[0].public_key = tx_outs[1].public_key;

        let mut rw_transaction: RwTransaction = env.begin_rw_txn().unwrap();
        match tx_out_store.push(&tx_outs[0], &mut rw_transaction) {
            Err(Error::LmdbError(lmdb::Error::KeyExist)) => {}
            Ok(_) => panic!("unexpected success"),
            Err(_) => panic!("unexpected error"),
        };
    }

    #[test]
    // `push` should add a TxOut to the correct index.
    fn test_push() {
        let (tx_out_store, env) = init_tx_out_store();
        let tx_outs = get_tx_outs(100);

        let mut rw_transaction: RwTransaction = env.begin_rw_txn().unwrap();
        assert_eq!(0, tx_out_store.num_tx_outs(&rw_transaction).unwrap());

        for (i, tx_out) in tx_outs.iter().enumerate() {
            let index = tx_out_store.push(tx_out, &mut rw_transaction).unwrap();
            assert_eq!(i as u64, index);
            let expected_count = (i + 1) as u64;
            assert_eq!(
                expected_count,
                tx_out_store.num_tx_outs(&rw_transaction).unwrap()
            );
            assert_eq!(
                *tx_out,
                tx_out_store
                    .get_tx_out_by_index(index, &rw_transaction)
                    .unwrap()
            );
        }
        rw_transaction.commit().unwrap();
    }

    #[test]
    fn test_containing_range() {
        // The subtree of size 2^0 containing leaf 5 contains leaves [5,5].
        assert_eq!((5, 5), containing_range(5, 0));

        // The subtree of size 2^1 containing leaf 5 contains leaves [4,5].
        assert_eq!((4, 5), containing_range(5, 1));

        // The subtree of size 2^2 containing leaf 5 contains leaves [4,7].
        assert_eq!((4, 7), containing_range(5, 2));

        // The subtree of size 2^3 containing leaf 5 contains leaves [0,7].
        assert_eq!((0, 7), containing_range(5, 3));

        // The subtree of size 2^4 containing leaf 5 contains leaves [0,15].
        assert_eq!((0, 15), containing_range(5, 4));

        // The returned ranges must have width 2^depth.
        for index in 0..17 {
            for depth in 0..13 {
                let (low, high) = containing_range(index, depth);
                let range_width: u64 = high - low + 1;
                assert_eq!(range_width, 2_u64.pow(depth));
            }
        }
    }

    #[test]
    fn test_containing_ranges() {
        let ranges: Vec<(u64, u64)> = containing_ranges(5, 13).unwrap();
        println!("{:?}", ranges);

        assert_eq!(5, ranges.len());

        assert!(ranges.contains(&(5, 5)));
        assert!(ranges.contains(&(4, 5)));
        assert!(ranges.contains(&(4, 7)));
        assert!(ranges.contains(&(0, 7)));
        assert!(ranges.contains(&(0, 15)));

        // Ranges must be in order from smallest to largest.
        assert_eq!((5, 5), *ranges.get(0).unwrap());
        assert_eq!((4, 5), *ranges.get(1).unwrap());
        assert_eq!((4, 7), *ranges.get(2).unwrap());
        assert_eq!((0, 7), *ranges.get(3).unwrap());
        assert_eq!((0, 15), *ranges.get(4).unwrap());
    }

    #[test]
    fn test_write_and_get_merkle_hash() {
        let (tx_out_store, env) = init_tx_out_store();
        let mut rw_transaction: RwTransaction = env.begin_rw_txn().unwrap();

        let range = Range::new(0, 7).unwrap();
        let hash = [7u8; 32];

        tx_out_store
            .write_merkle_hash(&range, &hash, &mut rw_transaction)
            .unwrap();

        let retrieved_hash = tx_out_store
            .get_merkle_hash(&range, &rw_transaction)
            .unwrap();
        assert_eq!(hash, retrieved_hash);
    }

    #[test]
    fn test_get_root_merkle_hash() {
        let (tx_out_store, env) = init_tx_out_store();
        let mut rw_transaction: RwTransaction = env.begin_rw_txn().unwrap();

        // Initially, the root hash should be the nil hash.
        let initial_hash = tx_out_store.get_root_merkle_hash(&rw_transaction).unwrap();
        assert_eq!(*NIL_HASH, initial_hash);

        let tx_outs = get_tx_outs(4);

        /*
                              root_hash = leaf_hash(tx_out_0)
                                           |
                                       tx_out_0
        */
        let tx_out_zero: &TxOut = tx_outs.get(0).unwrap();
        let leaf_hash_zero = hash_leaf(&tx_out_zero);
        {
            // The first root hash should be the leaf hash fn applied to the single TxOut.
            let _index = tx_out_store.push(tx_out_zero, &mut rw_transaction).unwrap();
            let root_hash = tx_out_store.get_root_merkle_hash(&rw_transaction).unwrap();
            let expected_root_hash = leaf_hash_zero;
            assert_eq!(expected_root_hash, root_hash);
        }

        /*
                             root_hash = internal_hash(left,right)
                                 ___________|  |__________
                                 |                       |
                         leaf_hash(tx_out_0)     leaf_hash(tx_out_1)
                                 |                       |
                             tx_out_0                tx_out_1
        */
        let tx_out_one: &TxOut = tx_outs.get(1).unwrap();
        let leaf_hash_one = hash_leaf(&tx_out_one);
        let root_hash_one = {
            // The second root hash should be the internal hash fn applied to the leaf hash
            // fn of tx_out_zero and tx_out_one.
            let _index = tx_out_store.push(tx_out_one, &mut rw_transaction).unwrap();
            let expected_root_hash = hash_nodes(&leaf_hash_zero, &leaf_hash_one);
            let root_hash = tx_out_store.get_root_merkle_hash(&rw_transaction).unwrap();
            assert_eq!(expected_root_hash, root_hash);
            root_hash
        };

        /*
                                  root_hash = internal_hash(left,right)
                                  __________________|   |_____________________
                                  |                                           |
                      internal_hash(left,right)                     internal_hash(left,right)
                     ___________|   |_________                    ___________|   |_________
                     |                       |                    |                       |
             leaf_hash(tx_out_0)     leaf_hash(tx_out_1)    leaf_hash(tx_out_2)         nil_hash
                     |                       |                    |
                 tx_out_0                tx_out_1              tx_out_2
        */
        let tx_out_two: &TxOut = tx_outs.get(2).unwrap();
        let leaf_hash_two = hash_leaf(&tx_out_two);
        {
            let _index = tx_out_store.push(tx_out_two, &mut rw_transaction).unwrap();
            let right = hash_nodes(&hash_leaf(&tx_out_two), &NIL_HASH);
            let expected_root_hash = hash_nodes(&root_hash_one, &right);
            let root_hash = tx_out_store.get_root_merkle_hash(&rw_transaction).unwrap();
            assert_eq!(expected_root_hash, root_hash);
        }

        /*
                              root_hash = internal_hash(left,right)
                              __________________|   |_____________________
                              |                                           |
                  internal_hash(left,right)                     internal_hash(left,right)
                 ___________|   |_________                    ___________|   |_________
                 |                       |                    |                       |
         leaf_hash(tx_out_0)     leaf_hash(tx_out_1)    leaf_hash(tx_out_2)    leaf_hash(tx_out_3)
                 |                       |                    |                       |
             tx_out_0                tx_out_1              tx_out_2               tx_out_3
        */
        let tx_out_three: &TxOut = tx_outs.get(3).unwrap();
        let leaf_hash_three = hash_leaf(&tx_out_three);
        {
            let _index = tx_out_store
                .push(tx_out_three, &mut rw_transaction)
                .unwrap();

            let right = hash_nodes(&leaf_hash_two, &leaf_hash_three);
            let expected_root_hash = hash_nodes(&root_hash_one, &right);
            let root_hash = tx_out_store.get_root_merkle_hash(&rw_transaction).unwrap();
            assert_eq!(expected_root_hash, root_hash);
        }
    }

    #[test]
    fn test_get_merkle_proof_of_membership_six_nodes() {
        let (tx_out_store, env) = init_tx_out_store();
        let num_tx_outs: u32 = 6;
        {
            // Populate the tx_out_store.
            let mut rw_transaction = env.begin_rw_txn().unwrap();
            for tx_out in &get_tx_outs(num_tx_outs) {
                tx_out_store.push(tx_out, &mut rw_transaction).unwrap();
            }
            rw_transaction.commit().unwrap();
        }

        let db_transaction = env.begin_ro_txn().unwrap();

        {
            // Get and verify a proof for TxOut 3.
            let proof = tx_out_store
                .get_merkle_proof_of_membership(3, &db_transaction)
                .unwrap();

            assert_eq!(3, proof.index);
            assert_eq!(5, proof.highest_index);

            /*
                The proof-of-membership for TxOut 3 should include the following ranges/hashes:

                               _______________|____________
                               |                          |
                         ______|________               H(4,7)
                        |              |
                     H(0,1)          __.____
                                    |      |
                                 H(2,2)  H(3,3)
                                   |       |
                   0       1       2      [3]      4       5       Nil       Nil

            */

            assert_eq!(4, proof.elements.len());

            let ranges: Vec<Range> = proof.elements.iter().map(|e| e.range).collect();

            assert_eq!(ranges[0], Range::new(3, 3).unwrap());
            assert_eq!(ranges[1], Range::new(2, 2).unwrap());
            assert_eq!(ranges[2], Range::new(0, 1).unwrap());
            assert_eq!(ranges[3], Range::new(4, 7).unwrap());

            for element in proof.elements {
                let expected_hash = tx_out_store
                    .get_merkle_hash(&element.range, &db_transaction)
                    .unwrap();
                assert_eq!(expected_hash, *element.hash.as_ref());
            }
        }

        {
            // Get and verify a proof for TxOut 5.
            let proof = tx_out_store
                .get_merkle_proof_of_membership(5, &db_transaction)
                .unwrap();

            assert_eq!(5, proof.index);
            assert_eq!(5, proof.highest_index);

            /*
                The proof-of-membership for TxOut 5 should include the following ranges/hashes:

                               _____________|_____________________
                               |                                  |
                            H(0,3)                       _________|________
                                                         |                |
                                                   ______|____          H(6,7) = H(Nil)
                                                   |         |
                                                 H(4,4)   H(5,5)
                                                   |        |
                   0       1       2       3       4       [5]       Nil       Nil

            */

            assert_eq!(4, proof.elements.len());

            let ranges: Vec<Range> = proof.elements.iter().map(|e| e.range).collect();

            println!("{:?}", ranges);
            assert_eq!(ranges[0], Range::new(5, 5).unwrap());
            assert_eq!(ranges[1], Range::new(4, 4).unwrap());
            assert_eq!(ranges[2], Range::new(6, 7).unwrap());
            assert_eq!(ranges[3], Range::new(0, 3).unwrap());

            for element in proof.elements {
                let expected_hash = if element.range.from >= num_tx_outs as u64 {
                    *NIL_HASH
                } else {
                    tx_out_store
                        .get_merkle_hash(&element.range, &db_transaction)
                        .unwrap()
                };

                assert_eq!(expected_hash, *element.hash.as_ref());
            }
        }
    }

    #[test]
    // `get_merkle_proof_of_membership` should return an error if the TxOut index is
    // out of bounds.
    fn test_get_merkle_proof_of_membership_errors() {
        let (tx_out_store, env) = init_tx_out_store();
        {
            // Populate the tx_out_store.
            let mut rw_transaction = env.begin_rw_txn().unwrap();
            for tx_out in &get_tx_outs(27) {
                tx_out_store.push(tx_out, &mut rw_transaction).unwrap();
            }
            rw_transaction.commit().unwrap();
        }

        let ro_transaction = env.begin_ro_txn().unwrap();
        match tx_out_store.get_merkle_proof_of_membership(43, &ro_transaction) {
            Ok(_proof) => panic!("43 is out of bounds"),
            Err(Error::IndexOutOfBounds(43)) => {
                // This is expected.
            }
            Err(e) => panic!("Unexpected error {:?}", e),
        }
    }
}
