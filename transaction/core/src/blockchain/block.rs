// Copyright (c) 2018-2020 MobileCoin Inc.

use crate::{
    tx::{TxOut, TxOutMembershipElement},
    BlockContents, BlockContentsHash, BlockID,
};
use alloc::vec::Vec;
use mc_crypto_digestible::{Digest, Digestible};
use prost::Message;
use serde::{Deserialize, Serialize};

/// Version identifier.
pub const BLOCK_VERSION: u32 = 0;

/// The index of a block in the blockchain.
pub type BlockIndex = u64;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Digestible, Message)]
/// A block of transactions in the blockchain.
pub struct Block {
    /// Block ID.
    #[prost(message, required, tag = "1")]
    pub id: BlockID,

    /// Block format version.
    #[prost(uint32, tag = "2")]
    pub version: u32,

    /// Id of the previous block.
    #[prost(message, required, tag = "3")]
    pub parent_id: BlockID,

    /// The index of this block in the blockchain.
    #[prost(uint64, tag = "4")]
    pub index: BlockIndex,

    /// The cumulative number of Txos in the blockchain, including this block.
    #[prost(uint64, tag = "5")]
    pub cumulative_txo_count: u64,

    /// Root hash of the membership proofs provided by the untrusted local system for validation.
    /// This captures the state of all TxOuts in the ledger that this block was validated against.
    #[prost(message, required, tag = "6")]
    pub root_element: TxOutMembershipElement,

    /// Hash of the block's contents.
    #[prost(message, required, tag = "7")]
    pub contents_hash: BlockContentsHash,
}

impl Block {
    /// Creates the origin block.
    ///
    /// # Arguments
    /// * `outputs` - Outputs "minted" by the origin block.
    pub fn new_origin_block(outputs: &[TxOut]) -> Self {
        let version = BLOCK_VERSION;
        let parent_id = BlockID::default();
        let index: BlockIndex = 0;
        let cumulative_txo_count = outputs.len() as u64;
        let root_element = TxOutMembershipElement::default();
        // The origin block does not contain any key images.
        let key_images = Vec::new();
        let block_contents = BlockContents::new(key_images, outputs.to_vec());
        let contents_hash = block_contents.hash();
        let id = compute_block_id(
            version,
            &parent_id,
            index,
            cumulative_txo_count,
            &root_element,
            &contents_hash,
        );
        Self {
            id,
            version,
            parent_id,
            index,
            cumulative_txo_count,
            root_element,
            contents_hash,
        }
    }

    /// Creates a new `Block`.
    ///
    /// # Arguments
    /// * `version` - The block format version.
    /// * `parent_id` - `BlockID` of previous block in the blockchain.
    /// * `index` - The index of this block in the blockchain.
    /// * `parent_cumulative_txo_count` - The cumulative txo count of the parent
    /// * `block_contents` - Contents of the block.
    pub fn new(
        version: u32,
        parent_id: &BlockID,
        index: BlockIndex,
        parent_cumulative_txo_count: u64,
        root_element: &TxOutMembershipElement,
        block_contents: &BlockContents,
    ) -> Self {
        let cumulative_txo_count =
            parent_cumulative_txo_count + block_contents.outputs.len() as u64;
        let contents_hash = block_contents.hash();
        let id = compute_block_id(
            version,
            &parent_id,
            index,
            cumulative_txo_count,
            &root_element,
            &contents_hash,
        );

        Self {
            id,
            version,
            parent_id: parent_id.clone(),
            index,
            cumulative_txo_count,
            root_element: root_element.clone(),
            contents_hash,
        }
    }

    /// Checks if the block's ID is valid for the block.
    /// A block constructed with `new` will be valid by virtue of `calling compute_block_id` on construction.
    /// However, when converting between different block representations, you need to validate that the contents
    /// of the converted structure is valid.
    pub fn is_block_id_valid(&self) -> bool {
        let expected_id = compute_block_id(
            self.version,
            &self.parent_id,
            self.index,
            self.cumulative_txo_count,
            &self.root_element,
            &self.contents_hash,
        );

        self.id == expected_id
    }
}

/// Computes the BlockID by hashing the contents of a block.
///
/// The identifier of a block is the result of hashing everything inside a block except the `id`
/// field.
pub fn compute_block_id<D: Digest>(
    version: u32,
    parent_id: &BlockID<D>,
    index: BlockIndex,
    cumulative_txo_count: u64,
    root_element: &TxOutMembershipElement,
    contents_hash: &BlockContentsHash<D>,
) -> BlockID<D> {
    let mut hasher = D::new();

    version.digest(&mut hasher);
    parent_id.digest(&mut hasher);
    index.digest(&mut hasher);
    cumulative_txo_count.digest(&mut hasher);
    root_element.digest(&mut hasher);
    contents_hash.digest(&mut hasher);

    BlockID(hasher.result())
}

#[cfg(test)]
mod block_tests {
    use crate::{
        account_keys::AccountKey,
        range::Range,
        tx::{TxOut, TxOutMembershipElement, TxOutMembershipHash},
        Block, BlockContents, BlockContentsHash, BlockID, BLOCK_VERSION,
    };
    use alloc::vec::Vec;
    use core::convert::TryFrom;
    use generic_array::GenericArray;
    use mc_crypto_keys::RistrettoPrivate;
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, CryptoRng, RngCore, SeedableRng};

    fn get_block<RNG: CryptoRng + RngCore>(rng: &mut RNG) -> Block {
        let bytes = [14u8; 32];
        let parent_id = BlockID::try_from(&bytes[..]).unwrap();

        let root_element = TxOutMembershipElement {
            range: Range::new(0, 15).unwrap(),
            hash: TxOutMembershipHash::from([0u8; 32]),
        };

        let recipient = AccountKey::random(rng);

        let outputs: Vec<TxOut> = (0..8)
            .map(|_i| {
                TxOut::new(
                    45,
                    &recipient.default_subaddress(),
                    &RistrettoPrivate::from_random(rng),
                    Default::default(),
                    rng,
                )
                .unwrap()
            })
            .collect();

        let key_images = Vec::new(); // TODO: include key images.
        let block_contents = BlockContents::new(key_images, outputs);
        Block::new(
            BLOCK_VERSION,
            &parent_id,
            3,
            400,
            &root_element,
            &block_contents,
        )
    }

    #[test]
    /// The block returned by `get_block` should have a valid BlockID.
    fn test_get_block_has_valid_id() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let block = get_block(&mut rng);
        assert!(block.is_block_id_valid());
    }

    #[test]
    /// The block ID should depend on the block version.
    fn test_block_id_includes_version() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut block = get_block(&mut rng);
        block.version += 1;
        assert!(!block.is_block_id_valid());
    }

    #[test]
    /// The block ID should depend on the parent_id.
    fn test_block_id_includes_parent_id() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut block = get_block(&mut rng);

        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let wrong_parent_id = BlockID(GenericArray::from_slice(&bytes).clone());

        block.parent_id = wrong_parent_id;
        assert!(!block.is_block_id_valid());
    }

    #[test]
    /// The block ID should depend on the block's index.
    fn test_block_id_includes_block_index() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut block = get_block(&mut rng);
        block.index += 1;
        assert!(!block.is_block_id_valid());
    }

    #[test]
    /// The block ID should depend on the root element.
    fn test_block_id_includes_root_element() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut block = get_block(&mut rng);

        let wrong_root_element = TxOutMembershipElement {
            range: Range::new(13, 17).unwrap(),
            hash: Default::default(),
        };
        block.root_element = wrong_root_element;
        assert!(!block.is_block_id_valid());
    }

    #[test]
    /// The block ID should depend on the content_hash.
    fn test_block_id_includes_content_hash() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut block = get_block(&mut rng);

        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let wrong_content_hash = BlockContentsHash(GenericArray::from_slice(&bytes).clone());

        block.contents_hash = wrong_content_hash;
        assert!(!block.is_block_id_valid());
    }

    #[test]
    #[ignore]
    // TODO: Block::new should return an error if `tx_hashes` contains duplicates.
    fn test_block_errors_on_duplicate_tx_hashes() {
        unimplemented!()
    }
}
