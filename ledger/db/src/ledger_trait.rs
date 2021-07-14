// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::Error;
use mc_common::Hash;
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_transaction_core::{
    ring_signature::KeyImage,
    tx::{TxOut, TxOutMembershipProof},
    Block, BlockContents, BlockData, BlockIndex, BlockSignature,
};
use mockall::*;

#[automock]
pub trait Ledger: Send {
    /// Appends a block along with transactions.
    fn append_block(
        &mut self,
        block: &Block,
        block_contents: &BlockContents,
        signature: Option<BlockSignature>,
    ) -> Result<(), Error>;

    /// Get the total number of blocks in the ledger.
    fn num_blocks(&self) -> Result<u64, Error>;

    /// Gets a Block by its index in the blockchain.
    fn get_block(&self, block_number: BlockIndex) -> Result<Block, Error>;

    /// Get the contents of a block.
    fn get_block_contents(&self, block_number: BlockIndex) -> Result<BlockContents, Error>;

    /// Gets a block signature by its index in the blockchain.
    fn get_block_signature(&self, block_number: BlockIndex) -> Result<BlockSignature, Error>;

    /// Gets a block and all of its associated data by its index in the
    /// blockchain.
    fn get_block_data(&self, block_number: BlockIndex) -> Result<BlockData, Error>;

    /// Gets block index by a TxOut global index.
    fn get_block_index_by_tx_out_index(&self, tx_out_index: u64) -> Result<BlockIndex, Error>;

    /// Get the total number of TxOuts in the ledger.
    fn num_txos(&self) -> Result<u64, Error>;

    /// Returns the index of the TxOut with the given hash.
    fn get_tx_out_index_by_hash(&self, tx_out_hash: &Hash) -> Result<u64, Error>;

    /// Returns the index of the TxOut with the given public key.
    fn get_tx_out_index_by_public_key(
        &self,
        tx_out_public_key: &CompressedRistrettoPublic,
    ) -> Result<u64, Error>;

    /// Gets a TxOut by its index in the ledger.
    fn get_tx_out_by_index(&self, index: u64) -> Result<TxOut, Error>;

    /// Gets a proof of memberships for TxOuts with indexes `indexes`.
    fn get_tx_out_proof_of_memberships(
        &self,
        indexes: &[u64],
    ) -> Result<Vec<TxOutMembershipProof>, Error>;

    /// Gets tx outs and proof of memberships for TxOuts with indexes `indices`.
    /// Returns None for those indices which are out-of-bounds.
    fn get_tx_outs_and_proofs_of_membership(
        &self,
        indices: &[u64],
    ) -> Result<Vec<Option<(TxOut, TxOutMembershipProof)>>, Error>;

    /// Returns true if the Ledger contains the given TxOut public key.
    fn contains_tx_out_public_key(
        &self,
        public_key: &CompressedRistrettoPublic,
    ) -> Result<bool, Error>;

    /// Returns true if the Ledger contains the given key image.
    fn contains_key_image(&self, key_image: &KeyImage) -> Result<bool, Error> {
        self.check_key_image(key_image).map(|x| x.is_some())
    }

    /// Checks if the ledger contains a given key image.
    /// If so, returns the index of the block in which it entered the ledger.
    /// Ok(None) is returned when the key image is not in the ledger.
    fn check_key_image(&self, key_image: &KeyImage) -> Result<Option<BlockIndex>, Error>;

    /// Gets the key images used by transactions in a single block.
    fn get_key_images_by_block(&self, block_number: BlockIndex) -> Result<Vec<KeyImage>, Error>;
}
