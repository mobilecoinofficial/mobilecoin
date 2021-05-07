// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::{Error, Ledger};
use mc_account_keys::AccountKey;
use mc_common::{HashMap, HashSet};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPrivate};
use mc_transaction_core::{
    ring_signature::KeyImage,
    tx::{TxOut, TxOutMembershipElement, TxOutMembershipProof},
    Block, BlockContents, BlockData, BlockID, BlockSignature, MemoPayload, BLOCK_VERSION,
};
use mc_util_from_random::FromRandom;
use rand::{rngs::StdRng, SeedableRng};
use rand_core::RngCore;
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Default)]
pub struct MockLedgerInner {
    pub blocks_by_block_number: HashMap<u64, Block>,
    pub blocks_by_block_id: HashMap<BlockID, Block>,
    pub block_contents_by_block_number: HashMap<u64, BlockContents>,
    pub block_number_by_tx_out_index: HashMap<u64, u64>,
    pub tx_outs: HashSet<TxOut>,
    pub membership_proofs: HashMap<u64, TxOutMembershipProof>,
    pub key_images_by_block_number: HashMap<u64, Vec<KeyImage>>,
    pub key_images: HashMap<KeyImage, u64>,
}

#[derive(Clone)]
pub struct MockLedger {
    inner: Arc<Mutex<MockLedgerInner>>,
}

impl Default for MockLedger {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(MockLedgerInner::default())),
        }
    }
}

impl MockLedger {
    pub fn lock(&self) -> MutexGuard<MockLedgerInner> {
        self.inner.lock().expect("mutex poisoned")
    }

    /// Writes a given index of the blockchain.
    ///
    /// # Arguments
    /// * `block` - Block to write.
    /// * `block_contents` - Contents of the block.
    pub fn set_block(&mut self, block: &Block, block_contents: &BlockContents) {
        let mut inner = self.lock();

        inner
            .blocks_by_block_number
            .insert(block.index, block.clone());
        inner
            .blocks_by_block_id
            .insert(block.id.clone(), block.clone());

        inner
            .block_contents_by_block_number
            .insert(block.index, block_contents.clone());

        for tx_out in &block_contents.outputs {
            let tx_out_index = inner.tx_outs.len() as u64;
            inner.tx_outs.insert(tx_out.clone());
            inner
                .block_number_by_tx_out_index
                .insert(tx_out_index, block.index);
        }

        let key_images = block_contents.key_images.clone();
        inner.key_images = key_images.iter().map(|ki| (*ki, block.index)).collect();

        inner
            .key_images_by_block_number
            .insert(block.index, key_images);
    }
}

impl Ledger for MockLedger {
    fn append_block(
        &mut self,
        block: &Block,
        block_contents: &BlockContents,
        _signature: Option<BlockSignature>,
    ) -> Result<(), Error> {
        assert_eq!(block.index, self.num_blocks().unwrap());
        self.set_block(block, block_contents);
        Ok(())
    }

    fn num_blocks(&self) -> Result<u64, Error> {
        Ok(self.lock().blocks_by_block_number.len() as u64)
    }

    fn num_txos(&self) -> Result<u64, Error> {
        Ok(self.lock().tx_outs.len() as u64)
    }

    fn get_block(&self, block_number: u64) -> Result<Block, Error> {
        self.lock()
            .blocks_by_block_number
            .get(&block_number)
            .cloned()
            .ok_or(Error::NotFound)
    }

    fn get_block_contents(&self, block_number: u64) -> Result<BlockContents, Error> {
        self.lock()
            .block_contents_by_block_number
            .get(&block_number)
            .cloned()
            .ok_or(Error::NotFound)
    }

    fn get_block_signature(&self, _block_number: u64) -> Result<BlockSignature, Error> {
        Err(Error::NotFound)
    }

    fn get_block_data(&self, block_number: u64) -> Result<BlockData, Error> {
        let block = self.get_block(block_number)?;
        let contents = self.get_block_contents(block_number)?;
        let signature = self.get_block_signature(block_number).ok();
        Ok(BlockData::new(block, contents, signature))
    }

    /// Gets block index by a TxOut global index.
    fn get_block_index_by_tx_out_index(&self, tx_out_index: u64) -> Result<u64, Error> {
        self.lock()
            .block_number_by_tx_out_index
            .get(&tx_out_index)
            .cloned()
            .ok_or(Error::NotFound)
    }

    fn get_tx_out_index_by_hash(&self, _tx_out_hash: &[u8; 32]) -> Result<u64, Error> {
        // Unused for these tests.
        unimplemented!()
    }

    fn get_tx_out_by_index(&self, _: u64) -> Result<TxOut, Error> {
        // Unused for these tests.
        unimplemented!()
    }

    fn get_tx_out_index_by_public_key(
        &self,
        _tx_out_public_key: &CompressedRistrettoPublic,
    ) -> Result<u64, Error> {
        unimplemented!();
    }

    fn contains_tx_out_public_key(
        &self,
        _public_key: &CompressedRistrettoPublic,
    ) -> Result<bool, Error> {
        unimplemented!();
    }

    fn check_key_image(&self, key_image: &KeyImage) -> Result<Option<u64>, Error> {
        // Unused for these tests.
        Ok(self.lock().key_images.get(key_image).cloned())
    }

    fn get_key_images_by_block(&self, _block_number: u64) -> Result<Vec<KeyImage>, Error> {
        // Unused for these tests.
        unimplemented!()
    }

    fn get_tx_out_proof_of_memberships(
        &self,
        indexes: &[u64],
    ) -> Result<Vec<TxOutMembershipProof>, Error> {
        let inner = self.lock();
        indexes
            .iter()
            .map(|index| {
                inner
                    .membership_proofs
                    .get(index)
                    .cloned()
                    .ok_or(Error::NotFound)
            })
            .collect()
    }
}

#[allow(dead_code)]
/// Creates a MockLedger and populates it with blocks and transactions.
pub fn get_mock_ledger(n_blocks: usize) -> MockLedger {
    let mut mock_ledger = MockLedger::default();
    let blocks_and_transactions = get_test_ledger_blocks(n_blocks);
    for (block, block_contents) in blocks_and_transactions {
        mock_ledger.set_block(&block, &block_contents);
    }
    mock_ledger
}

#[allow(dead_code)]
/// Creates a sequence of `Block`s and the transactions corresponding to each
/// block.
pub fn get_test_ledger_blocks(n_blocks: usize) -> Vec<(Block, BlockContents)> {
    let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

    // The owner of all outputs in the mock ledger.
    let account_key = AccountKey::random(&mut rng);
    let value = 134_217_728; // 2^27

    let mut block_ids: Vec<BlockID> = Vec::with_capacity(n_blocks);
    let mut blocks_and_contents: Vec<(Block, BlockContents)> = Vec::with_capacity(n_blocks);

    for block_index in 0..n_blocks {
        if block_index == 0 {
            // Create the origin block.
            let tx_out = TxOut::new(
                value,
                &account_key.default_subaddress(),
                &RistrettoPrivate::from_random(&mut rng),
                Default::default(),
                MemoPayload::default(),
            )
            .unwrap();

            let outputs = vec![tx_out];
            let origin_block = Block::new_origin_block(&outputs);
            let block_contents = BlockContents::new(vec![], outputs);
            block_ids.push(origin_block.id.clone());
            blocks_and_contents.push((origin_block, block_contents));
        } else {
            // Create a normal block.
            let tx_out = TxOut::new(
                16,
                &account_key.default_subaddress(),
                &RistrettoPrivate::from_random(&mut rng),
                Default::default(),
                MemoPayload::default(),
            )
            .unwrap();

            let outputs = vec![tx_out];
            let key_images = vec![KeyImage::from(rng.next_u64())];
            let block_contents = BlockContents::new(key_images, outputs);

            let block = Block::new_with_parent(
                BLOCK_VERSION,
                &blocks_and_contents[block_index - 1].0,
                &TxOutMembershipElement::default(),
                &block_contents,
            );
            block_ids.push(block.id.clone());
            blocks_and_contents.push((block, block_contents));
        }
    }

    blocks_and_contents
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_transaction_core::compute_block_id;

    #[test]
    // `get_test_ledger_blocks` should return a valid blockchain of the specified
    // length.
    fn test_get_test_ledger_blocks() {
        let blocks_and_transactions = get_test_ledger_blocks(3);
        assert_eq!(
            blocks_and_transactions.len(),
            3,
            "{:#?}",
            blocks_and_transactions
        );

        let blocks: Vec<Block> = blocks_and_transactions
            .iter()
            .map(|(block, _transactions)| block.clone())
            .collect();

        // The first block must be the origin block.
        let origin_block: &Block = blocks.get(0).unwrap();
        assert_eq!(origin_block.parent_id.as_ref(), [0u8; 32]);
        assert_eq!(origin_block.index, 0);

        // Each block's parent_id must be the block_id of the previous block.
        let mut previous_block = origin_block;
        for block in blocks[1..].iter() {
            assert_eq!(block.parent_id, previous_block.id);
            previous_block = block;
        }

        // Each block's ID must agree with the block content hashes.
        for (block, _transactions) in blocks_and_transactions.iter() {
            let derived_block_id = compute_block_id(
                block.version,
                &block.parent_id,
                block.index,
                block.cumulative_txo_count,
                &block.root_element,
                &block.contents_hash,
            );
            assert_eq!(block.id, derived_block_id);
        }

        // Contents hashes maust match contents
        for (block, block_contents) in blocks_and_transactions {
            assert_eq!(block.contents_hash, block_contents.hash());
        }
    }
}
