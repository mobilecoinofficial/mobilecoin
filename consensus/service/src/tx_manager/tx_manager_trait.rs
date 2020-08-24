// Copyright (c) 2018-2020 MobileCoin Inc.

use crate::tx_manager::TxManagerResult;
use mc_attest_enclave_api::{EnclaveMessage, PeerSession};
use mc_common::HashSet;
use mc_consensus_enclave::{TxContext, WellFormedEncryptedTx};
use mc_transaction_core::{tx::TxHash, Block, BlockContents, BlockSignature};

pub trait TxManagerTrait {
    /// Insert a transaction into the cache. The transaction must be well-formed.
    fn insert(&self, tx_context: TxContext) -> TxManagerResult<TxHash>;

    /// Remove expired transactions from the cache and return their hashes.
    ///
    /// # Arguments
    /// * `block_index` - Current block index.
    fn remove_expired(&self, block_index: u64) -> HashSet<TxHash>;

    /// Returns elements of `tx_hashes` that are not inside the cache.
    fn missing_hashes<T>(&self, tx_hashes: &T) -> Vec<TxHash>
    where
        for<'a> &'a T: IntoIterator<Item = &'a TxHash>;

    /// Number of cached entries.
    fn num_entries(&self) -> usize;

    /// Validate the transaction corresponding to the given hash against the current ledger.
    fn validate(&self, tx_hash: &TxHash) -> TxManagerResult<()>;

    /// Combines the transactions that correspond to the given hashes.
    fn combine(&self, tx_hashes: &[TxHash]) -> TxManagerResult<Vec<TxHash>>;

    /// Forms a Block containing the transactions that correspond to the given hashes.
    fn tx_hashes_to_block(
        &self,
        tx_hashes: &[TxHash],
        parent_block: &Block,
    ) -> TxManagerResult<(Block, BlockContents, BlockSignature)>;

    /// Creates a message containing a set of transactions that are encrypted for a peer.
    ///
    /// # Arguments
    /// * `tx_hashes` - transaction hashes.
    /// * `aad` - Additional authenticated data.
    /// * `peer` - Recipient of the encrypted message.
    fn encrypt_for_peer(
        &self,
        tx_hashes: &[TxHash],
        aad: &[u8],
        peer: &PeerSession,
    ) -> TxManagerResult<EnclaveMessage<PeerSession>>;

    /// Get the encrypted transaction corresponding to the given hash.
    fn get_encrypted_tx(&self, tx_hash: &TxHash) -> Option<WellFormedEncryptedTx>;
}
