// Copyright (c) 2018-2020 MobileCoin Inc.

//! MobileNode Internal Enclave Implementation
//!
//! This crate implements the inside-the-enclave version of the EnclaveAPI,
//! which would traditionally be inside the enclave crate. This, combined
//! with a form of dependency injection, would provide the machines with
//! all the unit testing they would ever need. Fate, it seems, has a sense
//! of irony...

#![no_std]

extern crate alloc;

mod identity;

use alloc::{collections::BTreeSet, format, vec::Vec};
use core::convert::{TryFrom, TryInto};
use identity::Ed25519Identity;
use mc_attest_core::{
    IasNonce, IntelSealed, Quote, QuoteNonce, Report, TargetInfo, VerificationReport,
};
use mc_attest_enclave_api::{
    ClientAuthRequest, ClientAuthResponse, ClientSession, EnclaveMessage,
    Error as AttestEnclaveError, PeerAuthRequest, PeerAuthResponse, PeerSession,
};
use mc_attest_trusted::SealAlgo;
use mc_common::ResponderId;
use mc_consensus_enclave_api::{
    ConsensusEnclave, Error, LocallyEncryptedTx, Result, SealedBlockSigningKey, TxContext,
    WellFormedEncryptedTx, WellFormedTxContext,
};
use mc_crypto_ake_enclave::AkeEnclaveState;
use mc_crypto_digestible::Digestible;
use mc_crypto_keys::{Ed25519Pair, Ed25519Public, RistrettoPrivate, RistrettoPublic, X25519Public};
use mc_crypto_message_cipher::{AesMessageCipher, MessageCipher};
use mc_crypto_rand::McRng;
use mc_sgx_compat::sync::Mutex;
use mc_transaction_core::{
    account_keys::{PublicAddress, CURRENT_ACCOUNT_KEY_VERSION},
    amount::Amount,
    blake2b_256::Blake2b256,
    constants::{FEE_SPEND_PUBLIC_KEY, FEE_VIEW_PUBLIC_KEY},
    onetime_keys::{compute_shared_secret, compute_tx_pubkey, create_onetime_public_key},
    ring_signature::{KeyImage, Scalar},
    tx::{Tx, TxOut, TxOutMembershipProof},
    Block, BlockContents, BlockSignature, BLOCK_VERSION,
};
use prost::Message;
use rand_core::{CryptoRng, RngCore};

/// Domain seperator for unified fees transaction private key.
pub const FEES_OUTPUT_PRIVATE_KEY_DOMAIN_TAG: &str = "mc_fees_output_private_key";

/// A well-formed transaction.
#[derive(Clone, Eq, PartialEq, Message)]
pub struct WellFormedTx {
    /// The actual transaction.
    #[prost(message, required, tag = "1")]
    tx: Tx,
}

impl WellFormedTx {
    pub fn tx(&self) -> &Tx {
        &self.tx
    }
}

impl From<Tx> for WellFormedTx {
    fn from(tx: Tx) -> Self {
        Self { tx }
    }
}

/// A list of transactions. This is the contents of the encrypted payload returned by
/// `txs_for_peer` and fed into `peer_tx_propose`.
/// We need to define this since that's the only way to get Prost to serialize a
/// list of transactions. Prost is used for the sake of uniformity - all other data inside
/// `consensus_enclave_impl` is also serialized using it.
#[derive(Message)]
pub struct TxList {
    /// Transactions.
    #[prost(message, repeated, tag = "1")]
    pub txs: Vec<Tx>,
}

/// Internal state of the enclave, including AKE and attestation related as well as any business logic state
pub struct SgxConsensusEnclave {
    /// All AKE and attestation related state including responder ids, established channels for peers and clients,
    /// and any pending quotes or ias reports
    ake: AkeEnclaveState<Ed25519Identity>,

    /// Cipher used to encrypt locally-cached transactions.
    locally_encrypted_tx_cipher: Mutex<AesMessageCipher>,

    /// Cipher used to encrypt well-formed-encrypted transactions.
    well_formed_encrypted_tx_cipher: Mutex<AesMessageCipher>,
}

impl core::default::Default for SgxConsensusEnclave {
    fn default() -> Self {
        Self {
            ake: Default::default(),
            locally_encrypted_tx_cipher: Mutex::new(AesMessageCipher::new(&mut McRng::default())),
            well_formed_encrypted_tx_cipher: Mutex::new(AesMessageCipher::new(
                &mut McRng::default(),
            )),
        }
    }
}

impl SgxConsensusEnclave {
    fn encrypt_well_formed_tx<R: RngCore + CryptoRng>(
        &self,
        well_formed_tx: &WellFormedTx,
        rng: &mut R,
    ) -> Result<WellFormedEncryptedTx> {
        let well_formed_tx_bytes = mc_util_serial::encode(well_formed_tx);

        Ok(WellFormedEncryptedTx(
            self.well_formed_encrypted_tx_cipher
                .lock()?
                .encrypt_bytes(rng, well_formed_tx_bytes),
        ))
    }

    fn decrypt_well_formed_tx(&self, encrypted: &WellFormedEncryptedTx) -> Result<WellFormedTx> {
        let mut cipher = self.well_formed_encrypted_tx_cipher.lock()?;
        let plaintext = cipher.decrypt_bytes(encrypted.0.clone())?;
        let well_formed_tx: WellFormedTx = mc_util_serial::decode(&plaintext)?;
        Ok(well_formed_tx)
    }
}

impl ConsensusEnclave for SgxConsensusEnclave {
    fn enclave_init(
        &self,
        peer_self_id: &ResponderId,
        client_self_id: &ResponderId,
        sealed_key: &Option<SealedBlockSigningKey>,
    ) -> Result<SealedBlockSigningKey> {
        self.ake
            .init(peer_self_id.clone(), client_self_id.clone())?;

        // if we were passed a sealed key, unseal it and overwrite the private key

        match sealed_key {
            Some(sealed) => {
                let cached = IntelSealed::try_from(sealed.clone()).unwrap();
                let (key, _mac) = cached.unseal_raw()?;
                let mut lock = self.ake.get_identity().signing_keypair.lock().unwrap();
                *lock = Ed25519Pair::try_from(&key[..]).unwrap();
            }
            None => (),
        }

        // either way seal the private key and return it
        let lock = self.ake.get_identity().signing_keypair.lock().unwrap();
        let key = (*lock).private_key();
        let sealed = IntelSealed::seal_raw(key.as_ref(), &[]).unwrap();

        Ok(sealed.as_ref().to_vec())
    }

    fn get_identity(&self) -> Result<X25519Public> {
        Ok(self.ake.get_kex_identity())
    }

    fn get_signer(&self) -> Result<Ed25519Public> {
        Ok(self.ake.get_identity().get_public_key())
    }

    fn new_ereport(&self, qe_info: TargetInfo) -> Result<(Report, QuoteNonce)> {
        Ok(self.ake.new_ereport(qe_info)?)
    }

    fn verify_quote(&self, quote: Quote, qe_report: Report) -> Result<IasNonce> {
        Ok(self.ake.verify_quote(quote, qe_report)?)
    }

    fn verify_ias_report(&self, ias_report: VerificationReport) -> Result<()> {
        self.ake.verify_ias_report(ias_report)?;
        Ok(())
    }

    fn get_ias_report(&self) -> Result<VerificationReport> {
        Ok(self.ake.get_ias_report()?)
    }

    fn client_accept(&self, req: ClientAuthRequest) -> Result<(ClientAuthResponse, ClientSession)> {
        Ok(self.ake.client_accept(req)?)
    }

    fn client_close(&self, channel_id: ClientSession) -> Result<()> {
        Ok(self.ake.client_close(channel_id)?)
    }

    fn client_discard_message(&self, msg: EnclaveMessage<ClientSession>) -> Result<()> {
        let _ = self.ake.client_decrypt(msg)?;
        Ok(())
    }

    fn peer_init(&self, peer_id: &ResponderId) -> Result<PeerAuthRequest> {
        Ok(self.ake.peer_init(peer_id)?)
    }

    fn peer_accept(&self, req: PeerAuthRequest) -> Result<(PeerAuthResponse, PeerSession)> {
        Ok(self.ake.peer_accept(req)?)
    }

    fn peer_connect(&self, peer_id: &ResponderId, msg: PeerAuthResponse) -> Result<PeerSession> {
        Ok(self.ake.peer_connect(peer_id, msg)?)
    }

    fn peer_close(&self, session_id: &PeerSession) -> Result<()> {
        Ok(self.ake.peer_close(session_id)?)
    }

    fn client_tx_propose(&self, msg: EnclaveMessage<ClientSession>) -> Result<TxContext> {
        let tx_bytes = self.ake.client_decrypt(msg)?;

        // Try and deserialize.
        let tx: Tx = mc_util_serial::decode(&tx_bytes)?;

        // Convert to TxContext
        let maybe_locally_encrypted_tx: Result<LocallyEncryptedTx> = {
            let mut cipher = self.locally_encrypted_tx_cipher.lock()?;
            let mut rng = McRng::default();

            Ok(LocallyEncryptedTx(cipher.encrypt_bytes(&mut rng, tx_bytes)))
        };
        let locally_encrypted_tx = maybe_locally_encrypted_tx?;

        let tx_hash = tx.tx_hash();
        let highest_indices = tx.get_membership_proof_highest_indices();
        let key_images: Vec<KeyImage> = tx.key_images();
        let output_public_keys = tx.output_public_keys();

        Ok(TxContext {
            locally_encrypted_tx,
            tx_hash,
            highest_indices,
            key_images,
            output_public_keys,
        })
    }

    fn peer_tx_propose(&self, msg: EnclaveMessage<PeerSession>) -> Result<Vec<TxContext>> {
        // Try and decrypt the message.
        let data = self.ake.peer_decrypt(msg)?;

        // Try and deserialize.
        // Use prost
        let txs = mc_util_serial::decode::<TxList>(&data)?.txs;

        // Convert to TxContexts
        let mut rng = McRng::default();
        txs.into_iter()
            .map(|tx| {
                let tx_bytes = mc_util_serial::encode(&tx);
                let maybe_locally_encrypted_tx: Result<LocallyEncryptedTx> = {
                    let mut cipher = self.locally_encrypted_tx_cipher.lock()?;
                    Ok(LocallyEncryptedTx(cipher.encrypt_bytes(&mut rng, tx_bytes)))
                };
                let locally_encrypted_tx = maybe_locally_encrypted_tx?;
                let tx_hash = tx.tx_hash();
                let highest_indices = tx.get_membership_proof_highest_indices();
                let key_images: Vec<KeyImage> = tx.key_images();
                let output_public_keys = tx.output_public_keys();

                Ok(TxContext {
                    locally_encrypted_tx,
                    tx_hash,
                    highest_indices,
                    key_images,
                    output_public_keys,
                })
            })
            .collect()
    }

    fn tx_is_well_formed(
        &self,
        locally_encrypted_tx: LocallyEncryptedTx,
        block_index: u64,
        proofs: Vec<TxOutMembershipProof>,
    ) -> Result<(WellFormedEncryptedTx, WellFormedTxContext)> {
        // Enforce that all membership proofs provided by the untrusted system for transaction validation
        // came from the same ledger state. This can be checked by requiring all proofs to have the same root hash.
        let mut root_elements = BTreeSet::new();
        for proof in &proofs {
            let root_element = proof
                .elements
                .last() // The last element contains the root hash.
                .ok_or(Error::InvalidLocalMembershipProof)?;
            root_elements.insert(root_element);
        }
        if root_elements.len() != 1 {
            return Err(Error::InvalidLocalMembershipProof);
        }

        // Decrypt the locally encrypted transaction.
        let decrypted_bytes = self
            .locally_encrypted_tx_cipher
            .lock()?
            .decrypt_bytes(locally_encrypted_tx.0)?;
        let tx: Tx = mc_util_serial::decode(&decrypted_bytes)?;

        // Validate.
        let mut csprng = McRng::default();
        mc_transaction_core::validation::validate(&tx, block_index, &proofs, &mut csprng)?;

        // Convert into a well formed encrypted transaction + context.
        let well_formed_tx_context = WellFormedTxContext::from(&tx);
        let well_formed_tx = WellFormedTx::from(tx);
        let well_formed_encrypted_tx = self.encrypt_well_formed_tx(&well_formed_tx, &mut csprng)?;

        Ok((well_formed_encrypted_tx, well_formed_tx_context))
    }

    fn txs_for_peer(
        &self,
        encrypted_txs: &[WellFormedEncryptedTx],
        aad: &[u8],
        peer: &PeerSession,
    ) -> Result<EnclaveMessage<PeerSession>> {
        // Quick check that we are aware of this peer. While it might still go away after this
        // check, this allows us to quickly bail out and skip expensive work if the peer is
        // definitely not known to us. This also lets us figure whether we are referencing an
        // incoming or outgoing connection
        if !self.ake.is_peer_known(peer)? {
            return Err(Error::Attest(AttestEnclaveError::NotFound));
        }

        // Decrypt transactions
        let txs: Result<Vec<Tx>> =
            encrypted_txs
                .iter()
                .try_fold(Vec::new(), |mut init, encrypted_tx| {
                    let well_formed_tx = self.decrypt_well_formed_tx(encrypted_tx)?;
                    init.push(well_formed_tx.tx().clone());
                    Ok(init)
                });

        // Serialize this for the peer.
        let serialized_txs = mc_util_serial::encode(&TxList { txs: txs? });

        // Encrypt for the peer.
        Ok(self.ake.peer_encrypt(peer, aad, &serialized_txs)?)
    }

    fn form_block(
        &self,
        parent_block: &Block,
        encrypted_txs_with_proofs: &[(WellFormedEncryptedTx, Vec<TxOutMembershipProof>)],
    ) -> Result<(Block, BlockContents, BlockSignature)> {
        // This implicitly converts Vec<Result<(Tx Vec<TxOutMembershipProof>),_>> into Result<Vec<(Tx, Vec<TxOutMembershipProof>)>, _>,
        // and terminates the iteration when the first Error is encountered.
        let transactions_with_proofs = encrypted_txs_with_proofs
            .iter()
            .map(|(encrypted_tx, proofs)| {
                Ok((
                    self.decrypt_well_formed_tx(encrypted_tx)?.tx,
                    proofs.clone(),
                ))
            })
            .collect::<Result<Vec<(Tx, Vec<TxOutMembershipProof>)>>>()?;

        // root_elements contains the root hash of the Merkle tree of all TxOuts in the ledger
        // that were used to validate the tranasctions.
        let mut root_elements = Vec::new();
        let mut rng = McRng::default();

        for (tx, proofs) in transactions_with_proofs.iter() {
            mc_transaction_core::validation::validate(
                tx,
                parent_block.index + 1,
                proofs,
                &mut rng,
            )?;

            for proof in proofs {
                let root_element = proof
                    .elements
                    .last() // The last element contains the root hash.
                    .ok_or(Error::InvalidLocalMembershipProof)?;
                root_elements.push(root_element.clone());
            }
        }

        root_elements.sort();
        root_elements.dedup();

        if root_elements.len() != 1 {
            return Err(Error::InvalidLocalMembershipProof);
        }

        let transactions: Vec<Tx> = transactions_with_proofs
            .into_iter()
            .map(|(tx, _proofs)| tx)
            .collect();

        // Duplicate transactions are not allowed.
        // This check is redundant with the duplicate key image check, but might be
        // helpful for early debugging.
        let mut tx_hashes = BTreeSet::new();
        for tx in &transactions {
            let tx_hash = tx.tx_hash();
            if tx_hashes.contains(&tx_hash) {
                return Err(Error::FormBlock(format!(
                    "Duplicate transaction: {}",
                    tx_hash
                )));
            }
            tx_hashes.insert(tx_hash);
        }

        // Duplicate key images are not allowed.
        let mut used_key_images = BTreeSet::default();
        for tx in &transactions {
            for key_image in tx.key_images() {
                if used_key_images.contains(&key_image) {
                    return Err(Error::FormBlock(format!(
                        "Duplicate key image: {:?}",
                        key_image
                    )));
                }
                used_key_images.insert(key_image);
            }
        }

        // Duplicate output public keys are not allowed.
        let mut seen_output_public_keys = BTreeSet::default();
        for tx in &transactions {
            for public_key in tx.output_public_keys() {
                if seen_output_public_keys.contains(&public_key) {
                    return Err(Error::FormBlock(format!(
                        "Duplicate output public key: {:?}",
                        public_key
                    )));
                }
                seen_output_public_keys.insert(public_key);
            }
        }

        // Create an aggregate fee output.
        let fee_tx_private_key = {
            let hash_value: [u8; 32] = {
                let mut hasher = Blake2b256::new();
                FEES_OUTPUT_PRIVATE_KEY_DOMAIN_TAG.digest(&mut hasher);
                parent_block.id.digest(&mut hasher);
                transactions.digest(&mut hasher);
                hasher
                    .result()
                    .as_slice()
                    .try_into()
                    .expect("Wrong length.")
            };

            // This private key is generated from the hash of all transactions in this block.
            // This ensures that all nodes generate the same fee output transaction.
            RistrettoPrivate::from(Scalar::from_bytes_mod_order(hash_value))
        };

        let total_fee: u64 = transactions.iter().map(|tx| tx.prefix.fee).sum();
        let fee_output = mint_aggregate_fee(&fee_tx_private_key, total_fee)?;

        let mut outputs: Vec<TxOut> = Vec::new();
        let mut key_images: Vec<KeyImage> = Vec::new();
        for tx in &transactions {
            outputs.extend(tx.prefix.outputs.iter().cloned());
            key_images.extend(tx.key_images().iter().cloned());
        }
        outputs.push(fee_output);

        // Sort outputs and key images. This removes ordering information which could be used to
        // infer the per-transaction relationships among outputs and/or key images.
        outputs.sort_by(|a, b| a.public_key.cmp(&b.public_key));
        key_images.sort();
        let block_contents = BlockContents::new(key_images, outputs);

        // Form the block.
        let block = Block::new_with_parent(
            BLOCK_VERSION,
            &parent_block,
            &root_elements[0],
            &block_contents,
        );

        // Sign the block.
        let public_key = self.ake.get_identity().signing_keypair.lock()?;
        let signature = BlockSignature::from_block_and_keypair(&block, &public_key)?;

        Ok((block, block_contents, signature))
    }
}

/// Creates a single output belonging to the fee recipient account.
///
/// # Arguments:
/// * `tx_private_key` - Transaction key used to output the aggregate fee.
/// * `total_fee` - The sum of all fees in the block.
fn mint_aggregate_fee(tx_private_key: &RistrettoPrivate, total_fee: u64) -> Result<TxOut> {
    let fee_recipient = PublicAddress::new(
        &RistrettoPublic::try_from(&FEE_SPEND_PUBLIC_KEY).unwrap(),
        &RistrettoPublic::try_from(&FEE_VIEW_PUBLIC_KEY).unwrap(),
        CURRENT_ACCOUNT_KEY_VERSION,
    );

    // Create a single TxOut
    let fee_output: TxOut = {
        let target_key = create_onetime_public_key(&fee_recipient, tx_private_key).into();
        let public_key =
            compute_tx_pubkey(&tx_private_key, fee_recipient.spend_public_key()).into();
        let amount = {
            let shared_secret =
                compute_shared_secret(fee_recipient.view_public_key(), tx_private_key);
            // The fee view key is publicly known, so there is no need for a blinding.
            Amount::new(total_fee, &shared_secret)
                .map_err(|e| Error::FormBlock(format!("AmountError: {:?}", e)))?
        };

        TxOut {
            amount,
            target_key,
            public_key,
            e_account_hint: Default::default(),
        }
    };

    Ok(fee_output)
}

#[cfg(test)]
mod tests {

    use super::*;
    use mc_ledger_db::Ledger;
    use mc_transaction_core::{
        account_keys::AccountKey, constants::FEE_VIEW_PRIVATE_KEY,
        onetime_keys::view_key_matches_output, tx::TxOutMembershipHash,
        validation::TransactionValidationError, view_key::ViewKey,
    };
    use mc_transaction_core_test_utils::{create_ledger, create_transaction, initialize_ledger};
    use rand_core::SeedableRng;
    use rand_hc::Hc128Rng;

    #[test]
    fn test_tx_is_well_formed_works() {
        let enclave = SgxConsensusEnclave::default();
        let mut rng = Hc128Rng::from_seed([1u8; 32]);

        // Create a valid test transaction.
        let sender = AccountKey::random(&mut rng);
        let recipient = AccountKey::random(&mut rng);

        let mut ledger = create_ledger();
        let n_blocks = 3;
        initialize_ledger(&mut ledger, n_blocks, &sender, &mut rng);

        // Choose a TxOut to spend. Only the TxOut in the last block is unspent.
        let block_contents = ledger.get_block_contents(n_blocks - 1).unwrap();
        let tx_out = block_contents.outputs[0].clone();

        let tx = create_transaction(
            &mut ledger,
            &tx_out,
            &sender,
            &recipient.default_subaddress(),
            n_blocks + 1,
            &mut rng,
        );

        // Create a LocallyEncryptedTx that can be fed into `tx_is_well_formed`.
        let tx_bytes = mc_util_serial::encode(&tx);
        let locally_encrypted_tx = LocallyEncryptedTx(
            enclave
                .locally_encrypted_tx_cipher
                .lock()
                .unwrap()
                .encrypt_bytes(&mut rng, tx_bytes.clone()),
        );

        // Call `tx_is_well_formed`.
        let highest_indices = tx.get_membership_proof_highest_indices();
        let proofs = ledger
            .get_tx_out_proof_of_memberships(&highest_indices)
            .expect("failed getting proofs");
        let block_index = ledger.num_blocks().unwrap();
        let (well_formed_encrypted_tx, well_formed_tx_context) = enclave
            .tx_is_well_formed(locally_encrypted_tx.clone(), block_index, proofs)
            .unwrap();

        // Check that the context we got back is correct.
        assert_eq!(well_formed_tx_context.tx_hash(), &tx.tx_hash());
        assert_eq!(well_formed_tx_context.fee(), tx.prefix.fee);
        assert_eq!(
            well_formed_tx_context.tombstone_block(),
            tx.prefix.tombstone_block
        );
        assert_eq!(*well_formed_tx_context.key_images(), tx.key_images());

        // All three tx representations should be different.
        assert_ne!(tx_bytes, locally_encrypted_tx.0);
        assert_ne!(tx_bytes, well_formed_encrypted_tx.0);
        assert_ne!(locally_encrypted_tx.0, well_formed_encrypted_tx.0);

        // Check that we can go back from the encrypted tx to the original tx.
        let well_formed_tx = enclave
            .decrypt_well_formed_tx(&well_formed_encrypted_tx)
            .unwrap();
        assert_eq!(tx, well_formed_tx.tx);
    }

    #[test]
    fn test_tx_is_well_formed_works_errors_on_bad_inputs() {
        let enclave = SgxConsensusEnclave::default();
        let mut rng = Hc128Rng::from_seed([77u8; 32]);

        // Create a valid test transaction.
        let sender = AccountKey::random(&mut rng);
        let recipient = AccountKey::random(&mut rng);

        let mut ledger = create_ledger();
        let n_blocks = 3;
        initialize_ledger(&mut ledger, n_blocks, &sender, &mut rng);

        // Choose a TxOut to spend. Only the TxOut in the last block is unspent.
        let block_contents = ledger.get_block_contents(n_blocks - 1).unwrap();
        let tx_out = block_contents.outputs[0].clone();

        let tx = create_transaction(
            &mut ledger,
            &tx_out,
            &sender,
            &recipient.default_subaddress(),
            n_blocks + 1,
            &mut rng,
        );

        // Create a LocallyEncryptedTx that can be fed into `tx_is_well_formed`.
        let tx_bytes = mc_util_serial::encode(&tx);
        let locally_encrypted_tx = LocallyEncryptedTx(
            enclave
                .locally_encrypted_tx_cipher
                .lock()
                .unwrap()
                .encrypt_bytes(&mut rng, tx_bytes.clone()),
        );

        // Call `tx_is_well_formed` with a block index that puts us past the tombstone block.
        let highest_indices = tx.get_membership_proof_highest_indices();
        let proofs = ledger
            .get_tx_out_proof_of_memberships(&highest_indices)
            .expect("failed getting proofs");
        let block_index = ledger.num_blocks().unwrap();

        assert_eq!(
            enclave.tx_is_well_formed(
                locally_encrypted_tx.clone(),
                block_index + mc_transaction_core::constants::MAX_TOMBSTONE_BLOCKS,
                proofs.clone(),
            ),
            Err(Error::MalformedTx(
                TransactionValidationError::TombstoneBlockExceeded
            ))
        );

        // Call `tx_is_well_formed` with a wrong proof.
        let mut bad_proofs = proofs.clone();
        bad_proofs[0].elements[0].hash = TxOutMembershipHash::from([123; 32]);

        assert_eq!(
            enclave.tx_is_well_formed(locally_encrypted_tx.clone(), block_index, bad_proofs,),
            Err(Error::MalformedTx(
                TransactionValidationError::InvalidTxOutMembershipProof
            ))
        );

        // Corrupt the encrypted data.
        let mut corrputed_locally_encrypted_tx = locally_encrypted_tx.clone();
        corrputed_locally_encrypted_tx.0[0] = !corrputed_locally_encrypted_tx.0[0];

        assert_eq!(
            enclave.tx_is_well_formed(corrputed_locally_encrypted_tx, block_index, proofs),
            Err(Error::CacheCipher(
                mc_crypto_message_cipher::CipherError::MacFailure
            ))
        );
    }

    #[test]
    // tx_is_well_formed rejects inconsistent root elements.
    fn test_tx_is_well_form_rejects_inconsistent_root_elements() {
        // Construct TxOutMembershipProofs.
        let mut ledger = create_ledger();
        let n_blocks = 16;
        let mut rng = Hc128Rng::from_seed([77u8; 32]);
        let account_key = AccountKey::random(&mut rng);
        initialize_ledger(&mut ledger, n_blocks, &account_key, &mut rng);

        let n_proofs = 10;
        let indexes: Vec<u64> = (0..n_proofs as u64).into_iter().collect();
        let mut membership_proofs = ledger.get_tx_out_proof_of_memberships(&indexes).unwrap();
        // Modify one of the proofs to have a different root hash.
        let inconsistent_proof = &mut membership_proofs[7];
        let root_element = inconsistent_proof.elements.last_mut().unwrap();
        root_element.hash = TxOutMembershipHash::from([33u8; 32]);

        // The membership proofs supplied by the server are checked before this is decrypted and
        // validated, so it can just be contstructed from an empty vector of bytes.
        let locally_encrypted_tx = LocallyEncryptedTx(Vec::new());
        let block_index = 77;
        let result = SgxConsensusEnclave::default().tx_is_well_formed(
            locally_encrypted_tx,
            block_index,
            membership_proofs,
        );
        let expected = Err(Error::InvalidLocalMembershipProof);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_form_block_works() {
        let mut rng = Hc128Rng::from_seed([77u8; 32]);
        let enclave = SgxConsensusEnclave::default();

        // Create a valid test transaction.
        let sender = AccountKey::random(&mut rng);
        let recipient = AccountKey::random(&mut rng);

        let mut ledger = create_ledger();
        let n_blocks = 1;
        initialize_ledger(&mut ledger, n_blocks, &sender, &mut rng);

        // Spend outputs from the origin block.
        let origin_block_contents = ledger.get_block_contents(0).unwrap();

        let input_transactions: Vec<Tx> = (0..3)
            .map(|i| {
                let tx_out = origin_block_contents.outputs[i].clone();

                create_transaction(
                    &mut ledger,
                    &tx_out,
                    &sender,
                    &recipient.default_subaddress(),
                    n_blocks + 1,
                    &mut rng,
                )
            })
            .collect();

        let total_fee: u64 = input_transactions.iter().map(|tx| tx.prefix.fee).sum();

        // Create WellFormedEncryptedTxs + proofs
        let well_formed_encrypted_txs_with_proofs: Vec<_> = input_transactions
            .iter()
            .map(|tx| {
                let well_formed_tx = WellFormedTx::from(tx.clone());
                let encrypted_tx = enclave
                    .encrypt_well_formed_tx(&well_formed_tx, &mut rng)
                    .unwrap();

                let highest_indices = well_formed_tx.tx.get_membership_proof_highest_indices();
                let membership_proofs = ledger
                    .get_tx_out_proof_of_memberships(&highest_indices)
                    .expect("failed getting proof");
                (encrypted_tx, membership_proofs)
            })
            .collect();

        // Form block
        let parent_block = ledger.get_block(ledger.num_blocks().unwrap() - 1).unwrap();

        let (block, block_contents, signature) = enclave
            .form_block(&parent_block, &well_formed_encrypted_txs_with_proofs)
            .unwrap();

        // Verify signature.
        {
            assert_eq!(
                signature.signer(),
                &enclave
                    .ake
                    .get_identity()
                    .signing_keypair
                    .lock()
                    .unwrap()
                    .public_key()
            );

            assert!(signature.verify(&block).is_ok());
        }

        // `block_contents` should include the aggregate fee.

        let num_outputs: usize = input_transactions
            .iter()
            .map(|tx| tx.prefix.outputs.len())
            .sum();
        assert_eq!(num_outputs + 1, block_contents.outputs.len());

        // One of the outputs should be the aggregate fee.
        let view_secret_key = RistrettoPrivate::try_from(&FEE_VIEW_PRIVATE_KEY).unwrap();

        let fee_view_key = {
            let public_address = PublicAddress::new(
                &RistrettoPublic::try_from(&FEE_SPEND_PUBLIC_KEY).unwrap(),
                &RistrettoPublic::from(&view_secret_key),
                CURRENT_ACCOUNT_KEY_VERSION,
            );
            ViewKey::new(view_secret_key, *public_address.spend_public_key())
        };

        let fee_output = block_contents
            .outputs
            .iter()
            .find(|output| {
                let output_public_key = RistrettoPublic::try_from(&output.public_key).unwrap();
                let output_target_key = RistrettoPublic::try_from(&output.target_key).unwrap();
                view_key_matches_output(&fee_view_key, &output_target_key, &output_public_key)
            })
            .unwrap();

        let fee_output_public_key = RistrettoPublic::try_from(&fee_output.public_key).unwrap();

        // The value of the aggregate fee should equal the total value of fees in the input transaction.
        let shared_secret = compute_shared_secret(&fee_output_public_key, &view_secret_key);
        let (value, _blinding) = fee_output.amount.get_value(&shared_secret).unwrap();
        assert_eq!(value, total_fee);
    }

    #[test]
    /// form_block should return an error if the input transactions contain a double-spend.
    fn test_form_block_prevents_duplicate_spend() {
        let enclave = SgxConsensusEnclave::default();
        let mut rng = Hc128Rng::from_seed([77u8; 32]);

        // Initialize a ledger. `sender` is the owner of all outputs in the initial ledger.
        let sender = AccountKey::random(&mut rng);
        let mut ledger = create_ledger();
        let n_blocks = 3;
        initialize_ledger(&mut ledger, n_blocks, &sender, &mut rng);

        // Create a few transactions from `sender` to `recipient`.
        let num_transactions = 5;
        let recipient = AccountKey::random(&mut rng);

        // The first block contains RING_SIZE outputs.
        let block_zero_contents = ledger.get_block_contents(0).unwrap();

        let mut new_transactions = Vec::new();
        for i in 0..num_transactions {
            let tx_out = &block_zero_contents.outputs[i];

            let tx = create_transaction(
                &mut ledger,
                tx_out,
                &sender,
                &recipient.default_subaddress(),
                n_blocks + 1,
                &mut rng,
            );
            new_transactions.push(tx);
        }

        // Create another transaction that spends the zero^th output in block zero.
        let double_spend = {
            let tx_out = &block_zero_contents.outputs[0];

            create_transaction(
                &mut ledger,
                tx_out,
                &sender,
                &recipient.default_subaddress(),
                n_blocks + 1,
                &mut rng,
            )
        };
        new_transactions.push(double_spend);

        // Create WellFormedEncryptedTxs + proofs
        let well_formed_encrypted_txs_with_proofs: Vec<_> = new_transactions
            .iter()
            .map(|tx| {
                let well_formed_tx = WellFormedTx::from(tx.clone());
                let encrypted_tx = enclave
                    .encrypt_well_formed_tx(&well_formed_tx, &mut rng)
                    .unwrap();

                let highest_indices = well_formed_tx.tx.get_membership_proof_highest_indices();
                let membership_proofs = ledger
                    .get_tx_out_proof_of_memberships(&highest_indices)
                    .expect("failed getting proof");
                (encrypted_tx, membership_proofs)
            })
            .collect();

        // Form block
        let parent_block = ledger.get_block(ledger.num_blocks().unwrap() - 1).unwrap();

        let form_block_result =
            enclave.form_block(&parent_block, &well_formed_encrypted_txs_with_proofs);
        let expected_duplicate_key_image = new_transactions[0].key_images()[0];

        // Check
        let expected = Err(Error::FormBlock(format!(
            "Duplicate key image: {:?}",
            expected_duplicate_key_image
        )));

        assert_eq!(form_block_result, expected);
    }

    #[test]
    /// form_block should return an error if the input transactions contain a duplicate output
    /// public key.
    fn test_form_block_prevents_duplicate_output_public_key() {
        let enclave = SgxConsensusEnclave::default();
        let mut rng = Hc128Rng::from_seed([77u8; 32]);

        // Initialize a ledger. `sender` is the owner of all outputs in the initial ledger.
        let sender = AccountKey::random(&mut rng);
        let mut ledger = create_ledger();
        let n_blocks = 3;
        initialize_ledger(&mut ledger, n_blocks, &sender, &mut rng);

        // Create a few transactions from `sender` to `recipient`.
        let num_transactions = 5;
        let recipient = AccountKey::random(&mut rng);

        // The first block contains RING_SIZE outputs.
        let block_zero_contents = ledger.get_block_contents(0).unwrap();

        // Re-create the rng so that we could more easily generate a duplicate output public key.
        let mut rng = Hc128Rng::from_seed([77u8; 32]);

        let mut new_transactions = Vec::new();
        for i in 0..num_transactions - 1 {
            let tx_out = &block_zero_contents.outputs[i];

            let tx = create_transaction(
                &mut ledger,
                tx_out,
                &sender,
                &recipient.default_subaddress(),
                n_blocks + 1,
                &mut rng,
            );
            new_transactions.push(tx);
        }

        // Re-creating the rng here would result in a duplicate output public key.
        {
            let mut rng = Hc128Rng::from_seed([77u8; 32]);
            let tx_out = &block_zero_contents.outputs[num_transactions - 1];

            let tx = create_transaction(
                &mut ledger,
                tx_out,
                &sender,
                &recipient.default_subaddress(),
                n_blocks + 1,
                &mut rng,
            );
            new_transactions.push(tx);

            assert_eq!(
                new_transactions[0].prefix.outputs[0].public_key,
                new_transactions[num_transactions - 1].prefix.outputs[0].public_key,
            );
        }

        // Create WellFormedEncryptedTxs + proofs
        let well_formed_encrypted_txs_with_proofs: Vec<_> = new_transactions
            .iter()
            .map(|tx| {
                let well_formed_tx = WellFormedTx::from(tx.clone());
                let encrypted_tx = enclave
                    .encrypt_well_formed_tx(&well_formed_tx, &mut rng)
                    .unwrap();

                let highest_indices = well_formed_tx.tx.get_membership_proof_highest_indices();
                let membership_proofs = ledger
                    .get_tx_out_proof_of_memberships(&highest_indices)
                    .expect("failed getting proof");
                (encrypted_tx, membership_proofs)
            })
            .collect();

        // Form block
        let parent_block = ledger.get_block(ledger.num_blocks().unwrap() - 1).unwrap();

        let form_block_result =
            enclave.form_block(&parent_block, &well_formed_encrypted_txs_with_proofs);
        let expected_duplicate_output_public_key = new_transactions[0].output_public_keys()[0];

        // Check
        let expected = Err(Error::FormBlock(format!(
            "Duplicate output public key: {:?}",
            expected_duplicate_output_public_key
        )));

        assert_eq!(form_block_result, expected);
    }

    #[test]
    fn form_block_refuses_duplicate_root_elements() {
        let enclave = SgxConsensusEnclave::default();
        let mut rng = Hc128Rng::from_seed([77u8; 32]);

        // Initialize a ledger. `sender` is the owner of all outputs in the initial ledger.
        let sender = AccountKey::random(&mut rng);
        let mut ledger = create_ledger();
        let n_blocks = 3;
        initialize_ledger(&mut ledger, n_blocks, &sender, &mut rng);

        let mut ledger2 = create_ledger();
        initialize_ledger(&mut ledger2, n_blocks + 1, &sender, &mut rng);

        // Create a few transactions from `sender` to `recipient`.
        let num_transactions = 6;
        let recipient = AccountKey::random(&mut rng);

        // The first block contains a single transaction with RING_SIZE outputs.
        let block_zero_contents = ledger.get_block_contents(0).unwrap();

        let mut new_transactions = Vec::new();
        for i in 0..num_transactions {
            let tx_out = &block_zero_contents.outputs[i];

            let tx = create_transaction(
                &mut ledger,
                tx_out,
                &sender,
                &recipient.default_subaddress(),
                n_blocks + 1,
                &mut rng,
            );
            new_transactions.push(tx);
        }

        // Create WellFormedEncryptedTxs + proofs
        let well_formed_encrypted_txs_with_proofs: Vec<(
            WellFormedEncryptedTx,
            Vec<TxOutMembershipProof>,
        )> = new_transactions
            .iter()
            .enumerate()
            .map(|(tx_idx, tx)| {
                let well_formed_tx = WellFormedTx::from(tx.clone());
                let encrypted_tx = enclave
                    .encrypt_well_formed_tx(&well_formed_tx, &mut rng)
                    .unwrap();

                let highest_indices = well_formed_tx.tx.get_membership_proof_highest_indices();
                let membership_proofs = highest_indices
                    .iter()
                    .map(|index| {
                        // Make one of the proofs have a different root element by creating it from a different
                        if tx_idx == 0 {
                            ledger2
                                .get_tx_out_proof_of_memberships(&[*index])
                                .expect("failed getting proof")[0]
                                .clone()
                        } else {
                            ledger
                                .get_tx_out_proof_of_memberships(&[*index])
                                .expect("failed getting proof")[0]
                                .clone()
                        }
                    })
                    .collect();
                (encrypted_tx, membership_proofs)
            })
            .collect();

        // Form block
        let parent_block = ledger.get_block(ledger.num_blocks().unwrap() - 1).unwrap();

        let form_block_result =
            enclave.form_block(&parent_block, &well_formed_encrypted_txs_with_proofs);

        // Check
        let expected = Err(Error::MalformedTx(
            TransactionValidationError::InvalidTxOutMembershipProof,
        ));
        assert_eq!(form_block_result, expected);
    }
}
