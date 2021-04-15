// Copyright (c) 2018-2021 The MobileCoin Foundation

use core::{cell::RefCell, convert::TryFrom};
use lazy_static::lazy_static;
use mc_account_keys::{AccountKey, PublicAddress};
use mc_attest_core::{MrSignerVerifier, Verifier, DEBUG_ENCLAVE};
use mc_common::{
    logger::{create_app_logger, log, o, Logger},
    HashMap, HashSet, ResponderId,
};
use mc_connection::{
    HardcodedCredentialsProvider, RetryError, RetryableUserTxConnection, SyncConnection,
    ThickClient,
};
use mc_consensus_scp::QuorumSet;
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPublic};
use mc_fog_report_validation::FogResolver;
use mc_ledger_db::{Ledger, LedgerDB};
use mc_ledger_sync::{LedgerSyncServiceThread, PollingNetworkState, ReqwestTransactionsFetcher};
use mc_slam::SlamConfig;
use mc_transaction_core::{
    constants::MINIMUM_FEE,
    get_tx_out_shared_secret,
    onetime_keys::{recover_onetime_private_key, view_key_matches_output},
    ring_signature::KeyImage,
    tx::{Tx, TxOut, TxOutMembershipProof},
};
use mc_transaction_std::{InputCredentials, TransactionBuilder};
use mc_util_uri::ConnectionUri;
use rand::{seq::SliceRandom, thread_rng, Rng};
use std::{
    iter::empty,
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, RwLock,
    },
    thread,
    time::Duration,
};
use structopt::StructOpt;
use tempdir::TempDir;

thread_local! {
    pub static CONNS: RefCell<Option<Vec<SyncConnection<ThickClient<HardcodedCredentialsProvider>>>>> = RefCell::new(None);
}
fn set_conns(config: &SlamConfig, logger: &Logger) {
    let conns = config.get_connections(logger).unwrap();
    CONNS.with(|c| *c.borrow_mut() = Some(conns));
}
fn get_conns(
    config: &SlamConfig,
    logger: &Logger,
) -> Vec<SyncConnection<ThickClient<HardcodedCredentialsProvider>>> {
    let conns = CONNS.with(|c| c.borrow().clone());
    match conns {
        Some(c) => c,
        None => {
            set_conns(config, logger);
            CONNS.with(|c| c.borrow().clone()).unwrap()
        }
    }
}

lazy_static! {
    pub static ref BLOCK_HEIGHT: AtomicU64 = AtomicU64::default();

    // A map of tx pub keys to account index. This is used in conjunction with ledger syncing to
    // identify which new txs belong to which accounts without having to do any slow crypto.
    pub static ref TX_PUB_KEY_TO_ACCOUNT_KEY: Mutex<HashMap::<CompressedRistrettoPublic, AccountKey>> = Mutex::new(HashMap::default());

}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpendableTxOut {
    pub tx_out: TxOut,
    pub amount: u64,
    from_account_key: AccountKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmitTxMessage {
    pub utxos: Vec<SpendableTxOut>,
    //pub account_index: usize,
    //pub from_account: AccountKey,
    pub to_address: PublicAddress,
    //pub ring_size: usize,
}

fn main() {
    mc_common::setup_panic_handler();
    let (logger, _global_logger_guard) = create_app_logger(o!());

    let config = SlamConfig::from_args();

    // Read account keys from disk
    let accounts: Vec<AccountKey> = mc_util_keyfile::keygen::read_default_mnemonics(
        config.sample_data_dir.join(Path::new("keys")),
    )
    .expect("Could not read default mnemonic keys");

    // Open the ledger_db to process the bootstrapped ledger
    log::info!(logger, "Loading ledger");

    let ledger_dir = TempDir::new("slam_ledger").unwrap();
    std::fs::copy(
        config.sample_data_dir.join("ledger").join("data.mdb"),
        ledger_dir.path().join("data.mdb"),
    )
    .expect("failed copying ledger");

    let ledger_db =
        LedgerDB::open(ledger_dir.path().to_path_buf()).expect("Could not open ledger_db");

    BLOCK_HEIGHT.store(ledger_db.num_blocks().unwrap(), Ordering::SeqCst);

    // The number of blocks we've processed so far.
    let mut block_count = 0;

    // Load the bootstrapped transactions.
    log::info!(logger, "Processing transactions");
    let mut num_transactions_per_account = config.num_transactions_per_account;

    let (spendable_txouts_sender, spendable_txouts_receiver) =
        crossbeam_channel::unbounded::<SpendableTxOut>();

    while let Ok(block_contents) = ledger_db.get_block_contents(block_count) {
        let transactions = block_contents.outputs;
        // Only get num_transactions per account for the first block, then assume
        // future blocks that were bootstrapped are similar
        if num_transactions_per_account == 0 {
            num_transactions_per_account =
                get_num_transactions_per_account(&accounts[0], &transactions, &logger);
        }
        log::info!(
            logger,
            "Loaded {:?} transactions from block {:?}",
            transactions.len(),
            block_count
        );

        // NOTE: This will start at the same offset per block - we may want just the
        // first offset
        let mut account_index = config.account_offset;
        let mut account = &accounts[account_index];
        let mut num_per_account_processed = 0;
        for (index, tx_out) in transactions.iter().enumerate().skip(config.start_offset) {
            // Makes strong assumption about bootstrapped ledger layout
            if num_per_account_processed >= num_transactions_per_account {
                log::trace!(
                    logger,
                    "Moving on to next account {:?} at tx index {:?}",
                    account_index + 1,
                    index
                );
                account_index += 1;
                if account_index >= accounts.len() {
                    log::info!(logger, "Finished processing accounts. If no transactions sent, you may need to re-bootstrap.");
                    break;
                }
                account = &accounts[account_index];
                num_per_account_processed = 0;
            }

            let public_key = RistrettoPublic::try_from(&tx_out.public_key).unwrap();
            let shared_secret = get_tx_out_shared_secret(account.view_private_key(), &public_key);
            let (input_amount, _blinding_factor) = tx_out
                .amount
                .get_value(&shared_secret)
                .expect("Malformed amount");

            log::trace!(
                logger,
                "(account = {:?}) and (tx_index {:?}) = {}",
                account_index,
                index,
                input_amount,
            );

            // Push to queue
            spendable_txouts_sender
                .send(SpendableTxOut {
                    tx_out: tx_out.clone(),
                    amount: input_amount,
                    from_account_key: account.clone(),
                })
                .expect("failed sending to spendable_txouts_sender");
            num_per_account_processed += 1;
        }
        block_count += 1;
    }

    // Spawn worker threads
    for i in 0..config.max_threads {
        let spendable_txouts_receiver2 = spendable_txouts_receiver.clone();
        let config2 = config.clone();
        let ledger_db2 = ledger_db.clone();
        let mut accounts2 = accounts.clone();
        let logger2 = logger.new(o!("num" => i));

        accounts2.shuffle(&mut thread_rng());

        thread::Builder::new()
            .name(format!("worker{}", i))
            .spawn(move || {
                worker_thread_entry(
                    spendable_txouts_receiver2,
                    config2,
                    ledger_db2,
                    accounts2,
                    logger2,
                )
            })
            .expect("failed starting thread");
    }

    if config.with_ledger_sync {
        if config.tx_source_urls.is_empty() {
            panic!("--with-ledger-sync requires at least one --tx-source-url");
        }

        // Set up ledger syncing
        log::info!(logger, "Starting ledger syncing...");
        let peer_manager = {
            let mut mr_signer_verifier =
                MrSignerVerifier::from(mc_consensus_enclave_measurement::sigstruct());
            mr_signer_verifier.allow_hardening_advisory("INTEL-SA-00334");

            let mut verifier = Verifier::default();
            verifier.mr_signer(mr_signer_verifier).debug(DEBUG_ENCLAVE);

            config.peers_config.create_peer_manager(verifier, &logger)
        };

        let node_ids = config
            .peers_config
            .peers
            .clone()
            .unwrap()
            .iter()
            .map(|p| {
                p.responder_id().unwrap_or_else(|_| {
                    panic!("Could not get responder_id from uri {}", p.to_string())
                })
            })
            .collect::<Vec<ResponderId>>();
        let quorum_set = QuorumSet::new_with_node_ids(node_ids.len() as u32, node_ids);

        let network_state = Arc::new(RwLock::new(PollingNetworkState::new(
            quorum_set,
            peer_manager.clone(),
            logger.clone(),
        )));

        let transactions_fetcher =
            ReqwestTransactionsFetcher::new(config.tx_source_urls, logger.clone())
                .expect("Failed creating ReqwestTransactionsFetcher");

        let mut next_block_idx = ledger_db.num_blocks().unwrap();

        let _ledger_sync_service_thread = LedgerSyncServiceThread::new(
            ledger_db.clone(),
            peer_manager,
            network_state,
            transactions_fetcher,
            Duration::from_secs(1),
            logger.clone(),
        );

        loop {
            let block_contents = match ledger_db.get_block_contents(next_block_idx) {
                Ok(contents) => contents,
                Err(_) => {
                    log::info!(logger, "Waiting on block #{}...", next_block_idx);
                    thread::sleep(Duration::from_secs(1));
                    continue;
                }
            };

            log::debug!(logger, "Synced block #{}", next_block_idx);
            next_block_idx += 1;

            for tx_out in block_contents.outputs {
                if let Some(account) = TX_PUB_KEY_TO_ACCOUNT_KEY
                    .lock()
                    .unwrap()
                    .remove(&tx_out.public_key)
                {
                    log::info!(
                        logger,
                        "Got account {} for {}",
                        account.default_subaddress(),
                        tx_out.public_key,
                    );

                    let public_key = RistrettoPublic::try_from(&tx_out.public_key).unwrap();
                    let shared_secret =
                        get_tx_out_shared_secret(account.view_private_key(), &public_key);
                    let (input_amount, _blinding_factor) = tx_out
                        .amount
                        .get_value(&shared_secret)
                        .expect("Malformed amount");
                    log::trace!(
                        logger,
                        "amount of {} is {}",
                        tx_out.public_key,
                        input_amount
                    );

                    // Push to queue
                    spendable_txouts_sender
                        .send(SpendableTxOut {
                            tx_out: tx_out.clone(),
                            amount: input_amount,
                            from_account_key: account.clone(),
                        })
                        .expect("failed sending to spendable_txouts_sender");
                } else {
                    log::warn!(logger, "Got unknown tx pub key {}", tx_out.public_key);
                }
            }
        }
    } else {
        log::info!(logger, "Main thread entering infinite loop");
        loop {
            thread::sleep(Duration::from_secs(100));
        }
    }
}

fn worker_thread_entry(
    spendable_txouts_receiver: crossbeam_channel::Receiver<SpendableTxOut>,
    config: SlamConfig,
    ledger_db: LedgerDB,
    accounts: Vec<AccountKey>,
    logger: Logger,
) {
    log::info!(logger, "Worker started.");
    let mut txs_created: usize = 0;

    let mut conns = get_conns(&config, &logger);
    conns.shuffle(&mut thread_rng());

    loop {
        let mut pending_spendable_txouts = Vec::<SpendableTxOut>::new();
        while pending_spendable_txouts.len() < config.num_inputs {
            log::trace!(
                logger,
                "Waiting for {} more inputs",
                config.num_inputs - pending_spendable_txouts.len()
            );
            pending_spendable_txouts.push(
                spendable_txouts_receiver
                    .recv()
                    .expect("failed getting txout"),
            );
        }

        // Select a random account to send to
        let to_account = &accounts[txs_created % accounts.len()];

        // Got our inputs, construct transaction.
        let tx = build_tx(
            &pending_spendable_txouts,
            to_account,
            &config,
            &ledger_db,
            &logger,
        );

        txs_created += 1;

        // Submit tx
        if submit_tx(txs_created, &conns, &tx, &config, &logger) {
            let mut map = TX_PUB_KEY_TO_ACCOUNT_KEY.lock().unwrap();
            map.insert(tx.prefix.outputs[0].public_key, to_account.clone());
        }
    }
}

fn submit_tx(
    counter: usize,
    conns: &[SyncConnection<ThickClient<HardcodedCredentialsProvider>>],
    tx: &Tx,
    config: &SlamConfig,
    logger: &Logger,
) -> bool {
    let max_retries = 10;
    let retry_sleep_duration = Duration::from_millis(300);

    for i in 0..max_retries {
        // Submit to a node in round robin fashion, starting with a random node
        let node_index = (i + counter) % conns.len();
        let conn = &conns[node_index];
        log::debug!(
            logger,
            "Submitting transaction {} to node {} (attempt {} / {})",
            counter,
            conn,
            i,
            max_retries
        );
        thread::sleep(Duration::from_millis(config.add_tx_delay_ms));
        match conn.propose_tx(&tx, empty()) {
            Ok(block_height) => {
                log::debug!(
                    logger,
                    "Successfully submitted {:?}, at block height {:?} (attempt {} / {})",
                    counter,
                    block_height,
                    i,
                    max_retries
                );

                BLOCK_HEIGHT.fetch_max(block_height, Ordering::SeqCst);
                return true;
            }
            Err(RetryError::Operation { error, .. }) => {
                log::warn!(
                    logger,
                    "Failed to submit transaction {:?} to node {} (attempt {} / {}): {}",
                    counter,
                    conn,
                    i,
                    max_retries,
                    error
                );
                thread::sleep(retry_sleep_duration);
            }
            Err(RetryError::Internal(s)) => {
                log::warn!(
                    logger,
                    "Internal retry error while submitting transaction {:?} to node {} (attempt {} / {}): {}",
                    counter,
                    conn,
                    i,
                    max_retries,
                    s
                );
                return false;
            }
        }
    }
    log::error!(
        logger,
        "Failed to submit tx {:?} and max retries exceeded: {:?}",
        counter,
        max_retries
    );
    false
}

fn build_tx(
    spendable_txouts: &[SpendableTxOut],
    to_account: &AccountKey,
    config: &SlamConfig,
    ledger_db: &LedgerDB,
    logger: &Logger,
) -> Tx {
    let utxos_with_proofs = get_membership_proofs(ledger_db, spendable_txouts);
    let rings = get_rings(ledger_db, config.ring_size, utxos_with_proofs.len());

    let mut rng = rand::thread_rng();

    // Sanity
    assert_eq!(utxos_with_proofs.len(), rings.len());

    // Create tx_builder. No fog reports.
    let mut tx_builder = TransactionBuilder::new(FogResolver::default());

    tx_builder.set_fee(MINIMUM_FEE);

    // Unzip each vec of tuples into a tuple of vecs.
    let mut rings_and_proofs: Vec<(Vec<TxOut>, Vec<TxOutMembershipProof>)> = rings
        .into_iter()
        .map(|tuples| tuples.into_iter().unzip())
        .collect();

    // Add inputs to the tx.
    for (utxo, proof) in utxos_with_proofs.clone() {
        let (mut ring, mut membership_proofs) = rings_and_proofs.pop().unwrap();
        assert_eq!(
            ring.len(),
            membership_proofs.len(),
            "Each ring element must have a corresponding membership proof."
        );

        // Add the input to the ring.
        let position_opt = ring.iter().position(|tx_out| *tx_out == utxo.tx_out);
        let real_key_index = match position_opt {
            Some(position) => {
                // The input is already present in the ring.
                // This could happen if ring elements are sampled randomly from the ledger.
                position
            }
            None => {
                // The input is not already in the ring.
                if ring.is_empty() {
                    // Append the input and its proof of membership.
                    ring.push(utxo.tx_out.clone());
                    membership_proofs.push(proof.clone());
                } else {
                    // Replace the first element of the ring.
                    ring[0] = utxo.tx_out.clone();
                    membership_proofs[0] = proof.clone();
                }
                // The real input is always the first element. This is safe because
                // TransactionBuilder sorts each ring.
                0
            }
        };

        assert_eq!(
            ring.len(),
            membership_proofs.len(),
            "Each ring element must have a corresponding membership proof."
        );

        let public_key = RistrettoPublic::try_from(&utxo.tx_out.public_key).unwrap();
        let onetime_private_key = recover_onetime_private_key(
            &public_key,
            utxo.from_account_key.view_private_key(),
            &utxo.from_account_key.default_subaddress_spend_private(),
        );

        let key_image = KeyImage::from(&onetime_private_key);
        log::trace!(
            logger,
            "Adding input: ring {:?}, utxo index {:?}, key image {:?}, pubkey {:?}",
            ring,
            real_key_index,
            key_image,
            public_key
        );

        tx_builder.add_input(
            InputCredentials::new(
                ring,
                membership_proofs,
                real_key_index,
                onetime_private_key,
                *utxo.from_account_key.view_private_key(),
            )
            .expect("add_input failed"),
        );
    }

    // Add ouputs
    for (i, (utxo, _proof)) in utxos_with_proofs.iter().enumerate() {
        let mut amount = utxo.amount;
        // Use the first input to pay for the fee.
        if i == 0 {
            amount -= MINIMUM_FEE;
        }

        tx_builder
            .add_output(amount, &to_account.default_subaddress(), &mut rng)
            .expect("failed to add output");
    }

    // Set tombstone block.
    let tombstone_block = BLOCK_HEIGHT.load(Ordering::SeqCst) + config.tombstone_block;
    tx_builder.set_tombstone_block(tombstone_block);

    // Build and return tx.
    tx_builder.build(&mut rng).expect("failed building tx")
}

fn get_membership_proofs(
    ledger_db: &LedgerDB,
    utxos: &[SpendableTxOut],
) -> Vec<(SpendableTxOut, TxOutMembershipProof)> {
    let indexes: Vec<u64> = utxos
        .iter()
        .map(|utxo| {
            ledger_db
                .get_tx_out_index_by_hash(&utxo.tx_out.hash())
                .unwrap()
        })
        .collect();
    let proofs = ledger_db.get_tx_out_proof_of_memberships(&indexes).unwrap();

    utxos.iter().cloned().zip(proofs.into_iter()).collect()
}

fn get_rings(
    ledger_db: &LedgerDB,
    ring_size: usize,
    num_rings: usize,
) -> Vec<Vec<(TxOut, TxOutMembershipProof)>> {
    let num_requested = ring_size * num_rings;
    let num_txos = ledger_db.num_txos().unwrap();

    // Randomly sample `num_requested` TxOuts, without replacement and convert into
    // a Vec<u64>
    let mut rng = rand::thread_rng();
    let mut sampled_indices: HashSet<u64> = HashSet::default();
    while sampled_indices.len() < num_requested {
        let index = rng.gen_range(0, num_txos);
        sampled_indices.insert(index);
    }
    let sampled_indices_vec: Vec<u64> = sampled_indices.into_iter().collect();

    // Get proofs for all of those indexes.
    let proofs = ledger_db
        .get_tx_out_proof_of_memberships(&sampled_indices_vec)
        .unwrap();

    // Create an iterator that returns (index, proof) elements.
    let mut indexes_and_proofs_iterator = sampled_indices_vec.into_iter().zip(proofs.into_iter());

    // Convert that into a Vec<Vec<TxOut, TxOutMembershipProof>>
    let mut rings_with_proofs = Vec::new();

    for _ in 0..num_rings {
        let mut ring = Vec::new();
        for _ in 0..ring_size {
            let (index, proof) = indexes_and_proofs_iterator.next().unwrap();
            let tx_out = ledger_db.get_tx_out_by_index(index).unwrap();

            ring.push((tx_out, proof));
        }
        rings_with_proofs.push(ring);
    }

    rings_with_proofs
}

fn get_num_transactions_per_account(
    account: &AccountKey,
    transactions: &[TxOut],
    logger: &Logger,
) -> usize {
    for (i, tx_out) in transactions.iter().enumerate() {
        let target_key = RistrettoPublic::try_from(&tx_out.target_key).unwrap();
        let public_key = RistrettoPublic::try_from(&tx_out.public_key).unwrap();

        // Make sure the viewkey matches for this output that we are about to send
        // Assume accounts are numbered in order that they were processed by bootstrap
        if !view_key_matches_output(&account.view_key(), &target_key, &public_key) {
            log::trace!(
                logger,
                "Transaction {:?} does not belong to account. Total txs per account = {:?}",
                i,
                i,
            );
            return i;
        }
    }
    0
}
