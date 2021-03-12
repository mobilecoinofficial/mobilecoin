// Copyright (c) 2018-2021 The MobileCoin Foundation

//! The mobilecoind Service
//! * provides a GRPC server
//! * creates a managing thread and thread pool that scans a local database
//! * processes all transactions to discover transactions for monitors
//! * writes matching transactions to a local DB, organized by subaddress_id

use crate::{
    database::Database,
    error::Error,
    monitor_store::{MonitorData, MonitorId},
    payments::{Outlay, TransactionsManager, TxProposal},
    sync::SyncThread,
    utxo_store::{UnspentTxOut, UtxoId},
};
use grpcio::{EnvBuilder, RpcContext, RpcStatus, RpcStatusCode, ServerBuilder, UnarySink};
use mc_account_keys::{AccountKey, PublicAddress, RootIdentity, DEFAULT_SUBADDRESS_INDEX};
use mc_common::{
    logger::{log, Logger},
    HashMap,
};
use mc_connection::{BlockchainConnection, UserTxConnection};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPublic};
use mc_fog_report_validation::FogPubkeyResolver;
use mc_ledger_db::{Error as LedgerError, Ledger, LedgerDB};
use mc_ledger_sync::{NetworkState, PollingNetworkState};
use mc_mobilecoind_api::{
    mobilecoind_api_grpc::{create_mobilecoind_api, MobilecoindApi},
    MobilecoindUri,
};
use mc_transaction_core::{
    get_tx_out_shared_secret,
    onetime_keys::recover_onetime_private_key,
    ring_signature::KeyImage,
    tx::{TxOut, TxOutConfirmationNumber, TxOutMembershipProof},
};
use mc_util_from_random::FromRandom;
use mc_util_grpc::{
    rpc_internal_error, rpc_logger, send_result, AdminService, BuildInfoService,
    ConnectionUriGrpcioServer,
};
use mc_watcher::watcher_db::WatcherDB;
use protobuf::{ProtobufEnum, RepeatedField};
use std::{
    convert::TryFrom,
    sync::{Arc, Mutex, RwLock},
};

pub struct Service {
    /// Sync thread.
    _sync_thread: Arc<Mutex<Option<SyncThread>>>,

    /// GRPC server.
    _server: grpcio::Server,
}

impl Service {
    pub fn new<
        T: BlockchainConnection + UserTxConnection + 'static,
        FPR: FogPubkeyResolver + 'static,
    >(
        ledger_db: LedgerDB,
        mobilecoind_db: Database,
        watcher_db: Option<WatcherDB>,
        transactions_manager: TransactionsManager<T, FPR>,
        network_state: Arc<RwLock<PollingNetworkState<T>>>,
        listen_uri: &MobilecoindUri,
        num_workers: Option<usize>,
        logger: Logger,
    ) -> Self {
        let sync_thread = if mobilecoind_db.is_db_encrypted() {
            log::info!(logger, "Db encryption enabled, sync task would start once password is provided via the API.");
            Arc::new(Mutex::new(None))
        } else {
            log::info!(logger, "Starting mobilecoind sync task thread");
            Arc::new(Mutex::new(Some(SyncThread::start(
                ledger_db.clone(),
                mobilecoind_db.clone(),
                num_workers,
                logger.clone(),
            ))))
        };

        let start_sync_thread = {
            let ledger_db = ledger_db.clone();
            let mobilecoind_db = mobilecoind_db.clone();
            let logger = logger.clone();
            let sync_thread = sync_thread.clone();
            Arc::new(move || {
                let mut sync_thread = sync_thread.lock().expect("mutex poisoned");
                assert!(sync_thread.is_none());

                *sync_thread = Some(SyncThread::start(
                    ledger_db.clone(),
                    mobilecoind_db.clone(),
                    num_workers,
                    logger.clone(),
                ));
            })
        };

        let api = ServiceApi::new(
            transactions_manager,
            ledger_db,
            mobilecoind_db,
            watcher_db,
            network_state,
            start_sync_thread,
            logger.clone(),
        );

        // Package it into grpc service.
        let mobilecoind_service = create_mobilecoind_api(api);

        // Build info API service.
        let build_info_service = BuildInfoService::new(logger.clone()).into_service();

        // Health check service.
        let health_service = mc_util_grpc::HealthService::new(None, logger.clone()).into_service();

        // Admon service.
        let admin_service = AdminService::new(
            "mobilecoind".to_owned(),
            listen_uri.to_string(),
            None,
            logger.clone(),
        )
        .into_service();

        // Package service into grpc server.
        log::info!(logger, "Starting mobilecoind API Service on {}", listen_uri);
        let env = Arc::new(
            EnvBuilder::new()
                .cq_count(1)
                .name_prefix("Mobilecoind-RPC".to_string())
                .build(),
        );

        let server_builder = ServerBuilder::new(env)
            .register_service(admin_service)
            .register_service(build_info_service)
            .register_service(health_service)
            .register_service(mobilecoind_service)
            .bind_using_uri(listen_uri, logger.clone());

        let mut server = server_builder.build().unwrap();
        server.start();

        Self {
            _server: server,
            _sync_thread: sync_thread,
        }
    }
}

pub struct ServiceApi<
    T: BlockchainConnection + UserTxConnection + 'static,
    FPR: FogPubkeyResolver + 'static,
> {
    transactions_manager: TransactionsManager<T, FPR>,
    ledger_db: LedgerDB,
    mobilecoind_db: Database,
    watcher_db: Option<WatcherDB>,
    network_state: Arc<RwLock<PollingNetworkState<T>>>,
    start_sync_thread: Arc<dyn Fn() + Send + Sync>,
    logger: Logger,
}

impl<T: BlockchainConnection + UserTxConnection + 'static, FPR: FogPubkeyResolver + 'static> Clone
    for ServiceApi<T, FPR>
{
    fn clone(&self) -> Self {
        Self {
            transactions_manager: self.transactions_manager.clone(),
            ledger_db: self.ledger_db.clone(),
            mobilecoind_db: self.mobilecoind_db.clone(),
            watcher_db: self.watcher_db.clone(),
            network_state: self.network_state.clone(),
            start_sync_thread: self.start_sync_thread.clone(),
            logger: self.logger.clone(),
        }
    }
}

impl<T: BlockchainConnection + UserTxConnection + 'static, FPR: FogPubkeyResolver + 'static>
    ServiceApi<T, FPR>
{
    pub fn new(
        transactions_manager: TransactionsManager<T, FPR>,
        ledger_db: LedgerDB,
        mobilecoind_db: Database,
        watcher_db: Option<WatcherDB>,
        network_state: Arc<RwLock<PollingNetworkState<T>>>,
        start_sync_thread: Arc<dyn Fn() + Send + Sync>,
        logger: Logger,
    ) -> Self {
        Self {
            transactions_manager,
            ledger_db,
            mobilecoind_db,
            watcher_db,
            network_state,
            start_sync_thread,
            logger,
        }
    }

    fn add_monitor_impl(
        &mut self,
        request: mc_mobilecoind_api::AddMonitorRequest,
    ) -> Result<mc_mobilecoind_api::AddMonitorResponse, RpcStatus> {
        // Get the AccountKey from the GRPC request.
        let proto_account_key = request.account_key.as_ref().ok_or_else(|| {
            RpcStatus::new(
                RpcStatusCode::INVALID_ARGUMENT,
                Some("account_key".to_string()),
            )
        })?;
        let account_key = AccountKey::try_from(proto_account_key)
            .map_err(|err| rpc_internal_error("account_key.try_from", err, &self.logger))?;

        // Populate a new `MonitorData` instance.
        let data = MonitorData::new(
            account_key,
            request.first_subaddress,
            request.num_subaddresses,
            request.first_block,
            &request.name,
        )
        .map_err(|err| rpc_internal_error("monitor_data.new", err, &self.logger))?;

        // Insert into database. Return the id and flag if the monitor already existed.
        let (id, is_new) = match self.mobilecoind_db.add_monitor(&data) {
            Ok(id) => Ok((id, true)),
            Err(Error::MonitorIdExists) => Ok((MonitorId::from(&data), false)),
            Err(err) => Err(err),
        }
        .map_err(|err| rpc_internal_error("mobilecoind_db.add_monitor", err, &self.logger))?;

        // Return success response.
        let mut response = mc_mobilecoind_api::AddMonitorResponse::new();
        response.set_monitor_id(id.to_vec());
        response.set_is_new(is_new);
        Ok(response)
    }

    fn remove_monitor_impl(
        &mut self,
        request: mc_mobilecoind_api::RemoveMonitorRequest,
    ) -> Result<mc_mobilecoind_api::Empty, RpcStatus> {
        // Get MonitorId from from the GRPC request.
        let monitor_id = MonitorId::try_from(&request.monitor_id)
            .map_err(|err| rpc_internal_error("monitor_id.try_from.bytes", err, &self.logger))?;

        // Remove from database.
        self.mobilecoind_db
            .remove_monitor(&monitor_id)
            .map_err(|err| {
                rpc_internal_error("mobilecoind_db.remove_monitor", err, &self.logger)
            })?;

        // Return success response.
        let response = mc_mobilecoind_api::Empty::new();
        Ok(response)
    }

    fn get_monitor_list_impl(
        &mut self,
        _request: mc_mobilecoind_api::Empty,
    ) -> Result<mc_mobilecoind_api::GetMonitorListResponse, RpcStatus> {
        let monitor_map: HashMap<MonitorId, MonitorData> =
            self.mobilecoind_db.get_monitor_map().map_err(|err| {
                rpc_internal_error("mobilecoind_db.get_monitor_store_map", err, &self.logger)
            })?;

        let mut response = mc_mobilecoind_api::GetMonitorListResponse::new();
        for id in monitor_map.keys() {
            response.mut_monitor_id_list().push(id.to_vec());
        }
        Ok(response)
    }

    fn get_monitor_status_impl(
        &mut self,
        request: mc_mobilecoind_api::GetMonitorStatusRequest,
    ) -> Result<mc_mobilecoind_api::GetMonitorStatusResponse, RpcStatus> {
        let monitor_id = MonitorId::try_from(&request.monitor_id)
            .map_err(|err| rpc_internal_error("monitor_id.try_from.bytes", err, &self.logger))?;

        let data = self
            .mobilecoind_db
            .get_monitor_data(&monitor_id)
            .map_err(|err| {
                rpc_internal_error("mobilecoind_db.get_monitor_data", err, &self.logger)
            })?;

        let mut status = mc_mobilecoind_api::MonitorStatus::new();
        status.set_account_key(mc_api::external::AccountKey::from(&data.account_key));
        status.set_first_subaddress(data.first_subaddress);
        status.set_num_subaddresses(data.num_subaddresses);
        status.set_first_block(data.first_block);
        status.set_next_block(data.next_block);

        let mut response = mc_mobilecoind_api::GetMonitorStatusResponse::new();
        response.set_status(status);
        Ok(response)
    }

    fn get_unspent_tx_out_list_impl(
        &mut self,
        request: mc_mobilecoind_api::GetUnspentTxOutListRequest,
    ) -> Result<mc_mobilecoind_api::GetUnspentTxOutListResponse, RpcStatus> {
        // Get MonitorId from from the GRPC request.
        let monitor_id = MonitorId::try_from(&request.monitor_id)
            .map_err(|err| rpc_internal_error("monitor_id.try_from.bytes", err, &self.logger))?;

        // Get UnspentTxOuts.
        let utxos = self
            .mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, request.subaddress_index)
            .map_err(|err| {
                rpc_internal_error("mobilecoind_db.get_utxos_for_subaddress", err, &self.logger)
            })?;

        // Convert to protos.
        let proto_utxos: Vec<mc_mobilecoind_api::UnspentTxOut> =
            utxos.iter().map(|utxo| utxo.into()).collect();

        // Returrn response.
        let mut response = mc_mobilecoind_api::GetUnspentTxOutListResponse::new();
        response.set_output_list(RepeatedField::from_vec(proto_utxos));
        Ok(response)
    }

    fn generate_entropy_impl(
        &mut self,
        _request: mc_mobilecoind_api::Empty,
    ) -> Result<mc_mobilecoind_api::GenerateEntropyResponse, RpcStatus> {
        let mut rng = rand::thread_rng();
        let root_id = RootIdentity::from_random(&mut rng);
        let mut response = mc_mobilecoind_api::GenerateEntropyResponse::new();
        response.set_entropy(root_id.root_entropy.as_ref().to_vec());
        Ok(response)
    }

    fn get_account_key_impl(
        &mut self,
        request: mc_mobilecoind_api::GetAccountKeyRequest,
    ) -> Result<mc_mobilecoind_api::GetAccountKeyResponse, RpcStatus> {
        // Get the entropy.
        if request.get_entropy().len() != 32 {
            return Err(RpcStatus::new(
                RpcStatusCode::INVALID_ARGUMENT,
                Some("entropy".to_string()),
            ));
        }

        // Use root entropy to construct AccountKey.
        let mut root_entropy = [0u8; 32];
        root_entropy.copy_from_slice(request.get_entropy());
        let root_id = RootIdentity::from(&root_entropy);
        // we use expect here because AccountKey from a non-Fog identity should be infallible.
        let account_key = AccountKey::try_from(&root_id).expect("AccountKey Creation failed");

        // Return response.
        let mut response = mc_mobilecoind_api::GetAccountKeyResponse::new();
        response.set_account_key((&account_key).into());
        Ok(response)
    }

    fn get_public_address_impl(
        &mut self,
        request: mc_mobilecoind_api::GetPublicAddressRequest,
    ) -> Result<mc_mobilecoind_api::GetPublicAddressResponse, RpcStatus> {
        // Get MonitorId from from the GRPC request.
        let monitor_id = MonitorId::try_from(&request.monitor_id)
            .map_err(|err| rpc_internal_error("monitor_id.try_from.bytes", err, &self.logger))?;

        // Get monitor data.
        let data = self
            .mobilecoind_db
            .get_monitor_data(&monitor_id)
            .map_err(|err| {
                rpc_internal_error("mobilecoind_db.get_monitor_data", err, &self.logger)
            })?;

        // Verify subaddress falls in the range we are monitoring.
        if !data
            .subaddress_indexes()
            .contains(&request.subaddress_index)
        {
            return Err(RpcStatus::new(
                RpcStatusCode::INVALID_ARGUMENT,
                Some("subaddress_index".to_string()),
            ));
        }

        // Get the subaddress.
        let subaddress = data.account_key.subaddress(request.subaddress_index);

        // Also build the b58 wrapper
        let mut wrapper = mc_mobilecoind_api::printable::PrintableWrapper::new();
        wrapper.set_public_address((&subaddress).into());

        // Return response.
        let mut response = mc_mobilecoind_api::GetPublicAddressResponse::new();
        response.set_public_address((&subaddress).into());
        response.set_b58_code(
            wrapper
                .b58_encode()
                .map_err(|err| rpc_internal_error("b58_encode", err, &self.logger))?,
        );

        Ok(response)
    }

    fn parse_request_code_impl(
        &mut self,
        request: mc_mobilecoind_api::ParseRequestCodeRequest,
    ) -> Result<mc_mobilecoind_api::ParseRequestCodeResponse, RpcStatus> {
        let wrapper = mc_mobilecoind_api::printable::PrintableWrapper::b58_decode(
            request.get_b58_code().to_string(),
        )
        .map_err(|err| rpc_internal_error("PrintableWrapper_b58_decode", err, &self.logger))?;

        // A request code could be a public address or a payment request
        if wrapper.has_payment_request() {
            let payment_request = wrapper.get_payment_request();
            let mut response = mc_mobilecoind_api::ParseRequestCodeResponse::new();
            response.set_receiver(payment_request.get_public_address().clone());
            response.set_value(payment_request.get_value());
            response.set_memo(payment_request.get_memo().to_string());
            Ok(response)
        } else if wrapper.has_public_address() {
            let public_address = wrapper.get_public_address();
            let mut response = mc_mobilecoind_api::ParseRequestCodeResponse::new();
            response.set_receiver(public_address.clone());
            response.set_value(0);
            response.set_memo(String::new());
            Ok(response)
        } else {
            Err(RpcStatus::new(
                RpcStatusCode::INVALID_ARGUMENT,
                Some("Neither payment request nor public address".to_string()),
            ))
        }
    }

    fn create_request_code_impl(
        &mut self,
        request: mc_mobilecoind_api::CreateRequestCodeRequest,
    ) -> Result<mc_mobilecoind_api::CreateRequestCodeResponse, RpcStatus> {
        let receiver = PublicAddress::try_from(request.get_receiver())
            .map_err(|err| rpc_internal_error("PublicAddress.try_from", err, &self.logger))?;

        let mut payment_request = mc_mobilecoind_api::printable::PaymentRequest::new();
        payment_request.set_public_address((&receiver).into());
        payment_request.set_value(request.get_value());
        payment_request.set_memo(request.get_memo().to_string());

        let mut wrapper = mc_mobilecoind_api::printable::PrintableWrapper::new();
        wrapper.set_payment_request(payment_request);

        let encoded = wrapper
            .b58_encode()
            .map_err(|err| rpc_internal_error("b58_encode", err, &self.logger))?;

        let mut response = mc_mobilecoind_api::CreateRequestCodeResponse::new();
        response.set_b58_code(encoded);
        Ok(response)
    }

    fn parse_transfer_code_impl(
        &mut self,
        request: mc_mobilecoind_api::ParseTransferCodeRequest,
    ) -> Result<mc_mobilecoind_api::ParseTransferCodeResponse, RpcStatus> {
        let wrapper = mc_mobilecoind_api::printable::PrintableWrapper::b58_decode(
            request.get_b58_code().to_string(),
        )
        .map_err(|err| rpc_internal_error("PrintableWrapper.b58_decode", err, &self.logger))?;

        if !wrapper.has_transfer_payload() {
            return Err(RpcStatus::new(
                RpcStatusCode::INVALID_ARGUMENT,
                Some("has_transfer_payload".to_string()),
            ));
        }
        let transfer_payload = wrapper.get_transfer_payload();

        let tx_public_key = RistrettoPublic::try_from(transfer_payload.get_tx_out_public_key())
            .map_err(|err| rpc_internal_error("RistrettoPublic.try_from", err, &self.logger))?;

        let compressed_tx_public_key = CompressedRistrettoPublic::from(&tx_public_key);

        // build and include a UnspentTxOut that can be immediately spent

        let index = self
            .ledger_db
            .get_tx_out_index_by_public_key(&compressed_tx_public_key)
            .map_err(|err| {
                rpc_internal_error(
                    "ledger_db.get_tx_out_index_by_public_key",
                    err,
                    &self.logger,
                )
            })?;

        let tx_out = self.ledger_db.get_tx_out_by_index(index).map_err(|err| {
            rpc_internal_error("ledger_db.get_tx_out_by_index", err, &self.logger)
        })?;

        // Use root entropy to construct AccountKey.
        let mut root_entropy = [0u8; 32];
        root_entropy.copy_from_slice(transfer_payload.get_entropy());
        let root_id = RootIdentity::from(&root_entropy);
        // this is expect because AccountKey::from(RootIdentity) should be infallible
        let account_key =
            AccountKey::try_from(&root_id).expect("AccountKey creation from RootIdentity failed");

        let shared_secret =
            get_tx_out_shared_secret(account_key.view_private_key(), &tx_public_key);

        let (value, _blinding) = tx_out
            .amount
            .get_value(&shared_secret)
            .map_err(|err| rpc_internal_error("amount.get_value", err, &self.logger))?;

        let onetime_private_key = recover_onetime_private_key(
            &tx_public_key,
            account_key.view_private_key(),
            &account_key.subaddress_spend_private(DEFAULT_SUBADDRESS_INDEX),
        );

        let key_image = KeyImage::from(&onetime_private_key);

        let utxo = UnspentTxOut {
            tx_out,
            subaddress_index: DEFAULT_SUBADDRESS_INDEX,
            key_image,
            value,
            attempted_spend_height: 0,
            attempted_spend_tombstone: 0,
        };

        let mut response = mc_mobilecoind_api::ParseTransferCodeResponse::new();
        response.set_entropy(root_entropy.to_vec());
        response.set_tx_public_key((&tx_public_key).into());
        response.set_memo(transfer_payload.get_memo().to_string());
        response.set_utxo((&utxo).into());

        Ok(response)
    }

    fn create_transfer_code_impl(
        &mut self,
        request: mc_mobilecoind_api::CreateTransferCodeRequest,
    ) -> Result<mc_mobilecoind_api::CreateTransferCodeResponse, RpcStatus> {
        if request.entropy.len() != 32 {
            return Err(RpcStatus::new(
                RpcStatusCode::INVALID_ARGUMENT,
                Some("entropy".to_string()),
            ));
        }
        if request.get_tx_public_key().get_data().len() != 32 {
            return Err(RpcStatus::new(
                RpcStatusCode::INVALID_ARGUMENT,
                Some("tx_public_key".to_string()),
            ));
        }

        let mut transfer_payload = mc_mobilecoind_api::printable::TransferPayload::new();
        transfer_payload.set_entropy(request.get_entropy().to_vec());
        transfer_payload.set_tx_out_public_key(request.get_tx_public_key().clone());
        transfer_payload.set_memo(request.get_memo().to_string());

        let mut transfer_wrapper = mc_mobilecoind_api::printable::PrintableWrapper::new();
        transfer_wrapper.set_transfer_payload(transfer_payload);

        let encoded = transfer_wrapper
            .b58_encode()
            .map_err(|err| rpc_internal_error("b58_encode", err, &self.logger))?;

        let mut response = mc_mobilecoind_api::CreateTransferCodeResponse::new();
        response.set_b58_code(encoded);
        Ok(response)
    }

    fn parse_address_code_impl(
        &mut self,
        request: mc_mobilecoind_api::ParseAddressCodeRequest,
    ) -> Result<mc_mobilecoind_api::ParseAddressCodeResponse, RpcStatus> {
        let wrapper = mc_mobilecoind_api::printable::PrintableWrapper::b58_decode(
            request.get_b58_code().to_string(),
        )
        .map_err(|err| rpc_internal_error("PrintableWrapper_b58_decode", err, &self.logger))?;

        // An address code could be a public address or a payment request
        if wrapper.has_payment_request() {
            let payment_request = wrapper.get_payment_request();
            let mut response = mc_mobilecoind_api::ParseAddressCodeResponse::new();
            response.set_receiver(payment_request.get_public_address().clone());
            Ok(response)
        } else if wrapper.has_public_address() {
            let public_address = wrapper.get_public_address();
            let mut response = mc_mobilecoind_api::ParseAddressCodeResponse::new();
            response.set_receiver(public_address.clone());
            Ok(response)
        } else {
            Err(RpcStatus::new(
                RpcStatusCode::INVALID_ARGUMENT,
                Some("Neither payment request nor public address".to_string()),
            ))
        }
    }

    fn create_address_code_impl(
        &mut self,
        request: mc_mobilecoind_api::CreateAddressCodeRequest,
    ) -> Result<mc_mobilecoind_api::CreateAddressCodeResponse, RpcStatus> {
        let receiver = PublicAddress::try_from(request.get_receiver())
            .map_err(|err| rpc_internal_error("PublicAddress.try_from", err, &self.logger))?;

        let mut wrapper = mc_mobilecoind_api::printable::PrintableWrapper::new();
        wrapper.set_public_address((&receiver).into());

        let encoded = wrapper
            .b58_encode()
            .map_err(|err| rpc_internal_error("b58_encode", err, &self.logger))?;

        let mut response = mc_mobilecoind_api::CreateAddressCodeResponse::new();
        response.set_b58_code(encoded);
        Ok(response)
    }

    /// Get mixins
    fn get_mixins_impl(
        &mut self,
        request: mc_mobilecoind_api::GetMixinsRequest,
    ) -> Result<mc_mobilecoind_api::GetMixinsResponse, RpcStatus> {
        let num_mixins: usize = request.get_num_mixins() as usize;
        let excluded: Vec<TxOut> = request
            .get_excluded()
            .iter()
            .map(|tx_out| {
                // Proto -> Rust struct conversion.
                TxOut::try_from(tx_out)
                    .map_err(|err| rpc_internal_error("tx_out.try_from", err, &self.logger))
            })
            .collect::<Result<Vec<TxOut>, RpcStatus>>()?;

        let excluded_indexes = excluded
            .iter()
            .map(|tx_out| self.ledger_db.get_tx_out_index_by_hash(&tx_out.hash()))
            .collect::<Result<Vec<u64>, LedgerError>>()
            .map_err(|e| rpc_internal_error("ledger_error", e, &self.logger))?; // TODO better error handling

        let mixins_with_proofs: Vec<(TxOut, TxOutMembershipProof)> = self
            .transactions_manager
            .get_rings(num_mixins, 1, &excluded_indexes)
            .map(|nested| nested.into_iter().flatten().collect())
            .map_err(|e| rpc_internal_error("get_rings_error", e, &self.logger))?; // TODO better error handling

        let mut response = mc_mobilecoind_api::GetMixinsResponse::new();

        let tx_outs_with_proofs: Vec<mc_mobilecoind_api::TxOutWithProof> = mixins_with_proofs
            .iter()
            .map(|(tx_out, proof)| {
                let mut tx_out_with_proof = mc_mobilecoind_api::TxOutWithProof::new();
                tx_out_with_proof.set_output(tx_out.into());
                tx_out_with_proof.set_proof(proof.into());
                tx_out_with_proof
            })
            .collect();

        response.set_mixins(RepeatedField::from(tx_outs_with_proofs));
        Ok(response)
    }

    /// Get a proof of membership for each requested TxOut.
    fn get_membership_proofs_impl(
        &mut self,
        request: mc_mobilecoind_api::GetMembershipProofsRequest,
    ) -> Result<mc_mobilecoind_api::GetMembershipProofsResponse, RpcStatus> {
        let outputs: Vec<TxOut> = request
            .get_outputs()
            .iter()
            .map(|tx_out| {
                // Proto -> Rust struct conversion.
                TxOut::try_from(tx_out)
                    .map_err(|err| rpc_internal_error("tx_out.try_from", err, &self.logger))
            })
            .collect::<Result<Vec<TxOut>, RpcStatus>>()?;

        let proofs: Vec<TxOutMembershipProof> = self
            .transactions_manager
            .get_membership_proofs(&outputs)
            .map_err(|err| rpc_internal_error("get_membership_proofs", err, &self.logger))?;

        let mut response = mc_mobilecoind_api::GetMembershipProofsResponse::new();

        for (tx_out, proof) in outputs.iter().zip(proofs.iter()) {
            let mut tx_out_with_proof = mc_mobilecoind_api::TxOutWithProof::new();
            tx_out_with_proof.set_output(tx_out.into());
            tx_out_with_proof.set_proof(proof.into());
            response.mut_output_list().push(tx_out_with_proof);
        }

        Ok(response)
    }

    fn generate_tx_impl(
        &mut self,
        request: mc_mobilecoind_api::GenerateTxRequest,
    ) -> Result<mc_mobilecoind_api::GenerateTxResponse, RpcStatus> {
        // Get sender monitor id from request.
        let sender_monitor_id = MonitorId::try_from(&request.sender_monitor_id)
            .map_err(|err| rpc_internal_error("monitor_id.try_from.bytes", err, &self.logger))?;

        // Get monitor data for this monitor.
        let sender_monitor_data = self
            .mobilecoind_db
            .get_monitor_data(&sender_monitor_id)
            .map_err(|err| {
                rpc_internal_error("mobilecoind_db.get_monitor_data", err, &self.logger)
            })?;

        // Check that change_subaddress is covered by this monitor.
        if !sender_monitor_data
            .subaddress_indexes()
            .contains(&request.change_subaddress)
        {
            return Err(RpcStatus::new(
                RpcStatusCode::INVALID_ARGUMENT,
                Some("change_subaddress".to_string()),
            ));
        }

        // Get the list of potential inputs passed to.
        let input_list: Vec<UnspentTxOut> = request
            .get_input_list()
            .iter()
            .enumerate()
            .map(|(i, proto_utxo)| {
                // Proto -> Rust struct conversion.
                let utxo = UnspentTxOut::try_from(proto_utxo).map_err(|err| {
                    rpc_internal_error("unspent_tx_out.try_from", err, &self.logger)
                })?;

                // Verify this output belongs to the monitor.
                let subaddress_id = self
                    .mobilecoind_db
                    .get_subaddress_id_by_utxo_id(&UtxoId::from(&utxo))
                    .map_err(|err| {
                        rpc_internal_error(
                            "mobilecoind_db.get_subaddress_id_by_utxo_id",
                            err,
                            &self.logger,
                        )
                    })?;

                if subaddress_id.monitor_id != sender_monitor_id {
                    return Err(RpcStatus::new(
                        RpcStatusCode::INVALID_ARGUMENT,
                        Some(format!("input_list.{}", i)),
                    ));
                }

                // Success.
                Ok(utxo)
            })
            .collect::<Result<Vec<UnspentTxOut>, RpcStatus>>()?;

        // Get the list of outlays.
        let outlays: Vec<Outlay> = request
            .get_outlay_list()
            .iter()
            .map(|outlay_proto| {
                Outlay::try_from(outlay_proto)
                    .map_err(|err| rpc_internal_error("outlay.try_from", err, &self.logger))
            })
            .collect::<Result<Vec<Outlay>, RpcStatus>>()?;

        // Attempt to construct a transaction.
        let tx_proposal = self
            .transactions_manager
            .build_transaction(
                &sender_monitor_id,
                request.change_subaddress,
                &input_list,
                &outlays,
                request.fee,
                request.tombstone,
            )
            .map_err(|err| {
                rpc_internal_error("transactions_manager.build_transaction", err, &self.logger)
            })?;

        // Success.
        let mut response = mc_mobilecoind_api::GenerateTxResponse::new();
        response.set_tx_proposal((&tx_proposal).into());
        Ok(response)
    }

    fn generate_optimization_tx_impl(
        &mut self,
        request: mc_mobilecoind_api::GenerateOptimizationTxRequest,
    ) -> Result<mc_mobilecoind_api::GenerateOptimizationTxResponse, RpcStatus> {
        // Get monitor id from request.
        let monitor_id = MonitorId::try_from(&request.monitor_id)
            .map_err(|err| rpc_internal_error("monitor_id.try_from.bytes", err, &self.logger))?;

        // Generate optimization tx.
        let tx_proposal = self
            .transactions_manager
            .generate_optimization_tx(&monitor_id, request.subaddress)
            .map_err(|err| {
                rpc_internal_error(
                    "transactions_manager.generate_optimization_tx",
                    err,
                    &self.logger,
                )
            })?;

        // Success.
        let mut response = mc_mobilecoind_api::GenerateOptimizationTxResponse::new();
        response.set_tx_proposal((&tx_proposal).into());
        Ok(response)
    }

    fn generate_tx_from_tx_out_list_impl(
        &mut self,
        request: mc_mobilecoind_api::GenerateTxFromTxOutListRequest,
    ) -> Result<mc_mobilecoind_api::GenerateTxFromTxOutListResponse, RpcStatus> {
        let proto_account_key = request.account_key.as_ref().ok_or_else(|| {
            RpcStatus::new(
                RpcStatusCode::INVALID_ARGUMENT,
                Some("account_key".to_string()),
            )
        })?;

        let account_key = AccountKey::try_from(proto_account_key)
            .map_err(|err| rpc_internal_error("account_key.try_from", err, &self.logger))?;

        let input_list: Vec<UnspentTxOut> = request
            .get_input_list()
            .iter()
            .map(|proto_utxo| {
                // Proto -> Rust struct conversion.
                UnspentTxOut::try_from(proto_utxo)
                    .map_err(|err| rpc_internal_error("unspent_tx_out.try_from", err, &self.logger))
            })
            .collect::<Result<Vec<UnspentTxOut>, RpcStatus>>()?;

        let receiver = PublicAddress::try_from(request.get_receiver())
            .map_err(|err| rpc_internal_error("PublicAddress.try_from", err, &self.logger))?;

        let tx_proposal = self
            .transactions_manager
            .generate_tx_from_tx_list(&account_key, &input_list, &receiver, request.fee)
            .map_err(|err| {
                rpc_internal_error(
                    "transactions_manager.generate_tx_from_tx_list",
                    err,
                    &self.logger,
                )
            })?;

        let mut response = mc_mobilecoind_api::GenerateTxFromTxOutListResponse::new();
        response.set_tx_proposal((&tx_proposal).into());
        Ok(response)
    }

    fn generate_transfer_code_tx_impl(
        &mut self,
        request: mc_mobilecoind_api::GenerateTransferCodeTxRequest,
    ) -> Result<mc_mobilecoind_api::GenerateTransferCodeTxResponse, RpcStatus> {
        // Generate entropy.
        let entropy_response = self.generate_entropy_impl(mc_mobilecoind_api::Empty::new())?;
        let entropy = entropy_response.get_entropy().to_vec();

        let mut entropy_bytes = [0; 32];
        if entropy.len() != entropy_bytes.len() {
            return Err(RpcStatus::new(
                RpcStatusCode::INTERNAL,
                Some("entropy returned was not 32 bytes".to_owned()),
            ));
        }
        entropy_bytes.copy_from_slice(&entropy);

        // Generate a new account using this entropy.
        let mut account_key_request = mc_mobilecoind_api::GetAccountKeyRequest::new();
        account_key_request.set_entropy(entropy.clone());

        let account_key_response = self.get_account_key_impl(account_key_request)?;
        let account_key = AccountKey::try_from(account_key_response.get_account_key())
            .map_err(|err| rpc_internal_error("account_key.try_from", err, &self.logger))?;

        // The outlay we are sending the money to.
        let outlay = Outlay {
            receiver: account_key.default_subaddress(),
            value: request.value,
        };

        // Generate transaction.
        let mut generate_tx_request = mc_mobilecoind_api::GenerateTxRequest::new();
        generate_tx_request.set_sender_monitor_id(request.get_sender_monitor_id().to_vec());
        generate_tx_request.set_change_subaddress(request.change_subaddress);
        generate_tx_request.set_input_list(RepeatedField::from_vec(request.input_list.to_vec()));
        generate_tx_request.set_outlay_list(RepeatedField::from_vec(vec![(&outlay).into()]));
        generate_tx_request.set_fee(request.fee);
        generate_tx_request.set_tombstone(request.tombstone);

        let mut generate_tx_response = self.generate_tx_impl(generate_tx_request)?;
        let tx_proposal = generate_tx_response.take_tx_proposal();

        // Grab the public key of the relevant tx out.
        let proto_tx_public_key = {
            // We expect only a single outlay.
            if tx_proposal.get_outlay_index_to_tx_out_index().len() != 1 {
                return Err(RpcStatus::new(
                    RpcStatusCode::INTERNAL,
                    Some(format!(
                        "outlay_index_to_tx_out_index contains {} elements, was expecting 1",
                        tx_proposal.get_outlay_index_to_tx_out_index().len()
                    )),
                ));
            }

            // Get the TxOut index of our single outlay.
            let tx_out_index = tx_proposal
                .get_outlay_index_to_tx_out_index()
                .get(&0)
                .ok_or_else(|| {
                    RpcStatus::new(
                        RpcStatusCode::INTERNAL,
                        Some("outlay_index_to_tx_out_index doesn't contain index 0".to_owned()),
                    )
                })?;

            // Get the TxOut
            let tx_out = tx_proposal
                .get_tx()
                .get_prefix()
                .get_outputs()
                .get(*tx_out_index as usize)
                .ok_or_else(|| {
                    RpcStatus::new(
                        RpcStatusCode::INTERNAL,
                        Some(format!("tx out index {} not found", tx_out_index)),
                    )
                })?;

            // Get the public key
            tx_out.get_public_key().clone()
        };

        let tx_public_key = RistrettoPublic::try_from(&proto_tx_public_key)
            .map_err(|err| rpc_internal_error("ristretto_public.try_from", err, &self.logger))?;

        let mut transfer_payload = mc_mobilecoind_api::printable::TransferPayload::new();
        transfer_payload.set_entropy(entropy_bytes.to_vec());
        transfer_payload.set_tx_out_public_key((&tx_public_key).into());
        transfer_payload.set_memo(request.get_memo().to_string());

        let mut transfer_wrapper = mc_mobilecoind_api::printable::PrintableWrapper::new();
        transfer_wrapper.set_transfer_payload(transfer_payload);

        let b58_code = transfer_wrapper
            .b58_encode()
            .map_err(|err| rpc_internal_error("b58_encode", err, &self.logger))?;

        // Construct response.
        let mut response = mc_mobilecoind_api::GenerateTransferCodeTxResponse::new();
        response.set_tx_proposal(tx_proposal);
        response.set_entropy(entropy);
        response.set_tx_public_key(proto_tx_public_key);
        response.set_memo(request.get_memo().to_string());
        response.set_b58_code(b58_code);
        Ok(response)
    }

    fn submit_tx_impl(
        &mut self,
        request: mc_mobilecoind_api::SubmitTxRequest,
    ) -> Result<mc_mobilecoind_api::SubmitTxResponse, RpcStatus> {
        // Get TxProposal from request.
        let tx_proposal = TxProposal::try_from(request.get_tx_proposal())
            .map_err(|err| rpc_internal_error("tx_proposal.try_from", err, &self.logger))?;

        // Submit to network.
        let block_height = self
            .transactions_manager
            .submit_tx_proposal(&tx_proposal)
            .map_err(|err| {
                rpc_internal_error("transactions_manager.submit_tx_proposal", err, &self.logger)
            })?;

        // Update the attempted spend block height in db. Note that we swallow the error here since
        // our transaction did get sent to the network, and its better to have the user attempt a
        // double spend by having stale UnspentTxOut data than having them not be aware that the
        // transaction was submitted.
        let utxo_ids: Vec<UtxoId> = tx_proposal.utxos.iter().map(UtxoId::from).collect();
        if let Err(err) = self.mobilecoind_db.update_attempted_spend(
            &utxo_ids,
            block_height,
            tx_proposal.tx.prefix.tombstone_block,
        ) {
            log::error!(
                self.logger,
                "failed updating attempted_spend_height after submitting tx {}: {:?}",
                tx_proposal.tx,
                err
            );
        }

        // Construct sender receipt.
        let mut sender_tx_receipt = mc_mobilecoind_api::SenderTxReceipt::new();
        sender_tx_receipt.set_key_image_list(RepeatedField::from_vec(
            tx_proposal
                .utxos
                .iter()
                .map(|utxo| (&utxo.key_image).into())
                .collect(),
        ));
        sender_tx_receipt.set_tombstone(tx_proposal.tx.prefix.tombstone_block);

        // Construct receiver receipts.
        let receiver_tx_receipts: Vec<_> = tx_proposal
            .outlays
            .iter()
            .enumerate()
            .map(|(outlay_index, outlay)| {
                let tx_out_index = tx_proposal
                    .outlay_index_to_tx_out_index
                    .get(&outlay_index)
                    .ok_or_else(|| {
                        RpcStatus::new(
                            RpcStatusCode::INVALID_ARGUMENT,
                            Some("outlay_index_to_tx_out_index".to_string()),
                        )
                    })?;

                let tx_out = tx_proposal
                    .tx
                    .prefix
                    .outputs
                    .get(*tx_out_index)
                    .ok_or_else(|| {
                        RpcStatus::new(
                            RpcStatusCode::INVALID_ARGUMENT,
                            Some("outlay_index_to_tx_out_index".to_string()),
                        )
                    })?;

                let mut receiver_tx_receipt = mc_mobilecoind_api::ReceiverTxReceipt::new();
                receiver_tx_receipt.set_recipient((&outlay.receiver).into());
                receiver_tx_receipt.set_tx_public_key((&tx_out.public_key).into());
                receiver_tx_receipt.set_tx_out_hash(tx_out.hash().to_vec());
                receiver_tx_receipt.set_tombstone(tx_proposal.tx.prefix.tombstone_block);

                if tx_proposal.outlay_confirmation_numbers.len() > outlay_index {
                    receiver_tx_receipt.set_confirmation_number(
                        tx_proposal.outlay_confirmation_numbers[outlay_index].to_vec(),
                    );
                }

                Ok(receiver_tx_receipt)
            })
            .collect::<Result<Vec<mc_mobilecoind_api::ReceiverTxReceipt>, RpcStatus>>()?;

        // Return response.
        let mut response = mc_mobilecoind_api::SubmitTxResponse::new();
        response.set_sender_tx_receipt(sender_tx_receipt);
        response.set_receiver_tx_receipt_list(RepeatedField::from_vec(receiver_tx_receipts));
        Ok(response)
    }

    fn get_ledger_info_impl(
        &mut self,
        _request: mc_mobilecoind_api::Empty,
    ) -> Result<mc_mobilecoind_api::GetLedgerInfoResponse, RpcStatus> {
        let num_blocks = self
            .ledger_db
            .num_blocks()
            .map_err(|err| rpc_internal_error("ledger_db.num_blocks", err, &self.logger))?;

        let num_txos = self
            .ledger_db
            .num_txos()
            .map_err(|err| rpc_internal_error("ledger_db.num_txos", err, &self.logger))?;

        let mut response = mc_mobilecoind_api::GetLedgerInfoResponse::new();
        response.set_block_count(num_blocks);
        response.set_txo_count(num_txos);
        Ok(response)
    }

    fn get_block_info_impl(
        &mut self,
        request: mc_mobilecoind_api::GetBlockInfoRequest,
    ) -> Result<mc_mobilecoind_api::GetBlockInfoResponse, RpcStatus> {
        let block_contents = self
            .ledger_db
            .get_block_contents(request.block)
            .map_err(|err| rpc_internal_error("ledger_db.get_block_contents", err, &self.logger))?;

        let num_tx_outs = block_contents.outputs.len();
        let num_key_images = block_contents.key_images.len();

        // Return response.
        let mut response = mc_mobilecoind_api::GetBlockInfoResponse::new();
        response.set_key_image_count(num_key_images as u64);
        response.set_txo_count(num_tx_outs as u64);
        Ok(response)
    }

    fn get_block_impl(
        &mut self,
        request: mc_mobilecoind_api::GetBlockRequest,
    ) -> Result<mc_mobilecoind_api::GetBlockResponse, RpcStatus> {
        let mut response = mc_mobilecoind_api::GetBlockResponse::new();

        let block_data = self
            .ledger_db
            .get_block_data(request.block)
            .map_err(|err| rpc_internal_error("ledger_db.get_block_data", err, &self.logger))?;

        response.set_block(mc_consensus_api::blockchain::Block::from(
            block_data.block(),
        ));

        for key_image in &block_data.contents().key_images {
            response
                .mut_key_images()
                .push(mc_consensus_api::external::KeyImage::from(key_image));
        }
        for output in &block_data.contents().outputs {
            response
                .mut_txos()
                .push(mc_consensus_api::external::TxOut::from(output));
        }

        if let Some(watcher_db) = self.watcher_db.as_ref() {
            let signatures = watcher_db
                .get_block_signatures(request.block)
                .map_err(|err| {
                    rpc_internal_error("watcher_db.get_block_signatures", err, &self.logger)
                })?;
            for signature_data in signatures.iter() {
                let mut signature_message = mc_mobilecoind_api::ArchiveBlockSignatureData::new();
                signature_message.set_src_url(signature_data.src_url.clone());
                signature_message.set_filename(signature_data.archive_filename.clone());
                signature_message.set_signature(
                    mc_consensus_api::blockchain::BlockSignature::from(
                        &signature_data.block_signature,
                    ),
                );
                response.mut_signatures().push(signature_message);
            }
        }
        Ok(response)
    }

    fn get_tx_status_as_sender_impl(
        &mut self,
        request: mc_mobilecoind_api::SubmitTxResponse,
    ) -> Result<mc_mobilecoind_api::GetTxStatusAsSenderResponse, RpcStatus> {
        // Sanity-test the request.
        if request
            .get_sender_tx_receipt()
            .get_key_image_list()
            .is_empty()
        {
            return Err(RpcStatus::new(
                RpcStatusCode::INVALID_ARGUMENT,
                Some("sender_receipt.key_image_list".to_string()),
            ));
        }

        if request.get_sender_tx_receipt().tombstone == 0 {
            return Err(RpcStatus::new(
                RpcStatusCode::INVALID_ARGUMENT,
                Some("sender_receipt.tombstone".to_string()),
            ));
        }

        // Receiver receipt should have at least one output
        if request.get_receiver_tx_receipt_list().is_empty() {
            return Err(RpcStatus::new(
                RpcStatusCode::INVALID_ARGUMENT,
                Some("receiver_receipt.receiver_tx_receipt_list".to_string()),
            ));
        }

        // Get list of key images from the request.
        let key_images: Vec<KeyImage> = request
            .get_sender_tx_receipt()
            .get_key_image_list()
            .iter()
            .map(|key_image| {
                KeyImage::try_from(key_image)
                    .map_err(|err| rpc_internal_error("key_image.try_from", err, &self.logger))
            })
            .collect::<Result<Vec<KeyImage>, RpcStatus>>()?;

        // Get list of tx_public_keys from the request.
        let compressed_pubkeys: Vec<CompressedRistrettoPublic> = request
            .get_receiver_tx_receipt_list()
            .iter()
            .map(|r| {
                RistrettoPublic::try_from(r.get_tx_public_key())
                    .map_err(|err| {
                        rpc_internal_error("RistrettoPublic.try_from", err, &self.logger)
                    })
                    .map(|pubkey| CompressedRistrettoPublic::from(&pubkey))
            })
            .collect::<Result<Vec<CompressedRistrettoPublic>, RpcStatus>>()?;

        // Check the tx_public_keys in the receiver receipt, to also get the block_height. Note that
        // if the transaction has not yet landed, the result will be a vec of LedgerDb::NotFound errors.
        let found_pubkey_indices: Vec<u64> = compressed_pubkeys
            .iter()
            .map(|compressed_tx_public_key| {
                self.ledger_db
                    .get_tx_out_index_by_public_key(&compressed_tx_public_key)
                    .and_then(|txo_index| self.ledger_db.get_block_index_by_tx_out_index(txo_index))
            })
            .filter_map(Result::ok)
            .collect();

        // If we didn't find any of the tx_public_keys, then the transaction is either still pending,
        // or the inputs were spent in another transaction and this transaction will never land.
        if found_pubkey_indices.is_empty() {
            // Verify that the key images are not anywhere else in the ledger.
            let key_image_in_ledger: Vec<bool> = key_images
                .iter()
                .map(|key_image| {
                    self.ledger_db.contains_key_image(key_image).map_err(|err| {
                        rpc_internal_error("ledger_db.contains_key_image", err, &self.logger)
                    })
                })
                .collect::<Result<Vec<bool>, RpcStatus>>()?;
            if key_image_in_ledger
                .iter()
                .any(|key_image_in_ledger| *key_image_in_ledger)
            {
                let mut response = mc_mobilecoind_api::GetTxStatusAsSenderResponse::new();
                response.set_status(
                    mc_mobilecoind_api::TxStatus::TransactionFailureKeyImageAlreadySpent,
                );
                return Ok(response);
            }

            // Otherwise, the transaction is still pending or otherwise status unknown.
            let mut response = mc_mobilecoind_api::GetTxStatusAsSenderResponse::new();
            response.set_status(mc_mobilecoind_api::TxStatus::Unknown);
            return Ok(response);
        }

        // Verify that all block indices are the same value. If this fails, the receipt is likely
        // malformed, because it should be impossible to construct a transaction containing output
        // public keys that somehow end up landing in different blocks.
        if found_pubkey_indices.iter().min() != found_pubkey_indices.iter().max() {
            let mut response = mc_mobilecoind_api::GetTxStatusAsSenderResponse::new();
            response.set_status(mc_mobilecoind_api::TxStatus::PublicKeysInDifferentBlocks);
            return Ok(response);
        }

        // Get the block in which this transaction landed.
        let block_index = found_pubkey_indices[0];
        let block_contents = self
            .ledger_db
            .get_block_contents(block_index)
            .map_err(|err| rpc_internal_error("ledger_db.get_block_contents", err, &self.logger))?;

        // Convert key images to a list of booleans indicating whether they were found in the
        // block or not. All key_images from the same transaction should land in the same block.
        let key_image_found: Vec<bool> = key_images
            .iter()
            .map(|key_image| block_contents.key_images.contains(&key_image))
            .collect::<Vec<bool>>();

        // If all key images are in the block, the transaction was completed.
        if key_image_found
            .iter()
            .all(|key_image_found| *key_image_found)
        {
            let mut response = mc_mobilecoind_api::GetTxStatusAsSenderResponse::new();
            response.set_status(mc_mobilecoind_api::TxStatus::Verified);
            return Ok(response);
        }

        // If only some key images found their way to the block, they were likely spent from another transaction.
        if key_image_found
            .iter()
            .any(|key_image_found| *key_image_found)
        {
            let mut response = mc_mobilecoind_api::GetTxStatusAsSenderResponse::new();
            response
                .set_status(mc_mobilecoind_api::TxStatus::TransactionFailureKeyImageBlockMismatch);
            return Ok(response);
        }

        // Check if the tombstone block was exceeded.
        let num_blocks = self
            .ledger_db
            .num_blocks()
            .map_err(|err| rpc_internal_error("ledger_db.num_blocks", err, &self.logger))?;

        if num_blocks >= request.get_sender_tx_receipt().tombstone {
            let mut response = mc_mobilecoind_api::GetTxStatusAsSenderResponse::new();
            response.set_status(mc_mobilecoind_api::TxStatus::TombstoneBlockExceeded);
            return Ok(response);
        }

        // No key images in ledger, tombstone block not yet exceeded.
        let mut response = mc_mobilecoind_api::GetTxStatusAsSenderResponse::new();
        response.set_status(mc_mobilecoind_api::TxStatus::Unknown);
        Ok(response)
    }

    fn get_tx_status_as_receiver_impl(
        &mut self,
        request: mc_mobilecoind_api::GetTxStatusAsReceiverRequest,
    ) -> Result<mc_mobilecoind_api::GetTxStatusAsReceiverResponse, RpcStatus> {
        // Sanity-test the request.
        if request.get_receipt().get_tx_out_hash().len() != 32 {
            return Err(RpcStatus::new(
                RpcStatusCode::INVALID_ARGUMENT,
                Some("receipt.tx_out_hash".to_string()),
            ));
        }

        if request.get_receipt().tombstone == 0 {
            return Err(RpcStatus::new(
                RpcStatusCode::INVALID_ARGUMENT,
                Some("receipt.tombstone".to_string()),
            ));
        }

        // Check if the hash landed in the ledger.
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&request.get_receipt().tx_out_hash);

        match self.ledger_db.get_tx_out_index_by_hash(&hash_bytes) {
            Ok(_) => {
                // If a monitor ID was given then validate the confirmation number
                match request.get_monitor_id().len() {
                    0 => { /* no monitor ID given */ }
                    32 => {
                        let monitor_id =
                            MonitorId::try_from(&request.monitor_id).map_err(|err| {
                                rpc_internal_error("monitor_id.try_from.bytes", err, &self.logger)
                            })?;

                        // Get monitor data for this monitor.
                        let monitor_data = self
                            .mobilecoind_db
                            .get_monitor_data(&monitor_id)
                            .map_err(|err| {
                                rpc_internal_error(
                                    "mobilecoind_db.get_monitor_data",
                                    err,
                                    &self.logger,
                                )
                            })?;
                        let tx_public_key =
                            RistrettoPublic::try_from(request.get_receipt().get_tx_public_key())
                                .map_err(|err| {
                                    rpc_internal_error(
                                        "RistrettoPublic.try_from",
                                        err,
                                        &self.logger,
                                    )
                                })?;
                        let view_private_key = monitor_data.account_key.view_private_key();

                        if request.get_receipt().get_confirmation_number().len() != 32 {
                            return Err(RpcStatus::new(
                                RpcStatusCode::INVALID_ARGUMENT,
                                Some("receipt.confirmation_number".to_string()),
                            ));
                        }

                        // Test that the confirmation number is valid. Only the party constructing
                        // the transaction could have created the correct confirmation number.
                        let confirmation_number = {
                            let mut confirmation_bytes = [0u8; 32];
                            confirmation_bytes
                                .copy_from_slice(request.get_receipt().get_confirmation_number());
                            TxOutConfirmationNumber::from(confirmation_bytes)
                        };
                        if !confirmation_number.validate(&tx_public_key, &view_private_key) {
                            // If the confirmation number is invalid, this means that the transaction did
                            // get added to the ledger but the party constructing the receipt failed
                            // to prove that they created it. This prevents a third-party observer from
                            // taking credit for someone elses payment.
                            let mut response =
                                mc_mobilecoind_api::GetTxStatusAsReceiverResponse::new();
                            response.set_status(
                                mc_mobilecoind_api::TxStatus::InvalidConfirmationNumber,
                            );
                            return Ok(response);
                        }
                    }
                    _ => {
                        return Err(RpcStatus::new(
                            RpcStatusCode::INVALID_ARGUMENT,
                            Some("monitor_id".to_string()),
                        ));
                    }
                }

                // The hash found its way into the ledger, so the transaction succeeded.
                let mut response = mc_mobilecoind_api::GetTxStatusAsReceiverResponse::new();
                response.set_status(mc_mobilecoind_api::TxStatus::Verified);
                return Ok(response);
            }
            Err(mc_ledger_db::Error::NotFound) => {}
            Err(err) => {
                return Err(rpc_internal_error(
                    "ledger_db.get_tx_out_index_by_hash",
                    err,
                    &self.logger,
                ));
            }
        };

        // Check if the tombstone block was exceeded.
        let num_blocks = self
            .ledger_db
            .num_blocks()
            .map_err(|err| rpc_internal_error("ledger_db.num_blocks", err, &self.logger))?;

        if num_blocks >= request.get_receipt().tombstone {
            let mut response = mc_mobilecoind_api::GetTxStatusAsReceiverResponse::new();
            response.set_status(mc_mobilecoind_api::TxStatus::TombstoneBlockExceeded);
            return Ok(response);
        }

        // Tx out not in ledger, tombstone block not yet exceeded.
        let mut response = mc_mobilecoind_api::GetTxStatusAsReceiverResponse::new();
        response.set_status(mc_mobilecoind_api::TxStatus::Unknown);
        Ok(response)
    }

    fn get_processed_block_impl(
        &mut self,
        request: mc_mobilecoind_api::GetProcessedBlockRequest,
    ) -> Result<mc_mobilecoind_api::GetProcessedBlockResponse, RpcStatus> {
        // Get MonitorId from from the GRPC request.
        let monitor_id = MonitorId::try_from(&request.monitor_id)
            .map_err(|err| rpc_internal_error("monitor_id.try_from.bytes", err, &self.logger))?;

        // We will use the AccountKey to compute the Address Code
        let account_key = self
            .mobilecoind_db
            .get_monitor_data(&monitor_id)
            .map_err(|err| {
                rpc_internal_error("mobilecoind_db.get_monitor_data", err, &self.logger)
            })?
            .account_key;

        // Get all processed block data for the requested block.
        let processed_tx_outs = self
            .mobilecoind_db
            .get_processed_block(&monitor_id, request.block)
            .map_err(|err| {
                rpc_internal_error("mobilecoind_db.get_processed_block", err, &self.logger)
            })?
            .iter()
            .map(|src| {
                let mut dst = mc_mobilecoind_api::ProcessedTxOut::new();
                dst.set_monitor_id(monitor_id.to_vec());
                dst.set_subaddress_index(src.subaddress_index);
                dst.set_public_key((&src.public_key).into());
                dst.set_key_image((&src.key_image).into());
                dst.set_value(src.value);
                dst.set_direction(
                    mc_mobilecoind_api::ProcessedTxOutDirection::from_i32(src.direction)
                        .unwrap_or(mc_mobilecoind_api::ProcessedTxOutDirection::Invalid),
                );

                let subaddress = account_key.subaddress(src.subaddress_index);
                let mut wrapper = mc_mobilecoind_api::printable::PrintableWrapper::new();
                wrapper.set_public_address((&subaddress).into());
                let encoded = wrapper
                    .b58_encode()
                    .map_err(|err| rpc_internal_error("wrapper.b58_encode", err, &self.logger))?;
                dst.set_address_code(encoded);
                Ok(dst)
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Return response
        let mut response = mc_mobilecoind_api::GetProcessedBlockResponse::new();
        response.set_tx_outs(RepeatedField::from_vec(processed_tx_outs));
        Ok(response)
    }

    fn get_block_index_by_tx_pub_key_impl(
        &mut self,
        request: mc_mobilecoind_api::GetBlockIndexByTxPubKeyRequest,
    ) -> Result<mc_mobilecoind_api::GetBlockIndexByTxPubKeyResponse, RpcStatus> {
        let tx_public_key = RistrettoPublic::try_from(request.get_tx_public_key())
            .map_err(|err| rpc_internal_error("RistrettoPublic.try_from", err, &self.logger))?;

        let compressed_tx_public_key = CompressedRistrettoPublic::from(&tx_public_key);

        let tx_out_index = self
            .ledger_db
            .get_tx_out_index_by_public_key(&compressed_tx_public_key)
            .map_err(|err| {
                rpc_internal_error(
                    "ledger_db.get_tx_out_index_by_public_key",
                    err,
                    &self.logger,
                )
            })?;

        let block_index = self
            .ledger_db
            .get_block_index_by_tx_out_index(tx_out_index)
            .map_err(|err| {
                rpc_internal_error(
                    "ledger_db.get_block_index_by_tx_out_index",
                    err,
                    &self.logger,
                )
            })?;

        let mut response = mc_mobilecoind_api::GetBlockIndexByTxPubKeyResponse::new();
        response.set_block(block_index);
        Ok(response)
    }

    fn get_balance_impl(
        &mut self,
        request: mc_mobilecoind_api::GetBalanceRequest,
    ) -> Result<mc_mobilecoind_api::GetBalanceResponse, RpcStatus> {
        // Get MonitorId from from the GRPC request.
        let monitor_id = MonitorId::try_from(&request.monitor_id)
            .map_err(|err| rpc_internal_error("monitor_id.try_from.bytes", err, &self.logger))?;

        // Get all utxos for this monitor id.
        let utxos = self
            .mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, request.subaddress_index)
            .map_err(|err| {
                rpc_internal_error("mobilecoind_db.get_utxos_for_subaddress", err, &self.logger)
            })?;

        // Sum them up.
        let balance = utxos.iter().map(|utxo| utxo.value as u128).sum::<u128>();

        // It's possible the balance does not fit into a u64.
        if balance > u64::max_value().into() {
            return Err(RpcStatus::new(
                RpcStatusCode::INTERNAL,
                Some(format!(
                    "balance of {} won't fit in u64, fetch utxo list instead",
                    balance
                )),
            ));
        }

        // Return response.
        let mut response = mc_mobilecoind_api::GetBalanceResponse::new();
        response.set_balance(balance as u64);
        Ok(response)
    }

    fn send_payment_impl(
        &mut self,
        request: mc_mobilecoind_api::SendPaymentRequest,
    ) -> Result<mc_mobilecoind_api::SendPaymentResponse, RpcStatus> {
        // Get sender monitor id from request.
        let sender_monitor_id = MonitorId::try_from(&request.sender_monitor_id)
            .map_err(|err| rpc_internal_error("monitor_id.try_from.bytes", err, &self.logger))?;

        // Get all utxos for this monitor id.
        let mut utxos = self
            .mobilecoind_db
            .get_utxos_for_subaddress(&sender_monitor_id, request.sender_subaddress)
            .map_err(|err| {
                rpc_internal_error("mobilecoind_db.get_utxos_for_subaddress", err, &self.logger)
            })?;

        // Optionally filter for max value.
        if request.max_input_utxo_value > 0 {
            utxos.retain(|utxo| utxo.value <= request.max_input_utxo_value);
        }

        // Get the list of outlays.
        let outlays: Vec<Outlay> = request
            .get_outlay_list()
            .iter()
            .map(|outlay_proto| {
                Outlay::try_from(outlay_proto)
                    .map_err(|err| rpc_internal_error("outlay.try_from", err, &self.logger))
            })
            .collect::<Result<Vec<Outlay>, RpcStatus>>()?;

        // Set change address to sender address unless it has been overridden
        let change_subaddress = if request.override_change_subaddress {
            request.change_subaddress
        } else {
            request.sender_subaddress
        };

        // Attempt to construct a transaction.
        let tx_proposal = self
            .transactions_manager
            .build_transaction(
                &sender_monitor_id,
                change_subaddress,
                &utxos,
                &outlays,
                request.fee,
                request.tombstone,
            )
            .map_err(|err| {
                rpc_internal_error("transactions_manager.build_transaction", err, &self.logger)
            })?;

        let proto_tx_proposal = mc_mobilecoind_api::TxProposal::from(&tx_proposal);

        // Submit transaction.
        let mut submit_tx_request = mc_mobilecoind_api::SubmitTxRequest::new();
        submit_tx_request.set_tx_proposal(proto_tx_proposal.clone());
        let mut submit_tx_response = self.submit_tx_impl(submit_tx_request)?;

        // Return response.
        let mut response = mc_mobilecoind_api::SendPaymentResponse::new();
        response.set_sender_tx_receipt(submit_tx_response.take_sender_tx_receipt());
        response.set_receiver_tx_receipt_list(submit_tx_response.take_receiver_tx_receipt_list());
        response.set_tx_proposal(proto_tx_proposal);
        Ok(response)
    }

    fn pay_address_code_impl(
        &mut self,
        request: mc_mobilecoind_api::PayAddressCodeRequest,
    ) -> Result<mc_mobilecoind_api::SendPaymentResponse, RpcStatus> {
        // Sanity check.
        if request.get_amount() == 0 {
            return Err(RpcStatus::new(
                RpcStatusCode::INVALID_ARGUMENT,
                Some("amount".to_string()),
            ));
        }

        // Try and decode the address code.
        let mut parse_address_code_request = mc_mobilecoind_api::ParseAddressCodeRequest::new();
        parse_address_code_request.set_b58_code(request.get_receiver_b58_code().to_owned());
        let parse_address_code_response =
            self.parse_address_code_impl(parse_address_code_request)?;

        // Forward to SendPayment
        let mut outlay = mc_mobilecoind_api::Outlay::new();
        outlay.set_value(request.get_amount());
        outlay.set_receiver(parse_address_code_response.get_receiver().clone());

        let mut send_payment_request = mc_mobilecoind_api::SendPaymentRequest::new();
        send_payment_request.set_sender_monitor_id(request.get_sender_monitor_id().to_vec());
        send_payment_request.set_sender_subaddress(request.get_sender_subaddress());
        send_payment_request.set_outlay_list(RepeatedField::from_vec(vec![outlay]));
        send_payment_request.set_fee(request.get_fee());
        send_payment_request.set_tombstone(request.get_tombstone());
        send_payment_request.set_max_input_utxo_value(request.get_max_input_utxo_value());
        send_payment_request.set_override_change_subaddress(request.override_change_subaddress);
        send_payment_request.set_change_subaddress(request.change_subaddress);

        self.send_payment_impl(send_payment_request)
    }

    fn get_network_status_impl(
        &mut self,
        _request: mc_mobilecoind_api::Empty,
    ) -> Result<mc_mobilecoind_api::GetNetworkStatusResponse, RpcStatus> {
        let network_state = self.network_state.read().expect("lock poisoned");
        let num_blocks = self
            .ledger_db
            .num_blocks()
            .map_err(|err| rpc_internal_error("ledger_db.num_blocks", err, &self.logger))?;
        if num_blocks == 0 {
            return Err(RpcStatus::new(
                RpcStatusCode::INTERNAL,
                Some("no bootstrap block".to_owned()),
            ));
        }
        let local_block_index = num_blocks - 1;

        let mut response = mc_mobilecoind_api::GetNetworkStatusResponse::new();

        response.set_network_highest_block_index(
            network_state.highest_block_index_on_network().unwrap_or(0),
        );
        response.set_peer_block_index_map(
            network_state
                .peer_to_current_block_index()
                .iter()
                .map(|(responder_id, block_index)| (responder_id.to_string(), *block_index))
                .collect(),
        );
        response.set_local_block_index(local_block_index);
        response.set_is_behind(network_state.is_behind(local_block_index));

        Ok(response)
    }

    fn set_db_password_impl(
        &mut self,
        request: mc_mobilecoind_api::SetDbPasswordRequest,
    ) -> Result<mc_mobilecoind_api::Empty, RpcStatus> {
        // Check if the database is unlocked and allowing this operation.
        if !self.mobilecoind_db.is_unlocked() {
            return Err(RpcStatus::new(
                RpcStatusCode::INTERNAL,
                Some("must unlock before changing current password".to_owned()),
            ));
        }

        // Re-encrypt data using the new password.
        self.mobilecoind_db
            .re_encrypt(&request.get_password())
            .map_err(|err| rpc_internal_error("mobilecoind_db.re_encrypt", err, &self.logger))?;

        log::info!(self.logger, "DB encryption password updated successfully.");

        Ok(mc_mobilecoind_api::Empty::default())
    }

    fn unlock_db_impl(
        &mut self,
        request: mc_mobilecoind_api::UnlockDbRequest,
    ) -> Result<mc_mobilecoind_api::Empty, RpcStatus> {
        if self.mobilecoind_db.is_unlocked() {
            return Err(RpcStatus::new(
                RpcStatusCode::INTERNAL,
                Some("already unlocked".to_owned()),
            ));
        }

        self.mobilecoind_db
            .check_and_store_password(&request.get_password())
            .map_err(|err| {
                rpc_internal_error("mobilecoind_db.check_and_store_password", err, &self.logger)
            })?;

        log::info!(self.logger, "Successfully unlocked, starting sync thread.");
        (self.start_sync_thread)();

        Ok(mc_mobilecoind_api::Empty::default())
    }
}

macro_rules! build_api {
    ($( $service_function_name:ident $service_request_type:ident $service_response_type:ident $service_function_impl:ident ),+)
    =>
    (
        impl<T: BlockchainConnection + UserTxConnection + 'static, FPR: FogPubkeyResolver> MobilecoindApi for ServiceApi<T, FPR> {
            $(
                fn $service_function_name(
                    &mut self,
                    ctx: RpcContext,
                    request: mc_mobilecoind_api::$service_request_type,
                    sink: UnarySink<mc_mobilecoind_api::$service_response_type>,
                ) {
                    let logger = rpc_logger(&ctx, &self.logger);
                    send_result(
                        ctx,
                        sink,
                        self.$service_function_impl(request),
                        &logger,
                    )
                }
            )+
        }
    );
}

build_api! {
    // Monitors
    add_monitor AddMonitorRequest AddMonitorResponse add_monitor_impl,
    remove_monitor RemoveMonitorRequest Empty remove_monitor_impl,
    get_monitor_list Empty GetMonitorListResponse get_monitor_list_impl,
    get_monitor_status GetMonitorStatusRequest GetMonitorStatusResponse get_monitor_status_impl,
    get_unspent_tx_out_list GetUnspentTxOutListRequest GetUnspentTxOutListResponse get_unspent_tx_out_list_impl,

    // Utilities
    generate_entropy Empty GenerateEntropyResponse generate_entropy_impl,
    get_account_key GetAccountKeyRequest GetAccountKeyResponse get_account_key_impl,
    get_public_address GetPublicAddressRequest GetPublicAddressResponse get_public_address_impl,

    // b58 codes
    parse_request_code ParseRequestCodeRequest ParseRequestCodeResponse parse_request_code_impl,
    create_request_code CreateRequestCodeRequest CreateRequestCodeResponse create_request_code_impl,
    parse_transfer_code ParseTransferCodeRequest ParseTransferCodeResponse parse_transfer_code_impl,
    create_transfer_code CreateTransferCodeRequest CreateTransferCodeResponse create_transfer_code_impl,
    parse_address_code ParseAddressCodeRequest ParseAddressCodeResponse parse_address_code_impl,
    create_address_code CreateAddressCodeRequest CreateAddressCodeResponse create_address_code_impl,

    // Transactions
    get_mixins GetMixinsRequest GetMixinsResponse get_mixins_impl,
    get_membership_proofs GetMembershipProofsRequest GetMembershipProofsResponse get_membership_proofs_impl,
    generate_tx GenerateTxRequest GenerateTxResponse generate_tx_impl,
    generate_optimization_tx GenerateOptimizationTxRequest GenerateOptimizationTxResponse generate_optimization_tx_impl,
    generate_transfer_code_tx GenerateTransferCodeTxRequest GenerateTransferCodeTxResponse generate_transfer_code_tx_impl,
    generate_tx_from_tx_out_list GenerateTxFromTxOutListRequest GenerateTxFromTxOutListResponse generate_tx_from_tx_out_list_impl,
    submit_tx SubmitTxRequest SubmitTxResponse submit_tx_impl,

    // Databases
    get_ledger_info Empty GetLedgerInfoResponse get_ledger_info_impl,
    get_block_info GetBlockInfoRequest GetBlockInfoResponse get_block_info_impl,
    get_block GetBlockRequest GetBlockResponse get_block_impl,
    get_tx_status_as_sender SubmitTxResponse GetTxStatusAsSenderResponse get_tx_status_as_sender_impl,
    get_tx_status_as_receiver GetTxStatusAsReceiverRequest GetTxStatusAsReceiverResponse get_tx_status_as_receiver_impl,
    get_processed_block GetProcessedBlockRequest GetProcessedBlockResponse get_processed_block_impl,
    get_block_index_by_tx_pub_key GetBlockIndexByTxPubKeyRequest GetBlockIndexByTxPubKeyResponse get_block_index_by_tx_pub_key_impl,

    // Convenience calls
    get_balance GetBalanceRequest GetBalanceResponse get_balance_impl,
    send_payment SendPaymentRequest SendPaymentResponse send_payment_impl,
    pay_address_code PayAddressCodeRequest SendPaymentResponse pay_address_code_impl,

    // Network status
    get_network_status Empty GetNetworkStatusResponse get_network_status_impl,

    // Database encryption
    set_db_password SetDbPasswordRequest Empty set_db_password_impl,
    unlock_db UnlockDbRequest Empty unlock_db_impl
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        payments::DEFAULT_NEW_TX_BLOCK_ATTEMPTS,
        subaddress_store::SubaddressSPKId,
        test_utils::{
            self, add_block_to_ledger_db, add_txos_to_ledger_db, get_testing_environment,
            wait_for_monitors, DEFAULT_PER_RECIPIENT_AMOUNT,
        },
        utxo_store::UnspentTxOut,
    };
    use grpcio::{Error as GrpcError, RpcStatus};
    use mc_account_keys::{AccountKey, PublicAddress, DEFAULT_SUBADDRESS_INDEX};
    use mc_common::{logger::test_with_logger, HashSet};
    use mc_crypto_keys::RistrettoPrivate;
    use mc_crypto_rand::RngCore;
    use mc_fog_report_validation::{FullyValidatedFogPubkey, MockFogPubkeyResolver};
    use mc_fog_report_validation_test_utils::MockFogResolver;
    use mc_transaction_core::{
        constants::{MAX_INPUTS, MINIMUM_FEE, RING_SIZE},
        fog_hint::FogHint,
        get_tx_out_shared_secret,
        onetime_keys::{recover_onetime_private_key, recover_public_subaddress_spend_key},
        tx::{Tx, TxOut},
        Block, BlockContents, BLOCK_VERSION,
    };
    use mc_transaction_std::TransactionBuilder;
    use mc_util_repr_bytes::{typenum::U32, GenericArray, ReprBytes};
    use mc_util_uri::FogUri;
    use rand::{rngs::StdRng, SeedableRng};
    use std::{
        convert::{TryFrom, TryInto},
        iter::FromIterator,
        str::FromStr,
    };

    #[test_with_logger]
    fn test_add_monitor_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([20u8; 32]);

        // Three random recipients and no monitors.
        let (ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(3, &vec![], &vec![], logger.clone(), &mut rng);

        // Create request for adding a new monitor.
        let data = MonitorData::new(
            AccountKey::random(&mut rng),
            DEFAULT_SUBADDRESS_INDEX, // first_subaddress
            1,                        // num_subaddresses
            0,                        // first_block
            "",                       // name
        )
        .expect("failed to create data");

        let mut request = mc_mobilecoind_api::AddMonitorRequest::new();
        request.set_account_key(mc_api::external::AccountKey::from(&data.account_key));
        request.set_first_subaddress(data.first_subaddress);
        request.set_num_subaddresses(data.num_subaddresses);
        request.set_first_block(data.first_block);

        // Send request.
        let response = client.add_monitor(&request).expect("failed to add monitor");

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Compare the MonitorId we got back to the value we expected.
        let monitor_id = MonitorId::try_from(&response.monitor_id)
            .expect("failed to convert response to MonitorId");
        let expected_monitor_id = MonitorId::from(&data);

        assert_eq!(expected_monitor_id, monitor_id);

        // Check that the monitor is reported as new
        assert!(response.is_new);

        // Add the same monitor again
        let repeated_response = client.add_monitor(&request).expect("failed to add monitor");

        // Compare the MonitorId we got back to the value we expected.
        let repeated_monitor_id = MonitorId::try_from(&repeated_response.monitor_id)
            .expect("failed to convert repeated_response to MonitorId");

        assert_eq!(expected_monitor_id, repeated_monitor_id);

        // Check that the monitor is not reported as new
        assert!(!repeated_response.is_new);
    }

    #[test_with_logger]
    fn test_remove_monitor_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([22u8; 32]);

        // 10 random recipients and no monitors.
        let (_ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(10, &vec![], &vec![], logger.clone(), &mut rng);

        let monitors_map = mobilecoind_db.get_monitor_map().unwrap();
        assert_eq!(0, monitors_map.len());

        // Add some monitors directly to the database.
        let monitors_to_add = 10;
        let monitor_ids: Vec<MonitorId> = (0..monitors_to_add)
            .map(|_i| {
                let data = MonitorData::new(
                    AccountKey::random(&mut rng),
                    DEFAULT_SUBADDRESS_INDEX, // first_subaddress
                    1,                        // num_subaddresses
                    0,                        // first_block
                    "",                       // name
                )
                .unwrap();
                mobilecoind_db.add_monitor(&data).unwrap()
            })
            .collect();

        let monitors_map = mobilecoind_db.get_monitor_map().unwrap();
        assert_eq!(monitors_to_add, monitors_map.len());

        // Remove all the monitors we added.
        for id in monitor_ids {
            let mut request = mc_mobilecoind_api::RemoveMonitorRequest::new();
            request.set_monitor_id(id.to_vec());
            client
                .remove_monitor(&request)
                .expect("failed to remove monitor");
        }

        // Check that no monitors remain.
        let monitors_map = mobilecoind_db.get_monitor_map().unwrap();
        assert_eq!(0, monitors_map.len());
    }

    #[test_with_logger]
    fn test_get_monitor_list_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([21u8; 32]);

        // 10 random recipients and no monitors.
        let (_ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(10, &vec![], &vec![], logger.clone(), &mut rng);

        // Add some new monitors directly to the database.
        let monitors_to_add = 10;
        let monitor_ids: Vec<MonitorId> = (0..monitors_to_add)
            .map(|_i| {
                let data = MonitorData::new(
                    AccountKey::random(&mut rng),
                    DEFAULT_SUBADDRESS_INDEX, // first_subaddress
                    1,                        // num_subaddresses
                    0,                        // first_block
                    "",                       // name
                )
                .unwrap();
                let id = mobilecoind_db.add_monitor(&data).unwrap();
                log::debug!(logger, "adding monitor {}", id,);
                id
            })
            .collect();

        // Ask the api for a list of all monitors.
        let response = client
            .get_monitor_list(&mc_mobilecoind_api::Empty::new())
            .expect("failed to get monitor list");

        let monitor_id_list: Vec<MonitorId> = response
            .monitor_id_list
            .iter()
            .map(|bytes| {
                let id =
                    MonitorId::try_from(bytes).expect("failed to convert response to MonitorId");
                log::debug!(logger, "found monitor {}", id,);
                id
            })
            .collect();

        // Check monitor count.
        assert_eq!(monitors_to_add, monitor_id_list.len());

        // Check that all new monitors are present.
        assert_eq!(
            HashSet::from_iter(monitor_id_list.iter()),
            HashSet::from_iter(monitor_ids.iter()),
        );
    }

    #[test_with_logger]
    fn test_get_monitor_status_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // 10 random recipients and no monitors.
        let (ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(10, &vec![], &vec![], logger.clone(), &mut rng);

        let data = MonitorData::new(
            AccountKey::random(&mut rng),
            10, // first_subaddress
            20, // num_subaddresses
            30, // first_block
            "", // name
        )
        .unwrap();

        // Insert into database.
        let id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Query monitor status.
        let mut request = mc_mobilecoind_api::GetMonitorStatusRequest::new();
        request.set_monitor_id(id.to_vec());

        let response = client
            .get_monitor_status(&request)
            .expect("failed to get monitor status");
        let status = response.status.as_ref().expect("no status in response");

        // Verify the data we got matches what we expected
        assert_eq!(
            data.account_key,
            AccountKey::try_from(status.account_key.as_ref().unwrap()).unwrap(),
        );
        assert_eq!(status.first_subaddress, data.first_subaddress);
        assert_eq!(status.num_subaddresses, data.num_subaddresses);
        assert_eq!(status.first_block, data.first_block);
        assert_eq!(status.next_block, data.next_block);

        // Calling get_monitor_status for nonexistent or invalid monitor_id should return an error.
        mobilecoind_db.remove_monitor(&id).unwrap();

        let mut request = mc_mobilecoind_api::GetMonitorStatusRequest::new();
        request.set_monitor_id(id.to_vec());
        assert!(client.get_monitor_status(&request).is_err());

        let request = mc_mobilecoind_api::GetMonitorStatusRequest::new();
        assert!(client.get_monitor_status(&request).is_err());

        let mut request = mc_mobilecoind_api::GetMonitorStatusRequest::new();
        request.set_monitor_id(vec![3; 3]);
        assert!(client.get_monitor_status(&request).is_err());
    }

    #[test_with_logger]
    fn test_get_unspent_tx_out_list_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let account_key = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            account_key.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                3,
                &vec![account_key.default_subaddress()],
                &vec![],
                logger.clone(),
                &mut rng,
            );

        // Insert into database.
        let id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Query for unspent tx outs for a subaddress that did not receive any tx outs.
        let mut request = mc_mobilecoind_api::GetUnspentTxOutListRequest::new();
        request.set_monitor_id(id.to_vec());
        request.set_subaddress_index(1);

        let response = client
            .get_unspent_tx_out_list(&request)
            .expect("failed to get unspent tx out list");

        assert_eq!(response.output_list.to_vec(), vec![]);

        // Query with the correct subaddress index.
        let mut request = mc_mobilecoind_api::GetUnspentTxOutListRequest::new();
        request.set_monitor_id(id.to_vec());
        request.set_subaddress_index(0);

        let response = client
            .get_unspent_tx_out_list(&request)
            .expect("failed to get unspent tx out list");

        let utxos: Vec<UnspentTxOut> = response
            .output_list
            .iter()
            .map(|proto_utxo| {
                UnspentTxOut::try_from(proto_utxo).expect("failed converting proto utxo")
            })
            .collect();

        // Verify the data we got matches what we expected. This assumes knowledge about how the
        // test ledger is constructed by the test utils.
        let num_blocks = ledger_db.num_blocks().unwrap();
        let account_tx_outs: Vec<TxOut> = (0..num_blocks)
            .map(|idx| {
                let block_contents = ledger_db.get_block_contents(idx as u64).unwrap();
                // We grab the 4th tx out in each block since the test ledger had 3 random
                // recipients, followed by our known recipient.
                // See the call to `get_testing_environment` at the beginning of the test.
                block_contents.outputs[3].clone()
            })
            .collect();

        let expected_utxos: Vec<UnspentTxOut> = account_tx_outs
            .iter()
            .map(|tx_out| {
                // Calculate the key image for this tx out.
                let tx_public_key = RistrettoPublic::try_from(&tx_out.public_key).unwrap();
                let onetime_private_key = recover_onetime_private_key(
                    &tx_public_key,
                    account_key.view_private_key(),
                    &account_key.subaddress_spend_private(0),
                );
                let key_image = KeyImage::from(&onetime_private_key);

                // Craft the expected UnspentTxOut
                UnspentTxOut {
                    tx_out: tx_out.clone(),
                    subaddress_index: 0,
                    key_image,
                    value: test_utils::DEFAULT_PER_RECIPIENT_AMOUNT,
                    attempted_spend_height: 0,
                    attempted_spend_tombstone: 0,
                }
            })
            .collect();

        // Compare
        assert_eq!(utxos.len(), num_blocks as usize);
        assert_eq!(
            HashSet::from_iter(utxos),
            HashSet::from_iter(expected_utxos)
        );
    }

    #[test_with_logger]
    fn test_generate_root_entropy_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (_ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(3, &vec![], &vec![], logger.clone(), &mut rng);

        // call get entropy
        let response = client
            .generate_entropy(&mc_mobilecoind_api::Empty::default())
            .unwrap();
        let entropy = response.get_entropy().to_vec();
        assert_eq!(entropy.len(), 32);
        assert_ne!(entropy, vec![0; 32]);
    }

    #[test_with_logger]
    fn test_get_account_key_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (_ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(3, &vec![], &vec![], logger.clone(), &mut rng);

        // Use root entropy to construct AccountKey.
        let root_entropy = [123u8; 32];
        let root_id = RootIdentity::from(&root_entropy);
        // expect because AK::try_from(RI) should be infallible
        let account_key = AccountKey::try_from(&root_id)
            .expect("Could not construct AccountKey from RootIdentity");

        let mut request = mc_mobilecoind_api::GetAccountKeyRequest::new();
        request.set_entropy(root_entropy.to_vec());

        let response = client.get_account_key(&request).unwrap();

        assert_eq!(
            account_key,
            AccountKey::try_from(response.get_account_key()).unwrap(),
        );

        // Calling with no root entropy or invalid root entropy should error.
        let request = mc_mobilecoind_api::GetAccountKeyRequest::new();
        assert!(client.get_account_key(&request).is_err());

        let root_entropy = [123u8; 31];
        let mut request = mc_mobilecoind_api::GetAccountKeyRequest::new();
        request.set_entropy(root_entropy.to_vec());
        assert!(client.get_account_key(&request).is_err());
    }

    #[test_with_logger]
    fn test_get_public_address_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);
        let account_key = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            account_key.clone(),
            10, // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // no known recipient, 3 random recipients and no monitors.
        let (_ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(3, &vec![], &vec![], logger.clone(), &mut rng);

        // Insert into database.
        let id = mobilecoind_db.add_monitor(&data).unwrap();

        // Call get public address.
        let mut request = mc_mobilecoind_api::GetPublicAddressRequest::new();
        request.set_monitor_id(id.to_vec());
        request.set_subaddress_index(10);
        let response = client.get_public_address(&request).unwrap();

        assert_eq!(
            PublicAddress::try_from(response.get_public_address()).unwrap(),
            account_key.subaddress(10)
        );

        // Test that the b58 encoding is correct
        let mut wrapper = mc_mobilecoind_api::printable::PrintableWrapper::new();
        wrapper.set_public_address((&account_key.subaddress(10)).into());
        let b58_code = wrapper.b58_encode().unwrap();
        assert_eq!(response.get_b58_code(), b58_code,);

        // Subaddress that is out of index or an invalid monitor id should error.
        let request = mc_mobilecoind_api::GetPublicAddressRequest::new();
        assert!(client.get_public_address(&request).is_err());

        let mut request = mc_mobilecoind_api::GetPublicAddressRequest::new();
        request.set_monitor_id(vec![3; 3]);
        request.set_subaddress_index(10);
        assert!(client.get_public_address(&request).is_err());

        let mut request = mc_mobilecoind_api::GetPublicAddressRequest::new();
        request.set_monitor_id(id.to_vec());
        request.set_subaddress_index(0);
        assert!(client.get_public_address(&request).is_err());

        let mut request = mc_mobilecoind_api::GetPublicAddressRequest::new();
        request.set_monitor_id(id.to_vec());
        request.set_subaddress_index(1000);
        assert!(client.get_public_address(&request).is_err());
    }

    #[test_with_logger]
    fn test_get_ledger_info_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(3, &vec![], &vec![], logger.clone(), &mut rng);

        // Call get ledger info.
        let response = client
            .get_ledger_info(&mc_mobilecoind_api::Empty::new())
            .unwrap();
        assert_eq!(response.block_count, ledger_db.num_blocks().unwrap());
        assert_eq!(response.txo_count, ledger_db.num_txos().unwrap());
    }

    #[test_with_logger]
    fn test_get_block_info_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(3, &vec![], &vec![], logger.clone(), &mut rng);

        // Call get block info for a valid block.
        let mut request = mc_mobilecoind_api::GetBlockInfoRequest::new();
        request.set_block(0);

        let response = client.get_block_info(&request).unwrap();
        assert_eq!(response.key_image_count, 0); // test code does not generate any key images
        assert_eq!(response.txo_count, 3); // 3 recipients = 3 tx outs

        // Call with an invalid block number.
        let mut request = mc_mobilecoind_api::GetBlockInfoRequest::new();
        request.set_block(ledger_db.num_blocks().unwrap());

        assert!(client.get_block_info(&request).is_err());
    }

    #[test_with_logger]
    fn test_get_block_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(3, &vec![], &vec![], logger.clone(), &mut rng);

        // Call get block info for a valid block.
        let mut request = mc_mobilecoind_api::GetBlockRequest::new();
        request.set_block(0);

        let response = client.get_block(&request).unwrap();
        assert_eq!(
            Block::try_from(response.get_block()).unwrap(),
            ledger_db.get_block(0).unwrap()
        );
        // FIXME: Implement block signatures for mobilecoind and test
        assert_eq!(response.txos.len(), 3); // 3 recipients = 3 tx outs
        assert_eq!(response.key_images.len(), 0); // test code does not generate any key images
    }

    #[test_with_logger]
    fn test_get_tx_status_as_sender_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (mut ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(3, &vec![], &vec![], logger.clone(), &mut rng);

        // Insert a block with some key images in it.
        let recipient = AccountKey::random(&mut rng).default_subaddress();
        add_block_to_ledger_db(
            &mut ledger_db,
            &[recipient.clone()],
            DEFAULT_PER_RECIPIENT_AMOUNT,
            &[KeyImage::from(1), KeyImage::from(2), KeyImage::from(3)],
            &mut rng,
        );

        // Create receiver_tx_receipt based on the txout created in add_block_to_ledger_db
        let block = ledger_db
            .get_block_contents(ledger_db.num_blocks().unwrap() - 1)
            .unwrap();
        let output = block.outputs[0].clone();

        let mut receiver_receipt = mc_mobilecoind_api::ReceiverTxReceipt::new();
        receiver_receipt.set_recipient(mc_mobilecoind_api::external::PublicAddress::from(
            &recipient,
        ));
        receiver_receipt.set_tx_public_key(
            mc_mobilecoind_api::external::CompressedRistretto::from(&output.public_key),
        );
        receiver_receipt.set_tx_out_hash(output.hash().into());
        receiver_receipt.set_tombstone(1);
        // For this test, confirmation number is irrelevant, so left blank

        // A receipt with all key images in the same block is verified.
        {
            let mut sender_receipt = mc_mobilecoind_api::SenderTxReceipt::new();
            sender_receipt.set_key_image_list(RepeatedField::from_vec(vec![
                (&KeyImage::from(1)).into(),
                (&KeyImage::from(2)).into(),
                (&KeyImage::from(3)).into(),
            ]));
            sender_receipt.set_tombstone(1);

            let mut request = mc_mobilecoind_api::SubmitTxResponse::new();
            request.set_sender_tx_receipt(sender_receipt);
            request.set_receiver_tx_receipt_list(RepeatedField::from_vec(vec![
                receiver_receipt.clone()
            ]));

            let response = client.get_tx_status_as_sender(&request).unwrap();

            assert_eq!(
                response.get_status(),
                mc_mobilecoind_api::TxStatus::Verified
            );
        }

        // A receipt with an extra key image should be TransactionFailureKeyImageBlockMismatch.
        {
            let mut sender_receipt = mc_mobilecoind_api::SenderTxReceipt::new();
            sender_receipt.set_key_image_list(RepeatedField::from_vec(vec![
                (&KeyImage::from(1)).into(),
                (&KeyImage::from(2)).into(),
                (&KeyImage::from(3)).into(),
                (&KeyImage::from(4)).into(),
            ]));
            sender_receipt.set_tombstone(1);

            let mut request = mc_mobilecoind_api::SubmitTxResponse::new();
            request.set_sender_tx_receipt(sender_receipt);
            request.set_receiver_tx_receipt_list(RepeatedField::from_vec(vec![
                receiver_receipt.clone()
            ]));

            let response = client.get_tx_status_as_sender(&request).unwrap();

            assert_eq!(
                response.get_status(),
                mc_mobilecoind_api::TxStatus::TransactionFailureKeyImageBlockMismatch
            );
        }

        // A receipt with key images that are not in the ledger is pending (unknown) if its tombstone block
        // has not been exceeded.
        {
            let mut sender_receipt = mc_mobilecoind_api::SenderTxReceipt::new();
            sender_receipt.set_key_image_list(RepeatedField::from_vec(vec![
                (&KeyImage::from(4)).into(),
                (&KeyImage::from(5)).into(),
            ]));
            sender_receipt.set_tombstone(ledger_db.num_blocks().unwrap() as u64 + 1);

            let mut request = mc_mobilecoind_api::SubmitTxResponse::new();
            request.set_sender_tx_receipt(sender_receipt);
            request.set_receiver_tx_receipt_list(RepeatedField::from_vec(vec![
                receiver_receipt.clone()
            ]));

            let response = client.get_tx_status_as_sender(&request).unwrap();

            assert_eq!(response.get_status(), mc_mobilecoind_api::TxStatus::Unknown);
        }

        // A receipt with key images that are not in the ledger having its tombstone block exceeded.
        {
            let mut sender_receipt = mc_mobilecoind_api::SenderTxReceipt::new();
            sender_receipt.set_key_image_list(RepeatedField::from_vec(vec![
                (&KeyImage::from(4)).into(),
                (&KeyImage::from(5)).into(),
            ]));
            sender_receipt.set_tombstone(ledger_db.num_blocks().unwrap() as u64);

            let mut request = mc_mobilecoind_api::SubmitTxResponse::new();
            request.set_sender_tx_receipt(sender_receipt);
            request.set_receiver_tx_receipt_list(RepeatedField::from_vec(vec![
                receiver_receipt.clone()
            ]));

            let response = client.get_tx_status_as_sender(&request).unwrap();

            assert_eq!(
                response.get_status(),
                mc_mobilecoind_api::TxStatus::TombstoneBlockExceeded
            );
        }

        // Add another block to the ledger with different key images, to the same recipient
        add_block_to_ledger_db(
            &mut ledger_db,
            &[recipient.clone()],
            DEFAULT_PER_RECIPIENT_AMOUNT,
            &[KeyImage::from(4), KeyImage::from(5), KeyImage::from(6)],
            &mut rng,
        );

        // A receipt with all the key_images in the ledger, but in different blocks, should fail.
        {
            let mut sender_receipt = mc_mobilecoind_api::SenderTxReceipt::new();
            sender_receipt.set_key_image_list(RepeatedField::from_vec(vec![
                (&KeyImage::from(1)).into(),
                (&KeyImage::from(2)).into(),
                (&KeyImage::from(4)).into(),
            ]));
            sender_receipt.set_tombstone(1);

            let mut request = mc_mobilecoind_api::SubmitTxResponse::new();
            request.set_sender_tx_receipt(sender_receipt);
            request.set_receiver_tx_receipt_list(RepeatedField::from_vec(vec![
                receiver_receipt.clone()
            ]));

            let response = client.get_tx_status_as_sender(&request).unwrap();

            assert_eq!(
                response.get_status(),
                mc_mobilecoind_api::TxStatus::TransactionFailureKeyImageBlockMismatch
            );
        }

        // Create receiver_tx_receipt based on the txout created in add_block_to_ledger_db
        let block2 = ledger_db
            .get_block_contents(ledger_db.num_blocks().unwrap() - 1)
            .unwrap();
        let output2 = block2.outputs[0].clone();

        let mut receiver_receipt2 = mc_mobilecoind_api::ReceiverTxReceipt::new();
        receiver_receipt2.set_recipient(mc_mobilecoind_api::external::PublicAddress::from(
            &recipient,
        ));
        receiver_receipt2.set_tx_public_key(
            mc_mobilecoind_api::external::CompressedRistretto::from(&output2.public_key),
        );
        receiver_receipt2.set_tx_out_hash(output2.hash().into());
        receiver_receipt2.set_tombstone(1);
        // For this test, confirmation number is irrelevant, so left blank

        // A receiver receipt with multiple public keys in different blocks should fail
        {
            let mut sender_receipt = mc_mobilecoind_api::SenderTxReceipt::new();
            sender_receipt.set_key_image_list(RepeatedField::from_vec(vec![
                (&KeyImage::from(1)).into(),
                (&KeyImage::from(2)).into(),
            ]));
            sender_receipt.set_tombstone(1);

            let mut request = mc_mobilecoind_api::SubmitTxResponse::new();
            request.set_sender_tx_receipt(sender_receipt);
            request.set_receiver_tx_receipt_list(RepeatedField::from_vec(vec![
                receiver_receipt.clone(),
                receiver_receipt2,
            ]));

            let response = client.get_tx_status_as_sender(&request).unwrap();

            assert_eq!(
                response.get_status(),
                mc_mobilecoind_api::TxStatus::PublicKeysInDifferentBlocks
            );
        }

        // A receipt with a public key which has not landed in the ledger, but key_images which have
        // should fail.
        // A receiver receipt with multiple public keys in different blocks should fail
        {
            let mut sender_receipt = mc_mobilecoind_api::SenderTxReceipt::new();
            sender_receipt.set_key_image_list(RepeatedField::from_vec(vec![
                (&KeyImage::from(1)).into(),
                (&KeyImage::from(4)).into(),
            ]));
            sender_receipt.set_tombstone(1);

            let mut request = mc_mobilecoind_api::SubmitTxResponse::new();
            request.set_sender_tx_receipt(sender_receipt);
            // Modify the receiver_receipt to have a public key not in the ledger
            receiver_receipt.set_tx_public_key(
                mc_mobilecoind_api::external::CompressedRistretto::from(
                    &CompressedRistrettoPublic::from(&RistrettoPublic::from_random(&mut rng)),
                ),
            );
            request.set_receiver_tx_receipt_list(RepeatedField::from_vec(vec![receiver_receipt]));

            let response = client.get_tx_status_as_sender(&request).unwrap();

            assert_eq!(
                response.get_status(),
                mc_mobilecoind_api::TxStatus::TransactionFailureKeyImageAlreadySpent
            );
        }
    }

    #[test_with_logger]
    fn test_get_tx_status_as_receiver_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (mut ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(3, &vec![], &vec![], logger.clone(), &mut rng);

        // A call with an invalid hash should fail
        {
            let mut receipt = mc_mobilecoind_api::ReceiverTxReceipt::new();
            receipt.set_tombstone(1);

            let mut request = mc_mobilecoind_api::GetTxStatusAsReceiverRequest::new();
            request.set_receipt(receipt);

            assert!(client.get_tx_status_as_receiver(&request).is_err());
        }

        // A call with a hash thats in the ledger should return Verified
        {
            let tx_out = ledger_db.get_tx_out_by_index(1).unwrap();
            let hash = tx_out.hash();

            let mut receipt = mc_mobilecoind_api::ReceiverTxReceipt::new();
            receipt.set_tx_out_hash(hash.to_vec());
            receipt.set_tombstone(1);

            let mut request = mc_mobilecoind_api::GetTxStatusAsReceiverRequest::new();
            request.set_receipt(receipt);

            let response = client.get_tx_status_as_receiver(&request).unwrap();
            assert_eq!(
                response.get_status(),
                mc_mobilecoind_api::TxStatus::Verified
            );
        }

        // A call with a hash thats is not in the ledger and hasn't exceeded tombstone block should
        // return Unknown
        {
            let hash = [0; 32];

            let mut receipt = mc_mobilecoind_api::ReceiverTxReceipt::new();
            receipt.set_tx_out_hash(hash.to_vec());
            receipt.set_tombstone(ledger_db.num_blocks().unwrap() as u64 + 1);

            let mut request = mc_mobilecoind_api::GetTxStatusAsReceiverRequest::new();
            request.set_receipt(receipt);

            let response = client.get_tx_status_as_receiver(&request).unwrap();
            assert_eq!(response.get_status(), mc_mobilecoind_api::TxStatus::Unknown);
        }

        // A call with a hash thats is not in the ledger and has exceeded tombstone block should
        // return TombstoneBlockExceeded
        {
            let hash = [0; 32];

            let mut receipt = mc_mobilecoind_api::ReceiverTxReceipt::new();
            receipt.set_tx_out_hash(hash.to_vec());
            receipt.set_tombstone(ledger_db.num_blocks().unwrap() as u64);

            let mut request = mc_mobilecoind_api::GetTxStatusAsReceiverRequest::new();
            request.set_receipt(receipt);

            let response = client.get_tx_status_as_receiver(&request).unwrap();
            assert_eq!(
                response.get_status(),
                mc_mobilecoind_api::TxStatus::TombstoneBlockExceeded
            );
        }

        // Now create a monitor for the receiver to test confirmation numbers
        let receiver = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            receiver.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // Insert into database.
        let monitor_id = mobilecoind_db.add_monitor(&data).unwrap();
        let mut transaction_builder = TransactionBuilder::new(MockFogResolver::default());
        let (tx_out, tx_confirmation) = transaction_builder
            .add_output(10, &receiver.subaddress(0), &mut rng)
            .unwrap();

        add_txos_to_ledger_db(&mut ledger_db, &vec![tx_out.clone()], &mut rng);

        // A request with a valid confirmation number and monitor ID should return Verified
        {
            let hash = tx_out.hash();

            let mut receipt = mc_mobilecoind_api::ReceiverTxReceipt::new();
            receipt.set_tx_public_key(mc_mobilecoind_api::external::CompressedRistretto::from(
                &tx_out.public_key,
            ));
            receipt.set_tx_out_hash(hash.to_vec());
            receipt.set_tombstone(10);
            receipt.set_confirmation_number(tx_confirmation.to_vec());

            let mut request = mc_mobilecoind_api::GetTxStatusAsReceiverRequest::new();
            request.set_receipt(receipt);
            request.set_monitor_id(monitor_id.to_vec());

            let response = client.get_tx_status_as_receiver(&request).unwrap();
            assert_eq!(
                response.get_status(),
                mc_mobilecoind_api::TxStatus::Verified
            );
        }

        // A request with an a bad confirmation number and a monitor ID should return InvalidConfirmationNumber
        {
            let hash = tx_out.hash();

            let mut receipt = mc_mobilecoind_api::ReceiverTxReceipt::new();
            receipt.set_tx_public_key(mc_mobilecoind_api::external::CompressedRistretto::from(
                &tx_out.public_key,
            ));
            receipt.set_tx_out_hash(hash.to_vec());
            receipt.set_tombstone(10);
            receipt.set_confirmation_number(vec![0u8; 32]);

            let mut request = mc_mobilecoind_api::GetTxStatusAsReceiverRequest::new();
            request.set_receipt(receipt);
            request.set_monitor_id(monitor_id.to_vec());

            let response = client.get_tx_status_as_receiver(&request).unwrap();
            assert_eq!(
                response.get_status(),
                mc_mobilecoind_api::TxStatus::InvalidConfirmationNumber
            );
        }
    }

    #[test_with_logger]
    fn test_get_processed_block(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let account_key = AccountKey::random(&mut rng);
        // Note: we skip the first block to test what happens when we try and query a block that will never get processed.
        let monitor_data = MonitorData::new(
            account_key.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            1,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (mut ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                3,
                &vec![account_key.default_subaddress()],
                &vec![],
                logger.clone(),
                &mut rng,
            );

        // Insert into database.
        let monitor_id = mobilecoind_db.add_monitor(&monitor_data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Verify the data we got matches what we expected. This assumes knowledge about how the
        // test ledger is constructed by the test utils.
        let num_blocks = ledger_db.num_blocks().expect("failed getting num blocks");
        let account_tx_outs: Vec<TxOut> = (0..num_blocks)
            .map(|idx| {
                let block_contents = ledger_db.get_block_contents(idx as u64).unwrap();
                // We grab the 4th tx out in each block since the test ledger had 3 random
                // recipients, followed by our known recipient.
                // See the call to `get_testing_environment` at the beginning of the test.
                block_contents.outputs[3].clone()
            })
            .collect();

        let expected_utxos: Vec<UnspentTxOut> = account_tx_outs
            .iter()
            .map(|tx_out| {
                // Calculate the key image for this tx out.
                let tx_public_key = RistrettoPublic::try_from(&tx_out.public_key).unwrap();
                let onetime_private_key = recover_onetime_private_key(
                    &tx_public_key,
                    account_key.view_private_key(),
                    &account_key.subaddress_spend_private(0),
                );
                let key_image = KeyImage::from(&onetime_private_key);

                // Craft the expected UnspentTxOut
                UnspentTxOut {
                    tx_out: tx_out.clone(),
                    subaddress_index: 0,
                    key_image,
                    value: test_utils::DEFAULT_PER_RECIPIENT_AMOUNT,
                    attempted_spend_height: 0,
                    attempted_spend_tombstone: 0,
                }
            })
            .collect();

        // Query a bunch of blocks and verify the data.
        for block_index in 1..num_blocks {
            let mut request = mc_mobilecoind_api::GetProcessedBlockRequest::new();
            request.set_monitor_id(monitor_id.to_vec());
            request.set_block(block_index);

            let response = client
                .get_processed_block(&request)
                .expect("failed to get processed block");

            // We expect one utxo per block for our monitor.
            let tx_outs = response.get_tx_outs();
            assert_eq!(tx_outs.len(), 1);
            let tx_out = &tx_outs[0];

            let expected_utxo = &expected_utxos[block_index as usize];

            assert_eq!(tx_out.get_monitor_id().to_vec(), monitor_id.to_vec());
            assert_eq!(
                tx_out.get_subaddress_index(),
                expected_utxo.subaddress_index
            );
            assert_eq!(
                tx_out.get_public_key(),
                &(&expected_utxo.tx_out.public_key).into(),
            );
            assert_eq!(tx_out.get_key_image(), &(&expected_utxo.key_image).into());
            assert_eq!(tx_out.value, expected_utxo.value);
            assert_eq!(
                tx_out.get_direction(),
                mc_mobilecoind_api::ProcessedTxOutDirection::Received,
            );

            // test address code
            let mut request = mc_mobilecoind_api::GetPublicAddressRequest::new();
            request.set_monitor_id(monitor_id.to_vec());
            request.set_subaddress_index(expected_utxo.subaddress_index);
            let response = client.get_public_address(&request).unwrap();
            let public_address = PublicAddress::try_from(response.get_public_address()).unwrap();

            let mut request = mc_mobilecoind_api::CreateAddressCodeRequest::new();
            request.set_receiver(mc_api::external::PublicAddress::from(&public_address));
            let response = client.create_address_code(&request).unwrap();
            let b58_code = response.get_b58_code();

            assert_eq!(tx_out.get_address_code(), b58_code);
        }

        // Add a block with a key images that spend the first two utxos and see that we get the
        // data we expect.
        {
            let recipient = AccountKey::random(&mut rng).default_subaddress();
            add_block_to_ledger_db(
                &mut ledger_db,
                &[recipient],
                DEFAULT_PER_RECIPIENT_AMOUNT,
                &[
                    expected_utxos[monitor_data.first_block as usize].key_image,
                    expected_utxos[monitor_data.first_block as usize + 1].key_image,
                ],
                &mut rng,
            );

            wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

            let mut request = mc_mobilecoind_api::GetProcessedBlockRequest::new();
            request.set_monitor_id(monitor_id.to_vec());
            request.set_block(num_blocks);

            let response = client
                .get_processed_block(&request)
                .expect("failed to get processed block");

            let tx_outs = response.get_tx_outs();
            assert_eq!(tx_outs.len(), 2);

            let expected_utxos_by_key_image = HashMap::from_iter(
                expected_utxos
                    .iter()
                    .skip(monitor_data.first_block as usize)
                    .take(2)
                    .map(|utxo| (utxo.key_image, utxo.clone())),
            );

            for tx_out in tx_outs.iter() {
                let expected_utxo = expected_utxos_by_key_image
                    .get(
                        &KeyImage::try_from(tx_out.get_key_image().get_data())
                            .expect("failed constructing key image"),
                    )
                    .expect("failed getting expected utxo");

                assert_eq!(tx_out.get_monitor_id().to_vec(), monitor_id.to_vec());
                assert_eq!(
                    tx_out.get_subaddress_index(),
                    expected_utxo.subaddress_index
                );
                assert_eq!(
                    tx_out.get_public_key(),
                    &(&expected_utxo.tx_out.public_key).into(),
                );
                assert_eq!(tx_out.get_key_image(), &(&expected_utxo.key_image).into());
                assert_eq!(tx_out.value, expected_utxo.value);
                assert_eq!(
                    tx_out.get_direction(),
                    mc_mobilecoind_api::ProcessedTxOutDirection::Spent,
                );
            }
        }

        // Query a block that will never get processed since its before the monitor's first block.
        let mut request = mc_mobilecoind_api::GetProcessedBlockRequest::new();
        request.set_monitor_id(monitor_id.to_vec());
        request.set_block(0);

        assert!(client.get_processed_block(&request).is_err());

        // Query a block that hasn't been processed yet.
        let mut request = mc_mobilecoind_api::GetProcessedBlockRequest::new();
        request.set_monitor_id(monitor_id.to_vec());
        request.set_block(num_blocks + 1);

        assert!(client.get_processed_block(&request).is_err());

        // Query with an unknown monitor id.
        let mut request = mc_mobilecoind_api::GetProcessedBlockRequest::new();
        request.set_monitor_id(vec![1; 32]);
        request.set_block(1);

        assert!(client.get_processed_block(&request).is_err());
    }

    #[test_with_logger]
    /// Get mixins should return the correct number of distinct mixins.
    fn test_get_mixins(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([44u8; 32]);

        let sender = AccountKey::random(&mut rng);

        // 1 known recipient, 3 random recipients and no monitors.
        let (ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                3,
                &vec![sender.default_subaddress()],
                &vec![],
                logger.clone(),
                &mut rng,
            );

        // The ledger contains 40 transaction outputs.
        assert_eq!(ledger_db.num_txos().unwrap(), 40);

        // Response should contain the requested number of distinct mixins.
        {
            let mut request = mc_mobilecoind_api::GetMixinsRequest::new();
            request.set_num_mixins(13);
            let response = client.get_mixins(&request).unwrap();
            let mixins_with_proofs: Vec<mc_mobilecoind_api::TxOutWithProof> =
                response.get_mixins().to_vec();

            assert_eq!(mixins_with_proofs.len(), 13);

            // Mixins should be distinct.
            let mixin_hashes: HashSet<_> = mixins_with_proofs
                .iter()
                .map(|mixin| {
                    let tx_out: TxOut = TxOut::try_from(mixin.get_output()).unwrap();
                    tx_out.hash()
                })
                .collect();

            assert_eq!(mixin_hashes.len(), mixins_with_proofs.len());
        }

        // Requesting more mixins than exist in the ledger should return an error.
        // TODO: enforce a limit on the number of mixins that may be requested.
        {
            let mut bad_request = mc_mobilecoind_api::GetMixinsRequest::new();
            bad_request.set_num_mixins(10000);
            let response = client.get_mixins(&bad_request);

            assert!(response.is_err());
        }
    }

    #[test_with_logger]
    /// Get mixins should not return an "excluded" TxOut.
    fn test_get_mixins_excluded(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([74u8; 32]);

        let sender = AccountKey::random(&mut rng);

        // 1 known recipient, 3 random recipients and no monitors.
        let (ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                3,
                &vec![sender.default_subaddress()],
                &vec![],
                logger.clone(),
                &mut rng,
            );

        assert_eq!(ledger_db.num_txos().unwrap(), 40);

        // A list of outputs to exclude.
        let to_exclude: Vec<TxOut> = {
            let data = MonitorData::new(
                sender.clone(),
                0,  // first_subaddress
                20, // num_subaddresses
                0,  // first_block
                "", // name
            )
            .unwrap();

            // Insert into database.
            let monitor_id = mobilecoind_db.add_monitor(&data).unwrap();

            // Allow the new monitor to process the ledger.
            wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

            // Select some outputs from the ledger.
            mobilecoind_db
                .get_utxos_for_subaddress(&monitor_id, 0)
                .unwrap()
                .into_iter()
                .map(|utxo| utxo.tx_out)
                .collect()
        };

        assert_eq!(to_exclude.len(), 10);

        // The ledger contains 40 outputs. Requesting 30 and excluding 10 should return exactly the
        // remaining 30.
        let mut request = mc_mobilecoind_api::GetMixinsRequest::new();
        request.set_num_mixins(30);
        request.set_excluded(RepeatedField::from_vec(
            to_exclude
                .iter()
                .map(mc_mobilecoind_api::external::TxOut::from)
                .collect(),
        ));

        let response = client.get_mixins(&request).unwrap();

        let mixins_with_proofs: Vec<mc_mobilecoind_api::TxOutWithProof> =
            response.get_mixins().to_vec();

        // Should contain 30 mixins
        assert_eq!(mixins_with_proofs.len(), 30);

        // None of the excluded outputs should be returned as mixins.
        let excluded_hashes: HashSet<_> = to_exclude.iter().map(|tx_out| tx_out.hash()).collect();

        for mixin in &mixins_with_proofs {
            let mixin: TxOut = TxOut::try_from(mixin.get_output()).unwrap();
            assert!(!excluded_hashes.contains(&mixin.hash()));
        }
    }

    #[test_with_logger]
    /// Get mixins should return valid membership proofs.
    fn test_get_mixins_membership_proofs(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([89u8; 32]);
        let sender = AccountKey::random(&mut rng);

        // 1 known recipient, 3 random recipients and no monitors.
        let (ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                3,
                &vec![sender.default_subaddress()],
                &vec![],
                logger.clone(),
                &mut rng,
            );

        let mixins_with_proofs: Vec<mc_mobilecoind_api::TxOutWithProof> = {
            let mut request = mc_mobilecoind_api::GetMixinsRequest::new();
            request.set_num_mixins(13);
            let response = client.get_mixins(&request).unwrap();
            response.get_mixins().to_vec()
        };

        assert_eq!(mixins_with_proofs.len(), 13);

        // Each membership proof should be correct.
        for mixin_with_proof in &mixins_with_proofs {
            let mixin: TxOut = TxOut::try_from(mixin_with_proof.get_output()).unwrap();

            // The returned proof should be correct.
            let expected_proof = {
                let index = ledger_db.get_tx_out_index_by_hash(&mixin.hash()).unwrap();
                let proofs = ledger_db.get_tx_out_proof_of_memberships(&[index]).unwrap();
                assert_eq!(proofs.len(), 1);
                mc_mobilecoind_api::external::TxOutMembershipProof::from(&proofs[0])
            };

            assert_eq!(mixin_with_proof.get_proof(), &expected_proof);
        }
    }

    #[test_with_logger]
    /// Should return a correct proof-of-membership for each requested TxOut.
    fn test_get_membership_proofs(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let sender = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            sender.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                3,
                &vec![sender.default_subaddress()],
                &vec![],
                logger.clone(),
                &mut rng,
            );

        // Insert into database.
        let monitor_id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Select some outputs from the ledger.
        let outputs: Vec<TxOut> = {
            let unspent_outputs = mobilecoind_db
                .get_utxos_for_subaddress(&monitor_id, 0)
                .unwrap();

            vec![
                unspent_outputs[1].tx_out.clone(),
                unspent_outputs[3].tx_out.clone(),
                unspent_outputs[5].tx_out.clone(),
            ]
        };

        let mut request = mc_mobilecoind_api::GetMembershipProofsRequest::new();
        request.set_outputs(RepeatedField::from_vec(
            outputs
                .iter()
                .map(mc_mobilecoind_api::external::TxOut::from)
                .collect(),
        ));

        let response = client.get_membership_proofs(&request).unwrap();

        // The response should should contain an element for each requested output.
        assert_eq!(response.output_list.len(), outputs.len());

        for (tx_out, output_with_proof) in outputs.iter().zip(response.get_output_list().iter()) {
            // The response should contain a TxOutWithProof for each requested TxOut.
            assert_eq!(
                output_with_proof.get_output(),
                &mc_mobilecoind_api::external::TxOut::from(tx_out)
            );

            // The returned proof should be correct.
            let expected_proof = {
                let index = ledger_db.get_tx_out_index_by_hash(&tx_out.hash()).unwrap();
                let proofs = ledger_db.get_tx_out_proof_of_memberships(&[index]).unwrap();
                assert_eq!(proofs.len(), 1);

                mc_mobilecoind_api::external::TxOutMembershipProof::from(&proofs[0])
            };

            assert_eq!(output_with_proof.get_proof(), &expected_proof);
        }
    }

    #[test_with_logger]
    fn test_generate_tx(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let sender = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            sender.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                3,
                &vec![sender.default_subaddress()],
                &vec![],
                logger.clone(),
                &mut rng,
            );

        // Insert into database.
        let monitor_id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Get list of unspent tx outs
        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, 0)
            .unwrap();
        assert!(!utxos.is_empty());

        // Generate two random recipients.
        let receiver1 = AccountKey::random(&mut rng);
        let receiver2 = AccountKey::random(&mut rng);

        let outlays = vec![
            Outlay {
                value: 123,
                receiver: receiver1.default_subaddress(),
            },
            Outlay {
                value: 456,
                receiver: receiver2.default_subaddress(),
            },
        ];

        // Call generate tx.
        let mut request = mc_mobilecoind_api::GenerateTxRequest::new();
        request.set_sender_monitor_id(monitor_id.to_vec());
        request.set_change_subaddress(0);
        request.set_input_list(RepeatedField::from_vec(
            utxos
                .iter()
                .map(mc_mobilecoind_api::UnspentTxOut::from)
                .collect(),
        ));
        request.set_outlay_list(RepeatedField::from_vec(
            outlays
                .iter()
                .map(mc_mobilecoind_api::Outlay::from)
                .collect(),
        ));

        // Test the happy flow.
        {
            let response = client.generate_tx(&request).unwrap();

            // Sanity test the response.
            let tx_proposal = response.get_tx_proposal();

            let expected_num_inputs: u64 = (outlays.iter().map(|outlay| outlay.value).sum::<u64>()
                / test_utils::DEFAULT_PER_RECIPIENT_AMOUNT)
                + 1;
            assert_eq!(
                tx_proposal.get_input_list().len(),
                expected_num_inputs as usize
            );
            assert_eq!(
                tx_proposal.get_tx().get_prefix().get_inputs().len(),
                expected_num_inputs as usize
            );
            assert_eq!(tx_proposal.get_outlay_list(), request.get_outlay_list());
            assert_eq!(
                tx_proposal.get_tx().get_prefix().get_outputs().len(),
                outlays.len() + 1
            ); // Extra output for change.

            let tx = Tx::try_from(tx_proposal.get_tx()).unwrap();

            // The transaction should contain an output for each outlay, and one for change.
            assert_eq!(tx.prefix.outputs.len(), outlays.len() + 1);

            // The transaction should have a confirmation code for each outlay
            assert_eq!(
                outlays.len(),
                tx_proposal.get_outlay_confirmation_numbers().len()
            );

            let change_value = test_utils::DEFAULT_PER_RECIPIENT_AMOUNT
                - outlays.iter().map(|outlay| outlay.value).sum::<u64>()
                - MINIMUM_FEE;

            for (account_key, expected_value) in &[
                (&receiver1, outlays[0].value),
                (&receiver2, outlays[1].value),
                (&sender, change_value),
            ] {
                // Find the first output belonging to the account, and get its value.
                // This assumes that each output is sent to a different account key.
                let (value, _blinding) = tx
                    .prefix
                    .outputs
                    .iter()
                    .find_map(|tx_out| {
                        let output_public_key =
                            RistrettoPublic::try_from(&tx_out.public_key).unwrap();
                        let shared_secret = get_tx_out_shared_secret(
                            account_key.view_private_key(),
                            &output_public_key,
                        );
                        tx_out.amount.get_value(&shared_secret).ok()
                    })
                    .expect("There should be an output belonging to the account key.");

                assert_eq!(value, *expected_value);
            }

            // Santity test fee
            assert_eq!(tx_proposal.get_fee(), MINIMUM_FEE);
            assert_eq!(tx_proposal.get_tx().get_prefix().fee, MINIMUM_FEE);

            // Sanity test tombstone block
            let num_blocks = ledger_db.num_blocks().unwrap();
            assert_eq!(
                tx_proposal.get_tx().get_prefix().tombstone_block,
                num_blocks + DEFAULT_NEW_TX_BLOCK_ATTEMPTS
            );
        }

        // Invalid input scenarios should result in an error.
        {
            // No monitor id
            let mut request = request.clone();
            request.set_sender_monitor_id(vec![]);
            assert!(client.generate_tx(&request).is_err());
        }

        {
            // Unrecognized monitor id
            let sender = AccountKey::random(&mut rng);
            let data = MonitorData::new(
                sender.clone(),
                0,  // first_subaddress
                20, // num_subaddresses
                0,  // first_block
                "", // name
            )
            .unwrap();

            let mut request = request.clone();
            request.set_sender_monitor_id(MonitorId::from(&data).to_vec());
            assert!(client.generate_tx(&request).is_err());
        }

        {
            // Subaddress index out of range
            let mut request = request.clone();
            request.set_change_subaddress(data.first_subaddress + data.num_subaddresses + 1);
            assert!(client.generate_tx(&request).is_err());
        }

        {
            // Junk input
            let mut request = request.clone();
            request
                .mut_input_list()
                .push(mc_mobilecoind_api::UnspentTxOut::default());
            assert!(client.generate_tx(&request).is_err());
        }

        {
            // Attempt to spend more than we have
            let num_blocks = ledger_db.num_blocks().unwrap();
            let mut request = request.clone();
            request.set_outlay_list(RepeatedField::from_vec(vec![
                mc_mobilecoind_api::Outlay::from(&Outlay {
                    receiver: receiver1.default_subaddress(),
                    value: test_utils::DEFAULT_PER_RECIPIENT_AMOUNT * num_blocks,
                }),
            ]));
            assert!(client.generate_tx(&request).is_err());
        }
    }

    #[test_with_logger]
    fn test_get_block_index_by_tx_pub_key(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(3, &vec![], &vec![], logger.clone(), &mut rng);

        // Grab the first TxOut of each block in the database and verify its index.
        for block_index in 0..test_utils::GET_TESTING_ENVIRONMENT_NUM_BLOCKS as u64 {
            let block_contents = ledger_db.get_block_contents(block_index).unwrap();
            let tx_out_pub_key = mc_mobilecoind_api::external::CompressedRistretto::from(
                &block_contents.outputs[0].public_key,
            );

            let mut request = mc_mobilecoind_api::GetBlockIndexByTxPubKeyRequest::new();
            request.set_tx_public_key(tx_out_pub_key);

            let response = client.get_block_index_by_tx_pub_key(&request).unwrap();
            assert_eq!(block_index, response.block);
        }
    }

    #[test_with_logger]
    fn test_generate_transfer_code_tx(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let sender = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            sender.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (mut ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                3,
                &vec![sender.default_subaddress()],
                &vec![],
                logger.clone(),
                &mut rng,
            );

        // Insert into database.
        let monitor_id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Get list of unspent tx outs
        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, 0)
            .unwrap();
        assert!(!utxos.is_empty());

        // Call generate transfer code ctx.
        let mut request = mc_mobilecoind_api::GenerateTransferCodeTxRequest::new();
        request.set_sender_monitor_id(monitor_id.to_vec());
        request.set_change_subaddress(0);
        request.set_input_list(RepeatedField::from_vec(
            utxos
                .iter()
                .map(mc_mobilecoind_api::UnspentTxOut::from)
                .collect(),
        ));
        request.set_value(1337);

        let response = client.generate_transfer_code_tx(&request).unwrap();

        // Test that the generated transaction can be picked up by mobilecoind.
        {
            let tx_proposal = TxProposal::try_from(response.get_tx_proposal()).unwrap();
            let key_images = tx_proposal.tx.key_images();
            let outputs = tx_proposal.tx.prefix.outputs.clone();
            let block_contents = BlockContents::new(key_images, outputs);

            // Append to ledger.
            let num_blocks = ledger_db.num_blocks().unwrap();
            let parent = ledger_db.get_block(num_blocks - 1).unwrap();
            let new_block = Block::new_with_parent(
                BLOCK_VERSION,
                &parent,
                &Default::default(),
                &block_contents,
            );
            ledger_db
                .append_block(&new_block, &block_contents, None)
                .unwrap();

            // Use root entropy to construct AccountKey.
            let mut root_entropy = [0u8; 32];
            root_entropy.copy_from_slice(response.get_entropy());
            let root_id = RootIdentity::from(&root_entropy);
            let account_key = AccountKey::try_from(&root_id)
                .expect("Could not create account key from root identity");

            // Add a monitor based on the entropy we received.
            let monitor_data = MonitorData::new(
                account_key,
                DEFAULT_SUBADDRESS_INDEX, // first_subaddress
                1,                        // num_subaddresses
                0,                        // first_block
                "",                       // name
            )
            .unwrap();

            let monitor_id = mobilecoind_db.add_monitor(&monitor_data).unwrap();

            // Wait for sync to complete.
            wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

            // Get utxos for the new account and verify we only have one utxo.
            let utxos = mobilecoind_db
                .get_utxos_for_subaddress(&monitor_id, DEFAULT_SUBADDRESS_INDEX)
                .unwrap();
            assert_eq!(utxos.len(), 1);

            let utxo = &utxos[0];

            assert_eq!(utxo.value, 1337);
            assert_eq!(
                utxo.tx_out.public_key,
                RistrettoPublic::try_from(response.get_tx_public_key())
                    .unwrap()
                    .into()
            );
        }
    }

    #[test_with_logger]
    fn test_generate_optimization_tx(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let sender = AccountKey::random(&mut rng);
        let sender_default_subaddress = sender.default_subaddress();
        let data = MonitorData::new(
            sender.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, and a bunch of random recipients and no monitors.
        // The random recipients are needed for mixins.
        let num_random_recipients = MAX_INPUTS as u32 * RING_SIZE as u32
            / test_utils::GET_TESTING_ENVIRONMENT_NUM_BLOCKS as u32;
        let (mut ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                num_random_recipients as u32,
                &vec![sender_default_subaddress.clone()],
                &vec![],
                logger.clone(),
                &mut rng,
            );

        // Add a bunch of blocks/utxos for our recipient.
        for _ in 0..MAX_INPUTS {
            let _ = add_block_to_ledger_db(
                &mut ledger_db,
                &[sender_default_subaddress.clone()],
                DEFAULT_PER_RECIPIENT_AMOUNT,
                &[KeyImage::from(rng.next_u64())],
                &mut rng,
            );
        }

        // Insert into database.
        let monitor_id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Get list of unspent tx outs
        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, 0)
            .unwrap();
        assert!(!utxos.is_empty());

        // Call generate optimization tx.
        let mut request = mc_mobilecoind_api::GenerateOptimizationTxRequest::new();
        request.set_monitor_id(monitor_id.to_vec());
        request.set_subaddress(0);

        let response = client.generate_optimization_tx(&request).unwrap();

        // Sanity test the response.
        let tx_proposal = TxProposal::try_from(response.get_tx_proposal()).unwrap();

        let expected_num_inputs: usize = MAX_INPUTS as usize;
        assert_eq!(tx_proposal.utxos.len(), expected_num_inputs);
        assert_eq!(tx_proposal.tx.prefix.inputs.len(), expected_num_inputs);

        assert_eq!(tx_proposal.outlays.len(), 1);
        assert_eq!(
            tx_proposal.outlays[0].receiver,
            data.account_key.subaddress(0)
        );
        assert_eq!(
            tx_proposal.outlays[0].value,
            // Each UTXO we have has PER_RECIPIENT_AMOUNT coins. We will be merging MAX_INPUTS of those
            // into a single output, minus the fee.
            (DEFAULT_PER_RECIPIENT_AMOUNT * MAX_INPUTS as u64) - MINIMUM_FEE,
        );

        assert_eq!(tx_proposal.outlay_index_to_tx_out_index.len(), 1);
        assert_eq!(tx_proposal.outlay_index_to_tx_out_index[&0], 0);

        assert_eq!(tx_proposal.tx.prefix.outputs.len(), 1);
        let tx_out = &tx_proposal.tx.prefix.outputs[0];
        let tx_public_key = RistrettoPublic::try_from(&tx_out.public_key).unwrap();
        let shared_secret =
            get_tx_out_shared_secret(data.account_key.view_private_key(), &tx_public_key);
        let (value, _blinding) = tx_out.amount.get_value(&shared_secret).unwrap();
        assert_eq!(value, tx_proposal.outlays[0].value);

        // Santity test fee
        assert_eq!(tx_proposal.fee(), MINIMUM_FEE);
        assert_eq!(tx_proposal.tx.prefix.fee, MINIMUM_FEE);

        // Sanity test tombstone block
        let num_blocks = ledger_db.num_blocks().unwrap();
        assert_eq!(
            tx_proposal.tx.prefix.tombstone_block,
            num_blocks + DEFAULT_NEW_TX_BLOCK_ATTEMPTS
        );
    }

    #[test_with_logger]
    fn test_generate_tx_from_tx_out_list(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let sender = AccountKey::random(&mut rng);
        let _sender_default_subaddress = sender.default_subaddress();
        let data = MonitorData::new(
            sender.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                3,
                &vec![sender.default_subaddress()],
                &vec![],
                logger.clone(),
                &mut rng,
            );

        // Insert into database.
        let monitor_id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Get list of unspent tx outs
        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, 0)
            .unwrap();
        assert!(!utxos.is_empty());

        // Build a request to transfer the first two TxOuts
        let tx_utxos = utxos[0..2].to_vec();
        let mut request = mc_mobilecoind_api::GenerateTxFromTxOutListRequest::new();
        request.set_account_key((&sender).into());
        request.set_input_list(RepeatedField::from_vec(
            tx_utxos
                .iter()
                .map(mc_mobilecoind_api::UnspentTxOut::from)
                .collect(),
        ));
        let receiver = AccountKey::random(&mut rng);
        request.set_receiver((&receiver.default_subaddress()).into());
        request.set_fee(MINIMUM_FEE);

        let response = client.generate_tx_from_tx_out_list(&request).unwrap();
        let tx_proposal = TxProposal::try_from(response.get_tx_proposal()).unwrap();

        // We should end up with one output
        assert_eq!(tx_proposal.tx.prefix.outputs.len(), 1);

        // It should equal the sum of the inputs minus the fee
        let expected_value = tx_utxos.iter().map(|utxo| utxo.value).sum::<u64>() - MINIMUM_FEE;

        let tx_out = &tx_proposal.tx.prefix.outputs[0];
        let tx_public_key = RistrettoPublic::try_from(&tx_out.public_key).unwrap();
        let shared_secret = get_tx_out_shared_secret(receiver.view_private_key(), &tx_public_key);
        let (value, _blinding) = tx_out.amount.get_value(&shared_secret).unwrap();
        assert_eq!(value, expected_value);
    }

    #[test_with_logger]
    fn test_submit_tx(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let sender = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            sender.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (ledger_db, mobilecoind_db, client, _server, server_conn_manager) =
            get_testing_environment(
                3,
                &vec![sender.default_subaddress()],
                &vec![],
                logger.clone(),
                &mut rng,
            );

        // Insert into database.
        let monitor_id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Get list of unspent tx outs
        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, 0)
            .unwrap();
        assert!(!utxos.is_empty());

        // Generate two random recipients.
        let receiver1 = AccountKey::random(&mut rng);
        let receiver2 = AccountKey::random(&mut rng);

        let outlays = vec![
            Outlay {
                value: 123,
                receiver: receiver1.default_subaddress(),
            },
            Outlay {
                value: 456,
                receiver: receiver2.default_subaddress(),
            },
        ];

        // Call generate tx.
        let mut request = mc_mobilecoind_api::GenerateTxRequest::new();
        request.set_sender_monitor_id(monitor_id.to_vec());
        request.set_change_subaddress(0);
        request.set_input_list(RepeatedField::from_vec(
            utxos
                .iter()
                .map(mc_mobilecoind_api::UnspentTxOut::from)
                .collect(),
        ));
        request.set_outlay_list(RepeatedField::from_vec(
            outlays
                .iter()
                .map(mc_mobilecoind_api::Outlay::from)
                .collect(),
        ));

        // Get our propsal which we'll use for the test.
        let response = client.generate_tx(&request).unwrap();
        let tx_proposal = TxProposal::try_from(response.get_tx_proposal()).unwrap();
        let tx = tx_proposal.tx.clone();
        let outlay_confirmation_numbers = tx_proposal.outlay_confirmation_numbers.clone();

        // Test the happy flow.
        {
            let mut request = mc_mobilecoind_api::SubmitTxRequest::new();
            request.set_tx_proposal(mc_mobilecoind_api::TxProposal::from(&tx_proposal));

            let response = client.submit_tx(&request).unwrap();

            // Get the submitted transaction - it was submitted to one of our mock peers, but we
            // don't know to which. We enforce the invariant that only one transaction should've been
            // submitted.
            let mut opt_submitted_tx: Option<Tx> = None;
            for mock_peer in server_conn_manager.conns() {
                let inner = mock_peer.read();
                match (inner.proposed_txs.len(), opt_submitted_tx.clone()) {
                    (0, _) => {
                        // Nothing submitted to the current peer.
                    }
                    (1, None) => {
                        // Found our tx.
                        opt_submitted_tx = Some(inner.proposed_txs[0].clone())
                    }
                    (1, Some(_)) => {
                        panic!("Tx submitted to two peers?!");
                    }
                    (_, _) => {
                        panic!("Multiple transactions submitted?!");
                    }
                }
            }
            let submitted_tx = opt_submitted_tx.unwrap();
            assert_eq!(tx, submitted_tx);

            // Sanity test sender receipt
            let key_images: Vec<KeyImage> = response
                .get_sender_tx_receipt()
                .get_key_image_list()
                .iter()
                .map(|key_image| KeyImage::try_from(key_image).unwrap())
                .collect();
            assert_eq!(key_images.len(), tx.prefix.inputs.len());

            for key_image in key_images.iter() {
                let subaddress_id = mobilecoind_db
                    .get_subaddress_id_by_utxo_id(&UtxoId::from(key_image))
                    .unwrap();
                assert_eq!(subaddress_id.monitor_id, monitor_id);
            }

            assert_eq!(
                response.get_sender_tx_receipt().tombstone,
                tx.prefix.tombstone_block
            );

            // Sanity the receiver receipts.
            assert_eq!(response.get_receiver_tx_receipt_list().len(), outlays.len());
            for (outlay, receipt) in outlays
                .iter()
                .zip(response.get_receiver_tx_receipt_list().iter())
            {
                assert_eq!(
                    outlay.receiver,
                    PublicAddress::try_from(receipt.get_recipient()).unwrap()
                );

                assert_eq!(receipt.tombstone, tx.prefix.tombstone_block);
                let mut confirmation_bytes = [0u8; 32];
                confirmation_bytes.copy_from_slice(&receipt.confirmation_number);

                let confirmation_number = TxOutConfirmationNumber::from(confirmation_bytes);
                assert!(outlay_confirmation_numbers.contains(&confirmation_number));
            }

            assert_eq!(
                response.get_receiver_tx_receipt_list().len() + 1, // There's a change output that is not part of the receipts
                tx.prefix.outputs.len()
            );

            let tx_out_hashes: Vec<_> = tx.prefix.outputs.iter().map(TxOut::hash).collect();
            let tx_out_public_keys: Vec<_> = tx
                .prefix
                .outputs
                .iter()
                .map(|tx_out| tx_out.public_key.to_bytes())
                .collect();

            for receipt in response.get_receiver_tx_receipt_list().iter() {
                let hash: [u8; 32] = receipt.get_tx_out_hash().try_into().unwrap();
                assert!(tx_out_hashes.contains(&hash));

                let public_key =
                    GenericArray::<u8, U32>::from_slice(receipt.get_tx_public_key().get_data());
                assert!(tx_out_public_keys.contains(&public_key));
            }

            // Check that attempted_spend_height got updated for the relevant utxos.
            let account_utxos = mobilecoind_db
                .get_utxos_for_subaddress(&monitor_id, 0)
                .unwrap();
            let tx_proposal_utxo_ids: Vec<UtxoId> =
                tx_proposal.utxos.iter().map(UtxoId::from).collect();
            let mut matched_utxos = 0;
            for utxo in account_utxos.iter() {
                if tx_proposal_utxo_ids.contains(&UtxoId::from(utxo)) {
                    assert!(utxo.attempted_spend_height > 0);
                    matched_utxos += 1;
                } else {
                    assert_eq!(utxo.attempted_spend_height, 0);
                }
            }
            assert_eq!(matched_utxos, tx_proposal.utxos.len());
        }
    }

    #[test_with_logger]
    fn test_get_balance_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let account_key = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            account_key.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                3,
                &vec![account_key.default_subaddress()],
                &vec![],
                logger.clone(),
                &mut rng,
            );

        // Insert into database.
        let id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Get balance for a monitor_id/subaddress index that has a balance.
        let mut request = mc_mobilecoind_api::GetBalanceRequest::new();
        request.set_monitor_id(id.to_vec());
        request.set_subaddress_index(0);

        let response = client.get_balance(&request).unwrap();
        assert_eq!(
            response.balance,
            test_utils::DEFAULT_PER_RECIPIENT_AMOUNT * ledger_db.num_blocks().unwrap()
        );

        // Get balance for subaddress with no utxos should return 0.
        let mut request = mc_mobilecoind_api::GetBalanceRequest::new();
        request.set_monitor_id(id.to_vec());
        request.set_subaddress_index(1);

        let response = client.get_balance(&request).unwrap();
        assert_eq!(response.balance, 0);

        // Non-existent monitor id should return 0
        let mut id2 = id.clone().to_vec();
        id2[0] = !id2[0];

        let mut request = mc_mobilecoind_api::GetBalanceRequest::new();
        request.set_monitor_id(id2);
        request.set_subaddress_index(0);

        assert_eq!(response.balance, 0);

        // Invalid monitor id should error
        let mut request = mc_mobilecoind_api::GetBalanceRequest::new();
        request.set_monitor_id(vec![1; 2]);
        request.set_subaddress_index(0);

        assert!(client.get_balance(&request).is_err());
    }

    #[test_with_logger]
    fn test_send_payment(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let sender = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            sender.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (ledger_db, mobilecoind_db, client, _server, server_conn_manager) =
            get_testing_environment(
                3,
                &vec![sender.default_subaddress()],
                &vec![],
                logger.clone(),
                &mut rng,
            );

        // Insert into database.
        let monitor_id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Get list of unspent tx outs
        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, 0)
            .unwrap();
        assert!(!utxos.is_empty());

        // Generate two random recipients.
        let receiver1 = AccountKey::random(&mut rng);
        let receiver2 = AccountKey::random(&mut rng);

        let outlays = vec![
            Outlay {
                value: 123,
                receiver: receiver1.default_subaddress(),
            },
            Outlay {
                value: 456,
                receiver: receiver2.default_subaddress(),
            },
        ];

        // Call send payment.
        let mut request = mc_mobilecoind_api::SendPaymentRequest::new();
        request.set_sender_monitor_id(monitor_id.to_vec());
        request.set_sender_subaddress(0);
        request.set_outlay_list(RepeatedField::from_vec(
            outlays
                .iter()
                .map(mc_mobilecoind_api::Outlay::from)
                .collect(),
        ));

        let response = client.send_payment(&request).unwrap();

        // Get the submitted transaction - it was submitted to one of our mock peers, but we
        // don't know to which. We enforce the invariant that only one transaction should've been
        // submitted.
        let mut opt_submitted_tx: Option<Tx> = None;
        for mock_peer in server_conn_manager.conns() {
            let inner = mock_peer.read();
            match (inner.proposed_txs.len(), opt_submitted_tx.clone()) {
                (0, _) => {
                    // Nothing submitted to the current peer.
                }
                (1, None) => {
                    // Found our tx.
                    opt_submitted_tx = Some(inner.proposed_txs[0].clone())
                }
                (1, Some(_)) => {
                    panic!("Tx submitted to two peers?!");
                }
                (_, _) => {
                    panic!("Multiple transactions submitted?!");
                }
            }
        }
        let submitted_tx = opt_submitted_tx.unwrap();
        assert_eq!(
            submitted_tx,
            Tx::try_from(response.get_tx_proposal().get_tx()).unwrap()
        );

        // Sanity test sender receipt
        let key_images: Vec<KeyImage> = response
            .get_sender_tx_receipt()
            .get_key_image_list()
            .iter()
            .map(|key_image| KeyImage::try_from(key_image).unwrap())
            .collect();
        assert_eq!(key_images.len(), submitted_tx.prefix.inputs.len());

        for key_image in key_images.iter() {
            let subaddress_id = mobilecoind_db
                .get_subaddress_id_by_utxo_id(&UtxoId::from(key_image))
                .unwrap();
            assert_eq!(subaddress_id.monitor_id, monitor_id);
        }

        assert_eq!(
            response.get_sender_tx_receipt().tombstone,
            submitted_tx.prefix.tombstone_block
        );

        // Sanity the receiver receipts.
        assert_eq!(response.get_receiver_tx_receipt_list().len(), outlays.len());
        for (outlay, receipt) in outlays
            .iter()
            .zip(response.get_receiver_tx_receipt_list().iter())
        {
            assert_eq!(
                outlay.receiver,
                PublicAddress::try_from(receipt.get_recipient()).unwrap()
            );

            assert_eq!(receipt.tombstone, submitted_tx.prefix.tombstone_block);
        }

        assert_eq!(
            response.get_receiver_tx_receipt_list().len() + 1, // There's a change output that is not part of the receipts
            submitted_tx.prefix.outputs.len()
        );

        let tx_out_hashes: Vec<_> = submitted_tx
            .prefix
            .outputs
            .iter()
            .map(TxOut::hash)
            .collect();
        let tx_out_public_keys: Vec<_> = submitted_tx
            .prefix
            .outputs
            .iter()
            .map(|tx_out| tx_out.public_key.to_bytes())
            .collect();

        for receipt in response.get_receiver_tx_receipt_list().iter() {
            let hash: [u8; 32] = receipt.get_tx_out_hash().try_into().unwrap();
            assert!(tx_out_hashes.contains(&hash));

            let public_key =
                GenericArray::<u8, U32>::from_slice(receipt.get_tx_public_key().get_data());
            assert!(tx_out_public_keys.contains(&public_key));
        }

        // Check that attempted_spend_height got updated for the relevant utxos.
        let tx_proposal = TxProposal::try_from(response.get_tx_proposal()).unwrap();

        let account_utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, 0)
            .unwrap();
        let tx_proposal_utxo_ids: Vec<UtxoId> =
            tx_proposal.utxos.iter().map(UtxoId::from).collect();
        let mut matched_utxos = 0;
        for utxo in account_utxos.iter() {
            if tx_proposal_utxo_ids.contains(&UtxoId::from(utxo)) {
                assert!(utxo.attempted_spend_height > 0);
                matched_utxos += 1;
            } else {
                assert_eq!(utxo.attempted_spend_height, 0);
            }
        }
        assert_eq!(matched_utxos, tx_proposal.utxos.len());
    }

    #[test_with_logger]
    fn test_send_payment_with_max_input_utxo_value(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let sender = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            sender.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (mut ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(10, &vec![], &vec![], logger.clone(), &mut rng);

        // Add a few utxos to our recipient, such that all of them are required to create the test
        // transaction.
        for amount in &[10, 20, MINIMUM_FEE] {
            add_block_to_ledger_db(
                &mut ledger_db,
                &[sender.default_subaddress()],
                *amount,
                &[KeyImage::from(rng.next_u64())],
                &mut rng,
            );
        }

        // Insert into database.
        let monitor_id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Get list of unspent tx outs
        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, 0)
            .unwrap();
        assert!(!utxos.is_empty());

        let utxos_by_keyimage: HashMap<KeyImage, UnspentTxOut> = utxos
            .iter()
            .map(|utxo| (utxo.key_image.clone(), utxo.clone()))
            .collect();

        // Generate two random recipients.
        let receiver1 = AccountKey::random(&mut rng);
        let receiver2 = AccountKey::random(&mut rng);

        let outlays = vec![
            Outlay {
                value: 10,
                receiver: receiver1.default_subaddress(),
            },
            Outlay {
                value: 20,
                receiver: receiver2.default_subaddress(),
            },
        ];

        // Call send payment without a limit on UTXOs - a single large UTXO should be selected.
        let mut request = mc_mobilecoind_api::SendPaymentRequest::new();
        request.set_sender_monitor_id(monitor_id.to_vec());
        request.set_sender_subaddress(0);
        request.set_outlay_list(RepeatedField::from_vec(
            outlays
                .iter()
                .map(mc_mobilecoind_api::Outlay::from)
                .collect(),
        ));

        let response = client.send_payment(&request).unwrap();

        // Check which UTXOs were selected - it should be all of them.
        let selected_utxos: Vec<UnspentTxOut> = response
            .get_sender_tx_receipt()
            .get_key_image_list()
            .iter()
            .map(|proto_key_image| {
                let key_image = KeyImage::try_from(proto_key_image).unwrap();
                utxos_by_keyimage.get(&key_image).unwrap().clone()
            })
            .collect();
        assert_eq!(
            HashSet::from_iter(selected_utxos),
            HashSet::from_iter(utxos.clone())
        );

        // Try again, placing a cap at the max UTXO that can be selected. This should cause send
        // payment to fail.
        request.set_max_input_utxo_value(20);
        match client.send_payment(&request) {
            Ok(_) => panic!("Should've returned an error"),
            Err(GrpcError::RpcFailure(RpcStatus { details, .. })) => {
                assert_eq!(
                    details,
                    Some("transactions_manager.build_transaction: Insufficient funds".to_owned())
                );
            }
            Err(err) => panic!("Unexpected error: {:?}", err),
        };

        // Trying with a higher limit should work.
        request.set_max_input_utxo_value(MINIMUM_FEE);
        let response = client.send_payment(&request).unwrap();

        let selected_utxos: Vec<UnspentTxOut> = response
            .get_sender_tx_receipt()
            .get_key_image_list()
            .iter()
            .map(|proto_key_image| {
                let key_image = KeyImage::try_from(proto_key_image).unwrap();
                utxos_by_keyimage.get(&key_image).unwrap().clone()
            })
            .collect();
        assert_eq!(
            HashSet::from_iter(selected_utxos),
            HashSet::from_iter(utxos)
        );
    }

    #[test_with_logger]
    fn test_send_payment_to_fog(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // Fog resolver
        let fog_private_key = RistrettoPrivate::from_random(&mut rng);
        let fog_pubkey_resolver_factory: Arc<
            dyn Fn(&[FogUri]) -> Result<MockFogPubkeyResolver, String> + Send + Sync,
        > = Arc::new(move |_| -> Result<MockFogPubkeyResolver, String> {
            let mut fog_pubkey_resolver = MockFogPubkeyResolver::new();
            let pubkey = RistrettoPublic::from(&fog_private_key);
            fog_pubkey_resolver
                .expect_get_fog_pubkey()
                .return_once(move |_recipient| {
                    Ok(FullyValidatedFogPubkey {
                        pubkey,
                        pubkey_expiry: 10000,
                    })
                });
            Ok(fog_pubkey_resolver)
        });

        let sender = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            sender.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (ledger_db, mobilecoind_db) = test_utils::get_test_databases(
            3,
            &vec![sender.default_subaddress()],
            test_utils::GET_TESTING_ENVIRONMENT_NUM_BLOCKS,
            logger.clone(),
            &mut rng,
        );
        let port = test_utils::get_free_port();

        let uri = MobilecoindUri::from_str(&format!("insecure-mobilecoind://127.0.0.1:{}/", port))
            .unwrap();

        log::debug!(logger, "Setting up server {:?}", port);
        let (_server, server_conn_manager) = test_utils::setup_server::<MockFogPubkeyResolver>(
            logger.clone(),
            ledger_db.clone(),
            mobilecoind_db.clone(),
            None,
            Some(fog_pubkey_resolver_factory),
            &uri,
        );
        log::debug!(logger, "Setting up client {:?}", port);
        let client = test_utils::setup_client(&uri, &logger);

        // Insert into database.
        let monitor_id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Get list of unspent tx outs
        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, 0)
            .unwrap();
        assert!(!utxos.is_empty());

        // Generate two random recipients.
        let receiver1 = AccountKey::random(&mut rng);

        let der_bytes = pem::parse(mc_crypto_x509_test_vectors::ok_rsa_head())
            .expect("Could not parse RSA test vector as PEM")
            .contents;
        let fog_authority_spki = x509_signature::parse_certificate(&der_bytes)
            .expect("Could not parse X509 certificate from DER")
            .subject_public_key_info()
            .spki();

        let receiver2 = AccountKey::random_with_fog(
            &mut rng,
            "fog://fog.unittest.mobilecoin.com",
            "",
            fog_authority_spki,
        )
        .expect("Could not create AccountKey with fog data");

        let outlays = vec![
            Outlay {
                value: 123,
                receiver: receiver1.default_subaddress(),
            },
            Outlay {
                value: 456,
                receiver: receiver2.default_subaddress(),
            },
        ];

        // Call send payment.
        let mut request = mc_mobilecoind_api::SendPaymentRequest::new();
        request.set_sender_monitor_id(monitor_id.to_vec());
        request.set_sender_subaddress(0);
        request.set_outlay_list(RepeatedField::from_vec(
            outlays
                .iter()
                .map(mc_mobilecoind_api::Outlay::from)
                .collect(),
        ));

        let response = client.send_payment(&request).unwrap();

        // Get the submitted transaction - it was submitted to one of our mock peers, but we
        // don't know to which. We enforce the invariant that only one transaction should've been
        // submitted.
        let mut opt_submitted_tx: Option<Tx> = None;
        for mock_peer in server_conn_manager.conns() {
            let inner = mock_peer.read();
            match (inner.proposed_txs.len(), opt_submitted_tx.clone()) {
                (0, _) => {
                    // Nothing submitted to the current peer.
                }
                (1, None) => {
                    // Found our tx.
                    opt_submitted_tx = Some(inner.proposed_txs[0].clone())
                }
                (1, Some(_)) => {
                    panic!("Tx submitted to two peers?!");
                }
                (_, _) => {
                    panic!("Multiple transactions submitted?!");
                }
            }
        }
        let submitted_tx = opt_submitted_tx.unwrap();
        assert_eq!(
            submitted_tx,
            Tx::try_from(response.get_tx_proposal().get_tx()).unwrap()
        );

        // Verify that the first receipient TxOut hint cannot be decrypted with the fog key, since
        // that one was not going to a fog address.
        let tx_out_index1 = *(response
            .get_tx_proposal()
            .get_outlay_index_to_tx_out_index()
            .get(&0)
            .unwrap()) as usize;
        let tx_out1 = submitted_tx.prefix.outputs.get(tx_out_index1).unwrap();
        let mut output_fog_hint = FogHint::new(RistrettoPublic::from_random(&mut rng));
        assert!(!bool::from(FogHint::ct_decrypt(
            &fog_private_key,
            &tx_out1.e_fog_hint,
            &mut output_fog_hint
        )));

        // The second recipient (the fog recipient) should have a valid hint.
        let tx_out_index2 = *(response
            .get_tx_proposal()
            .get_outlay_index_to_tx_out_index()
            .get(&1)
            .unwrap()) as usize;
        let tx_out2 = submitted_tx.prefix.outputs.get(tx_out_index2).unwrap();
        let mut output_fog_hint = FogHint::new(RistrettoPublic::from_random(&mut rng));
        assert!(bool::from(FogHint::ct_decrypt(
            &fog_private_key,
            &tx_out2.e_fog_hint,
            &mut output_fog_hint
        )));
        assert_eq!(
            output_fog_hint.get_view_pubkey(),
            &CompressedRistrettoPublic::from(receiver2.default_subaddress().view_public_key())
        );
    }

    #[test_with_logger]
    fn test_send_payment_to_fog_fails_without_fog_resolver(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let sender = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            sender.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                3,
                &vec![sender.default_subaddress()],
                &vec![],
                logger.clone(),
                &mut rng,
            );

        // Insert into database.
        let monitor_id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Get list of unspent tx outs
        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, 0)
            .unwrap();
        assert!(!utxos.is_empty());

        // Generate two random recipients.
        let receiver1 = AccountKey::random(&mut rng);

        let der_bytes = pem::parse(mc_crypto_x509_test_vectors::ok_rsa_head())
            .expect("Could not parse RSA test vector as PEM")
            .contents;
        let fog_authority_spki = x509_signature::parse_certificate(&der_bytes)
            .expect("Could not parse X509 certificate from DER")
            .subject_public_key_info()
            .spki();

        let receiver2 = AccountKey::random_with_fog(
            &mut rng,
            "fog://fog.unittest.mobilecoin.com",
            "",
            fog_authority_spki,
        )
        .expect("Could not create AccountKey with fog details");

        let outlays = vec![
            Outlay {
                value: 123,
                receiver: receiver1.default_subaddress(),
            },
            Outlay {
                value: 456,
                receiver: receiver2.default_subaddress(),
            },
        ];

        // Call send payment.
        let mut request = mc_mobilecoind_api::SendPaymentRequest::new();
        request.set_sender_monitor_id(monitor_id.to_vec());
        request.set_sender_subaddress(0);
        request.set_outlay_list(RepeatedField::from_vec(
            outlays
                .iter()
                .map(mc_mobilecoind_api::Outlay::from)
                .collect(),
        ));

        let response = client.send_payment(&request);
        assert!(response.is_err());
    }

    #[test_with_logger]
    fn test_pay_address_code(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let sender = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            sender.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                3,
                &vec![sender.default_subaddress()],
                &vec![],
                logger.clone(),
                &mut rng,
            );

        // Insert into database.
        let monitor_id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Get list of unspent tx outs
        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, 0)
            .unwrap();
        assert!(!utxos.is_empty());

        // Generate a random recipient.
        let receiver = AccountKey::random(&mut rng);

        // Generate b58 address code for this recipient.
        let receiver_public_address = receiver.default_subaddress();
        let mut wrapper = mc_mobilecoind_api::printable::PrintableWrapper::new();
        wrapper.set_public_address((&receiver_public_address).into());
        let b58_code = wrapper.b58_encode().unwrap();

        // Call pay address code.
        let mut request = mc_mobilecoind_api::PayAddressCodeRequest::new();
        request.set_sender_monitor_id(monitor_id.to_vec());
        request.set_sender_subaddress(0);
        request.set_receiver_b58_code(b58_code);
        request.set_amount(1234);

        let response = client.pay_address_code(&request).unwrap();

        // Sanity the receiver receipt.
        assert_eq!(response.get_receiver_tx_receipt_list().len(), 1);

        let receipt = &response.get_receiver_tx_receipt_list()[0];
        assert_eq!(
            receipt.get_recipient(),
            &mc_mobilecoind_api::external::PublicAddress::from(&receiver_public_address)
        );
    }

    #[test_with_logger]
    fn test_pay_address_code_alternate_change(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let sender = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            sender.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (ledger_db, mobilecoind_db, client, _server, server_conn_manager) =
            get_testing_environment(
                3,
                &vec![sender.default_subaddress()],
                &vec![],
                logger.clone(),
                &mut rng,
            );

        // Insert into database.
        let monitor_id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Get list of unspent tx outs
        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, 0)
            .unwrap();
        assert!(!utxos.is_empty());

        // Generate a random recipient.
        let receiver = AccountKey::random(&mut rng);

        // Generate b58 address code for this recipient.
        let receiver_public_address = receiver.default_subaddress();
        let mut wrapper = mc_mobilecoind_api::printable::PrintableWrapper::new();
        wrapper.set_public_address((&receiver_public_address).into());
        let b58_code = wrapper.b58_encode().unwrap();

        let test_amount = 345;

        let mut request = mc_mobilecoind_api::PayAddressCodeRequest::new();
        request.set_sender_monitor_id(monitor_id.to_vec());
        request.set_sender_subaddress(0);
        request.set_receiver_b58_code(b58_code);
        request.set_amount(test_amount);
        request.set_override_change_subaddress(true);
        request.set_change_subaddress(1);

        // Explicitly set fee so we can check change amount
        let fee = 1000;
        request.set_fee(fee);

        let response = client.pay_address_code(&request).unwrap();
        let total_value = response
            .get_tx_proposal()
            .get_input_list()
            .iter()
            .map(|utxo| utxo.value as u64)
            .sum::<u64>();

        let mut opt_submitted_tx: Option<Tx> = None;
        for mock_peer in server_conn_manager.conns() {
            let inner = mock_peer.read();
            match (inner.proposed_txs.len(), opt_submitted_tx.clone()) {
                (0, _) => {
                    // Nothing submitted to the current peer.
                }
                (1, None) => {
                    // Found our tx.
                    opt_submitted_tx = Some(inner.proposed_txs[0].clone())
                }
                (1, Some(_)) => {
                    panic!("Tx submitted to two peers?!");
                }
                (_, _) => {
                    panic!("Multiple transactions submitted?!");
                }
            }
        }

        let submitted_tx = opt_submitted_tx.unwrap();
        let mut change_subaddress_found = false;
        for tx_out in submitted_tx.prefix.outputs {
            let tx_out_target_key = RistrettoPublic::try_from(&tx_out.target_key).unwrap();
            let tx_public_key = RistrettoPublic::try_from(&tx_out.public_key).unwrap();

            let subaddress_spk = SubaddressSPKId::from(&recover_public_subaddress_spend_key(
                &sender.view_private_key(),
                &tx_out_target_key,
                &tx_public_key,
            ));

            match mobilecoind_db.get_subaddress_id_by_spk(&subaddress_spk) {
                Ok(data) => {
                    if data.index == 1 {
                        assert!(!change_subaddress_found);
                        change_subaddress_found = true;
                        let shared_secret =
                            get_tx_out_shared_secret(sender.view_private_key(), &tx_public_key);

                        let (change_value, _blinding) = tx_out
                            .amount
                            .get_value(&shared_secret)
                            .expect("Malformed amount");

                        assert_eq!(total_value - test_amount - fee, change_value);
                    }
                }
                Err(Error::SubaddressSPKNotFound) => continue,
                Err(_err) => {
                    panic!("Error matching subaddress");
                }
            };
        }

        assert!(change_subaddress_found);
    }

    #[test_with_logger]
    fn test_request_code(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (_ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(3, &vec![], &vec![], logger.clone(), &mut rng);

        // Random receiver address.
        let receiver = AccountKey::random(&mut rng).default_subaddress();

        // Try with just a receiver
        {
            // Generate a request code
            let mut request = mc_mobilecoind_api::CreateRequestCodeRequest::new();
            request.set_receiver(mc_api::external::PublicAddress::from(&receiver));

            let response = client.create_request_code(&request).unwrap();
            let b58_code = response.get_b58_code();

            // Attempt to decode the b58.
            let mut request = mc_mobilecoind_api::ParseRequestCodeRequest::new();
            request.set_b58_code(b58_code.to_string());

            let response = client.parse_request_code(&request).unwrap();

            // Check that input equals output.
            assert_eq!(
                PublicAddress::try_from(response.get_receiver()).unwrap(),
                receiver
            );
            assert_eq!(response.value, 0);
            assert_eq!(response.get_memo(), "");
        }
        // Try with receiver and value
        {
            // Generate a request code
            let mut request = mc_mobilecoind_api::CreateRequestCodeRequest::new();
            request.set_receiver(mc_api::external::PublicAddress::from(&receiver));
            request.set_value(1234567890);

            let response = client.create_request_code(&request).unwrap();
            let b58_code = response.get_b58_code();

            // Attempt to decode it.
            let mut request = mc_mobilecoind_api::ParseRequestCodeRequest::new();
            request.set_b58_code(b58_code.to_string());

            let response = client.parse_request_code(&request).unwrap();

            // Check that input equals output.
            assert_eq!(
                PublicAddress::try_from(response.get_receiver()).unwrap(),
                receiver
            );
            assert_eq!(response.value, 1234567890);
            assert_eq!(response.get_memo(), "");
        }
        // Try with receiver, value and memo
        {
            // Generate a request code
            let mut request = mc_mobilecoind_api::CreateRequestCodeRequest::new();
            request.set_receiver(mc_api::external::PublicAddress::from(&receiver));
            request.set_value(1234567890);
            request.set_memo("hello there".to_owned());

            let response = client.create_request_code(&request).unwrap();
            let b58_code = response.get_b58_code();

            // Attempt to decode it.
            let mut request = mc_mobilecoind_api::ParseRequestCodeRequest::new();
            request.set_b58_code(b58_code.to_string());

            let response = client.parse_request_code(&request).unwrap();

            // Check that input equals output.
            assert_eq!(
                PublicAddress::try_from(response.get_receiver()).unwrap(),
                receiver
            );
            assert_eq!(response.value, 1234567890);
            assert_eq!(response.get_memo(), "hello there");
        }

        // Attempting to decode junk data should fail
        {
            let mut request = mc_mobilecoind_api::ParseRequestCodeRequest::new();
            request.set_b58_code("junk".to_owned());

            assert!(client.parse_request_code(&request).is_err());
        }
    }

    #[test_with_logger]
    fn test_transfer_code(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (mut ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(3, &vec![], &vec![], logger.clone(), &mut rng);

        // a valid transfer code must reference a tx_public_key that appears in the ledger
        // that is controlled by the root_entropy included in the code

        let root_entropy = [3u8; 32];

        // Use root entropy to construct AccountKey.
        let root_id = RootIdentity::from(&root_entropy);
        let account_key =
            AccountKey::try_from(&root_id).expect("Could not create AccountKey from RootIdentity");

        let mut transaction_builder = TransactionBuilder::new(MockFogResolver::default());
        let (tx_out, _tx_confirmation) = transaction_builder
            .add_output(
                10,
                &account_key.subaddress(DEFAULT_SUBADDRESS_INDEX),
                &mut rng,
            )
            .unwrap();

        add_txos_to_ledger_db(&mut ledger_db, &vec![tx_out.clone()], &mut rng);

        let tx_public_key = tx_out.public_key;

        // An invalid request should fail to encode.
        {
            let mut request = mc_mobilecoind_api::CreateTransferCodeRequest::new();
            request.set_entropy(vec![3u8; 8]); // key is wrong size
            request.set_tx_public_key((&tx_public_key).into());
            request.set_memo("memo".to_owned());
            assert!(client.create_transfer_code(&request).is_err());

            let mut request = mc_mobilecoind_api::CreateTransferCodeRequest::new();
            request.set_entropy(vec![4u8; 32]);
            request.set_memo("memo".to_owned()); // forgot to set tx_public_key
            assert!(client.create_transfer_code(&request).is_err());
        }

        // A valid request should allow us to encode to b58 and back to the original data.
        {
            // Encode
            let mut request = mc_mobilecoind_api::CreateTransferCodeRequest::new();
            request.set_entropy(root_entropy.to_vec());
            request.set_tx_public_key((&tx_public_key).into());
            request.set_memo("test memo".to_owned());

            let response = client.create_transfer_code(&request).unwrap();
            let b58_code = response.get_b58_code();

            // Decode
            let mut request = mc_mobilecoind_api::ParseTransferCodeRequest::new();
            request.set_b58_code(b58_code.to_string());

            let response = client.parse_transfer_code(&request).unwrap();

            // Compare
            assert_eq!(&root_entropy, response.get_entropy());
            assert_eq!(
                tx_public_key,
                CompressedRistrettoPublic::try_from(response.get_tx_public_key()).unwrap()
            );
            assert_eq!(response.get_memo(), "test memo");

            // check that the utxo that comes back from the code matches the ledger data

            // Add a monitor based on the entropy we received.
            let monitor_data = MonitorData::new(
                account_key,
                DEFAULT_SUBADDRESS_INDEX, // first_subaddress
                1,                        // num_subaddresses
                0,                        // first_block
                "",                       // name
            )
            .unwrap();

            let monitor_id = mobilecoind_db.add_monitor(&monitor_data).unwrap();

            // Wait for sync to complete.
            wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

            // Get utxos for the account and verify a match utxo.
            let utxos = mobilecoind_db
                .get_utxos_for_subaddress(&monitor_id, DEFAULT_SUBADDRESS_INDEX)
                .unwrap();
            assert_eq!(utxos.len(), 1);

            // Convert to proto utxo.
            let proto_utxo: mc_mobilecoind_api::UnspentTxOut = (&utxos[0]).into();

            assert_eq!(&proto_utxo, response.get_utxo());
        }
    }

    #[test_with_logger]
    fn test_address_code(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (_ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(3, &vec![], &vec![], logger.clone(), &mut rng);

        {
            // Random receiver address.
            let receiver = AccountKey::random(&mut rng).default_subaddress();

            // Generate a request code
            let mut request = mc_mobilecoind_api::CreateAddressCodeRequest::new();
            request.set_receiver(mc_api::external::PublicAddress::from(&receiver));

            let response = client.create_address_code(&request).unwrap();
            let b58_code = response.get_b58_code();

            // Attempt to decode it.
            let mut request = mc_mobilecoind_api::ParseAddressCodeRequest::new();
            request.set_b58_code(b58_code.to_string());

            let response = client.parse_address_code(&request).unwrap();

            // Check that input equals output.
            assert_eq!(
                PublicAddress::try_from(response.get_receiver()).unwrap(),
                receiver
            );
        }

        // Also accept a payment request code as an address code
        {
            // Random receiver address.
            let receiver = AccountKey::random(&mut rng).default_subaddress();

            // Generate a request code
            let mut request = mc_mobilecoind_api::CreateRequestCodeRequest::new();
            request.set_receiver(mc_api::external::PublicAddress::from(&receiver));
            request.set_value(1234567890);
            request.set_memo("hello there".to_owned());

            let response = client.create_request_code(&request).unwrap();
            let b58_code = response.get_b58_code();

            // Attempt to decode it.
            let mut request = mc_mobilecoind_api::ParseAddressCodeRequest::new();
            request.set_b58_code(b58_code.to_string());

            let response = client.parse_address_code(&request).unwrap();

            // Check that input equals output.
            assert_eq!(
                PublicAddress::try_from(response.get_receiver()).unwrap(),
                receiver
            );
        }

        // Attempting to decode junk data should fail
        {
            let mut request = mc_mobilecoind_api::ParseAddressCodeRequest::new();
            request.set_b58_code("junk".to_owned());

            assert!(client.parse_address_code(&request).is_err());
        }
    }

    #[test_with_logger]
    fn test_get_network_status(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let (ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(3, &vec![], &vec![], logger.clone(), &mut rng);

        let network_status = client
            .get_network_status(&mc_mobilecoind_api::Empty::new())
            .unwrap();

        assert_eq!(
            network_status.network_highest_block_index,
            ledger_db.num_blocks().unwrap() - 1
        );

        assert_eq!(
            network_status.local_block_index,
            ledger_db.num_blocks().unwrap() - 1
        );
    }

    #[test_with_logger]
    fn test_add_remove_add_monitor_with_spent_key_images(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let sender = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            sender.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (mut ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                3,
                &vec![sender.default_subaddress()],
                &vec![],
                logger.clone(),
                &mut rng,
            );

        let mut request = mc_mobilecoind_api::AddMonitorRequest::new();
        request.set_account_key(mc_api::external::AccountKey::from(&data.account_key));
        request.set_first_subaddress(data.first_subaddress);
        request.set_num_subaddresses(data.num_subaddresses);
        request.set_first_block(data.first_block);

        // Send request.
        let response = client.add_monitor(&request).expect("failed to add monitor");
        let monitor_id = response.get_monitor_id();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Verify we have the expected balance.
        let mut request = mc_mobilecoind_api::GetBalanceRequest::new();
        request.set_monitor_id(monitor_id.to_vec());
        request.set_subaddress_index(0);

        let response = client.get_balance(&request).unwrap();
        assert_eq!(
            response.balance,
            test_utils::DEFAULT_PER_RECIPIENT_AMOUNT * ledger_db.num_blocks().unwrap()
        );
        let orig_balance = response.balance;

        // Get our UTXOs and force one of them to be spent, since we want to test the
        // add-remove-add behavior with spent key images in the ledger.
        let mut request = mc_mobilecoind_api::GetUnspentTxOutListRequest::new();
        request.set_monitor_id(monitor_id.to_vec());
        request.set_subaddress_index(0);

        let response = client
            .get_unspent_tx_out_list(&request)
            .expect("failed to get unspent tx out list");

        let first_utxo = response.output_list[0].clone();
        let first_key_image = KeyImage::try_from(first_utxo.get_key_image())
            .expect("failed covnerting proto keyimage");

        let recipient = AccountKey::random(&mut rng).default_subaddress();
        add_block_to_ledger_db(
            &mut ledger_db,
            &[recipient],
            DEFAULT_PER_RECIPIENT_AMOUNT,
            &[first_key_image],
            &mut rng,
        );

        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Verify we have the expected balance.
        let mut request = mc_mobilecoind_api::GetBalanceRequest::new();
        request.set_monitor_id(monitor_id.to_vec());
        request.set_subaddress_index(0);

        let response = client.get_balance(&request).unwrap();
        assert_eq!(response.balance, orig_balance - first_utxo.value);

        // Verify we have processed block information for this monitor.
        let mut request = mc_mobilecoind_api::GetProcessedBlockRequest::new();
        request.set_monitor_id(monitor_id.to_vec());
        request.set_block(0);

        let response = client
            .get_processed_block(&request)
            .expect("Failed getting processed block");
        assert_eq!(response.get_tx_outs().len(), 1);

        // Remove the monitor.
        let mut request = mc_mobilecoind_api::RemoveMonitorRequest::new();
        request.set_monitor_id(monitor_id.to_vec());
        client
            .remove_monitor(&request)
            .expect("failed to remove monitor");

        // Check that no monitors remain.
        let monitors_map = mobilecoind_db.get_monitor_map().unwrap();
        assert_eq!(0, monitors_map.len());

        // Verify we no longer have processed block information for this monitor.
        let mut request = mc_mobilecoind_api::GetProcessedBlockRequest::new();
        request.set_monitor_id(monitor_id.to_vec());
        request.set_block(0);

        assert!(client.get_processed_block(&request).is_err());

        // Re-add the monitor.
        let mut request = mc_mobilecoind_api::AddMonitorRequest::new();
        request.set_account_key(mc_api::external::AccountKey::from(&data.account_key));
        request.set_first_subaddress(data.first_subaddress);
        request.set_num_subaddresses(data.num_subaddresses);
        request.set_first_block(data.first_block);

        let response = client.add_monitor(&request).expect("failed to add monitor");
        assert_eq!(monitor_id, response.get_monitor_id());

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Verify we have processed block information for this monitor.
        let mut request = mc_mobilecoind_api::GetProcessedBlockRequest::new();
        request.set_monitor_id(monitor_id.to_vec());
        request.set_block(0);

        let response = client
            .get_processed_block(&request)
            .expect("Failed getting processed block");
        assert_eq!(response.get_tx_outs().len(), 1);
    }
}
