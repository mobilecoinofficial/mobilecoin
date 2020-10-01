// Copyright (c) 2018-2020 MobileCoin Inc.

//! Serves node-to-node gRPC requests.

use crate::{
    api::grpc_error::ConsensusGrpcError,
    background_work_queue::BackgroundWorkQueueSenderFn,
    consensus_service::{IncomingConsensusMsg, ProposeTxCallback},
    counters,
    tx_manager::{TxManager, TxManagerError},
};
use grpcio::{RpcContext, UnarySink};
use mc_attest_api::attest::Message;
use mc_attest_enclave_api::{EnclaveMessage, PeerSession};
use mc_common::{
    logger::{log, Logger},
    ResponderId,
};
use mc_consensus_api::{
    consensus_common::ProposeTxResponse,
    consensus_peer::{
        ConsensusMsg as GrpcConsensusMsg, ConsensusMsgResponse, ConsensusMsgResult,
        FetchLatestMsgResponse, FetchTxsRequest, FetchTxsResponse, TxHashesNotInCache,
    },
    consensus_peer_grpc::ConsensusPeerApi,
    empty::Empty,
};
use mc_consensus_enclave::ConsensusEnclave;
use mc_ledger_db::Ledger;
use mc_peers::TxProposeAAD;
use mc_transaction_core::tx::TxHash;
use mc_util_grpc::{rpc_invalid_arg_error, rpc_logger, send_result};
use mc_util_metrics::SVC_COUNTERS;
use mc_util_serial::deserialize;
use std::{
    convert::{TryFrom, TryInto},
    str::FromStr,
    sync::Arc,
};

// Callback method for returning the latest SCP message issued by the local node, used to
// implement the `fetch_latest_msg` RPC call.
type FetchLatestMsgFn = Arc<dyn Fn() -> Option<mc_peers::ConsensusMsg> + Sync + Send>;

#[derive(Clone)]
pub struct PeerApiService {
    /// Enclave instance.
    consensus_enclave: Arc<dyn ConsensusEnclave + Send + Sync>,

    /// TxManager instance.
    tx_manager: Arc<dyn TxManager + Send + Sync>,

    /// Callback function for feeding consensus messages into ByzantineLedger.
    incoming_consensus_msgs_sender: BackgroundWorkQueueSenderFn<IncomingConsensusMsg>,

    /// Callback function for feeding transactions into ByzantineLedger.
    scp_client_value_sender: ProposeTxCallback,

    /// Ledger database.
    ledger: Arc<dyn Ledger + Send + Sync>,

    /// Callback function for getting the latest SCP statement the local node has issued.
    fetch_latest_msg_fn: FetchLatestMsgFn,

    /// List of recognized responder IDs to accept messages from.
    /// We only want to accept messages from peers we can initiate outgoing requests to. That is
    /// necessary for resolving TxHashes into Txs. If we received a consensus message from a peer
    /// not on this list, we won't be able to reach out to it to ask for the transaction contents.
    known_responder_ids: Vec<ResponderId>,

    /// Logger.
    logger: Logger,
}

impl PeerApiService {
    /// Creates a PeerApiService.
    ///
    /// # Arguments:
    /// * `consensus_enclave` - The local node's consensus enclave.
    /// * `ledger` - The local node's ledger.
    /// * `tx_manager` - The local node's TxManager.
    /// * `incoming_consensus_msgs_sender` - Callback for a new consensus message from a peer.
    /// * `scp_client_value_sender` - Callback for proposed transactions.
    /// * `fetch_latest_msg_fn` - Returns highest message emitted by this node.
    /// * `known_responder_ids` - Messages from peers not on this "whitelist" are ignored.
    /// * `logger` - Logger.
    pub fn new(
        consensus_enclave: Arc<dyn ConsensusEnclave + Send + Sync>,
        ledger: Arc<dyn Ledger + Send + Sync>,
        tx_manager: Arc<dyn TxManager + Send + Sync>,
        incoming_consensus_msgs_sender: BackgroundWorkQueueSenderFn<IncomingConsensusMsg>,
        scp_client_value_sender: ProposeTxCallback,
        fetch_latest_msg_fn: FetchLatestMsgFn,
        known_responder_ids: Vec<ResponderId>,
        logger: Logger,
    ) -> Self {
        Self {
            consensus_enclave,
            ledger,
            tx_manager,
            incoming_consensus_msgs_sender,
            scp_client_value_sender,
            fetch_latest_msg_fn,
            known_responder_ids,
            logger,
        }
    }

    /// Handle transactions proposed by clients to a different node.
    fn real_peer_tx_propose(
        &mut self,
        request: Message,
        logger: &Logger,
    ) -> Result<ProposeTxResponse, ConsensusGrpcError> {
        // TODO: Use the prost message directly when available, take a reference
        let enclave_msg: EnclaveMessage<PeerSession> = request.into();
        let aad = enclave_msg.aad.clone();
        let tx_contexts = self.consensus_enclave.peer_tx_propose(enclave_msg)?;

        // We fail silently here since the only effect of not having
        // origin_node/relayed_by node IDs is less efficient broadcasting.
        let (origin_node, relayed_by) = mc_util_serial::deserialize::<TxProposeAAD>(&aad)
            .map(|aad| (Some(aad.origin_node), Some(aad.relayed_by)))
            .unwrap_or((None, None));

        // Feed to manager
        for tx_context in tx_contexts {
            let tx_hash = tx_context.tx_hash;

            match self.tx_manager.insert(tx_context) {
                Ok(tx_hash) => {
                    // Submit for consideration in next SCP slot.
                    (*self.scp_client_value_sender)(
                        tx_hash,
                        origin_node.as_ref(),
                        relayed_by.as_ref(),
                    );
                }

                Err(TxManagerError::TransactionValidation(err)) => {
                    log::debug!(
                        logger,
                        "Error validating transaction {tx_hash}: {err}",
                        tx_hash = tx_hash.to_string(),
                        err = format!("{:?}", err)
                    );
                    counters::TX_VALIDATION_ERROR_COUNTER.inc(&format!("{:?}", err));
                }

                Err(err) => {
                    log::info!(
                        logger,
                        "tx_propose failed for {tx_hash}: {err}",
                        tx_hash = tx_hash.to_string(),
                        err = format!("{:?}", err)
                    );
                }
            };
        }

        Ok(ProposeTxResponse::new())
    }

    /// Returns the full, encrypted transactions corresponding to a list of transaction hashes.
    fn real_fetch_txs(
        &mut self,
        request: FetchTxsRequest,
        logger: &Logger,
    ) -> Result<FetchTxsResponse, ConsensusGrpcError> {
        let tx_hashes: Vec<TxHash> = request
            .get_tx_hashes()
            .iter()
            .map(|bytes| {
                TxHash::try_from(&bytes[..])
                    .map_err(|_| ConsensusGrpcError::InvalidArgument("Invalid TxHash".to_string()))
            })
            .collect::<Result<Vec<TxHash>, ConsensusGrpcError>>()?;

        match self.tx_manager.encrypt_for_peer(
            &tx_hashes,
            &[],
            &PeerSession::from(request.get_channel_id()),
        ) {
            Ok(enclave_message) => {
                let mut response = FetchTxsResponse::new();
                response.set_success(enclave_message.into());
                Ok(response)
            }
            Err(TxManagerError::NotInCache(tx_hashes)) => {
                let mut tx_hashes_not_in_cache = TxHashesNotInCache::new();
                tx_hashes_not_in_cache
                    .set_tx_hashes(tx_hashes.iter().map(|tx_hash| tx_hash.to_vec()).collect());

                let mut response = FetchTxsResponse::new();
                response.set_tx_hashes_not_in_cache(tx_hashes_not_in_cache);

                Ok(response)
            }
            Err(err) => {
                log::warn!(
                    logger,
                    "txs_for_peer with hashes {:?} failed: {}",
                    tx_hashes,
                    err
                );
                Err(err.into())
            }
        }
    }
}

impl ConsensusPeerApi for PeerApiService {
    /// Handle transactions proposed by clients to a different node.
    fn peer_tx_propose(
        &mut self,
        ctx: RpcContext,
        request: Message,
        sink: UnarySink<ProposeTxResponse>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(
                ctx,
                sink,
                self.real_peer_tx_propose(request, &logger)
                    .or_else(ConsensusGrpcError::into)
                    .and_then(|mut resp| {
                        resp.set_num_blocks(
                            self.ledger.num_blocks().map_err(ConsensusGrpcError::from)?,
                        );
                        Ok(resp)
                    }),
                &logger,
            )
        });
    }

    /// Handle a consensus message from another peer.
    fn send_consensus_msg(
        &mut self,
        ctx: RpcContext,
        request: GrpcConsensusMsg,
        sink: UnarySink<ConsensusMsgResponse>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            // Get the peer who delivered this message to us.
            let from_responder_id = match ResponderId::from_str(request.get_from_responder_id()) {
                Ok(val) => val,
                Err(err) => {
                    send_result(
                        ctx,
                        sink,
                        Err(rpc_invalid_arg_error(
                            "send_consensus_msg",
                            format!("From node ID deserialize error: {}", err),
                            &logger,
                        )),
                        &logger,
                    );
                    return;
                }
            };

            // Ignore consensus messages from unknown peers.
            if !self.known_responder_ids.contains(&from_responder_id) {
                let mut resp = ConsensusMsgResponse::new();
                resp.set_result(ConsensusMsgResult::UnknownPeer);
                send_result(ctx, sink, Ok(resp), &logger);
                log::warn!(
                    logger,
                    "Rejecting consensus message from unrecognized responder id {}",
                    from_responder_id
                );
                return;
            }

            let unverified_consensus_msg: mc_peers::ConsensusMsg =
                match deserialize(request.get_payload()) {
                    Ok(val) => val,
                    Err(err) => {
                        send_result(
                            ctx,
                            sink,
                            Err(rpc_invalid_arg_error(
                                "send_consensus_msg",
                                format!("Message deserialize error: {}", err),
                                &logger,
                            )),
                            &logger,
                        );
                        return;
                    }
                };

            // Validate message signature
            let consensus_msg: mc_peers::VerifiedConsensusMsg = match unverified_consensus_msg
                .clone()
                .try_into()
            {
                Ok(val) => val,
                Err(err) => {
                    log::error!(
                        logger,
                        "Signature verification failed for msg {:?} from node_id {:?}: {:?}, disregarding.",
                        unverified_consensus_msg,
                        from_responder_id,
                        err
                    );
                    send_result(
                        ctx,
                        sink,
                        Err(rpc_invalid_arg_error(
                            "send_consensus_msg",
                            format!("Signature verification failed: {}", err),
                            &logger,
                        )),
                        &logger,
                    );
                    return;
                }
            };

            log::trace!(
                logger,
                "received consensus message from {}: {:?}",
                from_responder_id,
                consensus_msg,
            );

            (self.incoming_consensus_msgs_sender)(IncomingConsensusMsg {
                from_responder_id,
                consensus_msg,
            })
            .expect("Could not send consensus input");
            let mut resp = ConsensusMsgResponse::new();
            resp.set_result(ConsensusMsgResult::Ok);
            send_result(ctx, sink, Ok(resp), &logger);
        });
    }

    /// Returns the highest consensus message issued by this node.
    fn fetch_latest_msg(
        &mut self,
        ctx: RpcContext,
        _request: Empty,
        sink: UnarySink<FetchLatestMsgResponse>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            let mut response = FetchLatestMsgResponse::new();
            if let Some(latest_msg) = (self.fetch_latest_msg_fn)() {
                let serialized_msg = mc_util_serial::serialize(&latest_msg)
                    .expect("Failed serializing consensus msg");
                response.set_payload(serialized_msg);
            }
            send_result(ctx, sink, Ok(response), &logger);
        });
    }

    /// Returns the full, encrypted transactions corresponding to a list of transaction hashes.
    fn fetch_txs(
        &mut self,
        ctx: RpcContext,
        request: FetchTxsRequest,
        sink: UnarySink<FetchTxsResponse>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(
                ctx,
                sink,
                self.real_fetch_txs(request, &logger)
                    .map_err(ConsensusGrpcError::into),
                &logger,
            )
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        api::peer_api_service::PeerApiService, background_work_queue::BackgroundWorkQueueError,
        consensus_service::IncomingConsensusMsg, tx_manager::MockTxManager,
    };
    use grpcio::{ChannelBuilder, Environment, Error::RpcFailure, Server, ServerBuilder};
    use mc_common::{
        logger::{test_with_logger, Logger},
        NodeID, ResponderId,
    };
    use mc_consensus_api::{
        consensus_peer::{ConsensusMsg, ConsensusMsgResult},
        consensus_peer_grpc,
        consensus_peer_grpc::ConsensusPeerApiClient,
    };
    use mc_consensus_enclave_mock::MockConsensusEnclave;
    use mc_consensus_scp::{
        msg::{NominatePayload, Topic::Nominate},
        Msg, QuorumSet,
    };
    use mc_crypto_keys::{Ed25519Pair, Ed25519Private};
    use mc_ledger_db::MockLedger;
    use mc_peers;
    use mc_transaction_core::{tx::TxHash, Block};
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};
    use std::sync::Arc;

    // Get sensibly-initialized mocks.
    fn get_mocks() -> (MockConsensusEnclave, MockLedger, MockTxManager) {
        let consensus_enclave = MockConsensusEnclave::new();
        let ledger = MockLedger::new();
        let tx_manager = MockTxManager::new();

        (consensus_enclave, ledger, tx_manager)
    }

    /// Always returns OK.
    fn get_incoming_consensus_msgs_sender_ok(
    ) -> Arc<dyn Fn(IncomingConsensusMsg) -> Result<(), BackgroundWorkQueueError> + Sync + Send>
    {
        Arc::new(|_msg: IncomingConsensusMsg| {
            // TODO: store inputs for inspection.
            Ok(())
        })
    }

    // Does nothing.
    fn get_scp_client_value_sender(
    ) -> Arc<dyn Fn(TxHash, Option<&NodeID>, Option<&ResponderId>) + Sync + Send> {
        Arc::new(
            |_tx_hash: TxHash, _node_id: Option<&NodeID>, _responder_id: Option<&ResponderId>| {
                // Do nothing.
            },
        )
    }

    // Returns None.
    fn get_fetch_latest_msg_fn() -> Arc<dyn Fn() -> Option<mc_peers::ConsensusMsg> + Sync + Send> {
        Arc::new(|| None)
    }

    fn get_client_server(instance: PeerApiService) -> (ConsensusPeerApiClient, Server) {
        let service = consensus_peer_grpc::create_consensus_peer_api(instance);
        let env = Arc::new(Environment::new(1));
        let mut server = ServerBuilder::new(env.clone())
            .register_service(service)
            .bind("127.0.0.1", 0)
            .build()
            .unwrap();
        server.start();
        let (_, port) = server.bind_addrs().next().unwrap();
        let ch = ChannelBuilder::new(env).connect(&format!("127.0.0.1:{}", port));
        let client = ConsensusPeerApiClient::new(ch);
        (client, server)
    }

    #[test_with_logger]
    // Should ignore a message from an unknown peer.
    fn test_send_consensus_msg_ignore_unknown_peer(logger: Logger) {
        let (consensus_enclave, ledger, tx_manager) = get_mocks();

        // ResponderIds seem to be "host:port" strings.
        let known_responder_ids = vec![
            ResponderId("A:port".to_string()),
            ResponderId("B:port".to_string()),
        ];

        let instance = PeerApiService::new(
            Arc::new(consensus_enclave),
            Arc::new(ledger),
            Arc::new(tx_manager),
            get_incoming_consensus_msgs_sender_ok(),
            get_scp_client_value_sender(),
            get_fetch_latest_msg_fn(),
            known_responder_ids.clone(),
            logger,
        );

        let (client, _server) = get_client_server(instance);

        // A message from an unknown peer.
        // The payload can be empty because the message should be ignored before the payload is read.
        let mut message = ConsensusMsg::new();
        message.set_from_responder_id("X:port".to_string());

        match client.send_consensus_msg(&message) {
            Ok(consensus_msg_response) => {
                assert_eq!(
                    consensus_msg_response.get_result(),
                    ConsensusMsgResult::UnknownPeer
                );
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test_with_logger]
    // Should accept a message from a known peer.
    fn test_send_consensus_msg_ok(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([77u8; 32]);
        let (consensus_enclave, ledger, tx_manager) = get_mocks();

        // Node A's private message signing keypair.
        let node_a_signer_key = {
            let private_key = Ed25519Private::from_random(&mut rng);
            Ed25519Pair::from(private_key)
        };

        // ResponderIds seem to be "host:port" strings.
        let known_responder_ids = vec![
            ResponderId("A:port".to_string()),
            ResponderId("B:port".to_string()),
        ];

        let instance = PeerApiService::new(
            Arc::new(consensus_enclave),
            Arc::new(ledger),
            Arc::new(tx_manager),
            get_incoming_consensus_msgs_sender_ok(),
            get_scp_client_value_sender(),
            get_fetch_latest_msg_fn(),
            known_responder_ids.clone(),
            logger,
        );

        let (client, _server) = get_client_server(instance);

        // A message from a known peer.
        let from = known_responder_ids[0].clone();

        let scp_msg = Msg {
            sender_id: NodeID {
                responder_id: from.clone(),
                public_key: node_a_signer_key.public_key(),
            },
            slot_index: 1,
            quorum_set: QuorumSet {
                threshold: 0,
                members: vec![],
            },
            topic: Nominate(NominatePayload {
                X: Default::default(),
                Y: Default::default(),
            }),
        };

        let payload = {
            // Node A's ledger.
            let mut ledger = MockLedger::new();
            ledger
                .expect_get_block()
                .return_const(Ok(Block::new_origin_block(&vec![])));
            mc_peers::ConsensusMsg::from_scp_msg(&ledger, scp_msg, &node_a_signer_key).unwrap()
        };

        let mut message = ConsensusMsg::new();
        message.set_from_responder_id(from.to_string());
        message.set_payload(mc_util_serial::serialize(&payload).unwrap());

        match client.send_consensus_msg(&message) {
            Ok(consensus_msg_response) => {
                assert_eq!(consensus_msg_response.get_result(), ConsensusMsgResult::Ok);
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }

        // TODO: Should pass the message to incoming_consensus_msgs_sender
    }

    #[test_with_logger]
    // Should return an error if the message cannot be deserialized.
    fn test_send_consensus_msg_deserialize_error(logger: Logger) {
        let (consensus_enclave, ledger, tx_manager) = get_mocks();

        // ResponderIds seem to be "host:port" strings.
        let known_responder_ids = vec![
            ResponderId("A:port".to_string()),
            ResponderId("B:port".to_string()),
        ];

        let instance = PeerApiService::new(
            Arc::new(consensus_enclave),
            Arc::new(ledger),
            Arc::new(tx_manager),
            get_incoming_consensus_msgs_sender_ok(),
            get_scp_client_value_sender(),
            get_fetch_latest_msg_fn(),
            known_responder_ids.clone(),
            logger,
        );

        let (client, _server) = get_client_server(instance);

        // A message from a known peer. The payload does not deserialize to a ConsensusMsg.
        let mut message = ConsensusMsg::new();
        let from = known_responder_ids[0].clone();
        message.set_from_responder_id(from.to_string());
        message.set_payload(vec![240, 159, 146, 150]); // UTF-8 "sparkle heart".

        match client.send_consensus_msg(&message) {
            Ok(response) => panic!("Unexpected response: {:?}", response),
            Err(RpcFailure(_rpc_status)) => {
                // This is expected.
                // TODO: check status code.
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test_with_logger]
    // Should return an error if the message signature is wrong.
    fn test_send_consensus_msg_signature_error(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([77u8; 32]);
        let (consensus_enclave, ledger, tx_manager) = get_mocks();

        // Node A's private message signing keypair.
        let node_a_signer_key = {
            let private_key = Ed25519Private::from_random(&mut rng);
            Ed25519Pair::from(private_key)
        };

        // ResponderIds seem to be "host:port" strings.
        let known_responder_ids = vec![
            ResponderId("A:port".to_string()),
            ResponderId("B:port".to_string()),
        ];

        let instance = PeerApiService::new(
            Arc::new(consensus_enclave),
            Arc::new(ledger),
            Arc::new(tx_manager),
            get_incoming_consensus_msgs_sender_ok(),
            get_scp_client_value_sender(),
            get_fetch_latest_msg_fn(),
            known_responder_ids.clone(),
            logger,
        );

        let (client, _server) = get_client_server(instance);

        // A message from a known peer.
        let from = known_responder_ids[0].clone();

        let scp_msg = Msg {
            sender_id: NodeID {
                responder_id: from.clone(),
                public_key: node_a_signer_key.public_key(),
            },
            slot_index: 1,
            quorum_set: QuorumSet {
                threshold: 0,
                members: vec![],
            },
            topic: Nominate(NominatePayload {
                X: Default::default(),
                Y: Default::default(),
            }),
        };

        let payload = {
            // Sign the message with a different signer key.
            let wrong_signer_key = {
                let private_key = Ed25519Private::from_random(&mut rng);
                Ed25519Pair::from(private_key)
            };
            let mut ledger = MockLedger::new();
            ledger
                .expect_get_block()
                .return_const(Ok(Block::new_origin_block(&vec![])));
            mc_peers::ConsensusMsg::from_scp_msg(&ledger, scp_msg, &wrong_signer_key).unwrap()
        };

        let mut message = ConsensusMsg::new();
        message.set_from_responder_id(from.to_string());
        message.set_payload(mc_util_serial::serialize(&payload).unwrap());

        match client.send_consensus_msg(&message) {
            Ok(response) => panic!("Unexpected response: {:?}", response),
            Err(RpcFailure(_rpc_status)) => {
                // This is expected.
                // TODO: check status code.
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    // TODO: fetch_latest_msg

    // TODO: fetch_txs

    // TODO: peer_tx_propose
}