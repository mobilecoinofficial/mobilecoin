// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A unit of time during which the nodes agree on transactions.
//!
//! The transactions validated in this slot determine the values to include in
//! the next block appended to the ledger.
use crate::{
    core_types::{Ballot, CombineFn, SlotIndex, ValidityFn, Value},
    msg::*,
    predicates::{
        BallotRangePredicate, BallotSetPredicate, FuncPredicate, Predicate, ValueSetPredicate,
    },
    quorum_set::QuorumSet,
    slot_state::SlotState,
    utils,
};
use core::cmp;
use maplit::{btreeset, hashset};
use mc_common::{
    logger::{log, o, Logger},
    NodeID,
};
#[cfg(test)]
use mockall::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fmt::Display,
    sync::Arc,
    time::{Duration, Instant},
};

/// The various phases of the SCP protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Phase {
    /// Nominate and Prepare begin concurrently.
    NominatePrepare,

    /// Nominate ends when some ballot is confirmed prepared.
    Prepare,

    /// Begins when some ballot is accepted committed.
    Commit,

    /// Begins when some ballot is confirmed committed. Ends whenever...
    Externalize,
}

/// A Single slot of the SCP protocol.
#[cfg_attr(test, automock)]
pub trait ScpSlot<V: Value>: Send {
    /// Get metrics about the slot.
    fn get_metrics(&self) -> SlotMetrics;

    /// The slot index.
    fn get_index(&self) -> SlotIndex;

    /// Last message sent by this node, if any.
    fn get_last_message_sent(&self) -> Option<Msg<V>>;

    /// Processes any timeouts that may have occurred.
    fn process_timeouts(&mut self) -> Vec<Msg<V>>;

    /// Propose values for this node to nominate.
    fn propose_values(&mut self, values: &BTreeSet<V>) -> Result<Option<Msg<V>>, String>;

    /// Handles an incoming message from a peer.
    fn handle_message(&mut self, msg: &Msg<V>) -> Result<Option<Msg<V>>, String>;

    /// Handle incoming messages from peers. Messages for other slots are
    /// ignored.
    fn handle_messages(&mut self, msgs: &[Msg<V>]) -> Result<Option<Msg<V>>, String>;

    /// Additional debug info, e.g. a JSON representation of the Slot's state.
    fn get_debug_snapshot(&self) -> String;
}

/// The SCP slot.
// Note: The fields representing the state of the slot are marked with
// pub(crate) so that they could be accessed by `SlotState`.
pub struct Slot<V: Value, ValidationError: Display> {
    /// Current slot number.
    pub(crate) slot_index: SlotIndex,

    /// Local node ID.
    pub(crate) node_id: NodeID,

    /// Local node quorum set.
    pub(crate) quorum_set: QuorumSet,

    /// Map of Node ID -> highest message from each node, including the local
    /// node.
    pub(crate) M: HashMap<NodeID, Msg<V>>,

    /// Set of values that have been proposed, but not yet voted for.
    pub(crate) W: HashSet<V>,

    /// Set of values we have voted to nominate.
    pub(crate) X: HashSet<V>,

    /// Set of values we have accepted as nominated.
    pub(crate) Y: HashSet<V>,

    /// Set of values we have confirmed as nominated.
    pub(crate) Z: HashSet<V>,

    /// Current ballot we are trying to pass.
    pub(crate) B: Ballot<V>,

    /// The highest accepted prepared ballot, if any.
    pub(crate) P: Option<Ballot<V>>,

    /// The highest accepted prepared ballot that is less-than-and-incompatible
    /// with P.
    pub(crate) PP: Option<Ballot<V>>,

    /// In Prepare: the highest ballot that this node confirms prepared, if any.
    /// In Commit: the highest ballot that this node accepts committed, if any.
    /// In Externalize: The highest ballot that this node confirms committed.
    pub(crate) H: Option<Ballot<V>>,

    /// In Prepare: The lowest ballot that this node votes to commit, if any.
    /// In Commit: The lowest ballot that this node accepts committed, if any.
    /// In Externalize: The lowest ballot that this node confirms committed.
    /// Invariant: if C is Some, C \lesssim H \lesssim B
    pub(crate) C: Option<Ballot<V>>,

    /// Current phase of the protocol.
    pub(crate) phase: Phase,

    /// Last message sent by us.
    pub(crate) last_sent_msg: Option<Msg<V>>,

    /// Max priority peers - nodes from which we listen to value nominations.
    pub(crate) max_priority_peers: HashSet<NodeID>,

    /// Current nomination round number.
    pub(crate) nominate_round: u32,

    /// Timer for the next nomination round.
    pub(crate) next_nominate_round_at: Option<Instant>,

    /// Timer for the next balloting round.
    pub(crate) next_ballot_at: Option<Instant>,

    /// Application-specific validation of value.
    validity_fn: ValidityFn<V, ValidationError>,

    /// Application-specific function for combining multiple values. Must be
    /// deterministic.
    combine_fn: CombineFn<V, ValidationError>,

    /// List of values that have been checked to be valid for the current slot.
    /// We can cache this and save on validation calls since the ledger doesn't
    /// change during a slot.
    pub(crate) valid_values: BTreeSet<V>,

    /// Logger.
    logger: Logger,

    /// This parameter sets the base interval for round timeout.
    /// SCP suggests this should be one second.
    pub base_round_interval: Duration,

    /// This parameter sets the base interval for ballot timeout.
    /// SCP suggests this should be one second.
    pub base_ballot_interval: Duration,
}

/// Metrics and information about a given slot.
pub struct SlotMetrics {
    /// Which phase of consensus are we in? (Nominate, NomPrepare, Prepare,
    /// Commit, Externalize)
    pub phase: Phase,

    /// The number of values voted nominated.
    pub num_voted_nominated: usize,

    /// The number of values accepted nominated.
    pub num_accepted_nominated: usize,

    /// The number of values confirmed nominated.
    pub num_confirmed_nominated: usize,

    /// Teh current nomination round.
    pub cur_nomination_round: u32,

    /// The highest ballot counter.
    pub bN: u32,
}

impl<V: Value, ValidationError: Display> ScpSlot<V> for Slot<V, ValidationError> {
    /// Get some metrics/information about the slot for debugging purposes.
    fn get_metrics(&self) -> SlotMetrics {
        SlotMetrics {
            phase: self.phase,
            num_voted_nominated: self.X.len(),
            num_accepted_nominated: self.Y.len(),
            num_confirmed_nominated: self.Z.len(),
            cur_nomination_round: self.nominate_round,
            bN: self.B.N,
        }
    }

    fn get_index(&self) -> u64 {
        self.slot_index
    }

    /// Last message sent by this node, if any.
    fn get_last_message_sent(&self) -> Option<Msg<V>> {
        self.last_sent_msg.clone()
    }

    /// Processes any timeouts that may have occurred.
    /// Returns list of messages to broadcast to network.
    fn process_timeouts(&mut self) -> Vec<Msg<V>> {
        let mut msgs = Vec::<Msg<V>>::new();

        let mut timeout_occurred = false;

        // Nomination round timeout.
        if self.next_nominate_round_at.is_some()
            && Instant::now() > self.next_nominate_round_at.unwrap()
        {
            timeout_occurred = true;
            // Canceling is required since schedule_next_nomination_round will not schedule
            // a round if one is already scheduled.
            self.cancel_next_nomination_round();

            self.nominate_round += 1;

            let max_priority_peer = self.find_max_priority_peer(self.nominate_round);
            self.max_priority_peers.insert(max_priority_peer);

            log::debug!(
                self.logger,
                "Nominate Round({:?}) with leaders: {:?}",
                self.nominate_round,
                self.max_priority_peers
            );

            self.do_nominate_phase();
        }

        // Ballot timeout.
        if self.next_ballot_at.is_some() && Instant::now() > self.next_ballot_at.unwrap() {
            log::debug!(
                self.logger,
                "Ballot {} timed out in {:?} phase",
                self.B.N,
                self.phase
            );

            timeout_occurred = true;
            self.cancel_next_ballot_timer();
            let next_counter = self.B.N + 1;

            match self.phase {
                Phase::NominatePrepare | Phase::Prepare => {
                    if let Some(x) = self.get_next_ballot_values() {
                        log::trace!(
                            self.logger,
                            "process_timeouts: updating B.N: {} -> {}",
                            self.B.N,
                            next_counter
                        );
                        self.B = Ballot::new(next_counter, &x);
                    }
                }
                Phase::Commit => {
                    // B.X can no longer change. Increment B.N
                    log::trace!(
                        self.logger,
                        "process_timeouts: updating B.N: {} -> {}",
                        self.B.N,
                        next_counter
                    );
                    self.B.N = next_counter;
                }
                Phase::Externalize => {
                    // B no longer changes.
                    log::warn!(
                        self.logger,
                        "Ballot timeout occurred during Externalize phase."
                    );
                }
            }
            self.do_ballot_protocol();
        }

        if timeout_occurred {
            if let Some(emitted) = self.out_msg() {
                msgs.push(emitted);
            }
        }

        msgs
    }

    /// Propose values for this node to nominate.
    fn propose_values(&mut self, values: &BTreeSet<V>) -> Result<Option<Msg<V>>, String> {
        // Only accept values during the Nominate phase and if no other values have been
        // confirmed nominated.
        if !(self.phase == Phase::NominatePrepare && self.Z.is_empty()) {
            return Ok(self.out_msg());
        }

        // Omit any invalid values.
        let valid_values: Vec<V> = values
            .iter()
            .filter(|value| self.is_valid(value).is_ok())
            .cloned()
            .collect();

        if valid_values.is_empty() {
            return Ok(None);
        }

        self.W.extend(valid_values.into_iter());
        self.do_nominate_phase();
        self.do_ballot_protocol();
        Ok(self.out_msg())
    }

    /// Handle an incoming message from a peer.
    fn handle_message(&mut self, msg: &Msg<V>) -> Result<Option<Msg<V>>, String> {
        self.handle_messages(&[msg.clone()])
    }

    /// Handle incoming messages from peers. Messages for other slots are
    /// ignored.
    fn handle_messages(&mut self, msgs: &[Msg<V>]) -> Result<Option<Msg<V>>, String> {
        // Ignore messages from self.
        let msgs: Vec<&Msg<V>> = msgs
            .iter()
            .filter(|&msg| msg.sender_id != self.node_id)
            .collect();

        // Omit messages for other slots.
        let (mut msgs_for_slot, msgs_for_other_slots): (Vec<_>, Vec<_>) = msgs
            .into_iter()
            .partition(|&msg| msg.slot_index == self.slot_index);

        if !msgs_for_other_slots.is_empty() {
            log::error!(
                self.logger,
                "Received {} messages for other slots.",
                msgs_for_other_slots.len(),
            );
        }

        // Set to true if any input message is higher than previous messages from the
        // same sender.
        let mut has_higher_messages = false;

        // Sort messages in descending order by topic. This lets us process them
        // greedily.
        msgs_for_slot.sort_by(|a, b| b.topic.cmp(&a.topic));

        'msg_loop: for msg in msgs_for_slot {
            let is_higher = match self.M.get(&msg.sender_id) {
                Some(existing_msg) => msg.topic > existing_msg.topic,
                None => true,
            };

            if is_higher {
                // This message is higher than previous messages from the same sender.
                if msg.validate().is_ok() {
                    // Reject messages with invalid values.
                    // This Validation can be skipped during the Externalize phase
                    // because this node no longer changes its ballot values.
                    if self.phase != Phase::Externalize {
                        for value in msg.values() {
                            if self.is_valid(&value).is_err() {
                                // Ignore this msg because it contains an invalid value.
                                continue 'msg_loop;
                            }
                        }
                    }

                    // TODO: Reject messages with incorrectly ordered values.

                    // The msg is valid and should be processed.
                    self.M.insert(msg.sender_id.clone(), msg.clone());
                    has_higher_messages = true;
                }
            }
        }

        if has_higher_messages {
            if self.phase == Phase::NominatePrepare {
                self.do_nominate_phase();
            }

            self.do_ballot_protocol();
            Ok(self.out_msg())
        } else {
            Ok(None)
        }
    }

    fn get_debug_snapshot(&self) -> String {
        serde_json::to_string(&SlotState::from(self)).expect("SlotState should yield JSON")
    }
}

impl<V: Value, ValidationError: Display> Slot<V, ValidationError> {
    ///////////////////////////////////////////////////////////////////////////
    // Public methods (how the Slot interfaces with the Node)
    ///////////////////////////////////////////////////////////////////////////

    /// Create a new slot.
    pub fn new(
        node_id: NodeID,
        quorum_set: QuorumSet,
        slot_index: SlotIndex,
        validity_fn: ValidityFn<V, ValidationError>,
        combine_fn: CombineFn<V, ValidationError>,
        logger: Logger,
    ) -> Self {
        let mut slot = Slot {
            slot_index,
            node_id,
            quorum_set,
            M: HashMap::default(),
            W: HashSet::default(),
            X: HashSet::default(),
            Y: HashSet::default(),
            Z: HashSet::default(),
            B: Ballot::new(0, &Vec::new()),
            P: None,
            PP: None,
            C: None,
            H: None,
            phase: Phase::NominatePrepare,
            last_sent_msg: None,
            max_priority_peers: HashSet::default(),
            nominate_round: 1,
            next_nominate_round_at: None,
            next_ballot_at: None,
            validity_fn,
            combine_fn,
            valid_values: BTreeSet::default(),
            logger: logger.new(o!("mc.scp.slot" => slot_index)),
            base_round_interval: Duration::from_millis(1000),
            base_ballot_interval: Duration::from_millis(1000),
        };

        let max_priority_peer = slot.find_max_priority_peer(slot.nominate_round);
        slot.max_priority_peers.insert(max_priority_peer);

        slot
    }

    fn is_valid(&mut self, value: &V) -> Result<(), String> {
        if self.valid_values.contains(value) {
            return Ok(());
        }

        match (self.validity_fn)(value) {
            Ok(()) => {
                self.valid_values.insert(value.clone());
                Ok(())
            }
            Err(err) => Err(err.to_string()),
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    // Nomination-specific methods
    ///////////////////////////////////////////////////////////////////////////

    /// Weight returns the fraction of n's quorum slices in which id
    /// appears.
    ///
    /// # Arguments
    /// * `node_id` - Node ID to calculate weight for
    ///
    /// # Returns
    /// * (numerator, denominator) representing the node's weight.
    fn weight(&self, node_id: &NodeID) -> (u32, u32) {
        if node_id == &self.node_id {
            (1, 1)
        } else {
            self.quorum_set.weight(node_id)
        }
    }

    /// Get a list of the node's neighbor's for the current slot and nomination
    /// round. Neighbors are nodes that the current node is willing to
    /// accept nomination values from. See p.10 of the [IETF draft](https://tools.ietf.org/pdf/draft-mazieres-dinrg-scp-04.pdf).
    /// See p.20 of the [Whitepaper](https://www.stellar.org/papers/stellar-consensus-protocol.pdf).
    fn neighbors(&self, slot_index: SlotIndex, nomination_round: u32) -> Vec<NodeID> {
        let mut self_and_peers = vec![self.node_id.clone()];
        self_and_peers.extend(self.quorum_set.nodes());

        let mut result = Vec::<NodeID>::new();
        for node_id in self_and_peers.iter() {
            // weight256 is the node's weight, scaled to 0..<max uint256>
            // (weight256 = <max uint256> * <num> / <denom>)
            let (num, denom) = self.weight(node_id);
            let mut tmp = bigint::U512::from(bigint::U256::max_value());
            tmp = tmp.saturating_mul(bigint::U512::from(num));
            tmp = tmp.overflowing_div(bigint::U512::from(denom)).0;
            let weight256 = bigint::U256::from(tmp);

            let gi_one = utils::slot_round_salted_keccak(
                slot_index,
                1,
                nomination_round,
                node_id.public_key.as_ref(),
            );

            if gi_one < weight256 {
                result.push(node_id.clone());
            }
        }

        result
    }

    /// The max priority peer for a given nomination round.
    fn find_max_priority_peer(&self, round: u32) -> NodeID {
        let neighbors = self.neighbors(self.slot_index, round);
        let mut result = self.node_id.clone();
        let mut max_priority = bigint::U256::zero();

        for node_id in neighbors.iter() {
            // NOTE: this deviates from the spec. Without doing this we may have nomination
            // rounds where no new peers gets added, so nothing changes which
            // slows the protocol down.
            if self.max_priority_peers.contains(node_id) {
                continue;
            }

            let node_priority = utils::slot_round_salted_keccak(
                self.slot_index,
                2,
                round,
                node_id.public_key.as_ref(),
            );
            if node_priority > max_priority {
                max_priority = node_priority;
                result = node_id.clone();
            }
        }

        result
    }

    /// Set the timer for the next nomination round.
    fn schedule_next_nomination_round(&mut self) {
        if self.next_nominate_round_at.is_none() {
            self.next_nominate_round_at =
                Some(Instant::now() + self.base_round_interval * self.nominate_round);
        }
    }

    /// Cancel the next nomination round timer.
    fn cancel_next_nomination_round(&mut self) {
        self.next_nominate_round_at = None;
    }

    /// Nominate phase message handling.
    fn do_nominate_phase(&mut self) {
        assert_eq!(self.phase, Phase::NominatePrepare);

        // Schedule a round if one is not already scheduled.
        self.schedule_next_nomination_round();

        // If no values have been confirmed nominated, the node may add new values to
        // its voted set.
        if self.Z.is_empty() {
            // Gather all nominate payloads from other nodes.
            let mut nominate_payloads: HashMap<NodeID, &NominatePayload<V>> = Default::default();
            for (node_id, msg) in &self.M {
                if *node_id == self.node_id {
                    continue;
                }
                match &msg.topic {
                    Topic::Nominate(nominate_payload)
                    | Topic::NominatePrepare(nominate_payload, _) => {
                        nominate_payloads.insert(node_id.clone(), nominate_payload);
                    }
                    _ => {}
                }
            }

            // This node may nominate new values when it is among max_priority_peers.
            if self.max_priority_peers.contains(&self.node_id) {
                for value in &self.W {
                    if !self.Y.contains(value) {
                        self.X.insert(value.clone());
                    }
                }
            }

            // Add voted or accepted values from max_priority_peers to self.X
            for (node_id, payload) in &nominate_payloads {
                if self.max_priority_peers.contains(node_id) {
                    for value in payload.X.iter().chain(payload.Y.iter()) {
                        if !self.Y.contains(value) {
                            self.X.insert(value.clone());
                        }
                    }
                }
            }
            // Invariant: X and Y are disjoint.
            assert!(self.X.is_disjoint(&self.Y));
        }

        // Move accepted-nominated values from X to Y, and confirmed-nominated values
        // from Y to Z.
        self.update_YZ();

        if !self.Z.is_empty() && self.B.is_zero() {
            let z_as_vec: Vec<V> = self.Z.iter().cloned().collect();
            match (self.combine_fn)(&z_as_vec) {
                Ok(values) => self.B = Ballot::new(1, &values),
                Err(_e) => log::error!(self.logger, "Failed to combine Z: {:?}", &z_as_vec),
            }
        }
    }

    /// Update Y (values accepted-nominated) and Z (values confirmed-nominated).
    fn update_YZ(&mut self) {
        for value in self.additional_values_accepted_nominated().into_iter() {
            self.X.remove(&value);
            self.Y.insert(value);
        }
        // Invariant: X and Y are disjoint.
        assert!(self.X.is_disjoint(&self.Y));

        self.Z
            .extend(self.additional_values_confirmed_nominated().into_iter());
        // let mut new_Z = self.additional_values_confirmed_nominated();
        // if !new_Z.is_empty() {
        //     new_Z.append(&mut self.Z);
        //     self.Z = (self.combine_fn)(new_Z);
        // }
    }

    fn do_ballot_protocol(&mut self) {
        // Set a ballot timeout if a quorum is on a higher slot.
        self.maybe_set_ballot_timer();

        // "Fall through" each phase of the ballot protocol. Each may change self.phase,
        // so a simple match statement on phase could prevent later phases from being
        // performed.

        if self.phase == Phase::NominatePrepare || self.phase == Phase::Prepare {
            self.do_prepare_phase();
        }

        if self.phase == Phase::Commit {
            self.do_commit_phase();
        }

        if self.phase == Phase::Externalize {
            self.do_externalize_phase();
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    // Prepare-specific methods
    ///////////////////////////////////////////////////////////////////////////

    fn check_prepare_phase_invariants(&self) {
        assert!(
            self.phase == Phase::NominatePrepare || self.phase == Phase::Prepare,
            "self.phase: {:?}",
            self.phase
        );

        // When some ballot has been accepted prepared...
        if let (Some(P), Some(PP)) = (&self.P, &self.PP) {
            // PP is less-than-and-incompatible-with P
            assert!(PP < P);
            assert_ne!(PP.X, P.X);
        }

        // When some ballot has been voted committed...
        if let Some(C) = &self.C {
            // C is less-than-and-compatible-with H
            if let Some(H) = &self.H {
                assert!(C.N <= H.N, "C.N: {}, H.N: {}", C.N, H.N);
                assert_eq!(C.X, H.X);
            } else {
                panic!("C is Some but H is None");
            }
        }
    }

    /// Prepare phase message handling.
    fn do_prepare_phase(&mut self) {
        self.check_prepare_phase_invariants();
        // Note: P and PP must be non-decreasing within the Prepare phase.
        // Note: H must be non-decreasing within the Prepare phase.

        // (1) Identify "accepted prepared" ballots.
        // Recalculate P and PP during the Prepare phase.
        // P is the highest accepted prepared ballot, if any.
        // PP is the second-highest accepted prepared ballot where P.X != PP.X.

        let accepted_prepared = self.ballots_accepted_prepared();

        // Find the highest ballot accepted prepared.
        if let Some(new_P) = accepted_prepared.iter().max() {
            match &self.P {
                Some(current_P) => {
                    // self.P should not decrease.
                    if new_P >= current_P {
                        self.P = Some(new_P.clone());
                    } else {
                        // decreasing P here does not cause failures or decrease performance
                        log::debug!(self.logger, "Step 1: Ignoring decreasing P");
                        return;
                    }
                }
                None => {
                    self.P = Some(new_P.clone());
                }
            }

            // Find the second-highest accepted prepared ballot where P.X != PP.X
            if let Some(current_P) = &self.P {
                let opt_PP = accepted_prepared
                    .iter()
                    .filter(|ballot| *ballot < current_P && ballot.X != current_P.X)
                    .max();

                if let Some(new_PP) = opt_PP {
                    match &self.PP {
                        Some(current_PP) => {
                            if new_PP < current_PP {
                                // decreasing PP here does not cause failures or decrease
                                // performance
                                log::debug!(self.logger, "Step 1: Allowing decreasing PP");
                            }
                            self.PP = Some(new_PP.clone());
                        }
                        None => {
                            self.PP = Some(new_PP.clone());
                        }
                    }
                } else {
                    self.PP = None;
                }
            }
        }

        // Invariants: p' is less-than-and-incompatible-with p.
        if let (Some(p), Some(pp)) = (&self.P, &self.PP) {
            assert!(pp < p, "p: {:?}, pp: {:?}", p, pp);
            assert_ne!(p.X, pp.X);
        }

        // If either P aborts C or PP aborts C, then set C to None.
        // Note: This follows the Stellar IETF draft and differs slightly from the
        // Stellar whitepaper, which tests if p or p' abort H.
        if let Some(c) = &self.C {
            let p_aborts_c = self.P.as_ref().map_or(false, |p| p > c && p.X != c.X);
            let pp_aborts_c = self.PP.as_ref().map_or(false, |pp| pp > c && pp.X != c.X);
            if p_aborts_c || pp_aborts_c {
                self.C = None;
            }
        }

        // (2) Identify "confirmed prepared" ballots.

        let h_opt = self.ballots_confirmed_prepared().into_iter().max();
        if let Some(h) = h_opt {
            // Some ballot has been confirmed prepared.
            if self.phase == Phase::NominatePrepare {
                // Nominate ends when some ballot has been confirmed prepared.
                self.cancel_next_nomination_round();
                self.phase = Phase::Prepare;
            }

            // self.H should not decrease.
            if let Some(current_h) = self.H.as_ref() {
                if h < *current_h {
                    // This may indicate messages from a faulty or malicious peer, or a bug.
                    // decreasing H here does not cause failures or decrease performance
                    log::debug!(
                        self.logger,
                        "Step 2: Ignoring decreasing H. self.H.N: {:?}, h.N: {:?}",
                        current_h.N,
                        h.N,
                    );
                }
                self.H = Some(core::cmp::max(&h, current_h).clone());
            } else {
                self.H = Some(h);
            }
        }

        if let (Some(C), Some(H)) = (&self.C, &self.H) {
            assert!(C.N <= H.N, "C.N: {}, H.N: {}", C.N, H.N);
        }

        // (3) Identify "voted committed" ballots.

        if let (None, Some(h)) = (&self.C, &self.H) {
            // C may never have been set before, or may have been cleared in step (1).
            if self.B <= *h {
                // "If p is greater-than-and-incompatible with h"
                let p_aborts_h = self.P.as_ref().map_or(false, |p| p > h && p.X != h.X);

                // "If pp is greater-than-and-incompatible with h"
                let pp_aborts_h = self.PP.as_ref().map_or(false, |pp| pp > h && pp.X != h.X);

                if !p_aborts_h && !pp_aborts_h {
                    // Set C to the lowest ballot for which this node:
                    // * may issue "confirm prepare(c)",
                    // * has not accepted "abort(c)",
                    // * not voted "abort(c)"

                    // H has not been aborted, which means some ballots with value H.X are confirmed
                    // prepared and not accepted aborted. This node may have voted to abort any
                    // ballot less than B so, conservatively, c is required to be
                    // greater-than-or-equal-to B.

                    let mut c = if h.X >= self.B.X {
                        Ballot::new(self.B.N, &h.X)
                    } else {
                        Ballot::new(self.B.N + 1, &h.X)
                    };

                    // If p aborts c, increase c's counter so that it p no longer aborts it.
                    if let Some(p) = &self.P {
                        let p_aborts_c = *p > c && p.X != c.X;
                        if p_aborts_c {
                            if c.X > p.X {
                                c.N = p.N;
                            } else {
                                c.N = p.N + 1;
                            }
                        }
                    }

                    // If pp aborts c, increase c's counter so that it p no longer aborts it.
                    if let Some(pp) = &self.PP {
                        let pp_aborts_c = *pp > c && pp.X != c.X;
                        if pp_aborts_c {
                            if c.X > pp.X {
                                c.N = pp.N;
                            } else {
                                c.N = pp.N + 1;
                            }
                        }
                    }

                    // B <= C less-than-and-compatible-with H
                    assert!(self.B <= c);
                    assert_eq!(c.X, h.X);
                    assert!(c.N <= h.N, "c.N: {}, h.N: {}", c.N, h.N);

                    self.C = Some(c);
                }
            }
        }

        if let (Some(C), Some(H)) = (&self.C, &self.H) {
            assert!(C.N <= H.N, "C.N: {}, H.N: {}", C.N, H.N);
        }

        // (4) Identify "accepted committed" ballots.
        // The Prepare phase ends when some ballot is accepted committed.

        let accept_commits = self.ballots_accepted_committed();

        let c_opt: Option<Ballot<V>> = accept_commits
            .iter()
            .map(|(values, &(a, _b))| Ballot::new(a, values))
            .min();

        if let Some(c) = c_opt {
            // c is the lowest ballot accepted committed.
            self.C = Some(c.clone());

            // The highest accepted committed ballot with the same value as C.
            let h = accept_commits
                .iter()
                .filter(|&(values, _)| *values == c.X)
                .map(|(values, &(_min, max))| Ballot::new(max, values))
                .max()
                .expect("H must exist");

            if let Some(current_h) = &self.H {
                if h < *current_h {
                    // decreasing H here does not cause failures or decrease performance
                    log::debug!(self.logger, "Step 4: Allowing decreasing H.");
                }
            }
            self.H = Some(h.clone());
            assert!(c.N <= h.N, "c.N: {}, h.N: {}", c.N, h.N);

            // "if h is not less-than-and-incompatible-with b, set b to h."
            //
            // The description from the whitepaper feels strange. At this point in the
            // protocol, some ballot has been accepted committed, which marks
            // the start of the Commit phase. The following seems to meet the
            // goal that in the commit phase, the node issues "accept commit(<n,
            // ballot.value>)" for every "cCounter <= n <= hCounter", and
            // also fulfills the requirement that the ballot value cannot change unless the
            // counter increases.

            if self.B.X != h.X {
                // Changing B's value requires changing its counter.
                log::trace!(
                    self.logger,
                    "do_prepare_phase: updating B.N: {} -> {}",
                    self.B.N,
                    core::cmp::max(self.B.N + 1, h.N)
                );
                self.B = Ballot::new(core::cmp::max(self.B.N + 1, h.N), &h.X);
            } else {
                log::trace!(
                    self.logger,
                    "do_prepare_phase: updating B.N: {} -> {}",
                    self.B.N,
                    core::cmp::max(self.B.N, h.N)
                );
                self.B = Ballot::new(core::cmp::max(self.B.N, h.N), &h.X);
            }

            self.phase = Phase::Commit;
            self.cancel_next_nomination_round();

            // In the commit phase, P must have the same value as B.
            self.P = self
                .ballots_accepted_prepared()
                .into_iter()
                .filter(|p| p.X == self.B.X)
                .max();
            assert!(self.P.is_some());
            // self.PP is not used in the Commit or Externalize phases.
            self.PP = None;
            return;
        }

        // (8) If b < h, set b to h.
        //
        // Note: The whitepaper seems to disagree with the IETF draft, which
        // says that B's "value is updated when and only when counter changes". Maybe
        // the assumption here is that h.N > b.N, so the counter increases
        // whenever the value changes?
        if let Some(h) = &self.H {
            if self.B.X != h.X {
                // Changing B's value requires changing its counter.
                log::trace!(
                    self.logger,
                    "do_prepare_phase: updating B.N: {} -> {}",
                    self.B.N,
                    core::cmp::max(self.B.N + 1, h.N)
                );
                self.B = Ballot::new(core::cmp::max(self.B.N + 1, h.N), &h.X);
            } else {
                log::trace!(
                    self.logger,
                    "do_prepare_phase: updating B.N: {} -> {}",
                    self.B.N,
                    core::cmp::max(self.B.N, h.N)
                );
                self.B = Ballot::new(core::cmp::max(self.B.N, h.N), &h.X);
            }
        }

        // (9) Check if the current ballot is blocked.

        let unblocking_counter = self.get_unblocking_ballot_counter();
        if self.B.N < unblocking_counter {
            // A blocking set of other nodes are on a higher ballot counter.

            if let Some(x) = self.get_next_ballot_values() {
                // This node is able to issue ballot statements for x.
                // Increase B.n to the lowest counter so that it is no longer blocked.
                // If necessary, set a new ballot timer.
                self.cancel_next_ballot_timer();
                log::trace!(
                    self.logger,
                    "do_prepare_phase: updating B.N: {} -> {}",
                    self.B.N,
                    unblocking_counter
                );
                self.B = Ballot::new(unblocking_counter, &x);
                self.maybe_set_ballot_timer();
                self.do_prepare_phase();
            }
        }

        // Check invariants.
        self.check_prepare_phase_invariants();
    }

    ///////////////////////////////////////////////////////////////////////////
    // Commit-specific methods
    ///////////////////////////////////////////////////////////////////////////

    fn check_commit_phase_invariants(&self) {
        assert_eq!(self.phase, Phase::Commit);
        assert!(!self.B.is_zero());

        if let Some(P) = &self.P {
            assert_eq!(P.X, self.B.X);
        } else {
            panic!(
                "Commit: P is None. self.B: {:?}, self.H: {:?}, self.C: {:?}",
                self.B, self.C, self.H
            );
        }

        // PP is not used in the commit phase.
        assert!(self.PP.is_none());

        if let Some(H) = &self.H {
            assert_eq!(H.X, self.B.X);
        } else {
            panic!("Commit: H is None.");
        }

        if let Some(C) = &self.C {
            assert_eq!(C.X, self.B.X);
        } else {
            panic!("Commit: C is None.");
        }
    }

    // Commit phase message handling.
    fn do_commit_phase(&mut self) {
        self.check_commit_phase_invariants();

        // (5) Set P to the highest accepted prepared ballot such that P.x = B.x.

        let accepted_prepared = self.ballots_accepted_prepared();
        if let Some(new_P) = accepted_prepared
            .into_iter()
            .filter(|p| p.X == self.B.X)
            .max()
        {
            // P should not decrease within the Commit phase.
            if new_P < *self.P.as_ref().unwrap() {
                // decreasing P here does not cause failures or decrease performance
                log::debug!(self.logger, "Step 5: Ignoring decreasing P");
            } else {
                self.P = Some(new_P);
            }
        }

        // (6) Identify "accepted committed" ballots.

        let accepted_committed_compatible_with_b: Option<(u32, u32)> =
            { self.ballots_accepted_committed().remove(&self.B.X) };

        if let Some((cn, hn)) = accepted_committed_compatible_with_b {
            self.C = Some(Ballot::new(cn, &self.B.X));
            self.H = Some(Ballot::new(hn, &self.B.X));
        }

        // (7) Identify "confirmed committed" ballots.

        if let Some((cn, hn)) = self.ballots_confirmed_committed() {
            // The lowest and highest ballots confirmed committed.
            self.C = Some(Ballot::new(cn, &self.B.X));
            self.H = Some(Ballot::new(hn, &self.B.X));

            // The node externalizes the values X.
            // Ballot timeouts are not performed during the Externalize phase.
            self.cancel_next_nomination_round();
            self.cancel_next_ballot_timer();
            self.phase = Phase::Externalize;
            return;
        }

        // (8) If B < H, set B to H.

        if let Some(h) = &self.H {
            // In the Commit phase, B and H must have the same value.
            if self.B.N < h.N {
                log::trace!(
                    self.logger,
                    "do_commit_phase: updating B.N: {} -> {}",
                    self.B.N,
                    h.N
                );
                self.B.N = h.N;
            }
        }

        // 9) If a blocking set of other nodes is on a higher counter,
        // increase B.n to the lowest counter so that no such blocking set exists.
        let unblocking_counter = self.get_unblocking_ballot_counter();
        if self.B.N < unblocking_counter {
            // A blocking set of other nodes are on a higher ballot counter.
            self.cancel_next_ballot_timer();
            log::trace!(
                self.logger,
                "do_commit_phase: updating B.N: {} -> {}",
                self.B.N,
                unblocking_counter
            );
            self.B.N = unblocking_counter;
            self.maybe_set_ballot_timer();
            self.do_commit_phase();
        }

        self.check_commit_phase_invariants();
    }

    fn check_externalize_phase_invariants(&self) {
        assert_eq!(self.phase, Phase::Externalize);
        assert!(!self.B.is_zero());

        // H is the highest confirmed committed ballot.
        if let Some(H) = &self.H {
            assert_eq!(H.X, self.B.X);
        } else {
            panic!("Externalize: H is None.");
        }

        // C is the lowest confirmed committed ballot.
        if let Some(C) = &self.C {
            assert_eq!(C.X, self.B.X);
        } else {
            panic!("Externalize: C is None.");
        }

        // PP is not used in the Externalize phase.
        assert!(self.PP.is_none());
    }

    fn do_externalize_phase(&mut self) {
        self.check_externalize_phase_invariants();

        // Update H.N to the highest ballot confirmed committed.
        if let Some((_cn, hn)) = self.ballots_confirmed_committed() {
            // The highest ballot confirmed committed.
            if hn >= self.H.as_ref().unwrap().N {
                self.H.as_mut().unwrap().N = hn;
            } else {
                log::debug!(
                    self.logger,
                    "Externalize: Ignoring decreasing H. self.H.N: {:?}, hn: {:?}",
                    self.H.as_ref().unwrap().N,
                    hn,
                );
            }
        }

        self.check_externalize_phase_invariants();
    }

    ///////////////////////////////////////////////////////////////////////////
    // Helper methods
    ///////////////////////////////////////////////////////////////////////////

    /// The lowest ballot counter such that no blocking set of other nodes
    /// exists with higher ballot counters.
    fn get_unblocking_ballot_counter(&mut self) -> u32 {
        let mut unblocking_counter = self.B.N;
        loop {
            let (blocking_set, _) = self.find_blocking_set(FuncPredicate {
                test_fn: &|msg: &Msg<V>| msg.bN() > unblocking_counter,
            });
            if blocking_set.is_empty() {
                break;
            }

            let min_ballot_counter: u32 = blocking_set
                .iter()
                .map(|node_id| self.M[node_id].bN())
                .min()
                .expect("Min counter must exist");
            unblocking_counter = min_ballot_counter;
        }

        unblocking_counter
    }

    /// Cancels the next ballot timer.
    fn cancel_next_ballot_timer(&mut self) {
        self.next_ballot_at = None;
    }

    /// Set a ballot timer if a quorum is on a higher ballot counter.
    fn maybe_set_ballot_timer(&mut self) {
        if self.phase == Phase::Externalize {
            // Ballot timers are not set during the Externalize phase.
            return;
        }

        // If no timer is currently set...
        if self.next_ballot_at.is_none() {
            // "When a node sees messages from a quorum to which it belongs such that each
            // message’s "ballot.counter" is greater than or equal to the local
            // "ballot.counter", the node arms a timer to fire in a number of
            // seconds equal to its "ballot.counter + 1"" See p.14 of the [IETF draft](https://tools.ietf.org/pdf/draft-mazieres-dinrg-scp-04.pdf).
            let (quorum_ids, _) = self.find_quorum(FuncPredicate::<V> {
                test_fn: &|msg: &Msg<V>| msg.bN() >= self.B.N,
            });

            if !quorum_ids.is_empty() {
                self.next_ballot_at =
                    Some(Instant::now() + self.base_ballot_interval * self.B.N.saturating_add(1));
            }
        }
    }

    /// The values, if any, for the next ballot.
    fn get_next_ballot_values(&self) -> Option<Vec<V>> {
        // "If any ballot has been confirmed prepared, then "ballot.value" is taken to
        // to be "h.value" for the highest confirmed prepared ballot "h"."
        if let Some(h) = self.ballots_confirmed_prepared().into_iter().max() {
            if let Some(h_old) = &self.H {
                if h_old > h {
                    return Some(h_old.X);
                }
            }
            return Some(h.X);
        }
        else if let Some(h_old) = &self.H {
            return Some(h_old.X);
        }

        // "Otherwise (if no such "h" exists), if one or more values are confirmed
        // nominated, then "ballot.value" is taken as the output of the
        // deterministic combining function applied to all confirmed nominated
        // values."
        if !self.Z.is_empty() {
            let z_as_vec: Vec<V> = self.Z.iter().cloned().collect();
            match (self.combine_fn)(&z_as_vec) {
                Ok(values) => return Some(values),
                Err(_e) => log::error!(self.logger, "Failed to combine Z: {:?}", &z_as_vec),
            }
        }

        // "Otherwise, if no ballot is confirmed prepared and no value is confirmed
        // nominated, but the node has accepted a ballot prepared... , then
        // "ballot.value" is the value of the highest such accepted prepared
        // ballot."
        if let Some(p) = self.ballots_accepted_prepared().into_iter().max() {
            if let Some(p_old) = &self.P {
                if p_old > p {
                    return Some(p_old.X);
                }
            }
            return Some(p.X);
        }
        else if let Some(p_old) = &self.P {
            return Some(p_old.X);
        }

        // Otherwise, values are unchanged.
        if !self.B.is_zero() {
            return Some(self.B.X.clone());
        }

        // This node may not emit Balloting statements at this time.
        None
    }

    /// Calculate the message to send to the network based on our current state.
    /// Any duplicate messages are suppressed.
    fn out_msg(&mut self) -> Option<Msg<V>> {
        // Prepared is " the highest accepted prepared ballot not exceeding the "ballot"
        // field... if "ballot = <n, x>" and the highest prepared ballot is "<n,
        // y>" where "x < y", then the "prepared" field in sent messages must be
        // set to "<n-1, y>" instead of "<n, y>"" See p.15 of the [IETF draft](https://tools.ietf.org/pdf/draft-mazieres-dinrg-scp-04.pdf).

        let mut clamped_P: Option<Ballot<V>> = None;
        if let Some(P) = &self.P {
            if *P > self.B {
                if P.X > self.B.X {
                    clamped_P = Some(Ballot::new(self.B.N - 1, &P.X));
                } else {
                    clamped_P = Some(Ballot::new(self.B.N, &P.X));
                }
            } else {
                clamped_P = Some(P.clone())
            }
        }

        let mut clamped_PP: Option<Ballot<V>> = None;
        if let (Some(clamped_P), Some(PP)) = (&clamped_P, &self.PP) {
            if PP > clamped_P {
                if PP.N > 0 {
                    if PP.X > clamped_P.X {
                        clamped_PP = Some(Ballot::new(clamped_P.N - 1, &PP.X))
                    } else {
                        clamped_PP = Some(Ballot::new(clamped_P.N, &PP.X))
                    }
                } else {
                    clamped_PP = None;
                }
            } else {
                clamped_PP = Some(PP.clone())
            }
        }

        let topic_opt = match self.phase {
            Phase::NominatePrepare => {
                let prepare_payload_opt = if self.B.is_zero() {
                    None
                } else {
                    let HN: u32 = if let Some(h) = &self.H {
                        // If "h" is the highest confirmed prepared ballot and "h.value ==
                        // ballot.value", then this field is set to "h.counter".  Otherwise,
                        // if no ballot is confirmed prepared or if "h.value != ballot.value",
                        // then this field is 0. Note that by the rules above, if "h" exists,
                        // then "ballot.value" will be set to "h.value" the next time "ballot"
                        // is updated.
                        if h.X == self.B.X {
                            h.N
                        } else {
                            // H and B have different values.
                            0
                        }
                    } else {
                        // No ballot confirmed prepared.
                        0
                    };

                    let CN: u32 = if let Some(c) = &self.C {
                        // The value "cCounter" is maintained based on an internally-
                        // maintained _commit ballot_ "c", initially "NULL".  "cCounter" is 0
                        // while "c == NULL" or "hCounter == 0", and is "c.counter"
                        // otherwise.
                        if HN != 0 {
                            c.N
                        } else {
                            0
                        }
                    } else {
                        0
                    };

                    Some(PreparePayload {
                        B: self.B.clone(),
                        P: clamped_P,
                        PP: clamped_PP,
                        HN,
                        CN,
                    })
                };

                if let Some(prepare_payload) = prepare_payload_opt {
                    // Issue NominatePrepare
                    Some(Topic::NominatePrepare(
                        NominatePayload::new(&self.X, &self.Y),
                        prepare_payload,
                    ))
                } else if !self.X.is_empty() || !self.Y.is_empty() {
                    // Issue Nominate
                    Some(Topic::Nominate(NominatePayload::new(&self.X, &self.Y)))
                } else {
                    None
                }
            }

            Phase::Prepare => {
                let HN: u32 = if let Some(h) = &self.H {
                    // If "h" is the highest confirmed prepared ballot and "h.value ==
                    // ballot.value", then this field is set to "h.counter".  Otherwise,
                    // if no ballot is confirmed prepared or if "h.value !=
                    // ballot.value", then this field is 0.  Note that by the rules
                    // above, if "h" exists, then "ballot.value" will be set to "h.value"
                    // the next time "ballot" is updated.
                    if h.X == self.B.X {
                        h.N
                    } else {
                        // H and B have different values.
                        0
                    }
                } else {
                    // No ballot confirmed prepared.
                    0
                };

                let CN: u32 = if let Some(c) = &self.C {
                    // The value "cCounter" is maintained based on an internally-
                    // maintained _commit ballot_ "c", initially "NULL".  "cCounter" is 0
                    // while "c == NULL" or "hCounter == 0", and is "c.counter"
                    // otherwise.
                    if HN != 0 {
                        c.N
                    } else {
                        0
                    }
                } else {
                    0
                };

                Some(Topic::Prepare(PreparePayload {
                    B: self.B.clone(),
                    P: clamped_P,
                    PP: clamped_PP,
                    HN,
                    CN,
                }))
            }

            Phase::Commit => Some(Topic::Commit(CommitPayload {
                B: self.B.clone(),
                PN: clamped_P.as_ref().map_or(0, |p| p.N),
                HN: self.H.as_ref().map_or(0, |h| h.N),
                CN: self.C.as_ref().map_or(0, |c| c.N),
            })),

            Phase::Externalize => Some(Topic::Externalize(ExternalizePayload {
                C: self.C.clone().unwrap(),
                HN: self.H.as_ref().unwrap().N,
            })),
        };

        let msg_opt = topic_opt.map(|topic| {
            Msg::new(
                self.node_id.clone(),
                self.quorum_set.clone(),
                self.slot_index,
                topic,
            )
        });

        // Suppress duplicate outgoing messages.
        if let Some(msg) = msg_opt {
            assert_eq!(msg.validate(), Ok(()));

            if let Some(last_msg) = &self.last_sent_msg {
                if msg != *last_msg {
                    self.last_sent_msg = Some(msg.clone());
                    return Some(msg);
                } else {
                    // Ignore duplicate outgoing message.
                    return None;
                }
            } else {
                // The first emitted message.
                self.last_sent_msg = Some(msg.clone());
                return Some(msg);
            }
        }

        None
    }

    /// Checks that at least one node in each quorum slice satisfies pred
    /// (excluding the slot's node).
    fn find_blocking_set<P: Predicate<V>>(&self, pred: P) -> (HashSet<NodeID>, P) {
        self.quorum_set.findBlockingSet(&self.M, pred)
    }

    /// Finds a quorum in which every node satisfies the given predicate.
    /// The slot's node itself is presumed to satisfy the predicate.
    fn find_quorum<P: Predicate<V>>(&self, pred: P) -> (HashSet<NodeID>, P) {
        self.quorum_set.findQuorum(&self.node_id, &self.M, pred)
    }

    /// "Accepted Nominated" values that are not yet in self.Y.
    fn additional_values_accepted_nominated(&self) -> BTreeSet<V> {
        // 1) Find values that can be accepted because a blocking set has issued accept
        // nominate.
        let mut accepted_from_blocking_set: BTreeSet<V> = {
            // All values accepted nominated by nodes other than the local node.
            let mut candidates: BTreeSet<V> = BTreeSet::default();
            for (node_id, msg) in &self.M {
                if *node_id == self.node_id {
                    continue;
                }
                if let Some(vals) = msg.accepts_nominated() {
                    candidates.extend(vals.iter().cloned());
                }
            }

            let mut results = BTreeSet::default();

            // Test if a blocking set has issued "accept nominate" for each value.
            for value in candidates {
                // Test if a blocking set has issued "accept nominate(v)".
                let predicate = ValueSetPredicate::<V> {
                    values: btreeset! {value.clone()},
                    test_fn: Arc::new(|msg, values| match msg.accepts_nominated() {
                        None => BTreeSet::default(),
                        Some(values_accepted_nominated) => values
                            .intersection(values_accepted_nominated)
                            .cloned()
                            .collect(),
                    }),
                };
                let (nodeIDs, _) = self.find_blocking_set(predicate);
                if !nodeIDs.is_empty() {
                    results.insert(value);
                }
            }

            results
        };

        // 2) Find values that can be accepted because a quorum has issued "vote
        // nominate" or "accept nominate".
        let mut accepted_from_quorum: BTreeSet<V> = {
            // Predicate for identifying values in self.X that can be moved to self.Y
            // because a quorum of nodes has issued "vote nominate" or "accept
            // nominate".
            let votes_or_accepts_predicate = ValueSetPredicate::<V> {
                values: self.X.iter().cloned().collect(),
                test_fn: Arc::new(|msg, values| match msg.votes_or_accepts_nominated() {
                    None => BTreeSet::default(),
                    Some(values_voted_or_accepted_nominated) => values
                        .intersection(&values_voted_or_accepted_nominated)
                        .cloned()
                        .collect(),
                }),
            };

            let (nodeIDs, pred) = self.find_quorum(votes_or_accepts_predicate);
            if !nodeIDs.is_empty() {
                pred.result()
            } else {
                Default::default()
            }
        };

        // Return the union
        let mut accepted_nominated: BTreeSet<V> = Default::default();
        accepted_nominated.append(&mut accepted_from_blocking_set);
        accepted_nominated.append(&mut accepted_from_quorum);

        accepted_nominated
    }

    /// "Confirmed Nominated" values that are not yet in self.Z.
    fn additional_values_confirmed_nominated(&self) -> BTreeSet<V> {
        let (quorum_ids, pred) = self.find_quorum(ValueSetPredicate::<V> {
            values: self.Y.difference(&self.Z).cloned().collect(),
            test_fn: Arc::new(|msg, values| match msg.accepts_nominated() {
                None => BTreeSet::default(),
                Some(values_accepted_nominated) => values
                    .intersection(&values_accepted_nominated)
                    .cloned()
                    .collect(),
            }),
        });

        if !quorum_ids.is_empty() {
            // Some values have been confirmed nominated.
            pred.result()
        } else {
            BTreeSet::new()
        }
    }

    /// All "accepted prepared" ballots.
    fn ballots_accepted_prepared(&self) -> Vec<Ballot<V>> {
        let accepted_from_blocking_set: HashSet<Ballot<V>> = {
            // Ballots for which any non-local node has issued "accept prepare(b)".
            let mut candidates: HashSet<Ballot<V>> = Default::default();
            for node_id in &self.quorum_set.nodes() {
                if let Some(msg) = self.M.get(node_id) {
                    candidates.extend(msg.accepts_prepared());
                }
            }

            let mut results: HashSet<Ballot<V>> = Default::default();

            for ballot in candidates.into_iter() {
                let predicate = BallotSetPredicate::<V> {
                    ballots: hashset! { ballot.clone()},
                    test_fn: Arc::new(|msg, candidates| {
                        let mut intersections: HashSet<Ballot<V>> = HashSet::default();

                        for ballot_a in &msg.accepts_prepared() {
                            for ballot_b in candidates {
                                if ballot_a.X == ballot_b.X {
                                    let min_counter = cmp::min(ballot_a.N, ballot_b.N);
                                    intersections.insert(Ballot::new(min_counter, &ballot_a.X));
                                }
                            }
                        }
                        intersections
                    }),
                };

                let (nodeIDs, _) = self.find_blocking_set(predicate);
                if !nodeIDs.is_empty() {
                    results.insert(ballot);
                }
            }

            results
        };

        // Ballots that can be accepted because a quorum has issued
        // vote-or-accept-prepare(b).
        let accepted_by_quorum: HashSet<Ballot<V>> = {
            let votes_or_accepts_predicate = {
                // Ballots for which the local node has issued vote-or-accept prepare(b).
                let mut candidates = HashSet::<Ballot<V>>::default();

                if !self.B.is_zero() {
                    candidates.insert(self.B.clone());
                }
                if let Some(P) = &self.P {
                    candidates.insert(P.clone());
                    if let Some(PP) = &self.PP {
                        candidates.insert(PP.clone());
                    }
                }

                BallotSetPredicate::<V> {
                    ballots: candidates,
                    test_fn: Arc::new(|msg, candidates| {
                        let mut intersections: HashSet<Ballot<V>> = HashSet::default();

                        for ballot_a in &msg.votes_or_accepts_prepared() {
                            for ballot_b in candidates {
                                if ballot_a.X == ballot_b.X {
                                    let min_counter = cmp::min(ballot_a.N, ballot_b.N);
                                    intersections.insert(Ballot::new(min_counter, &ballot_a.X));
                                }
                            }
                        }
                        intersections
                    }),
                }
            };

            let (nodeIDs, pred) = self.find_quorum(votes_or_accepts_predicate);
            if !nodeIDs.is_empty() {
                pred.result()
            } else {
                Default::default()
            }
        };

        // Return the union
        let accepted_prepared: Vec<Ballot<V>> = accepted_from_blocking_set
            .union(&accepted_by_quorum)
            .cloned()
            .collect();

        accepted_prepared
    }

    /// All "confirmed prepared" ballots.
    fn ballots_confirmed_prepared(&self) -> Vec<Ballot<V>> {
        let candidates: HashSet<_> = self.ballots_accepted_prepared().into_iter().collect();

        let (node_ids, pred) = self.find_quorum(BallotSetPredicate {
            ballots: candidates,
            test_fn: Arc::new(|msg, candidates| {
                let mut intersections: HashSet<Ballot<V>> = HashSet::default();
                for ballot_a in &msg.accepts_prepared() {
                    for ballot_b in candidates {
                        if ballot_a.X == ballot_b.X {
                            let min_counter = cmp::min(ballot_a.N, ballot_b.N);
                            intersections.insert(Ballot::new(min_counter, &ballot_a.X));
                        }
                    }
                }
                intersections
            }),
        });

        if !node_ids.is_empty() {
            pred.result().into_iter().collect()
        } else {
            Vec::new()
        }
    }

    /// All "accepted committed" ballots.
    ///
    /// Each entry (values, (a, b)) in the returned HashMap implies
    /// "accept commit(<n, values>)" for all n in [a,b].
    fn ballots_accepted_committed(&self) -> HashMap<Vec<V>, (u32, u32)> {
        let accepted_from_blocking_set: HashMap<Vec<V>, (u32, u32)> = {
            // Ballot ranges that have been accepted committed by other nodes in this node's
            // quorum set.
            let mut candidates: HashMap<Vec<V>, (u32, u32)> = Default::default();
            for node_id in &self.quorum_set.nodes() {
                if let Some(msg) = self.M.get(node_id) {
                    match msg.topic {
                        Topic::Commit(ref payload) => {
                            assert!(payload.CN <= payload.HN);
                            // "accept commit(<n, ballot.value>)" for every "cCounter <= n <=
                            // hCounter".
                            candidates.insert(payload.B.X.clone(), (payload.CN, payload.HN));
                        }
                        Topic::Externalize(ref payload) => {
                            // "accept commit(<n, commit.value>)" for every "n >= commit.counter"
                            candidates.insert(payload.C.X.clone(), (payload.C.N, INFINITY));
                        }
                        _ => {}
                    }
                }
            }

            let mut results: HashMap<Vec<V>, (u32, u32)> = Default::default();

            for (values, range) in candidates {
                let mut ballot_ranges: HashMap<Vec<V>, (u32, u32)> = Default::default();
                ballot_ranges.insert(values.clone(), range);
                let accepts_predicate = BallotRangePredicate::<V> {
                    ballot_ranges,
                    test_fn: Arc::new(|msg, ballot_ranges| {
                        let mut intersection: HashMap<Vec<V>, (u32, u32)> = Default::default();
                        for (values, &(min, max)) in ballot_ranges {
                            assert!(min <= max);
                            if let Some((a, b)) = msg.accepts_commits(values, min, max) {
                                assert!(a <= b);
                                intersection.insert(values.clone(), (a, b));
                            }
                        }
                        intersection
                    }),
                };

                let (nodeIDs, _) = self.find_blocking_set(accepts_predicate);
                if !nodeIDs.is_empty() {
                    results.insert(values, range);
                }
            }
            results
        };

        let accepted_by_quorum: HashMap<Vec<V>, (u32, u32)> = {
            let votes_or_accepts_predicate = {
                // Range of ballots for which the local node issues "vote-or-accept commit(b)".
                let mut candidates: HashMap<Vec<V>, (u32, u32)> = Default::default();
                if let (Some(C), Some(H)) = (&self.C, &self.H) {
                    assert!(C.N <= H.N, "C.N: {}, H.N: {}", C.N, H.N);
                    candidates.insert(self.B.X.clone(), (C.N, H.N));
                }

                BallotRangePredicate::<V> {
                    ballot_ranges: candidates,
                    test_fn: Arc::new(|msg, ballot_ranges| {
                        let mut intersection: HashMap<Vec<V>, (u32, u32)> = Default::default();
                        for (values, &(min, max)) in ballot_ranges {
                            if let Some((a, b)) = msg.votes_or_accepts_commits(values, min, max) {
                                intersection.insert(values.clone(), (a, b));
                            }
                        }
                        intersection
                    }),
                }
            };

            let (nodeIDs, pred) = self.find_quorum(votes_or_accepts_predicate);
            if !nodeIDs.is_empty() {
                pred.result()
            } else {
                Default::default()
            }
        };

        // The union of ranges accepted by quorum and accepted from blocking set.
        let mut ballot_ranges: HashMap<Vec<V>, (u32, u32)> = Default::default();

        for (values, (a, b)) in accepted_from_blocking_set
            .into_iter()
            .chain(accepted_by_quorum)
        {
            // "Upsert" values into ballot_ranges.
            match ballot_ranges.get_mut(&values) {
                Some((c, d)) => {
                    // TODO: If values maps to multiple ranges, take the union of those ranges?
                    let min = core::cmp::min(a, *c);
                    let max = core::cmp::max(b, *d);
                    ballot_ranges.insert(values, (min, max));
                }
                None => {
                    ballot_ranges.insert(values, (a, b));
                }
            }
        }

        ballot_ranges
    }

    /// All "confirmed committed" ballots compatible with self.B.X.
    fn ballots_confirmed_committed(&self) -> Option<(u32, u32)> {
        if !(self.phase == Phase::Commit || self.phase == Phase::Externalize || self.H.is_none()) {
            // This node has not yet issued "accept commit" for any ballot.
            return None;
        }

        // Ballot range accepted committed by this node.
        // self.C and self.H mean different things in the Commit and Externalize phase.
        let mut candidates: HashMap<Vec<V>, (u32, u32)> = Default::default();
        if self.phase == Phase::Commit {
            // In the Commit phase, C and H refer to ballots accepted committed.
            let hn = self.H.as_ref().map_or(0, |h| h.N);
            let cn = self.C.as_ref().map_or(0, |c| c.N);
            candidates.insert(self.B.X.clone(), (cn, hn));
        } else if self.phase == Phase::Externalize {
            // In the Externalize phase, C and H refer to ballots confirmed committed,
            // so re-compute the ballots that have been accepted committed.
            if let Some((low, high)) = self.ballots_accepted_committed().remove(&self.B.X) {
                candidates.insert(self.B.X.clone(), (low, high));
            }
        }

        let accepts_predicate = {
            BallotRangePredicate::<V> {
                ballot_ranges: candidates,
                test_fn: Arc::new(|msg, ballot_ranges| {
                    let mut intersection: HashMap<Vec<V>, (u32, u32)> = Default::default();
                    for (values, &(min, max)) in ballot_ranges {
                        assert!(min <= max);
                        if let Some((a, b)) = msg.accepts_commits(values, min, max) {
                            assert!(a <= b);
                            intersection.insert(values.clone(), (a, b));
                        }
                    }
                    intersection
                }),
            }
        };

        let (node_ids, pred) = self.find_quorum(accepts_predicate);

        if !node_ids.is_empty() {
            pred.result().remove(&self.B.X)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod nominate_protocol_tests {
    use super::*;
    use crate::{core_types::*, quorum_set::*, test_utils::*};
    use maplit::{btreeset, hashset};
    use mc_common::logger::test_with_logger;

    #[test_with_logger]
    // Should return no values if none can be accepted nominated.
    fn test_additional_values_accepted_nominated_none(logger: Logger) {
        //The four-node Fig.2 network.
        let (local_node, node_2, node_3, _node_4) = fig_2_network();

        let slot_index = 2;
        let mut slot = Slot::<u32, TransactionValidationError>::new(
            local_node.0.clone(),
            local_node.1,
            slot_index,
            Arc::new(trivial_validity_fn),
            Arc::new(trivial_combine_fn),
            logger,
        );

        // Initially, there should be no "accepted nominated" values.
        assert!(slot.additional_values_accepted_nominated().is_empty());

        // A blocking set issues "vote nominate", no values are accepted.
        {
            let msg = Msg::new(
                node_2.0.clone(),
                node_2.1,
                slot_index,
                Topic::Nominate(NominatePayload {
                    X: btreeset! {1000},
                    Y: BTreeSet::default(),
                }),
            );
            slot.M.insert(msg.sender_id.clone(), msg);
            assert!(slot.additional_values_accepted_nominated().is_empty());
        }

        // Another blocking set issues "vote nominate", no values are accepted.
        {
            let msg = Msg::new(
                node_3.0.clone(),
                node_3.1,
                slot_index,
                Topic::Nominate(NominatePayload {
                    X: btreeset! {1000},
                    Y: BTreeSet::default(),
                }),
            );
            slot.M.insert(msg.sender_id.clone(), msg);
            assert!(slot.additional_values_accepted_nominated().is_empty());
        }
    }

    #[test_with_logger]
    // Should return all values accepted nominated by any blocking set.
    fn test_additional_values_accepted_nominated_blocking_sets(logger: Logger) {
        //The four-node Fig.2 network.
        let (local_node, node_2, node_3, _node_4) = fig_2_network();

        let slot_index = 2;
        let mut slot = Slot::<u32, TransactionValidationError>::new(
            local_node.0.clone(),
            local_node.1,
            slot_index,
            Arc::new(trivial_validity_fn),
            Arc::new(trivial_combine_fn),
            logger,
        );

        // A blocking set (Node 2) issues "accept nominate(2222)".
        {
            let msg = Msg::new(
                node_2.0.clone(),
                node_2.1,
                slot_index,
                Topic::Nominate(NominatePayload {
                    X: BTreeSet::default(),
                    Y: btreeset! {2222},
                }),
            );
            slot.M.insert(msg.sender_id.clone(), msg);

            let expected = btreeset! {2222};
            assert_eq!(slot.additional_values_accepted_nominated(), expected);
        }

        // A different blocking set (Node 3) issues "accept nominate(3333)".
        {
            let msg = Msg::new(
                node_3.0.clone(),
                node_3.1,
                slot_index,
                Topic::Nominate(NominatePayload {
                    X: BTreeSet::default(),
                    Y: btreeset! {3333},
                }),
            );
            slot.M.insert(msg.sender_id.clone(), msg);

            let expected = btreeset! {2222, 3333};
            assert_eq!(slot.additional_values_accepted_nominated(), expected);
        }
    }

    #[test_with_logger]
    // Should return all values voted nominated by a quorum.
    fn test_additional_values_accepted_nominated_voted_by_quorum(logger: Logger) {
        //The four-node Fig.2 network.
        let (local_node, node_2, node_3, node_4) = fig_2_network();

        let slot_index = 2;
        let mut slot = Slot::<u32, TransactionValidationError>::new(
            local_node.0.clone(),
            local_node.1.clone(),
            slot_index,
            Arc::new(trivial_validity_fn),
            Arc::new(trivial_combine_fn),
            logger,
        );

        // Node 1 votes to nominate "1234".
        let msg_1 = Msg::new(
            local_node.0.clone(),
            local_node.1,
            slot_index,
            Topic::Nominate(NominatePayload {
                X: btreeset! {1234, 1111},
                Y: BTreeSet::default(),
            }),
        );
        slot.X = hashset! { 1234};
        slot.M.insert(msg_1.sender_id.clone(), msg_1);
        let expected = BTreeSet::default();
        assert_eq!(slot.additional_values_accepted_nominated(), expected);

        // Nodes 2, and 3 vote to nominate "1234".
        for node in vec![node_2, node_3] {
            // Node 1 votes to nominate "1234".
            let msg = Msg::new(
                node.0.clone(),
                node.1.clone(),
                slot_index,
                Topic::Nominate(NominatePayload {
                    X: btreeset! {1234, 9999},
                    Y: BTreeSet::default(),
                }),
            );
            slot.M.insert(msg.sender_id.clone(), msg);
            let expected = BTreeSet::default();
            assert_eq!(slot.additional_values_accepted_nominated(), expected);
        }

        // Node 4 votes to nominate "1234". This completes a quorum.
        let msg_4 = Msg::new(
            node_4.0.clone(),
            node_4.1,
            slot_index,
            Topic::Nominate(NominatePayload {
                X: btreeset! {1234, 4444},
                Y: BTreeSet::default(),
            }),
        );
        slot.M.insert(msg_4.sender_id.clone(), msg_4);
        // Only the value "1234" was voted nominated by the quorum:
        let expected = btreeset! {1234};
        assert_eq!(slot.additional_values_accepted_nominated(), expected);
    }

    #[test_with_logger]
    // Test that a node can be convinced by a blocking set to extend it's list of
    // "accepted nominated" (Y) with whatever the blocking set has accepted.
    // In this test node 1 has "accepted nominated" the value "B", while a blocking
    // set of its peers accepted-nominated "A","B","C","D". When updateYZ() is
    // called, it should extend it's "accepted nominated" (Y) list with "B", "C"
    // and "D".
    fn test_blocking_set_forces_accept_vote(logger: Logger) {
        let slot_index = 10;

        // (V=1 I=4731 NOM/PREP X=<>, Y=<"B">, B=<378, 1:["B"]>, P=<>, PP=<>, HN=0,
        // CN=0) (V=2 I=4731 NOM/PREP X=<>, Y=<"A", "B", "C", "D">, B=<"A", "B",
        // "C">, P=<>, PP=<>, HN=0, CN=0) (V=3 I=4731 NOM/PREP X=<>, Y=<"A",
        // "B", "C", "D">, B=<"A", "B", "C", "D">, P=<>, PP=<>, HN=0, CN=0) (V=4
        // I=4731 NOM/PREP X=<>, Y=<"A", "B", "C", "D">, B=<"A", "B", "C", "D">, P=<>,
        // PP=<>, HN=0, CN=0) (V=5 I=4731 NOM/PREP X=<>, Y=<"A", "B", "C", "D">,
        // B=<"A", "B", "C", "D">, P=<>, PP=<>, HN=0, CN=0)

        // (V=2 I=4731 NOM/PREP X=<>, Y=<"A", "B", "C", "D">, B=<"A", "B", "C">, P=<>,
        // PP=<>, HN=0, CN=0)
        let msg_2 = Msg::new(
            test_node_id(2),
            QuorumSet::new_with_node_ids(
                3,
                vec![
                    test_node_id(1),
                    test_node_id(3),
                    test_node_id(4),
                    test_node_id(5),
                ],
            ),
            slot_index,
            Topic::NominatePrepare(
                NominatePayload {
                    X: BTreeSet::default(),
                    Y: btreeset! {"A", "B", "C", "D"},
                },
                PreparePayload {
                    B: Ballot::new(1234, &["A", "B", "C"]),
                    P: None,
                    PP: None,
                    HN: 0,
                    CN: 0,
                },
            ),
        );

        // (V=3 I=4731 NOM/PREP X=<>, Y=<"A", "B", "C", "D">, B=<"A", "B", "C", "D">,
        // P=<>, PP=<>, HN=0, CN=0)
        let msg_3 = Msg::new(
            test_node_id(3),
            QuorumSet::new_with_node_ids(
                3,
                vec![
                    test_node_id(1),
                    test_node_id(2),
                    test_node_id(4),
                    test_node_id(5),
                ],
            ),
            slot_index,
            Topic::NominatePrepare(
                NominatePayload {
                    X: BTreeSet::default(),
                    Y: btreeset! {"A", "B", "C", "D"},
                },
                PreparePayload {
                    B: Ballot::new(1234, &["A", "B", "C", "D"]),
                    P: None,
                    PP: None,
                    HN: 0,
                    CN: 0,
                },
            ),
        );

        // (V=4 I=4731 NOM/PREP X=<>, Y=<"A", "B", "C", "D">, B=<"A", "B", "C", "D">,
        // P=<>, PP=<>, HN=0, CN=0)
        let msg_4 = Msg::new(
            test_node_id(4),
            QuorumSet::new_with_node_ids(
                3,
                vec![
                    test_node_id(1),
                    test_node_id(2),
                    test_node_id(3),
                    test_node_id(5),
                ],
            ),
            slot_index,
            Topic::NominatePrepare(
                NominatePayload {
                    X: BTreeSet::default(),
                    Y: btreeset! {"A", "B", "C", "D"},
                },
                PreparePayload {
                    B: Ballot::new(1234, &["A", "B", "C", "D"]),
                    P: None,
                    PP: None,
                    HN: 0,
                    CN: 0,
                },
            ),
        );

        // (V=5 I=4731 NOM/PREP X=<>, Y=<"A", "B", "C", "D">, B=<"A", "B", "C", "D">,
        // P=<>, PP=<>, HN=0, CN=0)
        let msg_5 = Msg::new(
            test_node_id(5),
            QuorumSet::new_with_node_ids(
                3,
                vec![
                    test_node_id(1),
                    test_node_id(2),
                    test_node_id(3),
                    test_node_id(4),
                ],
            ),
            slot_index,
            Topic::NominatePrepare(
                NominatePayload {
                    X: BTreeSet::default(),
                    Y: btreeset! {"A", "B", "C", "D"},
                },
                PreparePayload {
                    B: Ballot::new(1234, &["A", "B", "C", "D"]),
                    P: None,
                    PP: None,
                    HN: 0,
                    CN: 0,
                },
            ),
        );

        // (V=1 I=4731 NOM/PREP X=<>, Y=<"B">, B=<378, 1:["B"]>, P=<>, PP=<>, HN=0,
        // CN=0)
        let mut slot = Slot::new(
            test_node_id(1),
            QuorumSet::new_with_node_ids(
                3,
                vec![
                    test_node_id(2),
                    test_node_id(3),
                    test_node_id(4),
                    test_node_id(5),
                ],
            ),
            slot_index,
            Arc::new(trivial_validity_fn),
            Arc::new(trivial_combine_fn),
            logger,
        );
        slot.Y = hashset! { "B"};
        slot.Z = hashset! { "B"};
        slot.M.insert(msg_2.sender_id.clone(), msg_2);
        slot.M.insert(msg_3.sender_id.clone(), msg_3);
        slot.M.insert(msg_4.sender_id.clone(), msg_4);
        slot.M.insert(msg_5.sender_id.clone(), msg_5);

        // Nodes 2,3,4,5 form a blocking set for the local node 1. updateYZ should cause
        // the local node to update it's accepted nominated (Y) list from what
        // the blocking set has agreed on.
        slot.update_YZ();
        assert_eq!(slot.Y, hashset! { "A", "B", "C", "D"});
    }

    #[test_with_logger]
    // This test verifies that a node that sees two separate quorums with different
    // but compatible "confirmed nominated" values ends up confirm-nominating
    // both set of values. In this test, node 2 has confirmed-nominated
    // "A","B","C" and accepted-nominated "A","B","C","D".
    // Looking at the quorum (1,2,3,4) would not cause node 2 to confirm-nominate
    // "D", but looking at the quorum (2,3,4,5) would. This test makes sure the
    // node confirms-nominates all the possible values from it's various quorums
    // (and not just the first one it sees when performing quorum checks).
    fn test_confirm_nominate_with_overlapping_quorums(logger: Logger) {
        let slot_index = 10;

        // (V=1 I=4731 NOM/PREP X=<>, Y=<"B">, B=<378, 1:["B"]>, P=<>, PP=<>, HN=0,
        // CN=0) (V=2 I=4731 NOM/PREP X=<>, Y=<"A", "B", "C", "D">, B=<"A", "B",
        // "C">, P=<>, PP=<>, HN=0, CN=0) (V=3 I=4731 NOM/PREP X=<>, Y=<"A",
        // "B", "C", "D">, B=<"A", "B", "C", "D">, P=<>, PP=<>, HN=0, CN=0) (V=4
        // I=4731 NOM/PREP X=<>, Y=<"A", "B", "C", "D">, B=<"A", "B", "C", "D">, P=<>,
        // PP=<>, HN=0, CN=0) (V=5 I=4731 NOM/PREP X=<>, Y=<"A", "B", "C", "D">,
        // B=<"A", "B", "C", "D">, P=<>, PP=<>, HN=0, CN=0)

        // (V=1 I=4731 NOM/PREP X=<>, Y=<"B">, B=<378, 1:["B"]>, P=<>, PP=<>, HN=0,
        // CN=0)
        let msg_1 = Msg::new(
            test_node_id(1),
            QuorumSet::new_with_node_ids(
                3,
                vec![
                    test_node_id(2),
                    test_node_id(3),
                    test_node_id(4),
                    test_node_id(5),
                ],
            ),
            slot_index,
            Topic::NominatePrepare(
                NominatePayload {
                    X: BTreeSet::default(),
                    Y: btreeset! { "B"},
                },
                PreparePayload {
                    B: Ballot::new(1234, &["B"]),
                    P: None,
                    PP: None,
                    HN: 0,
                    CN: 0,
                },
            ),
        );

        // (V=3 I=4731 NOM/PREP X=<>, Y=<"A", "B", "C", "D">, B=<"A", "B", "C", "D">,
        // P=<>, PP=<>, HN=0, CN=0)
        let msg_3 = Msg::new(
            test_node_id(3),
            QuorumSet::new_with_node_ids(
                3,
                vec![
                    test_node_id(1),
                    test_node_id(2),
                    test_node_id(4),
                    test_node_id(5),
                ],
            ),
            slot_index,
            Topic::NominatePrepare(
                NominatePayload {
                    X: BTreeSet::default(),
                    Y: btreeset! {"A", "B", "C", "D"},
                },
                PreparePayload {
                    B: Ballot::new(1234, &["A", "B", "C", "D"]),
                    P: None,
                    PP: None,
                    HN: 0,
                    CN: 0,
                },
            ),
        );

        // (V=4 I=4731 NOM/PREP X=<>, Y=<"A", "B", "C", "D">, B=<"A", "B", "C", "D">,
        // P=<>, PP=<>, HN=0, CN=0)
        let msg_4 = Msg::new(
            test_node_id(4),
            QuorumSet::new_with_node_ids(
                3,
                vec![
                    test_node_id(1),
                    test_node_id(2),
                    test_node_id(3),
                    test_node_id(5),
                ],
            ),
            slot_index,
            Topic::NominatePrepare(
                NominatePayload {
                    X: BTreeSet::default(),
                    Y: btreeset! {"A", "B", "C", "D"},
                },
                PreparePayload {
                    B: Ballot::new(1234, &["A", "B", "C", "D"]),
                    P: None,
                    PP: None,
                    HN: 0,
                    CN: 0,
                },
            ),
        );

        // (V=5 I=4731 NOM/PREP X=<>, Y=<"A", "B", "C", "D">, B=<"A", "B", "C", "D">,
        // P=<>, PP=<>, HN=0, CN=0)
        let msg_5 = Msg::new(
            test_node_id(5),
            QuorumSet::new_with_node_ids(
                3,
                vec![
                    test_node_id(1),
                    test_node_id(2),
                    test_node_id(3),
                    test_node_id(4),
                ],
            ),
            slot_index,
            Topic::NominatePrepare(
                NominatePayload {
                    X: BTreeSet::default(),
                    Y: btreeset! {"A", "B", "C", "D"},
                },
                PreparePayload {
                    B: Ballot::new(1234, &["A", "B", "C", "D"]),
                    P: None,
                    PP: None,
                    HN: 0,
                    CN: 0,
                },
            ),
        );

        // (V=2 I=4731 NOM/PREP X=<>, Y=<"A", "B", "C", "D">, B=<"A", "B", "C">, P=<>,
        // PP=<>, HN=0, CN=0)
        let mut slot = Slot::new(
            test_node_id(2),
            QuorumSet::new_with_node_ids(
                3,
                vec![
                    test_node_id(1),
                    test_node_id(3),
                    test_node_id(4),
                    test_node_id(5),
                ],
            ),
            slot_index,
            Arc::new(trivial_validity_fn),
            Arc::new(trivial_combine_fn),
            logger,
        );
        slot.Y = hashset! { "A", "B", "C", "D"};
        slot.Z = hashset! { "A", "B", "C"};
        slot.M.insert(msg_1.sender_id.clone(), msg_1);
        slot.M.insert(msg_3.sender_id.clone(), msg_3);
        slot.M.insert(msg_4.sender_id.clone(), msg_4);
        slot.M.insert(msg_5.sender_id.clone(), msg_5);

        // Calling updateYZ should add "D" to confirmed nominated (Z) since a quorum
        // (2,3,4,5) have accepted nominated (Y) it.
        slot.update_YZ();
        assert_eq!(slot.Z, hashset! { "A", "B", "C", "D"});
    }

    #[test_with_logger]
    /// A node should not nominate proposed values if it is not in
    /// max_priority_peers.
    fn test_wait_to_nominate_proposed_values(logger: Logger) {
        let (local_node, _node_2, _node_3) = three_node_cycle();

        let slot_index = 2;
        let mut slot = Slot::<u32, TransactionValidationError>::new(
            local_node.0.clone(),
            local_node.1.clone(),
            slot_index,
            Arc::new(trivial_validity_fn),
            Arc::new(trivial_combine_fn),
            logger,
        );

        println!("max_priority_peers: {:?}", slot.max_priority_peers);
        // Ensure that the local node **is not** in max_priority_peers.
        assert!(!slot.max_priority_peers.contains(&local_node.0));

        let values: BTreeSet<u32> = btreeset! { 1000, 2000};
        let msg_opt = slot
            .propose_values(&values)
            .expect("slot.propose_values failed");
        assert_eq!(msg_opt, None);
    }

    #[test_with_logger]
    /// A node should nominate proposed values if it is in max_priority_peers.
    fn test_nominate_proposed_values(logger: Logger) {
        let (local_node, _node_2, _node_3) = three_node_cycle();

        let slot_index = 2;
        let mut slot = Slot::<u32, TransactionValidationError>::new(
            local_node.0.clone(),
            local_node.1.clone(),
            slot_index,
            Arc::new(trivial_validity_fn),
            Arc::new(trivial_combine_fn),
            logger,
        );

        println!("max_priority_peers: {:?}", slot.max_priority_peers);
        // Ensure that the local node **is** in max_priority_peers.
        slot.max_priority_peers.insert(local_node.0.clone());

        {
            // The node should nominate proposed values.
            let values: BTreeSet<u32> = btreeset! { 1000, 2000};
            let emitted = slot
                .propose_values(&values)
                .expect("slot.propose_values failed")
                .expect("No message emitted");

            let expected = Msg::new(
                local_node.0.clone(),
                local_node.1.clone(),
                slot_index,
                Topic::Nominate(NominatePayload {
                    X: btreeset! { 1000, 2000},
                    Y: BTreeSet::default(),
                }),
            );

            assert_eq!(emitted, expected);
        }

        {
            // The node should continue to nominate new proposed values.
            let values: BTreeSet<u32> = btreeset! { 777, 4242};
            let emitted = slot
                .propose_values(&values)
                .expect("slot.propose_values failed")
                .expect("No message emitted");

            let expected = Msg::new(
                local_node.0.clone(),
                local_node.1.clone(),
                slot_index,
                Topic::Nominate(NominatePayload {
                    X: btreeset! { 777, 1000, 2000, 4242},
                    Y: BTreeSet::default(),
                }),
            );

            assert_eq!(emitted, expected);
        }
    }
}

#[cfg(test)]
mod ballot_protocol_tests {
    use super::*;
    use crate::{core_types::*, quorum_set::*, test_utils::*};
    use maplit::{btreeset, hashset};
    use mc_common::logger::test_with_logger;
    use pretty_assertions::assert_eq;
    use std::iter::FromIterator;

    // TODO: reject a message if it contains a ballot containing incorrectly ordered
    // values.

    // === Handling "confirmed nominated" values ===

    #[test_with_logger]
    // A node with the trivial quorum set should immediately externalize.
    fn test_on_nominated_trivial_quorum_set(logger: Logger) {
        let local_node = (test_node_id(1), QuorumSet::empty());

        let slot_index = 10;
        let mut slot = Slot::<u32, TransactionValidationError>::new(
            local_node.0.clone(),
            local_node.1.clone(),
            slot_index,
            Arc::new(trivial_validity_fn),
            Arc::new(trivial_combine_fn),
            logger,
        );

        let values = btreeset! { 5678, 1234, 1337, 1338};
        let emitted_msg = slot
            .propose_values(&values)
            .unwrap()
            .expect("No message emitted.");

        let expected = Msg::new(
            local_node.0.clone(),
            local_node.1.clone(),
            slot_index,
            Topic::Externalize(ExternalizePayload {
                C: Ballot::new(1, &vec![1234, 1337, 1338, 5678]),
                HN: 1,
            }),
        );
        assert_eq!(emitted_msg, expected);
    }

    #[test_with_logger]
    // An "uncommitted" node should issue `vote-or-accept prepare <1,V>` when
    // nomination produces values V.
    fn test_uncommitted_to_votes(logger: Logger) {
        let node_id = test_node_id(1);
        let quorum_set = QuorumSet::new_with_node_ids(1, vec![test_node_id(2)]);

        let mut slot = Slot::<u32, TransactionValidationError>::new(
            node_id.clone(),
            quorum_set.clone(),
            1,
            Arc::new(trivial_validity_fn),
            Arc::new(trivial_combine_fn),
            logger,
        );

        // Ensure our node id is inside max priority peers list.
        slot.max_priority_peers.insert(node_id.clone());

        let values: BTreeSet<u32> = btreeset! { 1000, 2000};
        let emitted_msg = slot
            .propose_values(&values)
            .expect("slot.propose_values failed")
            .expect("expected emitted message, got None");

        let expected_msg = Msg::new(
            node_id,
            quorum_set,
            1,
            Topic::Nominate(NominatePayload {
                X: btreeset! { 1000, 2000},
                Y: BTreeSet::default(),
            }),
        );

        assert_eq!(emitted_msg, expected_msg);
        assert_eq!(
            emitted_msg.votes_or_accepts_nominated(),
            Some(btreeset! { 1000, 2000})
        );
        assert_eq!(emitted_msg.accepts_nominated(), Some(&BTreeSet::default()));
    }

    #[test_with_logger]
    // A node that has not issued confirmed prepare(b) should continue to vote for
    // new, confirmed nominated values when it advances to a new ballot.
    fn test_additional_confirmed_nominated_values(logger: Logger) {
        let node_1 = (
            test_node_id(1),
            QuorumSet::new_with_node_ids(
                1,
                vec![test_node_id(2), test_node_id(3), test_node_id(4)],
            ),
        );
        let node_2 = (
            test_node_id(2),
            QuorumSet::new_with_node_ids(
                1,
                vec![test_node_id(1), test_node_id(3), test_node_id(4)],
            ),
        );

        let slot_index = 0;
        let mut slot = Slot::<u32, TransactionValidationError>::new(
            node_1.0.clone(),
            node_1.1.clone(),
            slot_index,
            Arc::new(trivial_validity_fn),
            Arc::new(trivial_combine_fn),
            logger,
        );

        // Ensure node_1 is inside max priority peers list.
        slot.max_priority_peers.insert(node_1.0.clone());

        // Vote nominate on 1337, 1338 and confirm nominate 5678, 1234.
        {
            let values: BTreeSet<u32> = btreeset! {5678, 1234, 1337, 1338};
            let emitted_msg = slot
                .propose_values(&values)
                .expect("slot.propose failed")
                .expect("no msg emitted");

            let expected = Msg::new(
                node_1.0.clone(),
                node_1.1.clone(),
                slot_index,
                Topic::Nominate(NominatePayload {
                    X: values.clone(),
                    Y: BTreeSet::default(),
                }),
            );

            // Node 1 issues vote nominate [5678, 1234, 1337, 1338].
            assert_eq!(emitted_msg, expected);

            // Node 2 issues confirm nominate [5678, 1234].
            let confirm_nominate_msg = Msg::new(
                node_2.0.clone(),
                node_2.1.clone(),
                slot_index,
                Topic::Nominate(NominatePayload {
                    X: BTreeSet::default(),
                    Y: btreeset! { 1234, 5678},
                }),
            );
            let emitted_msg = slot
                .handle_message(&confirm_nominate_msg)
                .expect("failed handling msg")
                .expect("no msg emitted");

            let expected_msg = Msg::new(
                node_1.0.clone(),
                node_1.1.clone(),
                slot_index,
                Topic::NominatePrepare(
                    NominatePayload {
                        X: btreeset! { 1337, 1338},
                        Y: btreeset! { 1234, 5678},
                    },
                    PreparePayload {
                        B: Ballot::new(1, &[1234, 5678]),
                        P: None,
                        PP: None,
                        HN: 0,
                        CN: 0,
                    },
                ),
            );
            // Node 1 confirms [5678, 1234] nominated, and votes to prepare them.
            assert_eq!(emitted_msg, expected_msg);
        }

        // Confirm nominate 1337, 1338. The ballot should not change.
        {
            let confirm_nominate_msg = Msg::new(
                node_2.0.clone(),
                node_2.1,
                slot_index,
                Topic::Nominate(NominatePayload {
                    X: BTreeSet::default(),
                    Y: btreeset! { 5678, 1234, 1337, 1338},
                }),
            );
            let emitted_msg = slot
                .handle_message(&confirm_nominate_msg)
                .expect("failed handling msg")
                .expect("no msg emitted");
            let expected_msg = Msg::new(
                node_1.0.clone(),
                node_1.1.clone(),
                slot_index,
                Topic::NominatePrepare(
                    NominatePayload {
                        X: BTreeSet::default(),
                        Y: btreeset! { 5678, 1234, 1337, 1338},
                    },
                    PreparePayload {
                        B: Ballot::new(1, &[1234, 5678]),
                        P: None,
                        PP: None,
                        HN: 0,
                        CN: 0,
                    },
                ),
            );
            assert_eq!(emitted_msg, expected_msg);
        }

        // Force ballot timeout timer to fire.
        slot.next_ballot_at = Some(Instant::now() - Duration::from_secs(1));

        // When the timer fires, we should advance to a new ballot with all 4 values.
        {
            let msgs = slot.process_timeouts();
            assert_eq!(msgs.len(), 1);

            let expected_msg = Msg::new(
                node_1.0.clone(),
                node_1.1,
                slot_index,
                Topic::NominatePrepare(
                    NominatePayload {
                        X: BTreeSet::default(),
                        Y: btreeset! { 5678, 1234, 1337, 1338},
                    },
                    PreparePayload {
                        B: Ballot::new(2, &[1234, 1337, 1338, 5678]),
                        P: None,
                        PP: None,
                        HN: 0,
                        CN: 0,
                    },
                ),
            );

            assert_eq!(msgs[0], expected_msg);
        }
    }

    #[test_with_logger]
    // A node that has issued "accept prepare(b)" but not "confirm prepare(b)"
    // should include confirmed nominated values when it advances to the next
    // ballot.
    fn test_confirmed_nominated_after_accepted_prepared(logger: Logger) {
        let node_1 = (
            test_node_id(1),
            QuorumSet::new_with_node_ids(
                1,
                vec![test_node_id(2), test_node_id(3), test_node_id(4)],
            ),
        );
        let node_2 = (
            test_node_id(2),
            QuorumSet::new_with_node_ids(
                1,
                vec![test_node_id(1), test_node_id(3), test_node_id(4)],
            ),
        );
        let node_3 = (
            test_node_id(3),
            QuorumSet::new_with_node_ids(
                1,
                vec![test_node_id(1), test_node_id(2), test_node_id(4)],
            ),
        );

        let slot_index = 0;
        let mut slot = Slot::<u32, TransactionValidationError>::new(
            node_1.0.clone(),
            node_1.1.clone(),
            slot_index,
            Arc::new(trivial_validity_fn),
            Arc::new(trivial_combine_fn),
            logger,
        );

        // Initialize slot so that it has issued "accept prepare(b)". This involves
        // adding a Prepare message from node 2 as well.
        {
            slot.phase = Phase::NominatePrepare;
            slot.X = hashset! { 1337, 1338};
            slot.Y = hashset! { 1234, 5678};
            slot.B = Ballot::new(2, &[1234, 5678]);
            slot.P = Some(slot.B.clone());
            slot.last_sent_msg = slot.out_msg();

            let accept_prepare_msg = Msg::new(
                node_2.0.clone(),
                node_2.1,
                slot_index,
                Topic::Prepare(PreparePayload {
                    B: Ballot::new(2, &[1234, 5678]),
                    P: None,
                    PP: None,
                    CN: 0,
                    HN: 0,
                }),
            );
            let emitted_msg = slot
                .handle_message(&accept_prepare_msg)
                .expect("failed handling msg");
            assert_eq!(emitted_msg, None);
        }

        // Confirm nominate 1337, 1338. The ballot should not change.
        {
            let confirm_nominate_msg = Msg::new(
                node_3.0.clone(),
                node_3.1,
                slot_index,
                Topic::Nominate(NominatePayload {
                    X: BTreeSet::default(),
                    Y: btreeset! { 5678, 1234, 1337, 1338},
                }),
            );
            let emitted_msg = slot
                .handle_message(&confirm_nominate_msg)
                .expect("failed handling msg")
                .expect("no msg emitted");
            let expected_msg = Msg::new(
                node_1.0.clone(),
                node_1.1.clone(),
                slot_index,
                Topic::NominatePrepare(
                    NominatePayload {
                        X: BTreeSet::default(),
                        Y: btreeset! { 5678, 1234, 1337, 1338},
                    },
                    PreparePayload {
                        B: Ballot::new(2, &[1234, 5678]),
                        P: Some(Ballot::new(2, &[1234, 5678])),
                        PP: None,
                        HN: 0,
                        CN: 0,
                    },
                ),
            );
            assert_eq!(emitted_msg, expected_msg);
        }

        // Force ballot timeout timer to fire.
        slot.next_ballot_at = Some(Instant::now() - Duration::from_secs(1));

        // When the timer fires, we should advance to a new ballot with all 4 values.
        // The prepared value should not change.
        {
            let msgs = slot.process_timeouts();
            assert_eq!(msgs.len(), 1);

            let expected_msg = Msg::new(
                node_1.0.clone(),
                node_1.1,
                slot_index,
                Topic::NominatePrepare(
                    NominatePayload {
                        X: BTreeSet::default(),
                        Y: btreeset! { 5678, 1234, 1337, 1338},
                    },
                    PreparePayload {
                        B: Ballot::new(3, &[1234, 1337, 1338, 5678]),
                        P: Some(Ballot::new(2, &[1234, 5678])),
                        PP: None,
                        HN: 0,
                        CN: 0,
                    },
                ),
            );

            assert_eq!(msgs[0], expected_msg);
        }
    }

    #[test_with_logger]
    // A node that has issued `confirm prepare(b)` should no longer include new
    // confirmed nominated values in its subsequent ballots.
    fn test_ignore_nominated_values_after_issuing_confirm_prepare(logger: Logger) {
        let node_1 = (
            test_node_id(1),
            QuorumSet::new_with_node_ids(
                1,
                vec![test_node_id(2), test_node_id(3), test_node_id(4)],
            ),
        );
        let node_2 = (
            test_node_id(2),
            QuorumSet::new_with_node_ids(
                1,
                vec![test_node_id(1), test_node_id(3), test_node_id(4)],
            ),
        );
        let node_3 = (
            test_node_id(3),
            QuorumSet::new_with_node_ids(
                1,
                vec![test_node_id(1), test_node_id(2), test_node_id(4)],
            ),
        );

        let slot_index = 0;
        let mut slot = Slot::<u32, TransactionValidationError>::new(
            node_1.0.clone(),
            node_1.1.clone(),
            slot_index,
            Arc::new(trivial_validity_fn),
            Arc::new(trivial_combine_fn),
            logger,
        );

        // Initialize slot so that it has issued "confirm prepare(b)".
        {
            slot.phase = Phase::Prepare;
            slot.X = hashset! { 1337, 1338};
            slot.Y = hashset! { 1234, 5678};
            slot.B = Ballot::new(3, &[1234, 5678]);
            slot.P = Some(Ballot::new(2, &[1234, 5678]));
            slot.H = slot.P.clone();
            slot.last_sent_msg = slot.out_msg();
            slot.M.insert(
                node_2.0.clone(),
                Msg::new(
                    node_2.0.clone(),
                    node_2.1,
                    slot_index,
                    Topic::Prepare(PreparePayload {
                        B: Ballot::new(2, &[1234, 5678]),
                        P: Some(Ballot::new(2, &[1234, 5678])),
                        PP: None,
                        CN: 0,
                        HN: 0,
                    }),
                ),
            );
        }

        // Confirm nominate 1337, 1338. The ballot should not change.
        {
            let confirm_nominate_msg = Msg::new(
                node_3.0.clone(),
                node_3.1,
                slot_index,
                Topic::Nominate(NominatePayload {
                    X: BTreeSet::default(),
                    Y: btreeset! { 5678, 1234, 1337, 1338},
                }),
            );
            let emitted_msg = slot
                .handle_message(&confirm_nominate_msg)
                .expect("failed handling msg");
            assert_eq!(emitted_msg, None);
        }

        // Force ballot timeout timer to fire.
        slot.next_ballot_at = Some(Instant::now() - Duration::from_secs(1));

        // The next higher ballot should **not** include the latest confirmed nominated
        // values.
        {
            let msgs = slot.process_timeouts();
            assert_eq!(msgs.len(), 1);

            let expected_msg = Msg::new(
                node_1.0.clone(),
                node_1.1,
                slot_index,
                Topic::Prepare(PreparePayload {
                    B: Ballot::new(4, &[1234, 5678]),
                    P: Some(Ballot::new(2, &[1234, 5678])),
                    PP: None,
                    HN: 2,
                    CN: 0,
                }),
            );

            assert_eq!(msgs[0], expected_msg);
        }
    }

    // == Issuing "accept prepare" ===

    #[test_with_logger]
    // A node should not issue "accept prepare(b)" if it has only
    // seen a blocking set of other nodes issue "vote prepare(b)".
    fn test_ballots_accepted_prepared_no_such_ballots(logger: Logger) {
        let (local_node, node_2, node_3) = three_node_cycle();

        let slot_index = 2;
        let mut slot = Slot::<u32, TransactionValidationError>::new(
            local_node.0.clone(),
            local_node.1.clone(),
            slot_index,
            Arc::new(trivial_validity_fn),
            Arc::new(trivial_combine_fn),
            logger,
        );

        let ballot = Ballot::new(1, &[5678, 1234]);

        // Node 2 has issued "vote-or-accept prepare(b)".
        {
            let msg = Msg::new(
                node_2.0.clone(),
                node_2.1,
                slot_index,
                Topic::Prepare(PreparePayload {
                    B: ballot.clone(),
                    P: None,
                    PP: None,
                    HN: 0,
                    CN: 0,
                }),
            );

            let emitted_msg = slot.handle_message(&msg);
            assert_eq!(emitted_msg.unwrap(), None);
        }

        // Force node 1 into  "vote-or-accept prepare(b)".
        {
            slot.phase = Phase::Prepare;
            slot.B = ballot.clone();
            slot.last_sent_msg = slot.out_msg();

            // Nodes 1 and 2 are not a quorum, so the local node may still not
            // issue "accept prepare(b)".
            assert_eq!(
                slot.last_sent_msg.as_ref().unwrap(),
                &Msg::new(
                    local_node.0.clone(),
                    local_node.1.clone(),
                    slot_index,
                    Topic::Prepare(PreparePayload {
                        B: ballot.clone(),
                        P: None,
                        PP: None,
                        HN: 0,
                        CN: 0,
                    }),
                )
            );
        }

        // Sanity for this test: Node 3 has issued "vote-or-accept prepare(b)", this
        // should get local node to issue "accept prepare(b)".
        {
            let msg = Msg::new(
                node_3.0.clone(),
                node_3.1,
                slot_index,
                Topic::Prepare(PreparePayload {
                    B: ballot.clone(),
                    P: None,
                    PP: None,
                    HN: 0,
                    CN: 0,
                }),
            );
            let emitted_msg = slot
                .handle_message(&msg)
                .expect("failed handling msg")
                .expect("no msg emitted");

            assert_eq!(
                emitted_msg,
                Msg::new(
                    local_node.0.clone(),
                    local_node.1,
                    slot_index,
                    Topic::Prepare(PreparePayload {
                        B: ballot.clone(),
                        P: Some(ballot),
                        PP: None,
                        HN: 0,
                        CN: 0,
                    }),
                )
            );
        }
    }

    #[test_with_logger]
    // An "uncommitted" node should issue `accept prepare <n,V>` when it sees a
    // blocking set that issues `accept prepare <n, V>`. It should not issue any
    // statement until then.
    fn test_uncommitted_to_blocking_set_accepts(logger: Logger) {
        let local_node_quorum_set: QuorumSet = {
            let inner_quorum_set_one = QuorumSet::new_with_node_ids(
                2,
                vec![test_node_id(2), test_node_id(3), test_node_id(4)],
            );
            let inner_quorum_set_two = QuorumSet::new_with_node_ids(
                2,
                vec![test_node_id(5), test_node_id(6), test_node_id(7)],
            );
            QuorumSet::new_with_inner_sets(2, vec![inner_quorum_set_one, inner_quorum_set_two])
        };
        let local_node_id = test_node_id(1);
        let slot_index = 0;

        let mut slot = Slot::<u32, TransactionValidationError>::new(
            local_node_id.clone(),
            local_node_quorum_set.clone(),
            slot_index,
            Arc::new(trivial_validity_fn),
            Arc::new(trivial_combine_fn),
            logger,
        );
        slot.phase = Phase::NominatePrepare;

        // Nodes 2 and 3 are a blocking set.
        let node_2_id = test_node_id(2);
        let node_2_quorum_set =
            QuorumSet::new_with_node_ids(1, vec![test_node_id(3), test_node_id(4)]);

        let node_3_id = test_node_id(3);
        let node_3_quorum_set =
            QuorumSet::new_with_node_ids(1, vec![test_node_id(2), test_node_id(4)]);

        // A statement from Node 2 is not enough for the local node to emit a statement.
        {
            let statement_from_node_2 = Msg::new(
                node_2_id,
                node_2_quorum_set,
                slot_index,
                Topic::Prepare(PreparePayload {
                    B: Ballot::new(3, &[5678, 1234]),
                    P: Some(Ballot::new(3, &[5678, 1234])),
                    PP: None,
                    HN: 0,
                    CN: 0,
                }),
            );

            let emitted_msg = slot
                .handle_message(&statement_from_node_2)
                .expect("failed handling msg");
            assert!(emitted_msg.is_none());
        }

        // With this statement, the local node has seen a blocking set who have issued
        // `accept prepare(b)`. The local node should also emit `accept
        // prepare(b)`.
        let statement_from_node_3 = Msg::new(
            node_3_id,
            node_3_quorum_set,
            slot_index,
            Topic::Prepare(PreparePayload {
                B: Ballot::new(3, &[5678, 1234]),
                P: Some(Ballot::new(3, &[5678, 1234])),
                PP: None,
                HN: 0,
                CN: 0,
            }),
        );

        {
            let emitted_msg = slot
                .handle_message(&statement_from_node_3)
                .expect("failed handling msg")
                .expect("no msg emitted");

            let expected_msg = Msg::new(
                local_node_id,
                local_node_quorum_set,
                slot_index,
                Topic::NominatePrepare(
                    NominatePayload {
                        X: BTreeSet::default(),
                        Y: BTreeSet::default(),
                    },
                    PreparePayload {
                        B: Ballot::new(3, &[5678, 1234]),
                        P: Some(Ballot::new(3, &[5678, 1234])),
                        PP: None,
                        HN: 0,
                        CN: 0,
                    },
                ),
            );

            assert_eq!(emitted_msg, expected_msg);
        }
    }

    #[test_with_logger]
    // A node who has issued `vote prepare<1,C>` should issue `accept prepare <1,C>`
    // when: 1) A blocking set issues `accept prepare<1,C>, or
    // 2) A quorum votes or accepts prepare<1,C>
    fn test_votes_to_accepts_same_value_case_1(logger: Logger) {
        let local_node_quorum_set: QuorumSet = {
            let inner_quorum_set_one = QuorumSet::new_with_node_ids(
                2,
                vec![test_node_id(2), test_node_id(3), test_node_id(4)],
            );
            let inner_quorum_set_two = QuorumSet::new_with_node_ids(
                2,
                vec![test_node_id(5), test_node_id(6), test_node_id(7)],
            );
            QuorumSet::new_with_inner_sets(2, vec![inner_quorum_set_one, inner_quorum_set_two])
        };

        let local_node_id = test_node_id(1);
        let slot_index = 0;

        let mut slot = Slot::<u32, TransactionValidationError>::new(
            local_node_id.clone(),
            local_node_quorum_set.clone(),
            slot_index,
            Arc::new(trivial_validity_fn),
            Arc::new(trivial_combine_fn),
            logger,
        );

        // Mutate slot so that it has issued `vote prepare<1,C>`.
        let ballot = Ballot::new(1, &[5678, 1234]);

        slot.phase = Phase::Prepare;
        slot.B = ballot.clone();
        slot.last_sent_msg = slot.out_msg();

        let initial_msg = Msg::new(
            local_node_id.clone(),
            local_node_quorum_set.clone(),
            slot_index,
            Topic::Prepare(PreparePayload {
                B: ballot,
                P: None,
                PP: None,
                HN: 0,
                CN: 0,
            }),
        );

        assert_eq!(slot.last_sent_msg, Some(initial_msg));

        // Nodes 2 and 3 are a blocking set.
        let node_2_id = test_node_id(2);
        let node_2_quorum_set =
            QuorumSet::new_with_node_ids(1, vec![test_node_id(3), test_node_id(4)]);

        let node_3_id = test_node_id(3);
        let node_3_quorum_set =
            QuorumSet::new_with_node_ids(1, vec![test_node_id(2), test_node_id(4)]);

        // A statement from only node_2 should not change the statement issued by the
        // local node.
        {
            let statement_from_node_2 = Msg::new(
                node_2_id,
                node_2_quorum_set,
                slot_index,
                Topic::Prepare(PreparePayload {
                    B: Ballot::new(3, &[5678, 1234]),
                    P: Some(Ballot::new(3, &[5678, 1234])),
                    PP: None,
                    HN: 0,
                    CN: 0,
                }),
            );

            let emitted_msg = slot
                .handle_message(&statement_from_node_2)
                .expect("failed handling msg");
            assert!(emitted_msg.is_none());
        }

        // With this statement, the local node has seen a blocking set who have issued
        // `accept prepare(b)`. The local node should also emit `accept
        // prepare(b)`.
        let statement_from_node_3 = Msg::new(
            node_3_id,
            node_3_quorum_set,
            slot_index,
            Topic::Prepare(PreparePayload {
                B: Ballot::new(3, &[5678, 1234]),
                P: Some(Ballot::new(3, &[5678, 1234])),
                PP: None,
                HN: 0,
                CN: 0,
            }),
        );

        {
            let emitted_msg = slot
                .handle_message(&statement_from_node_3)
                .expect("failed handling msg")
                .expect("no msg emitted");

            let expected_msg = Msg::new(
                local_node_id,
                local_node_quorum_set,
                slot_index,
                Topic::Prepare(PreparePayload {
                    B: Ballot::new(3, &[5678, 1234]),
                    P: Some(Ballot::new(3, &[5678, 1234])),
                    PP: None,
                    HN: 0,
                    CN: 0,
                }),
            );

            assert_eq!(emitted_msg, expected_msg);
        }
    }

    #[test_with_logger]
    // A node may issue "accept prepare(b)" if it sees a blocking set of other nodes
    // who have issued Prepare statements implying "accept prepare(b)".
    fn test_ballots_accepted_prepared_with_blocking_set(logger: Logger) {
        // A 3-node cycle.
        let (local_node, node_2, _node_3) = three_node_cycle();

        let slot_index = 2;
        let mut slot = Slot::<u32, TransactionValidationError>::new(
            local_node.0.clone(),
            local_node.1.clone(),
            slot_index,
            Arc::new(trivial_validity_fn),
            Arc::new(trivial_combine_fn),
            logger,
        );

        let ballot = Ballot::new(3, &[8888, 5678, 1234]);
        let prepared = Ballot::new(2, &[8888, 5678, 1234]);
        let prepared_prime = Ballot::new(1, &[1234]);

        slot.phase = Phase::NominatePrepare;
        slot.B = ballot.clone();

        // Node 2 is a blocking set for Node 1.
        // Node 2 issues "accept prepare(prepared)" and "accept prepare(prepared_prime).
        {
            let msg = Msg::new(
                node_2.0.clone(),
                node_2.1,
                slot_index,
                Topic::NominatePrepare(
                    NominatePayload {
                        X: BTreeSet::default(),
                        Y: BTreeSet::from_iter(ballot.X.clone()),
                    },
                    PreparePayload {
                        B: ballot.clone(),
                        P: Some(prepared.clone()),
                        PP: Some(prepared_prime.clone()),
                        HN: 0,
                        CN: 0,
                    },
                ),
            );

            let emitted = slot
                .handle_message(&msg)
                .expect("failed handling msg")
                .expect("no msg emitted");

            let expected = Msg::new(
                local_node.0.clone(),
                local_node.1,
                slot_index,
                Topic::NominatePrepare(
                    NominatePayload {
                        X: BTreeSet::default(),
                        Y: BTreeSet::from_iter(ballot.X.clone()),
                    },
                    PreparePayload {
                        B: ballot,
                        P: Some(prepared),
                        PP: Some(prepared_prime),
                        HN: 0,
                        CN: 0,
                    },
                ),
            );

            assert_eq!(emitted, expected);
        }
    }

    #[test_with_logger]
    // A node may issue "accept prepare(b)" if it sees a blocking set of other nodes
    // who have issued Prepare and Commit statements implying "accept
    // prepare(b)".
    fn test_ballots_accepted_prepared_blocking_with_commit_statements(logger: Logger) {
        // A 3-node cycle.
        let (local_node, node_2, _) = three_node_cycle();

        let slot_index = 2;
        let mut slot = Slot::<u32, _>::new(
            local_node.0.clone(),
            local_node.1.clone(),
            slot_index,
            Arc::new(trivial_validity_fn),
            Arc::new(trivial_combine_fn),
            logger,
        );
        slot.phase = Phase::NominatePrepare;

        // Node 2 is a blocking set.
        // It issues a CommitStatement implying "accept prepare(<3, [5678, 1234]>)".
        let msg = Msg::new(
            node_2.0.clone(),
            node_2.1,
            slot_index,
            Topic::Commit(CommitPayload {
                B: Ballot::new(5, &[1234, 5678]),
                PN: 3, // "accept prepare(<preparedCounter, ballot.value>)"
                CN: 1,
                HN: 3,
            }),
        );

        let emitted_msg = slot
            .handle_message(&msg)
            .expect("failed handling msg")
            .expect("no msg emitted");

        // Node 2 is a blocking set, so the ballot that it accepted prepared should be
        // accepted prepared by the local node.
        assert_eq!(
            emitted_msg,
            Msg::new(
                local_node.0.clone(),
                local_node.1,
                slot_index,
                Topic::Commit(CommitPayload {
                    B: Ballot::new(5, &[1234, 5678]),
                    PN: 3, // "accept prepare(<preparedCounter, ballot.value>)"
                    CN: 1,
                    HN: 3,
                }),
            )
        );
    }

    #[test_with_logger]
    // A node who has issued `vote prepare<1,C>` should issue `accept prepare <1,C>`
    // when: 1) A blocking set issues `accept prepare<1,C>, or
    // 2) A quorum votes or accepts prepare<1,C>
    fn test_votes_to_accepts_same_value_case_2(logger: Logger) {
        let local_node_quorum_set: QuorumSet = {
            let inner_quorum_set_one = QuorumSet::new_with_node_ids(
                2,
                vec![test_node_id(2), test_node_id(3), test_node_id(4)],
            );
            let inner_quorum_set_two = QuorumSet::new_with_node_ids(
                2,
                vec![test_node_id(5), test_node_id(6), test_node_id(7)],
            );
            QuorumSet::new_with_inner_sets(2, vec![inner_quorum_set_one, inner_quorum_set_two])
        };

        let local_node_id = test_node_id(1);
        let slot_index = 0;

        let mut slot = Slot::<u32, TransactionValidationError>::new(
            local_node_id.clone(),
            local_node_quorum_set.clone(),
            slot_index,
            Arc::new(trivial_validity_fn),
            Arc::new(trivial_combine_fn),
            logger,
        );

        // Mutate prepare_state so that it has issued `vote prepare<1,C>`.
        let ballot = Ballot::new(1, &[5678, 1234]);

        slot.phase = Phase::Prepare;
        slot.B = ballot.clone();
        slot.last_sent_msg = slot.out_msg();

        let initial_msg = Msg::new(
            local_node_id.clone(),
            local_node_quorum_set.clone(),
            slot_index,
            Topic::Prepare(PreparePayload {
                B: ballot.clone(),
                P: None,
                PP: None,
                HN: 0,
                CN: 0,
            }),
        );

        assert_eq!(slot.last_sent_msg, Some(initial_msg));

        // {local_node, 2, 3, 6, 7} is a quorum.
        let node2 = (
            test_node_id(2),
            QuorumSet::new_with_node_ids(1, vec![test_node_id(3), test_node_id(4)]),
        );
        let node3 = (
            test_node_id(3),
            QuorumSet::new_with_node_ids(1, vec![test_node_id(2), test_node_id(4)]),
        );
        let node6 = (
            test_node_id(6),
            QuorumSet::new_with_node_ids(1, vec![test_node_id(5), test_node_id(7)]),
        );
        let node7 = (
            test_node_id(7),
            QuorumSet::new_with_node_ids(1, vec![test_node_id(5), test_node_id(6)]),
        );
        let other_nodes = vec![node2, node3, node6, node7];

        let msgs: Vec<Msg<u32>> = other_nodes
            .iter()
            .map(|(node_id, quorum_set)| {
                Msg::new(
                    node_id.clone(),
                    quorum_set.clone(),
                    slot_index,
                    Topic::Prepare(PreparePayload {
                        B: ballot.clone(),
                        P: None,
                        PP: None,
                        HN: 0,
                        CN: 0,
                    }),
                )
            })
            .collect();

        // Not quorum; the local node emits its initial statement.
        for msg in msgs.iter().take(3) {
            let emitted_msg = slot.handle_message(&msg);
            assert!(emitted_msg.unwrap().is_none());
        }

        // Quorum; the local node emits `accept prepare<1,C>.
        {
            let emitted_msg = slot
                .handle_message(&msgs[3].clone())
                .expect("failed handling msg")
                .expect("no msg emitted");

            let expected_msg = Msg::new(
                local_node_id,
                local_node_quorum_set,
                slot_index,
                Topic::Prepare(PreparePayload {
                    B: ballot.clone(),
                    P: Some(ballot),
                    PP: None,
                    HN: 0,
                    CN: 0,
                }),
            );

            assert_eq!(emitted_msg, expected_msg);
        }
    }

    #[test_with_logger]
    // A node may issue "accept prepare(b)" if it is part of a quorum
    // who has issued "vote or accept prepare(b)".
    fn test_ballots_accepted_prepared_with_quorum(logger: Logger) {
        // The local_node and node_2 form a quorum.
        let local_node = (
            test_node_id(1),
            QuorumSet::new_with_node_ids(1, vec![test_node_id(2), test_node_id(3)]),
        );

        let node_2 = (
            test_node_id(2),
            QuorumSet::new_with_node_ids(1, vec![test_node_id(1), test_node_id(3)]),
        );

        let slot_index = 2;
        let mut slot = Slot::<u32, _>::new(
            local_node.0.clone(),
            local_node.1.clone(),
            slot_index,
            Arc::new(trivial_validity_fn),
            Arc::new(trivial_combine_fn),
            logger,
        );

        // Node 1 has issued "vote-or-accept prepare(b)".
        let ballot = Ballot::new(1, &[5678, 1234]);
        slot.phase = Phase::Prepare;
        slot.B = ballot.clone();
        slot.last_sent_msg = slot.out_msg();
        {
            let expected = Msg::new(
                local_node.0.clone(),
                local_node.1.clone(),
                slot_index,
                Topic::Prepare(PreparePayload {
                    B: ballot.clone(),
                    P: None,
                    PP: None,
                    HN: 0,
                    CN: 0,
                }),
            );
            assert_eq!(slot.last_sent_msg.as_ref().unwrap(), &expected);
        }

        // Node 2 issues "vote-or-accept prepare(<2, b.X>)".
        let ballot_two = Ballot::new(2, &[5678, 1234]);
        let msg = Msg::new(
            node_2.0.clone(),
            node_2.1,
            slot_index,
            Topic::Prepare(PreparePayload {
                B: ballot_two,
                P: None,
                PP: None,
                HN: 0,
                CN: 0,
            }),
        );

        // Node 1 issues "accept prepare(b)".
        let emitted_msg = slot
            .handle_message(&msg)
            .expect("failed handling msg")
            .expect("no msg emitted");

        let expected = Msg::new(
            local_node.0.clone(),
            local_node.1,
            slot_index,
            Topic::Prepare(PreparePayload {
                B: ballot.clone(),
                P: Some(ballot),
                PP: None,
                HN: 0,
                CN: 0,
            }),
        );
        assert_eq!(emitted_msg, expected);
    }

    #[test_with_logger]
    // A node may issue "accept prepare(b)" if it is part of a quorum
    // who has issued Prepare or Commit statements implying "vote or accept
    // prepare(b)".
    fn test_ballots_accepted_prepared_quorum_with_commit_statements(logger: Logger) {
        // {1, 2} is a quorum, and {1, 3} is a quorum.
        // This configuration is useful because {2} is not a blocking threshold for the
        // local node, which allows us to test the "is quorum but not blocking"
        // scenario.
        let local_node = (
            test_node_id(1),
            QuorumSet::new_with_node_ids(1, vec![test_node_id(2), test_node_id(3)]),
        );

        let node_2 = (
            test_node_id(2),
            QuorumSet::new_with_node_ids(1, vec![test_node_id(1)]),
        );

        let slot_index = 27;
        let mut slot = Slot::<u32, TransactionValidationError>::new(
            local_node.0.clone(),
            local_node.1.clone(),
            slot_index,
            Arc::new(trivial_validity_fn),
            Arc::new(trivial_combine_fn),
            logger,
        );

        let ballot = Ballot::new(3, &[1234, 5678]);

        // Node 1 has issued "vote prepare(b)".
        {
            slot.Y = hashset! { 1234, 5678};
            slot.B = ballot.clone();
            slot.last_sent_msg = slot.out_msg();

            assert_eq!(
                slot.last_sent_msg.as_ref().unwrap(),
                &Msg::new(
                    local_node.0.clone(),
                    local_node.1.clone(),
                    slot_index,
                    Topic::NominatePrepare(
                        NominatePayload {
                            X: BTreeSet::default(),
                            Y: btreeset! { 1234, 5678},
                        },
                        PreparePayload {
                            B: ballot,
                            P: None,
                            PP: None,
                            HN: 0,
                            CN: 0,
                        }
                    ),
                )
            );
        }

        // Node 2 issues a CommitStatement implying "accept commit(b)".
        {
            let msg = Msg::new(
                node_2.0.clone(),
                node_2.1,
                slot_index,
                Topic::Commit(CommitPayload {
                    B: Ballot::new(5, &[1234, 5678]),
                    PN: 3, // "accept prepare(<preparedCounter, ballot.value>)"
                    CN: 0,
                    HN: 3,
                }),
            );

            let emitted_msg = slot
                .handle_message(&msg)
                .expect("failed handling msg")
                .expect("no msg emitted");

            // The local node can fast-forward to externalize.
            assert_eq!(
                emitted_msg,
                Msg::new(
                    local_node.0.clone(),
                    local_node.1,
                    slot_index,
                    Topic::Externalize(ExternalizePayload {
                        C: Ballot::new(3, &[1234, 5678]),
                        HN: 3,
                    }),
                )
            );
        }
    }

    #[test_with_logger]
    // A node who has issued `vote prepare<1,C>` should issue `accept prepare
    // <n,C2>` for C != C2 when it sees a blocking set issue `accept prepare <n,
    // C2>.
    fn test_votes_to_accepts_different_value(logger: Logger) {
        let local_node_quorum_set: QuorumSet = {
            let inner_quorum_set_one = QuorumSet::new_with_node_ids(
                2,
                vec![test_node_id(2), test_node_id(3), test_node_id(4)],
            );
            let inner_quorum_set_two = QuorumSet::new_with_node_ids(
                2,
                vec![test_node_id(5), test_node_id(6), test_node_id(7)],
            );
            QuorumSet::new_with_inner_sets(2, vec![inner_quorum_set_one, inner_quorum_set_two])
        };

        let local_node_id = test_node_id(1);
        let slot_index = 0;

        let mut slot = Slot::<u32, TransactionValidationError>::new(
            local_node_id.clone(),
            local_node_quorum_set.clone(),
            slot_index,
            Arc::new(trivial_validity_fn),
            Arc::new(trivial_combine_fn),
            logger,
        );

        // Mutate slot so that it has issued `vote prepare<1,C>`.
        let ballot = Ballot::new(1, &[5678, 1234]);

        slot.phase = Phase::Prepare;
        slot.B = ballot.clone();
        slot.last_sent_msg = slot.out_msg();

        let initial_msg = Msg::new(
            local_node_id.clone(),
            local_node_quorum_set.clone(),
            slot_index,
            Topic::Prepare(PreparePayload {
                B: ballot,
                P: None,
                PP: None,
                HN: 0,
                CN: 0,
            }),
        );

        assert_eq!(slot.last_sent_msg, Some(initial_msg));

        // Nodes 2 and 3 are a blocking set.
        let node_2_id = test_node_id(2);
        let node_2_quorum_set =
            QuorumSet::new_with_node_ids(1, vec![test_node_id(3), test_node_id(4)]);

        let node_3_id = test_node_id(3);
        let node_3_quorum_set =
            QuorumSet::new_with_node_ids(1, vec![test_node_id(2), test_node_id(4)]);

        let blocking_set = vec![
            (node_2_id, node_2_quorum_set),
            (node_3_id, node_3_quorum_set),
        ];

        // The nodes forming a blocking threshold all have "ballot.counter" values
        // greater than the local "ballot.counter".
        let different_ballot = Ballot::new(2, &[1000, 2000]);

        let msgs: Vec<Msg<u32>> = blocking_set
            .iter()
            .map(|(node_id, quorum_set)| {
                Msg::new(
                    node_id.clone(),
                    quorum_set.clone(),
                    slot_index,
                    Topic::Prepare(PreparePayload {
                        B: different_ballot.clone(),
                        P: Some(different_ballot.clone()),
                        PP: None,
                        HN: 0,
                        CN: 0,
                    }),
                )
            })
            .collect();

        // A statement from only node_2 should not change the statement issued by the
        // local node.
        {
            let emitted_msg = slot.handle_message(&msgs[0].clone());
            assert!(emitted_msg.unwrap().is_none());
        }

        // With this statement, the local node has seen a blocking set who have issued
        // `accept prepare(b)`. The local node should also emit `accept
        // prepare(b)`.
        {
            let emitted_msg = slot
                .handle_message(&msgs[1].clone())
                .expect("failed handling msg")
                .expect("no msg emitted");

            let expected_msg = Msg::new(
                local_node_id,
                local_node_quorum_set,
                slot_index,
                Topic::Prepare(PreparePayload {
                    B: different_ballot.clone(),
                    P: Some(different_ballot),
                    PP: None,
                    HN: 0,
                    CN: 0,
                }),
            );

            assert_eq!(emitted_msg, expected_msg);
        }
    }

    #[test_with_logger]
    // A node that issues "accept prepare <n,V>" may not issue "accept prepare <n,
    // W>" for a different value W.
    fn test_contradicting_accept_prepare(logger: Logger) {
        // A 3-node network where the only quorum is the set of all three nodes.
        // Each node is a blocking set for each other.
        let (node_1, node_2, node_3) = three_node_dense_graph();

        let slot_index = 0;
        let mut slot = Slot::<u32, TransactionValidationError>::new(
            node_1.0.clone(),
            node_1.1.clone(),
            slot_index,
            Arc::new(trivial_validity_fn),
            Arc::new(trivial_combine_fn),
            logger,
        );

        let ballot_2_V = Ballot::new(2, &[1000]);

        // Node 2 issues "accept prepare <2,V>".
        // Node 1 responds by also issuing "accept prepare <2,V>".
        {
            let msg = Msg::new(
                node_2.0.clone(),
                node_2.1,
                slot_index,
                Topic::NominatePrepare(
                    NominatePayload {
                        X: BTreeSet::default(),
                        Y: btreeset! {1000},
                    },
                    PreparePayload {
                        B: ballot_2_V.clone(),
                        P: Some(ballot_2_V.clone()),
                        PP: None,
                        HN: 0,
                        CN: 0,
                    },
                ),
            );

            let emitted = slot
                .handle_message(&msg)
                .expect("failed handling msg")
                .expect("no msg emitted");

            let expected = Msg::new(
                node_1.0.clone(),
                node_1.1.clone(),
                slot_index,
                Topic::NominatePrepare(
                    NominatePayload {
                        X: BTreeSet::default(),
                        Y: btreeset! {1000},
                    },
                    PreparePayload {
                        B: ballot_2_V.clone(),
                        P: Some(ballot_2_V.clone()),
                        PP: None,
                        HN: 0,
                        CN: 0,
                    },
                ),
            );
            assert_eq!(emitted, expected);
        }

        // Node 3 issues "accept prepare <2,W>", where W > V.
        // Node 1 should not issue "accept prepare <2,W>".
        let ballot_2_W = Ballot::new(2, &[2000]);
        {
            let msg = Msg::new(
                node_3.0.clone(),
                node_3.1,
                slot_index,
                Topic::NominatePrepare(
                    NominatePayload {
                        X: BTreeSet::default(),
                        Y: btreeset! { 2000},
                    },
                    PreparePayload {
                        B: ballot_2_W.clone(),
                        P: Some(ballot_2_W),
                        PP: None,
                        HN: 0,
                        CN: 0,
                    },
                ),
            );

            let emitted = slot
                .handle_message(&msg)
                .expect("failed handling msg")
                .expect("no msg emitted");

            let expected = Msg::new(
                node_1.0.clone(),
                node_1.1,
                slot_index,
                Topic::NominatePrepare(
                    NominatePayload {
                        X: BTreeSet::default(),
                        Y: btreeset! { 1000, 2000},
                    },
                    PreparePayload {
                        B: ballot_2_V,
                        P: Some(Ballot::new(1, &[2000])),
                        PP: Some(Ballot::new(1, &[1000])),
                        HN: 0,
                        CN: 0,
                    },
                ),
            );
            assert_eq!(emitted, expected);
        }
    }

    // === Issuing "confirm prepare" ===

    #[test_with_logger]
    // A node issues "confirm prepare <n,C>" when a quorum issues "accept prepare
    // <n,C>".
    fn test_accept_prepare_to_confirm_prepare_cycle(logger: Logger) {
        // Nodes 1, 2, 3, 4 form a cyclic quorum structure.
        let local_node = (
            test_node_id(1),
            QuorumSet::new_with_node_ids(1, vec![test_node_id(2)]),
        );
        let node_2 = (
            test_node_id(2),
            QuorumSet::new_with_node_ids(1, vec![test_node_id(3)]),
        );
        let node_3 = (
            test_node_id(3),
            QuorumSet::new_with_node_ids(1, vec![test_node_id(4)]),
        );
        let node_4 = (
            test_node_id(4),
            QuorumSet::new_with_node_ids(1, vec![test_node_id(1)]),
        );

        let slot_index = 0;
        let mut slot = Slot::<u32, TransactionValidationError>::new(
            local_node.0.clone(),
            local_node.1.clone(),
            slot_index,
            Arc::new(trivial_validity_fn),
            Arc::new(trivial_combine_fn),
            logger,
        );

        // Mutate prepare_state so that the local node has issued `accept prepare <n,C>.
        let ballot = Ballot::new(7, &[5678, 1234]);

        slot.phase = Phase::Prepare;
        slot.B = ballot.clone();
        slot.P = Some(ballot.clone());
        slot.last_sent_msg = slot.out_msg();

        let initial_msg = Msg::new(
            local_node.0.clone(),
            local_node.1.clone(),
            slot_index,
            Topic::Prepare(PreparePayload {
                B: ballot.clone(),
                P: Some(ballot.clone()),
                PP: None,
                HN: 0,
                CN: 0,
            }),
        );

        assert_eq!(slot.last_sent_msg, Some(initial_msg));

        let other_nodes = vec![node_2, node_3, node_4];

        let msgs: Vec<Msg<u32>> = other_nodes
            .iter()
            .map(|(node_id, quorum_set)| {
                Msg::new(
                    node_id.clone(),
                    quorum_set.clone(),
                    slot_index,
                    Topic::Prepare(PreparePayload {
                        B: ballot.clone(),
                        P: Some(ballot.clone()),
                        PP: None,
                        HN: 0,
                        CN: 0,
                    }),
                )
            })
            .collect();

        // Not quorum; the local node does not emit anything.
        for msg in msgs.iter().take(2) {
            let emitted_msg = slot.handle_message(msg);
            assert!(emitted_msg.unwrap().is_none());
        }

        // Quorum; the local node emits `confirm prepare <n,C> and vote commit <n,C>`
        {
            let emitted_msg = slot
                .handle_message(&msgs[2].clone())
                .expect("failed handling msg")
                .expect("no msg emitted");

            let expected_msg = Msg::new(
                local_node.0.clone(),
                local_node.1,
                slot_index,
                Topic::Prepare(PreparePayload {
                    B: ballot.clone(),
                    P: Some(ballot.clone()),
                    PP: None,
                    HN: ballot.N, /*  "vote commit(<n, ballot.value>)" for every "cCounter <= n
                                   * <= hCounter". */
                    CN: ballot.N, //  "confirm prepare(<hCounter, ballot.value>)".
                }),
            );

            assert_eq!(emitted_msg, expected_msg);
        }
    }

    // === Issuing "accept commit" ===

    #[test_with_logger]
    // A node issues "accept commit <n,C>" when a blocking set has issued "accept
    // commit <n,C>".
    fn test_accept_commit_from_blocking_set(logger: Logger) {
        // Node 2 is a blocking set for Node 1.
        let (node_1, node_2, _node_3) = three_node_cycle();

        let slot_index = 0;
        let mut slot = get_slot(slot_index, &node_1.0, &node_1.1, logger);

        // Node 2 issues "accept commit <n,C>" for CN <= n <= HN.
        let ballot = Ballot::new(3, &[3333]);
        let msg = Msg::new(
            node_2.0.clone(),
            node_2.1,
            slot_index,
            Topic::Commit(CommitPayload {
                B: ballot.clone(),
                PN: 3,
                CN: 2,
                HN: 3,
            }),
        );

        // Node 1 responds by issuing "accept commit <n,C>".
        let emitted = slot
            .handle_message(&msg)
            .expect("failed handling msg")
            .expect("no msg emitted");

        let expected = Msg::new(
            node_1.0.clone(),
            node_1.1,
            slot_index,
            Topic::Commit(CommitPayload {
                B: ballot,
                PN: 3,
                CN: 2,
                HN: 3,
            }),
        );

        assert_eq!(emitted, expected);
    }

    #[test_with_logger]
    // A node issues "accept commit <n,C>" when a quorum issues "vote-or-accept
    // commit <n,C>".
    fn test_accept_commit_from_quorum(logger: Logger) {
        // The only quorum is all three nodes.
        let (node_1, node_2, node_3) = three_node_cycle();

        let slot_index = 0;
        let mut slot = get_slot(slot_index, &node_1.0, &node_1.1, logger);

        let ballot = Ballot::new(3, &[3333]);

        // Node 1 issues "vote commit <n,C>" for n >= CN.
        slot.phase = Phase::Prepare;
        slot.B = ballot.clone();
        slot.P = Some(ballot.clone());
        slot.C = Some(Ballot::new(1, &[3333]));
        slot.H = Some(ballot.clone());
        let initial_msg = slot.out_msg();
        slot.last_sent_msg = initial_msg;

        // Node 2 issues "vote commit <n,C>"
        // If "cCounter != 0": "vote commit(<n, ballot.value>)" for every "CN <= n <=
        // HN".
        {
            let msg_2 = Msg::new(
                node_2.0.clone(),
                node_2.1,
                slot_index,
                Topic::Prepare(PreparePayload {
                    B: ballot.clone(),
                    P: Some(ballot.clone()),
                    PP: None,
                    CN: 1,
                    HN: 3,
                }),
            );

            // Node 1 emits nothing.
            let emitted = slot.handle_message(&msg_2).expect("failed handling msg");

            assert_eq!(emitted, None);
        }

        // Node 3 issues "vote commit <n,C>"
        // If "cCounter != 0": "vote commit(<n, ballot.value>)" for every "CN <= n <=
        // HN".
        {
            let msg_3 = Msg::new(
                node_3.0.clone(),
                node_3.1,
                slot_index,
                Topic::Prepare(PreparePayload {
                    B: ballot.clone(),
                    P: Some(ballot.clone()),
                    PP: None,
                    CN: 1,
                    HN: 3,
                }),
            );

            // Node 1 responds by issuing "accept commit <n,C>".
            let emitted = slot
                .handle_message(&msg_3)
                .expect("failed handling msg")
                .expect("no msg emitted");

            let expected = Msg::new(
                node_1.0.clone(),
                node_1.1,
                slot_index,
                Topic::Commit(CommitPayload {
                    B: ballot,
                    PN: 3,
                    CN: 1,
                    HN: 3,
                }),
            );

            assert_eq!(emitted, expected);
        }
    }

    #[test_with_logger]
    // A node that issues "accept commit <n,V>" may not issue "accept commit <n, W>"
    // for a different value W.
    fn test_contradicting_accept_commit(logger: Logger) {
        // Node 2 is a blocking set for Node 1.
        let (node_1, node_2, node_3) = three_node_dense_graph();

        let slot_index = 0;
        let mut slot = get_slot(slot_index, &node_1.0, &node_1.1, logger);

        let ballot_V = Ballot::new(3, &[3333]);

        // Node 2 issues "accept commit V".
        // Node 2 is a blocking set for Node 1, so Node 1 issues "accept commit V".
        {
            let msg = Msg::new(
                node_2.0.clone(),
                node_2.1,
                slot_index,
                Topic::Commit(CommitPayload {
                    B: ballot_V.clone(),
                    PN: 3,
                    CN: 2,
                    HN: 3,
                }),
            );

            // Node 1 responds by issuing "accept commit V".
            let emitted = slot
                .handle_message(&msg)
                .expect("failed handling msg")
                .expect("no msg emitted");

            let expected = Msg::new(
                node_1.0.clone(),
                node_1.1,
                slot_index,
                Topic::Commit(CommitPayload {
                    B: ballot_V,
                    PN: 3,
                    CN: 2,
                    HN: 3,
                }),
            );

            assert_eq!(emitted, expected);
        }

        let ballot_W = Ballot::new(3, &[4444]);

        // Node 3 "accept commit W".
        // Node 1 emits nothing.
        {
            let msg = Msg::new(
                node_3.0.clone(),
                node_3.1,
                slot_index,
                Topic::Commit(CommitPayload {
                    B: ballot_W,
                    PN: 3,
                    CN: 2,
                    HN: 3,
                }),
            );

            // Node 1 emits nothing.
            let emitted = slot.handle_message(&msg).expect("failed handling msg");
            assert_eq!(emitted, None);
        }
    }

    // === Issuing "confirm commit" and externalizing ===

    #[test_with_logger]
    // A node should issue "confirm commit<n,C>" when a quorum issues "accept commit
    // <n,C>".
    fn test_issue_confirm_commit(logger: Logger) {
        // Each node is a blocking set for every other node, and the only quorum is all
        // nodes.
        let (node_1, node_2, node_3) = three_node_dense_graph();

        let slot_index = 0;
        let mut slot = get_slot(slot_index, &node_1.0, &node_1.1, logger);

        let ballot = Ballot::new(3, &[3333]);

        // Node 2 issues accept commit. This is a blocking set for Node 1.
        // Node 1 responds by issuing accept commit.
        {
            let msg = Msg::new(
                node_2.0.clone(),
                node_2.1.clone(),
                slot_index,
                Topic::Commit(CommitPayload {
                    B: ballot.clone(),
                    PN: 3,
                    CN: 1,
                    HN: 3,
                }),
            );

            let emitted = slot
                .handle_message(&msg)
                .expect("failed handling msg")
                .expect("no msg emitted");

            let expected = Msg::new(
                node_1.0.clone(),
                node_1.1.clone(),
                slot_index,
                Topic::Commit(CommitPayload {
                    B: ballot.clone(),
                    PN: 3,
                    CN: 1,
                    HN: 3,
                }),
            );

            assert_eq!(emitted, expected);
        }

        // Node 3 issues accept commit. This completes a quorum.
        // Node 1 responds by issuing confirm commit.
        {
            let msg = Msg::new(
                node_3.0.clone(),
                node_3.1.clone(),
                slot_index,
                Topic::Commit(CommitPayload {
                    B: ballot,
                    PN: 3,
                    CN: 1,
                    HN: 3,
                }),
            );

            let emitted = slot
                .handle_message(&msg)
                .expect("failed handling msg")
                .expect("no msg emitted");

            let expected = Msg::new(
                node_1.0.clone(),
                node_1.1.clone(),
                slot_index,
                Topic::Externalize(ExternalizePayload {
                    C: Ballot::new(1, &[3333]),
                    HN: 3,
                }),
            );

            assert_eq!(emitted, expected);
        }

        // Nodes 2 and 3 issue accept commit for a higher ballot.
        // Node 1 should issue Externalize with an increased HN value.
        {
            let ballot = Ballot::new(5, &[3333]);

            let msg_from_node_2 = Msg::new(
                node_2.0.clone(),
                node_2.1,
                slot_index,
                Topic::Commit(CommitPayload {
                    B: ballot.clone(),
                    PN: 5,
                    CN: 1,
                    HN: 5,
                }),
            );

            let emitted = slot
                .handle_message(&msg_from_node_2)
                .expect("failed handling msg");
            assert_eq!(emitted, None);

            let msg_from_node_3 = Msg::new(
                node_3.0.clone(),
                node_3.1,
                slot_index,
                Topic::Commit(CommitPayload {
                    B: ballot,
                    PN: 5,
                    CN: 1,
                    HN: 5,
                }),
            );

            let emitted = slot
                .handle_message(&msg_from_node_3)
                .expect("failed handling msg")
                .expect("no msg emitted");

            // Node 1 should increase HN to 5.
            let expected = Msg::new(
                node_1.0.clone(),
                node_1.1,
                slot_index,
                Topic::Externalize(ExternalizePayload {
                    C: Ballot::new(1, &[3333]),
                    HN: 5,
                }),
            );

            assert_eq!(emitted, expected);
        }
    }

    #[test_with_logger]
    // Regression test for Externalize with infinite counter.
    fn test_handle_externalize(logger: Logger) {
        // A two-node network, where the only quorum is both nodes.
        let node_1 = (
            test_node_id(1),
            QuorumSet::new_with_node_ids(1, vec![test_node_id(2)]),
        );

        let node_2 = (
            test_node_id(2),
            QuorumSet::new_with_node_ids(1, vec![test_node_id(1)]),
        );

        let slot_index = 2;
        let mut slot = Slot::<u32, _>::new(
            node_2.0.clone(),
            node_2.1.clone(),
            slot_index,
            Arc::new(trivial_validity_fn),
            Arc::new(trivial_combine_fn),
            logger,
        );

        let values = vec![100, 200, 300];

        // Node 1 emits "Externalize".
        let msg_1 = Msg::new(
            node_1.0,
            node_1.1,
            slot_index,
            Topic::Externalize(ExternalizePayload {
                C: Ballot::new(1, &values),
                HN: 1,
            }),
        );

        // Node 2 should issue "Externalize".
        let msg_2 = slot
            .handle_message(&msg_1)
            .expect("Error handling msg")
            .expect("No msg?");

        // Both nodes have issued Externalize, which implies
        // "accept prepare(<infinity, commit.value>)".
        // That means node 2 can also state "confirm prepare(<infinity, commit.value>)",
        // so HN is now INFINITY.
        let expected = Msg::new(
            node_2.0,
            node_2.1,
            slot_index,
            Topic::Externalize(ExternalizePayload {
                C: Ballot::new(1, &values),
                HN: INFINITY,
            }),
        );

        assert_eq!(msg_2, expected);
    }

    // === Setting / Clearing / Processing ballot timers ===

    #[test_with_logger]
    // The node sets a ballot timeout when it sees a quorum of nodes send messages
    // with ballot counters greater than or equal to the local node's ballot
    // counter. If a prior timeout exists, the prior timeout takes precedence.
    fn test_process_ballot_timeout_prepare_phase(logger: Logger) {
        // Each node is a blocking set for every other node, and the only quorum is all
        // nodes.
        let (node_1, node_2, node_3) = three_node_dense_graph();

        let slot_index = 0;
        let mut slot = get_slot(slot_index, &node_1.0, &node_1.1, logger);

        assert_eq!(slot.next_ballot_at, None);

        // Node 2 issues Prepare <1, [2222]>
        {
            let msg = Msg::new(
                node_2.0.clone(),
                node_2.1,
                slot_index,
                Topic::Prepare(PreparePayload {
                    B: Ballot::new(1, &[2222]),
                    P: None,
                    PP: None,
                    HN: 0,
                    CN: 0,
                }),
            );

            let _emitted = slot.handle_message(&msg).expect("Failed handling msg");

            assert_eq!(slot.next_ballot_at, None);
        }

        // Node 3 issues Prepare <2, [3333]>
        {
            let msg = Msg::new(
                node_3.0.clone(),
                node_3.1,
                slot_index,
                Topic::Prepare(PreparePayload {
                    B: Ballot::new(2, &[3333]),
                    P: None,
                    PP: None,
                    HN: 0,
                    CN: 0,
                }),
            );

            let _emitted = slot.handle_message(&msg).expect("Failed handling msg");

            // Node 1 has now seen messages from a quorum of nodes who
            // are on a ballot with counter greater than or equal to self.B.N.
            assert!(slot.next_ballot_at.is_some());
        }
    }

    #[ignore]
    #[test_with_logger]
    fn test_process_ballot_timeout_commit_phase(_logger: Logger) {
        // TODO
        unimplemented!()
    }

    #[ignore]
    #[test_with_logger]
    /// Ballot timeouts should not occur during the Externalize phase.
    fn test_process_ballot_timeout_externalize_phase(_logger: Logger) {
        // TODO
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{core_types::*, test_utils::*};
    use mc_common::logger::test_with_logger;

    #[test_with_logger]
    // `ballots_accepted_prepared` should return all ballots accepted prepared by
    // any blocking set.
    fn test_ballots_accepted_prepared_blocking_sets(logger: Logger) {
        //The four-node Fig.2 network.
        let (local_node, node_2, node_3, _node_4) = fig_2_network();

        let slot_index = 2;
        let mut slot = Slot::<u32, TransactionValidationError>::new(
            local_node.0.clone(),
            local_node.1,
            slot_index,
            Arc::new(trivial_validity_fn),
            Arc::new(trivial_combine_fn),
            logger,
        );

        let ballot_1 = Ballot::new(3, &[1111]);
        let ballot_2 = Ballot::new(3, &[2222]);
        let ballot_3 = Ballot::new(2, &[3333]);

        // A blocking set (Node 2) issues "accept prepare(b1)".
        {
            let msg = Msg::new(
                node_2.0.clone(),
                node_2.1,
                slot_index,
                Topic::Prepare(PreparePayload {
                    B: ballot_1.clone(),
                    P: Some(ballot_1.clone()),
                    PP: None,
                    CN: 0,
                    HN: 0,
                }),
            );
            slot.M.insert(msg.sender_id.clone(), msg);
            let accepted_prepared = slot.ballots_accepted_prepared();
            assert_eq!(accepted_prepared.len(), 1);
            assert!(accepted_prepared.contains(&ballot_1));
        }

        // A different blocking set (Node 3) issues "accept prepare(b2)".
        {
            let msg = Msg::new(
                node_3.0.clone(),
                node_3.1,
                slot_index,
                Topic::Prepare(PreparePayload {
                    B: ballot_2.clone(),
                    P: Some(ballot_2.clone()),
                    PP: Some(ballot_3.clone()),
                    CN: 0,
                    HN: 0,
                }),
            );
            slot.M.insert(msg.sender_id.clone(), msg);
            let accepted_prepared = slot.ballots_accepted_prepared();
            assert_eq!(accepted_prepared.len(), 3);
            assert!(accepted_prepared.contains(&ballot_1));
            assert!(accepted_prepared.contains(&ballot_2));
            assert!(accepted_prepared.contains(&ballot_3));
        }
    }

    // TODO: test_ballots_accepted_prepared_quorum

    // TODO: test_ballots_confirmed_prepared

    // TODO: test_ballots_accepted_committed_blocking_set

    // TODO: test_ballots_accepted_committed_quorum

    // TODO: test_ballots_confirmed_committed
}
