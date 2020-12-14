// Copyright (c) 2018-2020 MobileCoin Inc.

//! Mesh style network topologies.
//! (N nodes, each node has all other nodes as it's peers)

// We allow dead code because not all integration tests use all of the common code.
// https://github.com/rust-lang/rust/issues/46379
#![allow(dead_code)]

use crate::mock_network;
use mc_common::NodeID;
use mc_consensus_scp::{test_utils::test_node_id, QuorumSet};
use std::collections::HashSet;

/// Constructs a mesh network, where each node has all of it's peers as validators.
///
/// # Arguments
/// * `num_nodes` - Number of nodes in the network
/// * `k` - Number of nodes that must agree within the network
pub fn dense_mesh(num_nodes: usize, k: usize) -> mock_network::NetworkConfig {
    let mut nodes = Vec::<mock_network::NodeConfig>::new();
    for node_index in 0..num_nodes {
        let peers = (0..num_nodes)
            .filter(|other_node_index| other_node_index != &node_index)
            .map(|other_node_index| test_node_id(other_node_index as u32))
            .collect::<Vec<NodeID>>();

        nodes.push(mock_network::NodeConfig::new(
            format!("m{}", node_index),
            test_node_id(node_index as u32),
            peers.iter().cloned().collect::<HashSet<NodeID>>(),
            QuorumSet::new_with_node_ids(k as u32, peers),
        ));
    }

    mock_network::NetworkConfig::new(format!("m{}k{}", num_nodes, k), nodes)
}
