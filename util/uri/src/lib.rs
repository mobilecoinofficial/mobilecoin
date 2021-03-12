// Copyright (c) 2018-2021 The MobileCoin Foundation

use mc_common::NodeID;

mod traits;
pub use traits::{ConnectionUri, UriConversionError, UriScheme};

mod uri;
pub use uri::{Uri, UriParseError};

//
// Mobile-coin specific uri schemes and objects associated to them
//

pub type AdminUri = Uri<AdminScheme>;
pub type ConsensusClientUri = Uri<ConsensusClientScheme>;
pub type ConsensusPeerUri = Uri<ConsensusPeerScheme>;
pub type FogUri = Uri<FogScheme>;

// Conversions

impl From<&ConsensusClientUri> for NodeID {
    fn from(src: &ConsensusClientUri) -> NodeID {
        src.node_id().expect("Could not get node_id from uri")
    }
}

impl From<&ConsensusPeerUri> for NodeID {
    fn from(src: &ConsensusPeerUri) -> NodeID {
        src.node_id().expect("Could not get node_id from uri")
    }
}

// Extra ConsensusPeerUri api
pub trait ConsensusPeerUriApi {
    fn consensus_relay_incoming_txs(&self) -> bool;
}
impl ConsensusPeerUriApi for ConsensusPeerUri {
    /// Whether we should relay incoming txs from this peer.
    fn consensus_relay_incoming_txs(&self) -> bool {
        self.get_bool_param("consensus-relay-incoming-txs")
    }
}

/// Consensus Client Uri Scheme
#[derive(Debug, Hash, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct ConsensusClientScheme {}
impl UriScheme for ConsensusClientScheme {
    /// The part before the '://' of a URL.
    const SCHEME_SECURE: &'static str = "mc";
    const SCHEME_INSECURE: &'static str = "insecure-mc";

    /// Default port numbers
    const DEFAULT_SECURE_PORT: u16 = 443;
    const DEFAULT_INSECURE_PORT: u16 = 3223;
}

/// Consensus Peer Uri Scheme
#[derive(Debug, Hash, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct ConsensusPeerScheme {}
impl UriScheme for ConsensusPeerScheme {
    /// The part before the '://' of a URL.
    const SCHEME_SECURE: &'static str = "mcp";
    const SCHEME_INSECURE: &'static str = "insecure-mcp";

    /// Default port numbers
    const DEFAULT_SECURE_PORT: u16 = 8443;
    const DEFAULT_INSECURE_PORT: u16 = 8080;
}

/// Admin Uri Scheme
#[derive(Debug, Hash, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct AdminScheme {}
impl UriScheme for AdminScheme {
    /// The part before the '://' of a URL.
    const SCHEME_SECURE: &'static str = "mca";
    const SCHEME_INSECURE: &'static str = "insecure-mca";

    /// Default port numbers
    const DEFAULT_SECURE_PORT: u16 = 9443;
    const DEFAULT_INSECURE_PORT: u16 = 9090;
}

/// Fog Uri Scheme
/// Used in public addresses, and when talking to fog report server
#[derive(Debug, Hash, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct FogScheme {}

impl UriScheme for FogScheme {
    /// The part before the '://' of a URL.
    const SCHEME_SECURE: &'static str = "fog";
    const SCHEME_INSECURE: &'static str = "insecure-fog";

    /// Default port numbers
    const DEFAULT_SECURE_PORT: u16 = 443;
    const DEFAULT_INSECURE_PORT: u16 = 3225;
}

#[cfg(test)]
mod consensus_client_uri_tests {
    use super::{ConnectionUri, ConsensusClientUri as ClientUri, ConsensusPeerUri as PeerUri};
    use mc_common::ResponderId;
    use std::str::FromStr;

    #[test]
    fn test_valid_client_uris() {
        let uri = ClientUri::from_str("mc://127.0.0.1/").unwrap();
        assert_eq!(uri.addr(), "127.0.0.1:443");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("127.0.0.1:443").unwrap()
        );
        assert_eq!(uri.use_tls(), true);
        assert_eq!(uri.username(), "");
        assert_eq!(uri.password(), "");

        let uri = ClientUri::from_str("mc://node1.test.mobilecoin.com/").unwrap();
        assert_eq!(uri.addr(), "node1.test.mobilecoin.com:443");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("node1.test.mobilecoin.com:443").unwrap()
        );
        assert_eq!(uri.use_tls(), true);
        assert_eq!(uri.username(), "");
        assert_eq!(uri.password(), "");

        let uri = ClientUri::from_str("mc://node1.test.mobilecoin.com:666/").unwrap();
        assert_eq!(uri.addr(), "node1.test.mobilecoin.com:666");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("node1.test.mobilecoin.com:666").unwrap()
        );
        assert_eq!(uri.use_tls(), true);
        assert_eq!(uri.username(), "");
        assert_eq!(uri.password(), "");

        let uri = ClientUri::from_str("insecure-mc://127.0.0.1/").unwrap();
        assert_eq!(uri.addr(), "127.0.0.1:3223");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("127.0.0.1:3223").unwrap()
        );
        assert_eq!(uri.use_tls(), false);
        assert_eq!(uri.username(), "");
        assert_eq!(uri.password(), "");

        let uri = ClientUri::from_str("insecure-mc://localhost:3223/").unwrap();
        assert_eq!(uri.addr(), "localhost:3223");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("localhost:3223").unwrap()
        );
        assert_eq!(uri.use_tls(), false);
        assert_eq!(uri.username(), "");
        assert_eq!(uri.password(), "");

        let uri = ClientUri::from_str("insecure-mc://localhost:3223/?consensus-msg-key=MCowBQYDK2VwAyEAUBfht6884a45r0AjFRXgLlnw3yIDllTepWavLrT8Lfk=").unwrap();
        assert_eq!(uri.addr(), "localhost:3223");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("localhost:3223").unwrap()
        );
        assert_eq!(uri.use_tls(), false);
        assert_eq!(uri.username(), "");
        assert_eq!(uri.password(), "");

        let uri = ClientUri::from_str("insecure-mc://node1.test.mobilecoin.com/").unwrap();
        assert_eq!(uri.addr(), "node1.test.mobilecoin.com:3223");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("node1.test.mobilecoin.com:3223").unwrap()
        );
        assert_eq!(uri.use_tls(), false);
        assert_eq!(uri.username(), "");
        assert_eq!(uri.password(), "");

        let uri = ClientUri::from_str("insecure-mc://node1.test.mobilecoin.com:666/").unwrap();
        assert_eq!(uri.addr(), "node1.test.mobilecoin.com:666");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("node1.test.mobilecoin.com:666").unwrap()
        );
        assert_eq!(uri.use_tls(), false);
        assert_eq!(uri.username(), "");
        assert_eq!(uri.password(), "");

        let uri =
            ClientUri::from_str("insecure-mc://coiner@node1.test.mobilecoin.com:666/").unwrap();
        assert_eq!(uri.addr(), "node1.test.mobilecoin.com:666");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("node1.test.mobilecoin.com:666").unwrap()
        );
        assert_eq!(uri.use_tls(), false);
        assert_eq!(uri.username(), "coiner");
        assert_eq!(uri.password(), "");

        let uri =
            ClientUri::from_str("insecure-mc://:passw0rd@node1.test.mobilecoin.com:666/").unwrap();
        assert_eq!(uri.addr(), "node1.test.mobilecoin.com:666");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("node1.test.mobilecoin.com:666").unwrap()
        );
        assert_eq!(uri.use_tls(), false);
        assert_eq!(uri.username(), "");
        assert_eq!(uri.password(), "passw0rd");

        let uri =
            ClientUri::from_str("insecure-mc://abc:def@node1.test.mobilecoin.com:666/").unwrap();
        assert_eq!(uri.addr(), "node1.test.mobilecoin.com:666");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("node1.test.mobilecoin.com:666").unwrap()
        );
        assert_eq!(uri.use_tls(), false);
        assert_eq!(uri.username(), "abc");
        assert_eq!(uri.password(), "def");

        let uri = ClientUri::from_str("insecure-mc://abc:def:1:2:3@node1.test.mobilecoin.com:666/")
            .unwrap();
        assert_eq!(uri.addr(), "node1.test.mobilecoin.com:666");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("node1.test.mobilecoin.com:666").unwrap()
        );
        assert_eq!(uri.use_tls(), false);
        assert_eq!(uri.username(), "abc");
        assert_eq!(uri.password(), "def:1:2:3");
    }

    #[test]
    fn test_client_from_peer_should_fail() {
        let uri = PeerUri::from_str("insecure-mcp://localhost:3223/?consensus-msg-key=MCowBQYDK2VwAyEAUBfht6884a45r0AjFRXgLlnw3yIDllTepWavLrT8Lfk=").unwrap();
        assert_eq!(uri.addr(), "localhost:3223");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("localhost:3223").unwrap()
        );
        assert_eq!(uri.use_tls(), false);

        assert!(ClientUri::from_str(&uri.addr()).is_err());
    }

    #[test]
    fn test_invalid_client_uris() {
        assert!(ClientUri::from_str("http://127.0.0.1/").is_err());
        assert!(ClientUri::from_str("127.0.0.1").is_err());
        assert!(ClientUri::from_str("127.0.0.1:12345").is_err());
        assert!(ClientUri::from_str("mc://").is_err());
        assert!(ClientUri::from_str("mc:///").is_err());
        assert!(ClientUri::from_str("mc://    /").is_err());
    }

    #[test]
    fn test_tls_override() {
        assert_eq!(
            ClientUri::from_str("mc://node.com/")
                .unwrap()
                .tls_hostname_override(),
            None
        );
        assert_eq!(
            ClientUri::from_str("mc://node.com/?")
                .unwrap()
                .tls_hostname_override(),
            None
        );
        assert_eq!(
            ClientUri::from_str("mc://node.com/?tls-hostname=")
                .unwrap()
                .tls_hostname_override(),
            None
        );
        assert_eq!(
            ClientUri::from_str("mc://node.com/?tls-hostname=lol.com")
                .unwrap()
                .tls_hostname_override(),
            Some("lol.com".into())
        );
    }
}
#[cfg(test)]
mod consensus_peer_uri_tests {
    use super::{ConnectionUri, ConsensusPeerUri as PeerUri};
    use core::str::FromStr;
    use mc_common::{NodeID, ResponderId};
    use mc_crypto_keys::{Ed25519Pair, Ed25519Public};
    use mc_util_from_random::FromRandom;
    use rand::SeedableRng;
    use rand_hc::Hc128Rng as FixedRng;
    use std::convert::TryFrom;

    #[test]
    fn test_valid_peer_uris() {
        let uri = PeerUri::from_str("mcp://127.0.0.1/").unwrap();
        assert_eq!(uri.addr(), "127.0.0.1:8443");
        assert_eq!(uri.use_tls(), true);

        let uri = PeerUri::from_str("mcp://node1.test.mobilecoin.com/").unwrap();
        assert_eq!(uri.addr(), "node1.test.mobilecoin.com:8443");
        assert_eq!(uri.use_tls(), true);

        let uri = PeerUri::from_str("mcp://node1.test.mobilecoin.com:666/").unwrap();
        assert_eq!(uri.addr(), "node1.test.mobilecoin.com:666");
        assert_eq!(uri.use_tls(), true);

        let uri = PeerUri::from_str("insecure-mcp://127.0.0.1/").unwrap();
        assert_eq!(uri.addr(), "127.0.0.1:8080");
        assert_eq!(uri.use_tls(), false);

        let uri = PeerUri::from_str("insecure-mcp://node1.test.mobilecoin.com/").unwrap();
        assert_eq!(uri.addr(), "node1.test.mobilecoin.com:8080");
        assert_eq!(uri.use_tls(), false);

        let uri = PeerUri::from_str("insecure-mcp://node1.test.mobilecoin.com:666/").unwrap();
        assert_eq!(uri.addr(), "node1.test.mobilecoin.com:666");

        let mut seeded_rng: FixedRng = SeedableRng::from_seed([0u8; 32]);
        let signer_key = Ed25519Pair::from_random(&mut seeded_rng);
        let hex_pubkey = hex::encode(&signer_key.public_key());
        let uri = PeerUri::from_str(&format!(
            "mcp://node1.test.mobilecoin.com/?consensus-msg-key={}",
            hex_pubkey
        ))
        .unwrap();
        assert_eq!(
            NodeID::from(&uri),
            NodeID {
                responder_id: ResponderId::from_str("node1.test.mobilecoin.com:8443").unwrap(),
                public_key: signer_key.public_key(),
            }
        );
        assert_eq!(uri.use_tls(), true);

        // Base64 encoded with '+' -> '-', '/' -> '_'
        let uri = PeerUri::from_str(
            "mcp://node1.test.mobilecoin.com/?consensus-msg-key=MCowBQYDK2VwAyEA7ge_uIUtt3Us9T_xnERgSy9kb1NxdbDhxLsIPN-FA30=")
            .unwrap();
        assert_eq!(
            NodeID::from(&uri),
            NodeID {
                responder_id: ResponderId::from_str("node1.test.mobilecoin.com:8443").unwrap(),
                public_key: Ed25519Public::try_from(
                    [
                        238, 7, 191, 184, 133, 45, 183, 117, 44, 245, 63, 241, 156, 68, 96, 75, 47,
                        100, 111, 83, 113, 117, 176, 225, 196, 187, 8, 60, 223, 133, 3, 125
                    ]
                    .as_ref()
                )
                .unwrap(),
            }
        );
        assert_eq!(uri.use_tls(), true);
    }

    #[test]
    fn test_invalid_peer_uris() {
        assert!(PeerUri::from_str("http://127.0.0.1/").is_err());
        assert!(PeerUri::from_str("127.0.0.1").is_err());
        assert!(PeerUri::from_str("127.0.0.1:12345").is_err());
        assert!(PeerUri::from_str("mcp://").is_err());
        assert!(PeerUri::from_str("mcp:///").is_err());
        assert!(PeerUri::from_str("mcp://    /").is_err());
    }
}

#[cfg(test)]
mod fog_uri_tests {
    use super::{ConnectionUri, FogUri};
    use core::str::FromStr;
    use mc_common::ResponderId;

    #[test]
    fn test_valid_client_uris() {
        let uri = FogUri::from_str("fog://127.0.0.1/").unwrap();
        assert_eq!(uri.addr(), "127.0.0.1:443");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("127.0.0.1:443").unwrap()
        );
        assert_eq!(uri.use_tls(), true);

        let uri = FogUri::from_str("fog://node1.test.mobilecoin.com/").unwrap();
        assert_eq!(uri.addr(), "node1.test.mobilecoin.com:443");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("node1.test.mobilecoin.com:443").unwrap()
        );
        assert_eq!(uri.use_tls(), true);

        let uri = FogUri::from_str("fog://node1.test.mobilecoin.com:666/").unwrap();
        assert_eq!(uri.addr(), "node1.test.mobilecoin.com:666");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("node1.test.mobilecoin.com:666").unwrap()
        );
        assert_eq!(uri.use_tls(), true);

        let uri = FogUri::from_str("insecure-fog://127.0.0.1/").unwrap();
        assert_eq!(uri.addr(), "127.0.0.1:3225");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("127.0.0.1:3225").unwrap()
        );
        assert_eq!(uri.use_tls(), false);

        let uri = FogUri::from_str("insecure-fog://node1.test.mobilecoin.com/").unwrap();
        assert_eq!(uri.addr(), "node1.test.mobilecoin.com:3225");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("node1.test.mobilecoin.com:3225").unwrap()
        );
        assert_eq!(uri.use_tls(), false);

        let uri = FogUri::from_str("insecure-fog://node1.test.mobilecoin.com:666/").unwrap();
        assert_eq!(uri.addr(), "node1.test.mobilecoin.com:666");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("node1.test.mobilecoin.com:666").unwrap()
        );
        assert_eq!(uri.use_tls(), false);
    }

    #[test]
    fn test_invalid_client_uris() {
        assert!(FogUri::from_str("http://127.0.0.1/").is_err());
        assert!(FogUri::from_str("127.0.0.1").is_err());
        assert!(FogUri::from_str("127.0.0.1:12345").is_err());
        assert!(FogUri::from_str("fog://").is_err());
        assert!(FogUri::from_str("fog:///").is_err());
        assert!(FogUri::from_str("fog://    /").is_err());
    }

    #[test]
    fn test_tls_override() {
        assert_eq!(
            FogUri::from_str("fog://fog.unittest.mobilecoin.com")
                .unwrap()
                .tls_hostname_override(),
            None
        );
        assert_eq!(
            FogUri::from_str("fog://fog.unittest.mobilecoin.com/?")
                .unwrap()
                .tls_hostname_override(),
            None
        );
        assert_eq!(
            FogUri::from_str("fog://fog.unittest.mobilecoin.com/?tls-hostname=")
                .unwrap()
                .tls_hostname_override(),
            None
        );
        assert_eq!(
            FogUri::from_str("fog://fog.unittest.mobilecoin.com/?tls-hostname=lol.com")
                .unwrap()
                .tls_hostname_override(),
            Some("lol.com".into())
        );
    }
}
