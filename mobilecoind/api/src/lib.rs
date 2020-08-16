// Copyright (c) 2018-2020 MobileCoin Inc.

//! mobilecoind gRPC API.

use mc_util_uri::{Uri, UriScheme};

mod autogenerated_code {
    // Expose proto data types from included third-party/external proto files.
    pub use mc_api::{blockchain, external, printable};
    pub use protobuf::well_known_types::Empty;

    // Needed due to how to the auto-generated code references the Empty message.
    pub mod empty {
        pub use protobuf::well_known_types::Empty;
    }

    // Include the auto-generated code.
    include!(concat!(env!("OUT_DIR"), "/protos-auto-gen/mod.rs"));
}

pub use autogenerated_code::{mobilecoind_api::*, *};

pub type MobilecoindUri = Uri<MobilecoindScheme>;

/// Mobilecoind  Uri Scheme
#[derive(Debug, Hash, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct MobilecoindScheme {}
impl UriScheme for MobilecoindScheme {
    /// The part before the '://' of a URL.
    const SCHEME_SECURE: &'static str = "mobilecoind";
    const SCHEME_INSECURE: &'static str = "insecure-mobilecoind";

    /// Default port numbers
    const DEFAULT_SECURE_PORT: u16 = 4443;
    const DEFAULT_INSECURE_PORT: u16 = 4444;
}
