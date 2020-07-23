// Copyright (c) 2018-2020 MobileCoin Inc.

mod autogenerated_code {
    // Expose proto data types from included third-party/external proto files.
    pub use mc_api::{blockchain, external};
    pub use mc_mobilecoind_api::mobilecoind_api;
    pub use protobuf::well_known_types::Empty;

    // Needed due to how to the auto-generated code references the Empty message.
    pub mod empty {
        pub use protobuf::well_known_types::Empty;
    }

    // Include the auto-generated code.
    include!(concat!(env!("OUT_DIR"), "/protos-auto-gen/mod.rs"));
}

pub mod api {
    pub use super::autogenerated_code::{mobilecoind_mirror_api::*, *};
}

pub mod uri;
