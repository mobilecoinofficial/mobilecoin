// Copyright (c) 2018-2020 MobileCoin Inc.

#![cfg_attr(not(any(test, feature = "log")), no_std)]
#![feature(optin_builtin_traits)]
#![warn(unused_extern_crates)]

extern crate alloc;

use sha3::Digest;

mod hasher_builder;
mod node_id;
mod responder_id;
mod timestamp;

pub mod lru;
pub use lru::LruCache;

pub use node_id::NodeID;
pub use responder_id::{ResponderId, ResponderIdParseError};
pub use timestamp::TimestampResultCode;

// A HashMap that replaces the default hasher with an implementation that relies on mcrand for
// randomess.
pub type HashMap<K, V> = hashbrown::HashMap<K, V, hasher_builder::HasherBuilder>;
pub type HashSet<K> = hashbrown::HashSet<K, hasher_builder::HasherBuilder>;

pub type Hash = [u8; 32];

/// Note: This is only used by servers, for logging (maybe to anonymize logs?)
/// Please don't use it in e.g. transaction validation math, or actual hashing of
/// the blocks in the blockchain, where you should be specific about what hash you are using.
pub fn fast_hash(data: &[u8]) -> Hash {
    let hash = sha3::Sha3_256::digest(data);
    let mut output = [0u8; 32];

    output.copy_from_slice(hash.as_slice());
    output
}

// Logging related functionality
cfg_if::cfg_if! {
    if #[cfg(feature = "log")] {
        mod panic_handler;
        pub mod logger;

        pub use panic_handler::setup_panic_handler;
    }
}

// Loggers
cfg_if::cfg_if! {
    if #[cfg(feature = "loggers")] {
        pub mod sentry;
    }
}
