// Copyright (c) 2018-2021 The MobileCoin Foundation

//! CryptoNote-style View Key.
//!
//! A view key (a,B) contains half of a user's private information, and is used
//! to identify transaction outputs sent to the user, and to view the amounts of
//! those outputs.

use core::hash::{Hash, Hasher};
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use prost::Message;

/// The user's (a,B) keys.
#[derive(Clone, Message)]
pub struct ViewKey {
    /// The user's private key `a`.
    #[prost(message, required, tag = 1)]
    pub view_private_key: RistrettoPrivate,
    /// The user's public key `B`
    #[prost(message, required, tag = 2)]
    pub spend_public_key: RistrettoPublic,
}

impl ViewKey {
    /// A CryptoNote-style view key.
    ///
    /// # Arguments
    /// * `view_private_key` - The user's private view key `a`.
    /// * `spend_public_key` - The user's public spend key `B`.
    pub fn new(view_private_key: RistrettoPrivate, spend_public_key: RistrettoPublic) -> Self {
        ViewKey {
            view_private_key,
            spend_public_key,
        }
    }
}

impl Hash for ViewKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let view_public_key = RistrettoPublic::from(&self.view_private_key);
        view_public_key.hash(state);
        self.spend_public_key.hash(state);
    }
}

impl Eq for ViewKey {}

impl PartialEq for ViewKey {
    fn eq(&self, other: &Self) -> bool {
        RistrettoPublic::from(&self.view_private_key)
            .eq(&RistrettoPublic::from(&other.view_private_key))
            && self.spend_public_key.eq(&other.spend_public_key)
    }
}
