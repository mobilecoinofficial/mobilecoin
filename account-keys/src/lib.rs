#![no_std]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![feature(custom_test_frameworks)]
#![test_runner(datatest::runner)]

//! This crate defines account key structures, including private account keys,
//! public addresses, view keys, and subaddresses.
//! It also defines their serialization as protobufs.

extern crate alloc;

mod account_keys;
mod address_hash;
mod domain_separators;
mod error;
mod identity;
mod view_key;

pub use crate::{
    account_keys::{AccountKey, PublicAddress, CHANGE_SUBADDRESS_INDEX, DEFAULT_SUBADDRESS_INDEX},
    address_hash::AddressHash,
    error::{Error, Result},
    identity::{RootEntropy, RootIdentity},
    view_key::ViewKey,
};
