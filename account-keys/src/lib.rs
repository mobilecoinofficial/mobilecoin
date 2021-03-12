// Copyright (c) 2018-2021 The MobileCoin Foundation

//! This crate defines account key structures, including private account keys,
//! public addresses, view keys, and subaddresses.
//! It also defines their serialization as protobufs.

#![no_std]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![feature(custom_test_frameworks)]
#![test_runner(datatest::runner)]

extern crate alloc;

mod account_keys;
mod constants;
mod error;
mod identity;
mod limits;
mod view_key;

pub use crate::{
    account_keys::{AccountKey, PublicAddress},
    constants::DEFAULT_SUBADDRESS_INDEX,
    error::{Error, Result},
    identity::{RootEntropy, RootIdentity},
    limits::{
        check_fog_address_fields, check_fog_authority_sig_length, check_fog_authority_spki_length,
        check_fog_key_fields, check_fog_report_id_length, check_fog_report_url_length,
    },
    view_key::ViewKey,
};
