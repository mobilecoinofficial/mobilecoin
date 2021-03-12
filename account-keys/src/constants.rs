// Copyright (c) 2018-2021 The MobileCoin Foundation

//! This module defines constants used by this crate

/// An account's "default address" is its zero^th subaddress.
pub const DEFAULT_SUBADDRESS_INDEX: u64 = 0;

/// Domain separator for hashing a private view key and index into a subaddress.
pub(crate) const SUBADDRESS_DOMAIN_TAG: &str = "mc_subaddress";
