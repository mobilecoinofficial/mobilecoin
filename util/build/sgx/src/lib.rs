// Copyright (c) 2018-2020 MobileCoin Inc.

#![feature(external_doc)]
#![doc(include = "../README.md")]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod config;
mod edger8r;
mod env;
mod libraries;
mod sign;
mod vars;

pub use crate::{
    config::{ConfigBuilder, TcsPolicy},
    edger8r::{Edger8r, Error as Edger8rError},
    env::{Error as EnvironmentError, IasMode, SgxEnvironment, SgxMode},
    sign::SgxSign,
};
