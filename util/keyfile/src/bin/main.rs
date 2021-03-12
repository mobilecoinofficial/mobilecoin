// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A tool for inspecting binary keyfiles
//! Reads .bin file on stdin, or a path to .bin file, emits description on stdout

use mc_account_keys::{AccountKey, RootIdentity};
use std::convert::TryFrom;

fn main() {
    let root_id: RootIdentity = {
        let args: Vec<String> = std::env::args().collect();
        match args.get(1) {
            None => mc_util_keyfile::read_keyfile_data(&mut std::io::stdin())
                .expect("Could not read root identity from stdin"),
            Some(arg) => mc_util_keyfile::read_keyfile(arg)
                .unwrap_or_else(|_| panic!("Failed when reading from {}", arg)),
        }
    };
    let acct_key =
        AccountKey::try_from(&root_id).expect("Could not construct account key from root identity");
    println!("{:?}\n{:?}", root_id, acct_key,);
}
