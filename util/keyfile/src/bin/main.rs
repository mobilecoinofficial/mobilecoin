// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A tool for inspecting binary keyfiles
//! Reads .bin file on stdin, or a path to .bin file, emits description on
//! stdout

use mc_account_keys::AccountKey;
use std::{
    env, fs, io,
    io::{Cursor, Read},
};

fn print_keyfile_bytes(bytes: Vec<u8>) {
    let acct_key = if let Ok(identity) =
        mc_util_keyfile::read_root_entropy_keyfile_data(Cursor::new(bytes.as_slice()))
    {
        println!("{:?}", identity);
        AccountKey::from(&identity)
    } else {
        mc_util_keyfile::read_keyfile_data(Cursor::new(bytes.as_slice()))
            .expect("Could not parse key file as either mnemonic or legacy entropy")
    };

    println!("{:?}", acct_key);
}

fn main() {
    let mut n_files = 0usize;
    for file_str in env::args() {
        print_keyfile_bytes(fs::read(file_str).expect("Could not read file"));
        n_files += 1;
    }

    if n_files == 0 {
        let mut buf = Vec::with_capacity(256);
        io::stdin()
            .read_to_end(&mut buf)
            .expect("No files provided, and no stdin");
        print_keyfile_bytes(buf);
    }
}
