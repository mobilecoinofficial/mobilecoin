// Copyright (c) 2018-2021 The MobileCoin Foundation

use mc_util_keyfile::read_pubfile;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Config {
    /// Path to pubfile
    #[structopt(long)]
    pub pubfile: PathBuf,
}

fn main() {
    let config = Config::from_args();

    let pubaddress = read_pubfile(&config.pubfile).expect("Could not read pubfile");

    println!(
        "Public address for {:?}: \n\t {:?}",
        config.pubfile, pubaddress
    );

    println!(
        "View Public Bytes: {:?}",
        pubaddress.view_public_key().to_bytes()
    );

    println!(
        "View Public Bytes (hex): {:?}",
        hex::encode(pubaddress.view_public_key().to_bytes())
    );

    println!(
        "Spend Public Bytes: {:?}",
        pubaddress.spend_public_key().to_bytes()
    );

    println!(
        "Spend Public Bytes (hex): {:?}",
        hex::encode(pubaddress.spend_public_key().to_bytes())
    );
}
