// Copyright (c) 2018-2021 The MobileCoin Foundation

use std::{cmp, fs, path::PathBuf};
use structopt::StructOpt;

// Hack to work around Vec special handling in structopt
type VecBytes = Vec<u8>;

/// Common configuration for generating key files for a new user identity
#[derive(Debug, StructOpt)]
pub struct Config {
    /// Fog Report URL
    #[structopt(long)]
    pub fog_report_url: Option<String>,

    /// Fog Report ID
    #[structopt(long)]
    pub fog_report_id: Option<String>,

    /// Fog Authority subjectPublicKeyInfo, loaded from a PEM root certificate
    #[structopt(long = "fog-authority-root", parse(try_from_str=load_spki_from_pemfile))]
    pub fog_authority_spki: Option<VecBytes>,

    /// Output directory, defaults to current directory.
    #[structopt(long)]
    pub output_dir: Option<PathBuf>,

    /// Seed to use to generate entropy
    #[structopt(
        short,
        long,
        parse(try_from_str=parse_seed),
        env = "MC_SEED",
        default_value = "0101010101010101010101010101010101010101010101010101010101010101"
    )]
    pub seed: [u8; 32],
}

/// Given a path as a string, read the file, parse it as PEM into DER, parse the
/// DER into x509, and extract the subjectPublicKeyInfo as bytes.
fn load_spki_from_pemfile(src: &str) -> Result<Vec<u8>, String> {
    x509_signature::parse_certificate(
        &pem::parse(fs::read(src).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?
            .contents,
    )
    .map_err(|e| format!("{:?}", e))
    .map(|cert| cert.subject_public_key_info().spki().to_vec())
}

/// Parse a hex seed value into 32 bytes
fn parse_seed(s: &str) -> Result<[u8; 32], String> {
    hex::decode(s)
        .map(|mc_seed_bytes| {
            let mut retval = [0u8; 32];
            retval.copy_from_slice(&mc_seed_bytes[..cmp::min(32, mc_seed_bytes.len())]);
            retval
        })
        .map_err(|e| format!("{}", e))
}
