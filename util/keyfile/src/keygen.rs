// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A tool for writing private and public key files to disk,
//! corresponding to `mc_account_keys::RootIdentity`, and
//! `mc_account_keys::PublicAddress` respectively.

use crate::{
    error::Error, read_keyfile, read_pubfile, read_root_entropy_keyfile, write_keyfile,
    write_pubfile,
};
use bip39::{Language, Mnemonic};
use mc_account_keys::{AccountKey, PublicAddress, RootIdentity};
use mc_account_keys_slip10::Slip10KeyGenerator;
use rand::{RngCore, SeedableRng};
use rand_hc::Hc128Rng;
use std::{
    cmp::Ordering,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
};

/// Write a single pair of keyfiles using a given name and data
pub fn write_keyfiles<P: AsRef<Path>>(
    path: P,
    name: &str,
    mnemonic: &Mnemonic,
    account_index: u32,
    fog_report_url: Option<&str>,
    fog_report_id: Option<&str>,
    fog_authority_spki: Option<&[u8]>,
) -> Result<(), Error> {
    let slip10key = mnemonic.clone().derive_slip10_key(account_index);
    let acct_key = match (fog_report_url, fog_report_id, fog_authority_spki) {
        (None, None, None) => AccountKey::from(slip10key),
        (Some(fog_report_url), Some(fog_report_id), Some(fog_authority_spki)) => {
            slip10key.try_into_account_key(fog_report_url, fog_report_id, fog_authority_spki)?
        }
        _ => return Err(Error::MissingFogDetails),
    };

    fs::create_dir_all(&path)?;

    write_keyfile(
        path.as_ref().join(name).with_extension("json"),
        &mnemonic,
        account_index,
        fog_report_url,
        fog_report_id,
        fog_authority_spki,
    )?;
    write_pubfile(
        path.as_ref().join(name).with_extension("pub"),
        &acct_key.default_subaddress(),
    )?;
    Ok(())
}

// These functions help when implementing bootstrap / initialization / tests

/// Helper: Make i'th user's keyfiles' names
fn keyfile_name(i: usize) -> String {
    format!("account_keys_{}", i)
}

/// Write the sequence of default user key files used in tests and demos
pub fn write_default_keyfiles<P: AsRef<Path>>(
    path: P,
    num_accounts: usize,
    fog_report_url: Option<&str>,
    fog_report_id: Option<&str>,
    fog_authority_spki: Option<&[u8]>,
    seed: [u8; 32],
) -> Result<(), Error> {
    let mut keys_rng = Hc128Rng::from_seed(seed);

    // Generate user keys
    for i in 0..num_accounts {
        let mut entropy = [0u8; 32];
        keys_rng.fill_bytes(&mut entropy[..]);

        let mnemonic = Mnemonic::from_entropy(&entropy, Language::English)
            .map_err(|_e| Error::MnemonicSize)?;

        write_keyfiles(
            path.as_ref(),
            &keyfile_name(i),
            &mnemonic,
            0,
            fog_report_url,
            fog_report_id,
            fog_authority_spki,
        )?;
    }
    Ok(())
}

/// Read default pubkeys used in tests and demos
pub fn read_default_pubfiles<P: AsRef<Path>>(path: P) -> Result<Vec<PublicAddress>, Error> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(path)? {
        let filename = entry?.path();
        if let Some("pub") = filename.extension().and_then(OsStr::to_str) {
            entries.push(filename);
        }
    }
    entries.sort_by(compare_keyfile_names);
    let result: Vec<PublicAddress> = entries
        .iter()
        .map(|f| read_pubfile(f).expect("Could not read pubfile"))
        .collect();
    Ok(result)
}

fn read_default_keyfiles<P: AsRef<Path>>(path: P) -> Result<Vec<PathBuf>, Error> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(path)? {
        let filename = entry?.path();
        if let Some("json") = filename.extension().and_then(OsStr::to_str) {
            entries.push(filename);
        }
    }
    entries.sort_by(compare_keyfile_names);
    Ok(entries)
}

/// Read default mnemonic keyfiles
pub fn read_default_mnemonics<P: AsRef<Path>>(path: P) -> Result<Vec<AccountKey>, Error> {
    read_default_keyfiles(path)?
        .into_iter()
        .map(read_keyfile)
        .collect()
}

/// Read default root entropies
#[deprecated]
pub fn read_default_root_entropies<P: AsRef<Path>>(path: P) -> Result<Vec<RootIdentity>, Error> {
    read_default_keyfiles(path)?
        .into_iter()
        .map(read_root_entropy_keyfile)
        .collect()
}

// This comparator is used when sorting the files so that the i'th keyfile
// written is also the i'th keyfile in the vector that is returned when reading
//
// The implementation is, first sort by length, and then if there's a tie,
// sort lexicographically. This makes keyfile_name(a) < keyfile_name(b) iff a <
// b
fn compare_keyfile_names(a: &PathBuf, b: &PathBuf) -> Ordering {
    let a = a.as_os_str();
    let b = b.as_os_str();
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::mnemonic_acct::UncheckedMnemonicAccount;
    use std::convert::TryFrom;

    const DEFAULT_SEED: [u8; 32] = [1u8; 32];

    /// Reads the default pubfiles written to two directories and compares them.
    fn assert_default_pubfiles_eq<P1: AsRef<Path>, P2: AsRef<Path>>(dir1: P1, dir2: P2) {
        let pub1 = read_default_pubfiles(dir1).unwrap();
        let pub2 = read_default_pubfiles(dir2).unwrap();

        assert_eq!(pub1.len(), 10);
        assert_eq!(pub2.len(), 10);
        assert_eq!(&pub1[..], &pub2[..]);
    }

    /// Reads the default pubfiles written to two directories and compares them.
    fn assert_default_mnemonics_eq<P1: AsRef<Path>, P2: AsRef<Path>>(dir1: P1, dir2: P2) {
        let bin1 = read_default_mnemonics(dir1).unwrap();
        let bin2 = read_default_mnemonics(dir2).unwrap();

        assert_eq!(bin1.len(), 10);
        assert_eq!(bin2.len(), 10);
        assert_eq!(&bin1[..], &bin2[..]);
    }

    /// Test [`compare_keyfile_names()`] is a natural sort
    #[test]
    fn keyfile_is_natural_sort() {
        let entries = vec![
            PathBuf::from(keyfile_name(1)).with_extension("json"),
            PathBuf::from(keyfile_name(9)).with_extension("json"),
            PathBuf::from(keyfile_name(10)).with_extension("json"),
            PathBuf::from(keyfile_name(19)).with_extension("json"),
            PathBuf::from(keyfile_name(91)).with_extension("json"),
            PathBuf::from(keyfile_name(100)).with_extension("json"),
        ];
        let mut entries2 = entries.clone();
        entries2.sort_by(compare_keyfile_names);
        assert_eq!(entries, entries2);
    }

    /// Test that two runs of default generation come up with the same results
    /// with fog details.
    #[test]
    fn default_generation_roundtrip_with_fog() {
        let dir1 = tempfile::tempdir().expect("Could not create temporary dir1");
        let dir2 = tempfile::tempdir().expect("Could not create temporary dir2");

        let der_bytes = pem::parse(mc_crypto_x509_test_vectors::ok_rsa_head())
            .expect("Could not parse DER bytes from PEM certificate file")
            .contents;
        let fog_authority_spki = x509_signature::parse_certificate(&der_bytes)
            .expect("Could not parse X509 certificate from DER bytes")
            .subject_public_key_info()
            .spki();

        let fqdn = "fog://fog.unittest.com";
        let fog_report_id = "1";
        write_default_keyfiles(
            &dir1,
            10,
            Some(fqdn),
            Some(fog_report_id),
            Some(&fog_authority_spki),
            DEFAULT_SEED,
        )
        .expect("Error writing default keyfiles to dir1");
        write_default_keyfiles(
            &dir2,
            10,
            Some(fqdn),
            Some(fog_report_id),
            Some(&fog_authority_spki),
            DEFAULT_SEED,
        )
        .expect("Error writing default keyfiles to dir2");

        assert_default_pubfiles_eq(&dir1, &dir2);
        assert_default_mnemonics_eq(&dir1, &dir2);
    }

    /// Test that two runs of default generation come up with the same results
    /// without fog.
    #[test]
    fn default_generation_no_fog() {
        let dir1 = tempfile::tempdir().expect("Could not create temporary dir1");
        let dir2 = tempfile::tempdir().expect("Could not create temporary dir2");

        write_default_keyfiles(&dir1, 10, None, None, None, DEFAULT_SEED)
            .expect("Could not write keyfiles to dir1");
        write_default_keyfiles(&dir2, 10, None, None, None, DEFAULT_SEED)
            .expect("Could not write keyfiles to dir2");

        assert_default_pubfiles_eq(&dir1, &dir2);
        assert_default_mnemonics_eq(&dir1, &dir2);
    }

    const KEYS_JSON: &str = include_str!("backwards_compatibility.json");

    /// Test that the accounts generated here match those generated by earlier
    /// versions.
    #[test]
    fn backwards_compatibility() {
        let mut expected = serde_json::from_str::<Vec<UncheckedMnemonicAccount>>(KEYS_JSON)
            .expect("Could not parse backwards_compatibility.json")
            .into_iter()
            .map(AccountKey::try_from)
            .collect::<Result<Vec<_>, _>>()
            .expect("Could not parse backwards_compatibility.json");
        expected.sort();

        let dir1 = tempfile::tempdir().expect("Could not create temporary dir1");

        write_default_keyfiles(&dir1, 10, None, None, None, DEFAULT_SEED)
            .expect("Could not write example keyfiles");

        let mut actual = read_default_keyfiles(&dir1)
            .expect("Could not read default keyfiles dir")
            .into_iter()
            .map(read_keyfile)
            .collect::<Result<Vec<_>, Error>>()
            .expect("Could not read keyfiles just written");
        actual.sort();

        assert_eq!(expected, actual);
    }
}
