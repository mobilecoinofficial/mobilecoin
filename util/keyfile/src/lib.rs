// Copyright (c) 2018-2021 The MobileCoin Foundation

pub mod config;
pub mod keygen;

mod error;
mod json_format;
mod mnemonic_acct;

use crate::{error::Error, json_format::RootIdentityJson, mnemonic_acct::UncheckedMnemonicAccount};
use bip39::Mnemonic;
use mc_account_keys::{AccountKey, PublicAddress, RootIdentity};
use prost::Message;
use std::{convert::TryInto, fs, fs::File, io, path::Path};

/// Write a user's account details to disk
pub fn write_keyfile<P: AsRef<Path>>(
    path: P,
    mnemonic: &Mnemonic,
    account_index: u32,
    fog_report_url: Option<&str>,
    fog_report_id: Option<&str>,
    fog_authority_spki: Option<&[u8]>,
) -> Result<(), Error> {
    let json = UncheckedMnemonicAccount {
        mnemonic: Some(mnemonic.clone().into_phrase()),
        account_index: Some(account_index),
        fog_report_url: fog_report_url.map(ToOwned::to_owned),
        fog_report_id: fog_report_id.map(ToOwned::to_owned),
        fog_authority_spki: fog_authority_spki.map(ToOwned::to_owned),
    };
    Ok(serde_json::to_writer(File::create(path)?, &json)?)
}

/// Read a keyfile intended for use with the legacy `RootEntropy`
/// key-derivation method.
pub fn read_root_entropy_keyfile<P: AsRef<Path>>(path: P) -> Result<RootIdentity, Error> {
    read_root_entropy_keyfile_data(File::open(path)?)
}

/// Read keyfile data from the given buffer into a legacy `RootIdentity`
/// structure
pub fn read_root_entropy_keyfile_data<R: io::Read>(buffer: R) -> Result<RootIdentity, Error> {
    Ok(serde_json::from_reader::<R, RootIdentityJson>(buffer)?.into())
}

/// Read user root identity from disk
pub fn read_keyfile<P: AsRef<Path>>(path: P) -> Result<AccountKey, Error> {
    read_keyfile_data(File::open(path)?)
}

/// Read user root identity from any implementor of `Read`
pub fn read_keyfile_data<R: io::Read>(buffer: R) -> Result<AccountKey, Error> {
    Ok(serde_json::from_reader::<R, UncheckedMnemonicAccount>(buffer)?.try_into()?)
}

/// Write user public address to disk
pub fn write_pubfile<P: AsRef<Path>>(path: P, addr: &PublicAddress) -> Result<(), Error> {
    let mut buf = Vec::with_capacity(addr.encoded_len());
    addr.encode(&mut buf)?;
    fs::write(path, buf)?;
    Ok(())
}

/// Read user public address from disk
pub fn read_pubfile<P: AsRef<Path>>(path: P) -> Result<PublicAddress, Error> {
    Ok(PublicAddress::decode(fs::read(path)?.as_slice())?)
}

#[cfg(test)]
mod test {
    use super::*;
    use bip39::{Language, MnemonicType};
    use mc_account_keys::AccountKey;
    use mc_account_keys_slip10::{Slip10Key, Slip10KeyGenerator};

    /// Test that round-tripping through a keyfile without fog gets the same
    /// result as creating the key directly.
    #[test]
    fn keyfile_roundtrip_no_fog() {
        let dir = tempfile::tempdir().expect("Could not create temp dir");
        let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
        let path = dir.path().join("no_fog");
        write_keyfile(&path, &mnemonic, 0, None, None, None).expect("Could not write keyfile");
        let expected = AccountKey::from(mnemonic.derive_slip10_key(0));
        let actual = read_keyfile(&path).expect("Could not read keyfile");
        assert_eq!(expected, actual);
    }

    /// Test that round-tripping through a keyfile with fog gets the same result
    /// as creating the key directly.
    #[test]
    fn keyfile_roundtrip_with_fog() {
        let fog_report_url = "fog://unittest.mobilecoin.com";
        let fog_report_id = "1";
        let der_bytes = pem::parse(mc_crypto_x509_test_vectors::ok_rsa_head())
            .expect("Could not parse DER bytes from PEM certificate file")
            .contents;
        let fog_authority_spki = x509_signature::parse_certificate(&der_bytes)
            .expect("Could not parse X509 certificate from DER bytes")
            .subject_public_key_info()
            .spki();

        let dir = tempfile::tempdir().expect("Could not create temp dir");
        let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);

        let path = dir.path().join("with_fog");
        write_keyfile(
            &path,
            &mnemonic,
            0,
            Some(fog_report_url),
            Some(fog_report_id),
            Some(fog_authority_spki),
        )
        .expect("Could not write keyfile");

        let expected = mnemonic
            .derive_slip10_key(0)
            .try_into_account_key(fog_report_url, fog_report_id, fog_authority_spki)
            .expect("Could not create expected account key");
        let actual = read_keyfile(&path).expect("Could not read keyfile");
        assert_eq!(expected, actual);
    }

    /// Test that writing a [`PublicAddress`](mc_account_keys::PublicAddress)
    /// and reading it back without fog details gets the same results.
    #[test]
    fn pubfile_roundtrip_no_fog() {
        let expected = AccountKey::from(Slip10Key::from(Mnemonic::new(
            MnemonicType::Words24,
            Language::English,
        )))
        .default_subaddress();

        let dir = tempfile::tempdir().expect("Could not create temporary directory");
        let path = dir.path().join("pubfile_no_fog");
        write_pubfile(&path, &expected).expect("Could not write pubfile");
        let actual = read_pubfile(&path).expect("Could not read back pubfile");
        assert_eq!(expected, actual);
    }

    /// Test that writing a [`PublicAddress`](mc_account_keys::PublicAddress)
    /// and reading it back with fog details gets the same results.
    #[test]
    fn pubfile_roundtrip_with_fog() {
        let fog_report_url = "fog://unittest.mobilecoin.com";
        let fog_report_id = "1";
        let der_bytes = pem::parse(mc_crypto_x509_test_vectors::ok_rsa_head())
            .expect("Could not parse DER bytes from PEM certificate file")
            .contents;
        let fog_authority_spki = x509_signature::parse_certificate(&der_bytes)
            .expect("Could not parse X509 certificate from DER bytes")
            .subject_public_key_info()
            .spki();
        let expected = Slip10Key::from(Mnemonic::new(MnemonicType::Words24, Language::English))
            .try_into_account_key(fog_report_url, fog_report_id, fog_authority_spki)
            .expect("Could not create expected account key")
            .default_subaddress();

        let dir = tempfile::tempdir().expect("Could not create temporary directory");
        let path = dir.path().join("pubfile_with_fog");
        write_pubfile(&path, &expected).expect("Could not write fog pubfile");
        let actual = read_pubfile(&path).expect("Could not read back fog pubfile");
        assert_eq!(expected, actual);
    }
}
