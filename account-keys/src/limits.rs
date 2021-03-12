// Copyright (c) 2018-2021 The MobileCoin Foundation

//! This module contains hard-coded length limits and methods to check and
//! convert overflows into relevant errors.

use crate::error::{Error, Result};
use mc_crypto_keys::RistrettoSignature;
use mc_util_repr_bytes::ReprBytes;

/// The minimum length of a Fog URL string, in UTF-8 characters
///
/// This is `"fog://a.b".len();`
const FOG_REPORT_URL_MIN_LENGTH: usize = 9;

/// The maximum length of a Fog URL string, in UTF-8 characters
const FOG_REPORT_URL_MAX_LENGTH: usize = 255;

/// The maximum length of a Fog Report ID, in UTF-8 characters
const FOG_REPORT_ID_MAX_LENGTH: usize = 8;

/// The minimum length of a operator authority's subjectPublicKeyInfo, in bytes.
///
/// This is the DER encoded length of an Ed25519 subjectPublicKeyInfo, in bytes.
const FOG_AUTHORITY_SPKI_MIN_LENGTH: usize = 44;

/// The maximum length of a operator authority's subjectPublicKeyInfo, in bytes
const FOG_AUTHORITY_SPKI_MAX_LENGTH: usize = 2048;

/// Check if the fog report URL is a reasonable length
#[inline]
pub fn check_fog_report_url_length(url: &str) -> Result<()> {
    let len = url.len();
    if FOG_REPORT_URL_MIN_LENGTH > len || len > FOG_REPORT_URL_MAX_LENGTH {
        Err(Error::ReportUrlLength)
    } else {
        Ok(())
    }
}

/// Check if the fog report URL is a reasonable length
#[inline]
pub fn check_fog_report_id_length(id: &str) -> Result<()> {
    if id.len() > FOG_REPORT_ID_MAX_LENGTH {
        Err(Error::ReportIdLength)
    } else {
        Ok(())
    }
}

/// Check if the fog authority subjectPublicKeyInfo is a reasonable length
#[inline]
pub fn check_fog_authority_spki_length(spki: &[u8]) -> Result<()> {
    if FOG_AUTHORITY_SPKI_MIN_LENGTH > spki.len() || spki.len() > FOG_AUTHORITY_SPKI_MAX_LENGTH {
        Err(Error::AuthoritySubjectLength)
    } else {
        Ok(())
    }
}

/// Check if the fog authority signature is a reasonable length
#[inline]
pub fn check_fog_authority_sig_length(sig: &[u8]) -> Result<()> {
    if sig.len() != RistrettoSignature::size() {
        Err(Error::SignatureLength)
    } else {
        Ok(())
    }
}

/// Batch-check all fog-related (private) account fields
#[inline]
pub fn check_fog_key_fields(
    fog_report_url: &str,
    fog_report_id: &str,
    fog_authority_spki: &[u8],
) -> Result<()> {
    check_fog_report_url_length(fog_report_url)?;
    check_fog_report_id_length(fog_report_id)?;
    check_fog_authority_spki_length(fog_authority_spki)
}

/// Batch-check all fog-related (public) address fields
#[inline]
pub fn check_fog_address_fields(
    fog_report_url: &str,
    fog_report_id: &str,
    fog_authority_sig: &[u8],
) -> Result<()> {
    check_fog_report_url_length(fog_report_url)?;
    check_fog_report_id_length(fog_report_id)?;
    check_fog_authority_sig_length(fog_authority_sig)
}
