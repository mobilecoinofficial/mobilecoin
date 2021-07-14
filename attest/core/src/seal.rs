// Copyright (c) 2018-2021 The MobileCoin Foundation

//! This module defines `Sealable` trait, `IntelSealed` object, and
//! `ParseSealedError` These objects are portable and can be used without
//! reference to any attestation or sgx crates, however the tests confirm some
//! offsets on x86_64 arch using sgx_types crate.

use crate::SgxError;
use alloc::vec::Vec;
use core::convert::TryFrom;
use failure::Fail;
use prost::Message;

/// A `Sealed<T>` is a Sealed representation of a T, with some additional
/// mac text which has been computed from T and whcih is visible.
///
/// Implementors of Sealed<T> are expected to be newtypes around IntelSealed,
/// and to provide structured access to the mac text. By implementing
/// compute_mac_txt they determine the format of the mac which they will later
/// read.
pub trait Sealed: AsRef<IntelSealed> + Into<IntelSealed> {
    /// The un-encrypted payload type
    type Source: Message + Default;
    /// Type for the mac bytes
    type MacType: AsRef<[u8]>;
    /// Type for the parsing error, which must generalize ParseSealedError
    type Error: Fail + From<ParseSealedError> + From<SgxError>;

    /// Given an object, get the bytes to be used as mac text when it is sealed.
    fn compute_mac_txt(obj: &Self::Source) -> Self::MacType;

    /// Given a IntelSealed, validate the format of the mac text
    /// Note: we could instead do this with a trait bound like
    /// TryFrom<IntelSealed, Error: Into<ParseSealedError>>
    /// but `associated type bounds are unstable` so we avoid
    fn validate_mac_txt(blob: IntelSealed) -> Result<Self, Self::Error>;

    /// Rust does not let us implement TryFrom<&[u8]> for all Sealed because of
    /// coherence issues
    fn try_from_slice(arg: &[u8]) -> Result<Self, Self::Error> {
        Self::validate_mac_txt(IntelSealed::try_from(arg)?)
    }

    /// Rust does not let us implement TryFrom<&[u8]> for all Sealed because of
    /// coherence issues
    fn try_from_vec(arg: Vec<u8>) -> Result<Self, Self::Error> {
        Self::validate_mac_txt(IntelSealed::try_from(arg)?)
    }

    /// Rust does not let us implement AsRef<[u8]> for all Sealed because of
    /// coherence issues
    fn as_bytes(&self) -> &[u8] {
        <Self as AsRef<IntelSealed>>::as_ref(self).as_ref()
    }

    /// Rust does not let us implement Into<Vec<u8>> for all Sealed because of
    /// coherence issues
    fn into_bytes(self) -> Vec<u8> {
        <Self as Into<IntelSealed>>::into(self).into()
    }
}

/// Given an implementation of Sealed, implement each of
/// - TryFrom<&[u8]>
/// - TryFrom<Vec<u8>>
/// - AsRef<[u8]>
/// - Into<Vec<u8>>
///
/// by pulling from the default impls given above
///
/// This should be done in the crate where Sealed is implemented on a given
/// type.
#[macro_export]
macro_rules! impl_sealed_traits {
    ($sealed:ty) => {
        impl ::core::convert::TryFrom<&[u8]> for $sealed {
            type Error = <Self as ::mc_attest_core::Sealed>::Error;
            fn try_from(src: &[u8]) -> Result<Self, Self::Error> {
                <Self as ::mc_attest_core::Sealed>::try_from_slice(src)
            }
        }

        impl ::core::convert::TryFrom<alloc::vec::Vec<u8>> for $sealed {
            type Error = <Self as ::mc_attest_core::Sealed>::Error;
            fn try_from(src: ::alloc::vec::Vec<u8>) -> Result<Self, Self::Error> {
                <Self as ::mc_attest_core::Sealed>::try_from_vec(src)
            }
        }

        impl AsRef<[u8]> for $sealed {
            fn as_ref(&self) -> &[u8] {
                <Self as ::mc_attest_core::Sealed>::as_bytes(self)
            }
        }
        impl From<$sealed> for ::alloc::vec::Vec<u8> {
            fn from(src: $sealed) -> ::alloc::vec::Vec<u8> {
                <Self as ::mc_attest_core::Sealed>::to_bytes(self)
            }
        }
    };
}

/// Intel provides an API for doing AEAD using an identity derived from
/// MRENCLAVE and the EPID key, which they call "sealing".
///
/// This portable API allows to access a sealed blob in order to get the
/// "additional mac text" without unsealing the data. For e.g. sealed
/// transactions, this allows that the hash of the transaction can be additional
/// mac text, and used in the tx-cache, while still being covered by the mac.
///
/// We also provide a IntelSealed wrapper object that owns a Vec containing
/// the sealed data, and uses the additional mac text to implement Eq, Hash,
/// etc. This makes it easy to implement the planned Sealed Tx Cache object.
#[derive(Clone, Debug)]
pub struct IntelSealed {
    payload: Vec<u8>,
    mac_offset: usize,
}

/// This part could probably be a separate trait e.g. SealedBlob, so that
/// all this would be compatible with non-intel AEAD implementations.
/// But for now we don't bother
impl IntelSealed {
    // Get the additional mac text associated to this payload
    pub fn get_mac_txt(&self) -> &[u8] {
        &self.payload[self.mac_offset..]
    }
}

impl AsRef<[u8]> for IntelSealed {
    fn as_ref(&self) -> &[u8] {
        &self.payload[..]
    }
}

impl From<IntelSealed> for Vec<u8> {
    fn from(src: IntelSealed) -> Vec<u8> {
        src.payload
    }
}

impl TryFrom<&[u8]> for IntelSealed {
    type Error = ParseSealedError;
    fn try_from(sealed_data: &[u8]) -> Result<Self, ParseSealedError> {
        let mac_offset = get_add_mac_txt_offset(sealed_data)? as usize;
        Ok(IntelSealed {
            payload: sealed_data.to_vec(),
            mac_offset,
        })
    }
}

impl TryFrom<Vec<u8>> for IntelSealed {
    type Error = ParseSealedError;
    fn try_from(sealed_data: Vec<u8>) -> Result<Self, ParseSealedError> {
        let mac_offset = get_add_mac_txt_offset(&sealed_data)? as usize;
        Ok(IntelSealed {
            payload: sealed_data,
            mac_offset,
        })
    }
}

// Low level function that attempts to parse a sealed blob from x86-64 enclave,
// and find the offset of the additional mac txt within it.
// It is assumed to be the last item in the AES-GCM payload, so we just need to
// know where it starts.
pub fn get_add_mac_txt_offset(sealed_data: &[u8]) -> Result<u32, ParseSealedError> {
    if sealed_data.len() < SGX_SEALED_DATA_T_SIZE {
        return Err(ParseSealedError::TooShort(
            sealed_data.len(),
            SGX_SEALED_DATA_T_SIZE,
        ));
    }
    let result: u32 = {
        let mut result_bytes = [0u8; 4];
        result_bytes[..].copy_from_slice(&sealed_data[MAC_TEXT_OFFSET..MAC_TEXT_OFFSET + 4]);
        // x86-64 is a little endian arch
        u32::from_le_bytes(result_bytes)
    };
    if result as usize > sealed_data.len() {
        return Err(ParseSealedError::MacTxtOffsetOutOfBounds(
            result as usize,
            sealed_data.len(),
        ));
    }
    Ok(result)
}

#[derive(Debug, Clone, Eq, PartialEq, Fail, Serialize, Deserialize)]
pub enum ParseSealedError {
    /// The bytes were too short to contain a sgx_sealed_data_t header
    #[fail(
        display = "Byte range is too short to be a sealed blob: {} < {}",
        _0, _1
    )]
    TooShort(usize, usize),
    /// The mac_text_offset parameter pointed out of the buffer
    #[fail(
        display = "The mac text offset is invalid, because it points outside the buffer: {} > {}",
        _0, _1
    )]
    MacTxtOffsetOutOfBounds(usize, usize),
    /// Unexpected mac text length
    #[fail(
        display = "The mac text length doesn't match what we expected: actual {} != {}",
        _0, _1
    )]
    UnexpectedMacTextLen(usize, usize),
}

// Serde implementations for IntelSealed

impl ::serde::ser::Serialize for IntelSealed {
    #[inline]
    fn serialize<S: ::serde::ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.as_ref())
    }
}

impl<'de> ::serde::de::Deserialize<'de> for IntelSealed {
    fn deserialize<DS: ::serde::de::Deserializer<'de>>(
        deserializer: DS,
    ) -> Result<Self, DS::Error> {
        struct KeyVisitor;

        impl<'de> ::serde::de::Visitor<'de> for KeyVisitor {
            type Value = IntelSealed;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> core::fmt::Result {
                write!(formatter, concat!("An IntelSealed"))
            }

            #[inline]
            fn visit_bytes<E: ::serde::de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
                IntelSealed::try_from(value).map_err(<E as ::serde::de::Error>::custom)
            }
            #[inline]
            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: ::serde::de::SeqAccess<'de>,
            {
                let mut res = alloc::vec::Vec::new();
                while let Some(elem) = seq.next_element()? {
                    res.push(elem);
                }
                self.visit_bytes(&res)
            }
        }

        deserializer.deserialize_bytes(KeyVisitor)
    }
}

// This should match the size_of sgx_sealed_data_t in x86_64 arch, as in the
// enclave
const SGX_SEALED_DATA_T_SIZE: usize = 560;

// This should match the offset of sgx_sealed_data_t::plain_text_offset in
// x86-64 arch, as it is in the enclave
const MAC_TEXT_OFFSET: usize = 512;

#[cfg(test)]
#[cfg(target_arch = "x86_64")]
mod conformance_tests {
    use super::*;
    use mc_sgx_types::sgx_sealed_data_t;

    /// Validates SGX_SEALED_DATA_T
    #[test]
    fn size_test() {
        assert_eq!(
            core::mem::size_of::<sgx_sealed_data_t>(),
            SGX_SEALED_DATA_T_SIZE
        );
    }

    /// Validates MAC_TEXT_OFFSET
    /// Check that MAC_TEXT_OFFSET is the offset of plain_text_offset in x86-64
    /// arch
    #[test]
    fn offset_test() {
        let st = sgx_sealed_data_t::default();
        let base_ptr = &st as *const sgx_sealed_data_t as *const u8;
        let offset_ptr = &st.plain_text_offset as *const u32 as *const u8;
        assert_eq!(MAC_TEXT_OFFSET as isize, unsafe {
            offset_ptr.offset_from(base_ptr)
        });
    }
}
