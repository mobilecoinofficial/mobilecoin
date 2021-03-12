// Copyright (c) 2018-2021 The MobileCoin Foundation

#![no_std]

// Exports are used so that macros can do $crate::_exports and obtain symbols
// from this crate.
#[doc(hidden)]
pub mod _exports {
    pub use generic_array::{typenum, ArrayLength, GenericArray};

    #[cfg(feature = "alloc")]
    pub extern crate alloc;

    #[cfg(feature = "prost")]
    pub use prost;

    #[cfg(feature = "serde")]
    pub use serde;
}

use core::fmt::Display;
use typenum::Unsigned;

// These can be used by who implements ReprBytes
pub use generic_array::{typenum, ArrayLength, GenericArray};

/// ReprBytes represents a type that has a canonical representation as a fixed
/// number of bytes. This interface is meant to support generic programming.
///
/// ReprBytes is meant to be general enough to support many forms of cryptographic
/// primitives. Most cryptographic primitives implement AsRef<[u8]> and TryFrom<&[u8]>,
/// but not all of them can -- RistrettoPoint requires an (expensive) compression
/// step before the bytes of the canonical representation can be accessed.
///
/// ReprBytes provides an API very close to AsRef<[u8]> and TryFrom<&[u8]> which
/// can be used in generic code that handles cryptographic primitives, and in
/// glue code so that these primitives can be used easily with serialization
/// libraries and frameworks.
///
/// The error types are constrained with Display so that both Prost and Serde can make effective use of them
///
/// To be useful, ReprBytes wants to provide many "blanket implementations" that
/// connect it with core traits and traits from Prost and Serde.
/// However, blanket implementations don't work very well in rust outside of stdlib.
/// Instead, we provide macros so that these blanket implementations can be obtained
/// on a per-type basis, and these macros are exported from this crate. We believe
/// that this is consistent with current best practices around blanket implementations.
pub trait ReprBytes: Sized {
    /// A typenum representing the size, in bytes, of the canonical representation
    type Size: ArrayLength<u8>;

    /// The error type which may be returned by from_bytes.
    type Error: Display;

    /// Try to convert from canonical representation bytes to this type
    fn from_bytes(src: &GenericArray<u8, Self::Size>) -> Result<Self, Self::Error>;

    /// Convert to canonical representation bytes.
    fn to_bytes(&self) -> GenericArray<u8, Self::Size>;

    /// In-place visitation of the canonical bytes representation, using a closure
    ///
    /// Implementation note: The default implementation is not the best when your
    /// type implements AsRef<[u8]>, it will make a needless copy in that case.
    /// If your type implements AsRef<[u8]>, then you are strongly recommended to use
    /// the macro `derive_repr_bytes_from_as_ref_try_from`.
    /// Otherwise the default implementation is probably the best.
    /// See also the suggested impl `derive_into_vec_from_repr_bytes`.
    fn map_bytes<T, F: FnOnce(&[u8]) -> T>(&self, f: F) -> T {
        f(self.to_bytes().as_slice())
    }

    /// Convenient helper: Get the representation size as a usize
    fn size() -> usize {
        Self::Size::USIZE
    }
}

/// Error that indicates that we got a different number of bytes than expected
#[derive(Debug)]
pub struct LengthMismatch {
    pub expected: usize,
    pub found: usize,
}

impl Display for LengthMismatch {
    fn fmt(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            formatter,
            "Expected exactly {} bytes, got {}",
            self.expected, self.found
        )
    }
}

////
// Suggested Implementations:
// These macros provide instances of what can be thought of as "blanket implementations"
// on a per-type basis.
// These are macros because rust's coherence rules mean that blanket implementations
// won't work out well for this use-case.
//
// There are two types of suggested impls:
// - Impls of other traits in terms of ReprBytes
// - Impls of ReprBytes in terms of other traits
////

/// Derive ReprBytes from AsRef<[u8]>, TryFrom<&[u8]>, and Size as a typenum.
/// This is expected to be the right implementation for almost all cryptographic
/// primitives, e.g. X25519, CompressedRistretto, etc.
/// It can't work for e.g. RistrettoPoint, which doesn't have AsRef<[u8]>.
///
/// Arguments:
///   - $mytype is the type you want to impl ReprBytes
///   - $mysize is a typenum, representing the size of the canonical representation
///
/// Requirements:
///   - <AsRef<[u8]> for $mytype>::as_ref().len() always equals $mysize::USIZE
///   - <TryFrom<&[u8]> for $mytype>::Error implements core::fmt::Display
///   - <TryFrom<&'a[u8]> for $mytype>::Error is the same for all values of 'a,
///     OR they are all convertible to the value when 'a = 'static, via core::convert::From.
#[macro_export]
macro_rules! derive_repr_bytes_from_as_ref_and_try_from {
    ($mytype:ty, $mysize:ty) => {
        impl $crate::ReprBytes for $mytype {
            type Size = $mysize;
            type Error = <$mytype as ::core::convert::TryFrom<&'static [u8]>>::Error;

            fn from_bytes(
                src: &$crate::GenericArray<u8, Self::Size>,
            ) -> ::core::result::Result<Self, Self::Error> {
                Ok(<Self as ::core::convert::TryFrom<&[u8]>>::try_from(
                    src.as_slice(),
                )?)
            }

            fn to_bytes(&self) -> $crate::GenericArray<u8, Self::Size> {
                use $crate::{typenum::Unsigned, GenericArray};
                let slice = <Self as AsRef<[u8]>>::as_ref(self);
                debug_assert!(slice.len() == <Self::Size as Unsigned>::USIZE);
                <GenericArray<u8, Self::Size>>::from_slice(slice).clone()
            }

            // Optimization: Use AsRef<[u8]> here, which also makes Into<Vec<u8>> better
            fn map_bytes<T, F>(&self, f: F) -> T
            where
                F: FnOnce(&[u8]) -> T,
            {
                f(<Self as AsRef<[u8]>>::as_ref(self))
            }
        }
    };
}

/// Derive Into<Vec<u8>> from a ReprBytes implementation
#[cfg(feature = "alloc")]
#[macro_export]
macro_rules! derive_into_vec_from_repr_bytes {
    ($mytype:ty) => {
        impl Into<$crate::_exports::alloc::vec::Vec<u8>> for $mytype {
            fn into(self) -> $crate::_exports::alloc::vec::Vec<u8> {
                <$mytype as $crate::ReprBytes>::map_bytes(&self, |slice| slice.to_vec())
            }
        }
    };
}

/// Derive TryFrom<&[u8]> from a ReprBytes implementation
/// Preconditions: ReprBytes::Error implements From<LengthMismatch>
#[macro_export]
macro_rules! derive_try_from_slice_from_repr_bytes {
    ($mytype:ty) => {
        impl<'a> ::core::convert::TryFrom<&'a [u8]> for $mytype {
            type Error = <Self as $crate::ReprBytes>::Error;
            fn try_from(src: &'a [u8]) -> ::core::result::Result<Self, Self::Error> {
                if src.len() != <Self as $crate::ReprBytes>::size() {
                    return Err(Self::Error::from($crate::LengthMismatch {
                        expected: <Self as $crate::ReprBytes>::size(),
                        found: src.len(),
                    }));
                }
                <$mytype as $crate::ReprBytes>::from_bytes(<$crate::GenericArray<
                    u8,
                    <Self as $crate::ReprBytes>::Size,
                >>::from_slice(src))
            }
        }
    };
}

/// Derive prost::Message from a ReprBytes implementation
/// The corresponding protobuf has exactly one member, of type `bytes`.
#[cfg(feature = "prost")]
#[macro_export]
macro_rules! derive_prost_message_from_repr_bytes {
    ($mytype:ty) => {
        impl $crate::_exports::prost::Message for $mytype {
            fn encode_raw<B>(&self, buf: &mut B)
            where
                B: $crate::_exports::prost::bytes::BufMut,
            {
                use $crate::_exports::prost::encoding::*;
                let tag = 1;
                encode_key(tag, WireType::LengthDelimited, buf);
                encode_varint(<Self as $crate::ReprBytes>::size() as u64, buf);
                <Self as $crate::ReprBytes>::map_bytes(self, |bytes| buf.put_slice(bytes));
            }

            fn merge_field<B>(
                &mut self,
                tag: u32,
                wire_type: $crate::_exports::prost::encoding::WireType,
                buf: &mut B,
                ctx: $crate::_exports::prost::encoding::DecodeContext,
            ) -> ::core::result::Result<(), $crate::_exports::prost::DecodeError>
            where
                B: $crate::_exports::prost::bytes::Buf,
            {
                use ::core::convert::TryInto;
                use $crate::_exports::{alloc::string::ToString, prost::encoding::*};
                if tag == 1 {
                    let expected_size = <Self as $crate::ReprBytes>::size();

                    check_wire_type(WireType::LengthDelimited, wire_type)?;
                    let len = decode_varint(buf)?;
                    if len > buf.remaining() as u64 {
                        return Err($crate::_exports::prost::DecodeError::new(
                            "buffer underflow",
                        ));
                    }
                    if len != expected_size as u64 {
                        return Err($crate::_exports::prost::DecodeError::new(
                            $crate::LengthMismatch {
                                expected: expected_size,
                                found: len as usize,
                            }
                            .to_string(),
                        ));
                    }
                    let result = <Self as $crate::ReprBytes>::from_bytes(
                        (&buf.bytes()[0..expected_size])
                            .try_into()
                            .expect("buffer size arithmetic"),
                    );
                    buf.advance(expected_size);
                    *self = result
                        .map_err(|e| $crate::_exports::prost::DecodeError::new(e.to_string()))?;
                    Ok(())
                } else {
                    skip_field(wire_type, tag, buf, ctx)
                }
            }

            fn encoded_len(&self) -> usize {
                use $crate::_exports::prost::encoding::*;
                let size = <Self as $crate::ReprBytes>::size();
                key_len(1) + encoded_len_varint(size as u64) + size
            }

            fn clear(&mut self) {
                *self = Self::default();
            }
        }
    };
}

/// Derive serde::{Deserialize, Serialize} from a ReprBytes implementation
/// This is represented within serde as a bytes primitive. During deserialization,
/// a sequence of individual bytes also works, which helps serde_json.
#[cfg(feature = "serde")]
#[macro_export]
macro_rules! derive_serde_from_repr_bytes {
    ($mytype:ty) => {
        impl $crate::_exports::serde::ser::Serialize for $mytype {
            fn serialize<S: $crate::_exports::serde::ser::Serializer>(
                &self,
                serializer: S,
            ) -> ::core::result::Result<S::Ok, S::Error> {
                <Self as $crate::ReprBytes>::map_bytes(self, |bytes| {
                    serializer.serialize_bytes(&bytes)
                })
            }
        }

        impl<'de> $crate::_exports::serde::de::Deserialize<'de> for $mytype {
            fn deserialize<D: $crate::_exports::serde::de::Deserializer<'de>>(
                deserializer: D,
            ) -> ::core::result::Result<$mytype, D::Error> {
                struct KeyVisitor;

                impl<'de> $crate::_exports::serde::de::Visitor<'de> for KeyVisitor {
                    type Value = $mytype;

                    fn expecting(
                        &self,
                        formatter: &mut ::core::fmt::Formatter,
                    ) -> ::core::fmt::Result {
                        write!(
                            formatter,
                            concat!("A ", stringify!($mytype), " as array of bytes")
                        )
                    }

                    fn visit_bytes<E: $crate::_exports::serde::de::Error>(
                        self,
                        value: &[u8],
                    ) -> ::core::result::Result<Self::Value, E> {
                        use $crate::{GenericArray, LengthMismatch, ReprBytes};
                        if value.len() != <$mytype as ReprBytes>::size() {
                            return Err(<E as $crate::_exports::serde::de::Error>::custom(
                                LengthMismatch {
                                    expected: <$mytype as ReprBytes>::size(),
                                    found: value.len(),
                                },
                            ));
                        }
                        let value =
                            &<GenericArray<u8, <$mytype as ReprBytes>::Size>>::from_slice(value);
                        Ok(<$mytype as ReprBytes>::from_bytes(value).map_err(|err| {
                            <E as $crate::_exports::serde::de::Error>::custom(err)
                        })?)
                    }

                    fn visit_seq<V>(
                        self,
                        mut seq: V,
                    ) -> ::core::result::Result<Self::Value, V::Error>
                    where
                        V: $crate::_exports::serde::de::SeqAccess<'de>,
                    {
                        use $crate::{GenericArray, LengthMismatch, ReprBytes};
                        let expected_len = <$mytype as ReprBytes>::size();
                        let mut res = <GenericArray<u8, <$mytype as ReprBytes>::Size>>::default();
                        let mut idx = 0;
                        while let Some(elem) = seq.next_element()? {
                            if idx >= expected_len {
                                return Err(
                                    <V::Error as $crate::_exports::serde::de::Error>::custom(
                                        LengthMismatch {
                                            expected: expected_len,
                                            found: expected_len + 1,
                                        },
                                    ),
                                );
                            }
                            res[idx] = elem;
                            idx += 1;
                        }
                        if idx != expected_len {
                            return Err(<V::Error as $crate::_exports::serde::de::Error>::custom(
                                LengthMismatch {
                                    expected: expected_len,
                                    found: idx,
                                },
                            ));
                        }
                        self.visit_bytes(res.as_slice())
                    }
                }

                deserializer.deserialize_bytes(KeyVisitor)
            }
        }
    };
}

/// Derive PartialOrd, Ord, PartialEq, Hash from AsRef<T>.
/// This means we will compare or hash ourselves by first converting to T via AsRef.
///
/// These impls are generally needed to put the type in an associative container.
/// NOTE: DO NOT DO THIS FOR PRIVATE keys! This is a hazard that can be a source of leaks.
///
/// This is not connected to ReprBytes but it is a macro like the above macros
/// that is often needed for public key type wrappers.
/// You probably don't want to try to implement this for types that don't have AsRef,
/// because it will be slow. For Ristretto, maybe use CompressedRistretto.
#[macro_export]
macro_rules! derive_core_cmp_from_as_ref {
    ($mytype:ty, $asref:ty) => {
        impl PartialOrd for $mytype {
            fn partial_cmp(&self, other: &Self) -> Option<::core::cmp::Ordering> {
                <Self as AsRef<$asref>>::as_ref(self)
                    .partial_cmp(<Self as AsRef<$asref>>::as_ref(other))
            }
        }

        impl Ord for $mytype {
            fn cmp(&self, other: &Self) -> ::core::cmp::Ordering {
                <Self as AsRef<$asref>>::as_ref(self).cmp(<Self as AsRef<$asref>>::as_ref(other))
            }
        }

        impl PartialEq for $mytype {
            fn eq(&self, other: &Self) -> bool {
                <Self as AsRef<$asref>>::as_ref(self).eq(<Self as AsRef<$asref>>::as_ref(other))
            }
        }

        impl ::core::hash::Hash for $mytype {
            fn hash<H: ::core::hash::Hasher>(&self, hasher: &mut H) {
                use ::core::hash::Hash;
                <Self as AsRef<$asref>>::as_ref(self).hash(hasher)
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    use generic_array::sequence::{Concat, Split};
    use typenum::{U12, U20, U4};

    use core::convert::{TryFrom, TryInto};

    extern crate alloc;
    use alloc::vec::Vec;

    extern crate serde_cbor;

    use prost::Message;

    // A test type which can implement AsRef<[u8]>
    #[derive(Default, Debug, Eq, PartialEq)]
    struct TwentyBytes {
        bytes: [u8; 20],
    }

    impl AsRef<[u8]> for TwentyBytes {
        fn as_ref(&self) -> &[u8] {
            &self.bytes
        }
    }

    impl<'a> TryFrom<&'a [u8]> for TwentyBytes {
        type Error = <[u8; 20] as TryFrom<&'a [u8]>>::Error;

        fn try_from(src: &'a [u8]) -> ::core::result::Result<Self, Self::Error> {
            Ok(Self {
                bytes: <[u8; 20]>::try_from(src)?,
            })
        }
    }

    derive_repr_bytes_from_as_ref_and_try_from!(TwentyBytes, U20);
    derive_into_vec_from_repr_bytes!(TwentyBytes);
    derive_prost_message_from_repr_bytes!(TwentyBytes);
    derive_serde_from_repr_bytes!(TwentyBytes);

    // A test type which cannot implement AsRef<[u8]> due to padding rules
    #[derive(Default, Debug, Eq, PartialEq)]
    struct Numbers {
        a: u32,
        b: u64,
    }

    impl ReprBytes for Numbers {
        type Error = LengthMismatch;
        type Size = U12;

        fn to_bytes(&self) -> GenericArray<u8, U12> {
            GenericArray::from(self.a.to_le_bytes())
                .concat(GenericArray::from(self.b.to_le_bytes()))
        }

        fn from_bytes(src: &GenericArray<u8, U12>) -> Result<Self, Self::Error> {
            let (a_bytes, b_bytes) = Split::<u8, U4>::split(*src);
            Ok(Self {
                a: u32::from_le_bytes(a_bytes.try_into().unwrap()),
                b: u64::from_le_bytes(b_bytes.try_into().unwrap()),
            })
        }
    }

    derive_try_from_slice_from_repr_bytes!(Numbers);
    derive_into_vec_from_repr_bytes!(Numbers);
    derive_prost_message_from_repr_bytes!(Numbers);
    derive_serde_from_repr_bytes!(Numbers);

    #[test]
    fn round_trip_twenty_bytes_serde_cbor() {
        let value = TwentyBytes { bytes: [7u8; 20] };
        let serialized = serde_cbor::to_vec(&value).unwrap();
        let value2 = serde_cbor::from_slice(&serialized).unwrap();
        assert_eq!(value, value2);
    }

    #[test]
    fn round_trip_numbers_serde_cbor() {
        let value = Numbers { a: 3, b: 4 };
        let serialized = serde_cbor::to_vec(&value).unwrap();
        let value2 = serde_cbor::from_slice(&serialized).unwrap();
        assert_eq!(value, value2);
    }

    #[test]
    fn round_trip_twenty_bytes_prost() {
        let value = TwentyBytes { bytes: [7u8; 20] };
        let mut buf = Vec::<u8>::new();
        value.encode(&mut buf).unwrap();
        let value2 = TwentyBytes::decode(&buf[..]).unwrap();
        assert_eq!(value, value2);
    }

    #[test]
    fn round_trip_numbers_prost() {
        let value = Numbers { a: 3, b: 4 };
        let mut buf = Vec::<u8>::new();
        value.encode(&mut buf).unwrap();
        let value2 = Numbers::decode(&buf[..]).unwrap();
        assert_eq!(value, value2);
    }

    #[test]
    fn round_trip_numbers_try_from_slice() {
        let value = Numbers { a: 3, b: 4 };
        let buf: Vec<u8> = value.into();
        let value2 = Numbers::try_from(&buf[..]).unwrap();
        let value = Numbers { a: 3, b: 4 };
        assert_eq!(value, value2);
    }
}
