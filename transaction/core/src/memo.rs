//! Definition of memo payload type
//!
//! The encrypted memo of TxOut's is designed to have one encryption scheme and
//! the payload is an extensible format. Two bytes are used for a schema type,
//! and thirty two bytes are used for data according to that schema.
//!
//! The encryption details are defined in the transaction crate, but we would
//! like to avoid making the introduction of a new schema require changes to
//! the transaction-core crate, because this would require a new consensus
//! enclave.
//!
//! We also would like to avoid implementing the interpretation of memo data
//! in the transaction crate, for much the same reasons.
//!
//! Therefore, the code is organized as follows:
//! - A MemoPayload is the collection of 34 bytes ready to be encrypted. This
//!   can be used to construct a TxOut, and it is encrypted at that time. This
//!   is defined in transaction-core crate.
//! - The memo module in transaction-std crate defines specific structures that
//!   can be converted to a MemoPayload, and provides a function that can
//!   interpret a MemoPayload as one of the known high-level objects.
//! - The TransactionBuilder has optional values that can be set on it to set
//!   the "policy" around memos for this transaction, so that low-level handling
//!   of memos is not needed by the user of the TransactionBuilder.
//! - When interpretting memos on TxOut's that you recieved, the memo module
//!   functionality can be used to assist.

use aes::{
    cipher::{FromBlockCipher, StreamCipher},
    Aes256, Aes256Ctr, NewBlockCipher,
};
use core::convert::{TryFrom, TryInto};
use displaydoc::Display;
use generic_array::{
    sequence::Split,
    typenum::{U32, U34, U48},
    GenericArray,
};
use hkdf::Hkdf;
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPublic};
use serde::{Deserialize, Serialize};
use sha2::Sha512;

/// A plaintext memo payload, with accessors to easily access the memo type
/// bytes and memo data bytes. High-level memo objects should be convertible
/// to MemoPayload. Deserialization, across all high-level memo types, is
/// done in mc-memo crate.
///
/// Note that a memo payload may be invalid / uninterpretable, or refer to new
/// memo types that have been introduced at a later date.
#[derive(Clone, Deserialize, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Debug)]
pub struct MemoPayload(GenericArray<u8, U34>);

impl MemoPayload {
    /// Create a new memo payload from given type bytes and data bytes
    pub fn new(memo_type: [u8; 2], memo_data: [u8; 32]) -> Self {
        let mut result = Self::default();
        result.0[0..2].copy_from_slice(&memo_type);
        result.0[2..34].copy_from_slice(&memo_data);
        result
    }

    /// Get the memo type bytes (two bytes)
    pub fn get_memo_type(&self) -> &[u8; 2] {
        self.0.as_slice()[0..2].try_into().unwrap()
    }

    /// Get the memo data bytes (thirty-two bytes)
    pub fn get_memo_data(&self) -> &[u8; 32] {
        self.0.as_slice()[2..34].try_into().unwrap()
    }

    /// Encrypt this memo payload using a given shared-secret, consuming it and
    /// returning underlying buffer.
    ///
    /// The shared-secret is expected to be the TxOut shared secret associated
    /// to the memo.
    pub fn encrypt(mut self, shared_secret: &RistrettoPublic) -> GenericArray<u8, U34> {
        self.apply_keystream(&shared_secret);
        self.0
    }

    /// Try to decrypt given e_memo bytes using a shared secret.
    ///
    /// Note: The results of this call are unauthenticated.
    pub fn try_decrypt(src: &[u8], shared_secret: &RistrettoPublic) -> Result<Self, LengthError> {
        let mut result = Self::try_from(src)?;
        result.apply_keystream(&shared_secret);
        Ok(result)
    }

    // Apply AES256 keystream to internal buffer.
    // This is not a user-facing API, since from the user's point of view this
    // object always represents decrypted bytes.
    //
    // The argument is supposed to be the TxOut shared secret associated to the
    // memo.
    fn apply_keystream(&mut self, shared_secret: &RistrettoPublic) {
        // Use HKDF-SHA512 to produce an AES key and AES nonce
        let shared_secret = CompressedRistrettoPublic::from(shared_secret);
        let kdf = Hkdf::<Sha512>::new(Some(b"mc-memo-okm"), shared_secret.as_ref());
        let mut okm = GenericArray::<u8, U48>::default();
        kdf.expand(b"", okm.as_mut_slice())
            .expect("Digest output size is insufficient");

        let (key, nonce) = Split::<u8, U32>::split(okm);

        // Apply AES-256 in counter mode to the buffer
        let mut aes256ctr = Aes256Ctr::from_block_cipher(Aes256::new(&key), &nonce);
        aes256ctr.apply_keystream(self.0.as_mut_slice());
    }
}

impl AsRef<[u8]> for MemoPayload {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl AsRef<GenericArray<u8, U34>> for MemoPayload {
    fn as_ref(&self) -> &GenericArray<u8, U34> {
        &self.0
    }
}

impl From<MemoPayload> for GenericArray<u8, U34> {
    fn from(src: MemoPayload) -> Self {
        src.0
    }
}

impl From<GenericArray<u8, U34>> for MemoPayload {
    fn from(src: GenericArray<u8, U34>) -> Self {
        Self(src)
    }
}

impl TryFrom<&[u8]> for MemoPayload {
    type Error = LengthError;
    fn try_from(src: &[u8]) -> Result<MemoPayload, Self::Error> {
        if src.len() == 34 {
            Ok(Self(*GenericArray::from_slice(src)))
        } else {
            Err(LengthError::BadLength(src.len()))
        }
    }
}

#[derive(Display, Debug)]
pub enum LengthError {
    /// Wrong length for memo payload: {0}
    BadLength(usize),
}
