use crate::{CtAeadDecrypt, CtDecryptResult};

use alloc::vec::Vec;
use aes_gcm::{AesGcm, Tag, A_MAX, C_MAX};
use block_cipher::{
    consts::U16,
    generic_array::{ArrayLength, GenericArray},
    Block, BlockCipher,
};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

impl<Aes, NonceSize> CtAeadDecrypt for AesGcm<Aes, NonceSize>
where
    Aes: BlockCipher<BlockSize = U16>,
    Aes::ParBlocks: ArrayLength<Block<Aes>>,
    NonceSize: ArrayLength<u8>,
{
    /// A constant time version of the original
    /// https://docs.rs/aes-gcm/0.6.0/src/aes_gcm/lib.rs.html#251
    fn ct_decrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> CtDecryptResult {
        let len = buffer.len();

        if len as u64 > C_MAX || associated_data.len() as u64 > A_MAX {
            return CtDecryptResult(Choice::from(0));
        }

        // TODO(tarcieri): interleave encryption with GHASH
        // See: <https://github.com/RustCrypto/AEADs/issues/74>
        let mut expected_tag = self.compute_tag(associated_data, buffer);
        let mut ctr = self.init_ctr(nonce);
        let mut ciphertext = Vec::with_capacity(len);

        ciphertext.copy_from_slice(&buffer);

        ctr.apply_keystream(&self.cipher, expected_tag.as_mut_slice());
        ctr.apply_keystream(&self.cipher, &mut ciphertext);

        let result = expected_tag.ct_eq(&tag);

        // Conditionally copy the actual plaintext _only_ if the tag verified
        // correctly, in order to increase misuse resistance and reduce attack
        // surface for chosen ciphertext attacks.
        for i in 0..len {
            buffer[i] = u8::conditional_select(&buffer[i], &ciphertext[i], result);
        }
        // Unconditionally zeroize the decryption result to refrain from keeping
        // a CCA oracle in memory.
        ciphertext.zeroize();

        CtDecryptResult(result)
    }
}
