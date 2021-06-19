//! Convert to/from external::TxOut

use crate::{convert::ConversionError, external};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPublic};
use mc_transaction_core::{encrypted_fog_hint::EncryptedFogHint, tx, Amount};
use std::convert::TryFrom;

/// Convert tx::TxOut --> external::TxOut.
impl From<&tx::TxOut> for external::TxOut {
    fn from(source: &tx::TxOut) -> Self {
        let mut tx_out = external::TxOut::new();

        let amount = external::Amount::from(&source.amount);
        tx_out.set_amount(amount);

        let target_key_bytes = source.target_key.as_bytes().to_vec();
        tx_out.mut_target_key().set_data(target_key_bytes);

        let public_key_bytes = source.public_key.as_bytes().to_vec();
        tx_out.mut_public_key().set_data(public_key_bytes);

        let hint_bytes = source.e_fog_hint.as_ref().to_vec();
        tx_out.mut_e_fog_hint().set_data(hint_bytes);

        let memo_bytes = source.e_memo.clone();
        tx_out.set_e_memo(memo_bytes);

        tx_out
    }
}

/// Convert external::TxOut --> tx::TxOut.
impl TryFrom<&external::TxOut> for tx::TxOut {
    type Error = ConversionError;

    fn try_from(source: &external::TxOut) -> Result<Self, Self::Error> {
        let amount = Amount::try_from(source.get_amount())?;

        let target_key_bytes: &[u8] = source.get_target_key().get_data();
        let target_key: CompressedRistrettoPublic = RistrettoPublic::try_from(target_key_bytes)
            .map_err(|_| ConversionError::KeyCastError)?
            .into();

        let public_key_bytes: &[u8] = source.get_public_key().get_data();
        let public_key: CompressedRistrettoPublic = RistrettoPublic::try_from(public_key_bytes)
            .map_err(|_| ConversionError::KeyCastError)?
            .into();

        let e_fog_hint = EncryptedFogHint::try_from(source.get_e_fog_hint().get_data())
            .map_err(|_| ConversionError::ArrayCastError)?;

        let e_memo = source.get_e_memo().to_vec();

        let tx_out = tx::TxOut {
            amount,
            target_key,
            public_key,
            e_fog_hint,
            e_memo,
        };
        Ok(tx_out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_crypto_keys::RistrettoPublic;
    use mc_transaction_core::{encrypted_fog_hint::ENCRYPTED_FOG_HINT_LEN, Amount};
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    // tx::TxOut -> external::TxOut --> tx::TxOut
    fn test_tx_out_from_tx_out_stored() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let source = tx::TxOut {
            amount: Amount::new(1u64 << 13, &RistrettoPublic::from_random(&mut rng)).unwrap(),
            target_key: RistrettoPublic::from_random(&mut rng).into(),
            public_key: RistrettoPublic::from_random(&mut rng).into(),
            e_fog_hint: (&[0u8; ENCRYPTED_FOG_HINT_LEN]).into(),
            e_memo: vec![0u8; 34],
        };

        let converted = external::TxOut::from(&source);

        let recovered_tx_out = tx::TxOut::try_from(&converted).unwrap();
        assert_eq!(source.amount, recovered_tx_out.amount);
    }
}
