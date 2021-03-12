//! Convert to/from external::PublicAddress

use crate::{convert::ConversionError, external};
use mc_account_keys::PublicAddress;
use std::convert::TryFrom;

impl From<&PublicAddress> for external::PublicAddress {
    fn from(src: &PublicAddress) -> Self {
        let mut dst = external::PublicAddress::new();

        dst.set_view_public_key(external::CompressedRistretto::from(src.view_public_key()));
        dst.set_spend_public_key(external::CompressedRistretto::from(src.spend_public_key()));

        if let Some(url) = src.fog_report_url() {
            dst.set_fog_report_url(url.to_string());
        }

        if let Some(sig) = src.fog_authority_sig() {
            dst.set_fog_authority_sig(sig.to_vec());
        }

        if let Some(key) = src.fog_report_id() {
            dst.set_fog_report_id(key.to_string());
        }

        dst
    }
}

impl TryFrom<&external::PublicAddress> for PublicAddress {
    type Error = ConversionError;

    fn try_from(src: &external::PublicAddress) -> Result<Self, Self::Error> {
        let spend_public_key = src
            .spend_public_key
            .as_ref()
            .ok_or(mc_crypto_keys::KeyError::LengthMismatch(0, 32))
            .and_then(|key| mc_crypto_keys::RistrettoPublic::try_from(&key.data[..]))?;

        let view_public_key = src
            .view_public_key
            .as_ref()
            .ok_or(mc_crypto_keys::KeyError::LengthMismatch(0, 32))
            .and_then(|key| mc_crypto_keys::RistrettoPublic::try_from(&key.data[..]))?;

        if src.fog_report_url.is_empty() {
            Ok(PublicAddress::new(&spend_public_key, &view_public_key))
        } else {
            Ok(PublicAddress::new_with_fog(
                &spend_public_key,
                &view_public_key,
                &src.fog_report_url,
                src.fog_report_id.clone(),
                src.fog_authority_sig.clone(),
            )?)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_account_keys::AccountKey;
    use rand::{rngs::StdRng, SeedableRng};

    /// Test converting between external::PublicAddress and account_keys::PublicAddress
    #[test]
    fn test_public_address_conversion() {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);

        // public_addresss -> external
        let public_address = AccountKey::random(&mut rng).default_subaddress();
        let proto_credentials = external::PublicAddress::from(&public_address);
        assert_eq!(
            *proto_credentials.get_view_public_key(),
            external::CompressedRistretto::from(public_address.view_public_key())
        );
        assert_eq!(
            *proto_credentials.get_spend_public_key(),
            external::CompressedRistretto::from(public_address.spend_public_key())
        );
        assert_eq!(proto_credentials.fog_report_url, String::from(""));

        assert_eq!(proto_credentials.fog_authority_sig.len(), 0);

        assert_eq!(proto_credentials.fog_report_id, String::from(""));

        // external -> public_addresss
        let public_address2 = PublicAddress::try_from(&proto_credentials).unwrap();
        assert_eq!(public_address, public_address2);
    }

    /// Test converting between external::PublicAddress and
    /// account_keys::PublicAddress when fog data is present.
    ///
    /// This is, strictly-speaking, a superset of
    /// test_public_address_conversion().
    #[test]
    fn test_public_address_conversion_with_fog() {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);

        // public_addresss -> external
        let tmp_public_address = AccountKey::random(&mut rng).default_subaddress();
        let public_address = PublicAddress::new_with_fog(
            tmp_public_address.spend_public_key(),
            tmp_public_address.view_public_key(),
            "fog://fog.unittest.mobilecoin.com",
            "99".to_string(),
            vec![9u8; 64],
        )
        .expect("Could not create public address with manual fog details");

        let proto_credentials = external::PublicAddress::from(&public_address);
        assert_eq!(
            *proto_credentials.get_view_public_key(),
            external::CompressedRistretto::from(public_address.view_public_key())
        );
        assert_eq!(
            *proto_credentials.get_spend_public_key(),
            external::CompressedRistretto::from(public_address.spend_public_key())
        );
        assert_eq!(
            proto_credentials.fog_report_url,
            String::from("fog://fog.unittest.mobilecoin.com")
        );

        assert_eq!(proto_credentials.fog_authority_sig, vec![9u8; 64]);

        assert_eq!(proto_credentials.fog_report_id, "99");

        // external -> public_addresss
        let public_address2 = PublicAddress::try_from(&proto_credentials).unwrap();
        assert_eq!(public_address, public_address2);
    }
}
