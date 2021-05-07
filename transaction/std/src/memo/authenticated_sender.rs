//! Object for Authenticated Sender memo type

use core::convert::TryInto;
use hmac::{Hmac, Mac, NewMac};
use mc_account_keys::{AccountKey, AddressHash, PublicAddress};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPrivate, RistrettoPublic};
use mc_transaction_core::MemoPayload;
use sha2::Sha512;
use subtle::{Choice, ConstantTimeEq};

type HmacSha512 = Hmac<Sha512>;

/// A credential that a sender can use to make an Authenticated Sender Memo.
///
/// This can in principle correspond to any subaddress, but usually it
/// corresponds to the default subaddress. The function which creates this from
/// an AccountKey will use the default subaddress.
#[derive(Debug, Clone)]
pub struct SenderMemoCredential {
    address_hash: AddressHash,
    subaddress_spend_private_key: RistrettoPrivate,
}

impl SenderMemoCredential {
    /// Make a new SenderMemoCredential from a public address, and the spend
    /// private key corresponding to that subaddress
    pub fn new_from_address_and_spend_private_key(
        address: &PublicAddress,
        subaddress_spend_private_key: RistrettoPrivate,
    ) -> Self {
        debug_assert!(
            address.spend_public_key() == &RistrettoPublic::from(&subaddress_spend_private_key),
            "provided sender private key didn't match sender public address!"
        );
        let address_hash = AddressHash::from(address);
        Self {
            address_hash,
            subaddress_spend_private_key,
        }
    }
}

impl From<&AccountKey> for SenderMemoCredential {
    fn from(src: &AccountKey) -> Self {
        Self::new_from_address_and_spend_private_key(
            &src.default_subaddress(),
            src.default_subaddress_spend_private(),
        )
    }
}

/// A memo that the sender writes to convey their identity in an authenticated
/// but deniable way, for the recipient of a TxOut.
///
/// Here, deniability arises because the authentication is done using hmac over
/// a shared secret between sender and recipient. The creator is able to compute
/// hmac just as the verifier is.
/// - The honest verifier knows that they didn't create this memo, and the only
///   other person who could has the private key of the sender, so they are
///   convinced of the authenticity.
/// - If the verifier tries to use the memo to prove to a third party that the
///   sender created the memo, the third party who doesn't trust the verifier
///   can't be sure of that, because the verifier could have created the memo
///   just as easily as the sender, and could now be trying to trick the third
///   party.
///
/// This kind of deniability is a propery of Signal messages and is desirable
/// here. If we didn't want this, we would have to use full digital signatures
/// to establish authenticity.
///
/// The layout of the memo data in 32 bytes is:
/// [0-16]: sender_address_hash
/// [16-32]: hmac value
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct AuthenticatedSenderMemo {
    /// The standard 16 byte address hash of the sender's public address we are
    /// authenticating
    pub sender_address_hash: AddressHash,
    /// The first 16 bytes of hmac-sha512 output where:
    /// - the hmac key is created by key exchange between sender spend key and
    ///   recipient view key
    /// - the hmac message is the tx out public key, which uniquely identifies
    ///   the TxOut
    pub hmac_value: [u8; 16],
}

impl AuthenticatedSenderMemo {
    /// Create a new AuthenticatedSenderMemo given credential, recipient public
    /// key, and tx out public key
    ///
    /// # Arguments:
    /// * cred: A sender memo credential tied to the address we wish to identify
    ///   ourselves as
    /// * recieving_subaddress_view_public_key: This is the view public key from
    ///   the public address of recipient
    /// * tx_out_public_key: The public_key of the TxOut to which we will attach
    ///   this memo
    pub fn new(
        cred: &SenderMemoCredential,
        recieving_subaddress_view_public_key: &RistrettoPublic,
        tx_out_public_key: &CompressedRistrettoPublic,
    ) -> Self {
        let sender_address_hash = cred.address_hash.clone();

        use mc_crypto_keys::KexReusablePrivate;
        let shared_secret = cred
            .subaddress_spend_private_key
            .key_exchange(recieving_subaddress_view_public_key);

        let hmac_value = Self::compute_hmac(shared_secret.as_ref(), tx_out_public_key);
        Self {
            sender_address_hash,
            hmac_value,
        }
    }

    /// Validate an AuthenticatedSenderMemo
    ///
    /// First, the client should look up the sender's Public Address from their
    /// hash. If it isn't a known contact we won't be able to authenticate
    /// them.
    ///
    /// Then they need to get the view private key corresponding to the
    /// subaddress that this TxOut was sent to. This is usually our default
    /// subaddress view private key.
    ///
    /// Finally we can validate the memo against these data. The
    /// tx_out_public_key is also under the mac, which prevents replay
    /// attacks.
    ///
    /// Arguments:
    /// * sender_address: The public address of the sender. This can be looked
    ///   up by the AddressHash provided.
    /// * recieving_subaddress_view_private_key: This is usually our
    ///   default_subaddress_view_private_key, but should correspond to whatever
    ///   subaddress recieved this TxOut.
    /// * tx_out_public_key: The public key of the TxOut to which this memo is
    ///   attached.
    ///
    /// Returns:
    /// * subtle::Choice(1u8) if validation passed, subtle::Choice(0u8) if hmac
    ///   comparison failed.
    ///
    /// This function is constant-time.
    pub fn validate(
        &self,
        sender_address: &PublicAddress,
        recieving_subaddress_view_private_key: &RistrettoPrivate,
        tx_out_public_key: &CompressedRistrettoPublic,
    ) -> Choice {
        let mut result = Choice::from(1u8);
        let sender_address_hash = AddressHash::from(sender_address);
        result &= sender_address_hash.ct_eq(&self.sender_address_hash);

        use mc_crypto_keys::KexReusablePrivate;
        let shared_secret =
            recieving_subaddress_view_private_key.key_exchange(sender_address.spend_public_key());

        let expected_hmac = Self::compute_hmac(shared_secret.as_ref(), tx_out_public_key);
        result &= expected_hmac.ct_eq(&self.hmac_value);
        result
    }

    // Encapsulates hmac-sha512 computation
    fn compute_hmac(
        shared_secret: &[u8; 32],
        tx_out_public_key: &CompressedRistrettoPublic,
    ) -> [u8; 16] {
        let mut mac = HmacSha512::new_from_slice(shared_secret.as_ref())
            .expect("hmac can take a key of any size");
        mac.update(tx_out_public_key.as_ref());
        let mut result = [0u8; 16];
        result.copy_from_slice(&mac.finalize().into_bytes()[0..16]);
        result
    }
}

impl From<&[u8; 32]> for AuthenticatedSenderMemo {
    fn from(src: &[u8; 32]) -> Self {
        let address_hash: [u8; 16] = src[0..16].try_into().expect("arithmetic error");
        let hmac_value: [u8; 16] = src[16..32].try_into().expect("arithmetic error");
        Self {
            sender_address_hash: address_hash.into(),
            hmac_value,
        }
    }
}

impl From<AuthenticatedSenderMemo> for MemoPayload {
    fn from(src: AuthenticatedSenderMemo) -> MemoPayload {
        let memo_type = [0u8, 1u8];
        let mut memo_data = [0u8; 32];
        memo_data[0..16].copy_from_slice(src.sender_address_hash.as_ref());
        memo_data[16..32].copy_from_slice(&src.hmac_value);
        MemoPayload::new(memo_type, memo_data)
    }
}
