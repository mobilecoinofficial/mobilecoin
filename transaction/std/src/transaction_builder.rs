// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Utility for building and signing a transaction.
//!
//! See https://cryptonote.org/img/cryptonote_transaction.png

use crate::{
    AuthenticatedSenderMemo, DestinationMemo, InputCredentials, SenderMemoCredential,
    TxBuilderError,
};
use core::cmp::min;
use curve25519_dalek::scalar::Scalar;
use mc_account_keys::{AccountKey, PublicAddress};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPrivate, RistrettoPublic};
use mc_fog_report_validation::FogPubkeyResolver;
use mc_transaction_core::{
    constants::MINIMUM_FEE,
    encrypted_fog_hint::EncryptedFogHint,
    fog_hint::FogHint,
    onetime_keys::create_shared_secret,
    ring_signature::SignatureRctBulletproofs,
    tx::{Tx, TxIn, TxOut, TxOutConfirmationNumber, TxPrefix},
    CompressedCommitment, MemoPayload,
};
use mc_util_from_random::FromRandom;
use rand_core::{CryptoRng, RngCore};

/// This is an API type for the transaction builder that helps name and organize
/// data that is passed when creating a change output.
///
/// When creating a standard change output, the primary address is used to
/// create the fog hint, and the change subaddress actually owns the change
/// output.
///
/// This object can be created from an AccountKey, but it could also be created
/// offline and then serialized and sent to a different machine.
#[derive(Clone, Debug)]
pub struct ChangeDestination {
    /// This is normally the default subaddress of an account. It is used to
    /// create the fog hint.
    pub primary_address: PublicAddress,
    /// This is a secret subaddress not known except by the owner of the
    /// account. It is the account to which all change outputs are actually
    /// sent. The account owner is able to confirm that an output is change
    /// by checking that it matches to the change subaddress.
    pub change_subaddress: PublicAddress,
}

impl From<&AccountKey> for ChangeDestination {
    fn from(src: &AccountKey) -> Self {
        Self {
            primary_address: src.default_subaddress(),
            change_subaddress: src.change_subaddress(),
        }
    }
}

/// Helper utility for building and signing a CryptoNote-style transaction,
/// and attaching fog hint and memos as appropriate.
///
/// Note: This is generic over FogPubkeyResolver, because otherwise, to test
/// this object, we must create fake IAS reports which is quite difficult.
#[derive(Debug)]
pub struct TransactionBuilder<FPR: FogPubkeyResolver> {
    /// The input credentials used to form the transaction
    input_credentials: Vec<InputCredentials>,
    /// The outputs created by the transaction, and associated shared secrets
    outputs_and_shared_secrets: Vec<(TxOut, RistrettoPublic)>,
    /// The tombstone_block value, a block index in which the transaction
    /// expires, and can no longer be added to the blockchain
    tombstone_block: u64,
    /// The fee paid in connection to this transaction
    fee: u64,
    /// The source of validated fog pubkeys used for this transaction
    fog_resolver: FPR,
    /// The limit on the tombstone block value imposed pubkey_expiry values in
    /// fog pubkeys used so far
    fog_tombstone_block_limit: u64,
    /// A credential used for creating Authenticated Sender Memos. If set, then
    /// by default these are attached to any new outputs that are created using
    /// add_output. These identify the sender, in a deniable way, for the
    /// recipient, and create recoverable transaction history for the
    /// recipient.
    ///
    /// Authenticated Sender Memos are not used with the change output.
    sender_memo_credential: Option<SenderMemoCredential>,
}

impl<FPR: FogPubkeyResolver> TransactionBuilder<FPR> {
    /// Initializes a new TransactionBuilder.
    ///
    /// # Arguments
    /// * `fog_resolver` - Source of validated fog keys to use with this
    ///   transaction
    pub fn new(fog_resolver: FPR) -> Self {
        TransactionBuilder {
            input_credentials: Vec::new(),
            outputs_and_shared_secrets: Vec::new(),
            tombstone_block: u64::max_value(),
            fee: MINIMUM_FEE,
            fog_resolver,
            fog_tombstone_block_limit: u64::max_value(),
            sender_memo_credential: None,
        }
    }

    /// Set the sender memo credential
    /// This causes authenticated sender memos to used with (non-change) outputs
    pub fn set_sender_memo_credential(&mut self, cred: SenderMemoCredential) {
        self.sender_memo_credential = Some(cred);
    }

    /// Clear the sender memo credential value
    pub fn clear_sender_memo_credential(&mut self) {
        self.sender_memo_credential = None;
    }

    /// Add an Input to the transaction.
    ///
    /// # Arguments
    /// * `input_credentials` - Credentials required to construct a ring
    ///   signature for an input.
    pub fn add_input(&mut self, input_credentials: InputCredentials) {
        self.input_credentials.push(input_credentials);
    }

    /// Add a non-change output to the transaction.
    ///
    /// If a sender memo credential has been set, this will create an
    /// authenticated sender memo for the TxOut. Otherwise the memo will be
    /// unused.
    ///
    /// # Arguments
    /// * `value` - The value of this output, in picoMOB.
    /// * `recipient` - The recipient's public address
    /// * `rng` - RNG used to generate blinding for commitment
    pub fn add_output<RNG: CryptoRng + RngCore>(
        &mut self,
        value: u64,
        recipient: &PublicAddress,
        rng: &mut RNG,
    ) -> Result<(TxOut, TxOutConfirmationNumber), TxBuilderError> {
        let (mut tx_out, conf_num) = self.add_output_with_fog_hint_address(
            value,
            recipient,
            recipient,
            MemoPayload::default(),
            rng,
        )?;
        // Hack: we can't build authenticated sender memo until we know TxOut public
        // key, so if we need to do that, modify the TxOut.e_memo now after it
        // has been added to outputs_and_shared_secrets
        if let Some(cred) = &self.sender_memo_credential {
            let (ref mut tx_out_ref, ref shared_secret) = self
                .outputs_and_shared_secrets
                .last_mut()
                .expect("should not be empty after we added something");
            let memo: MemoPayload = AuthenticatedSenderMemo::new(
                &cred,
                recipient.view_public_key(),
                &tx_out_ref.public_key,
            )
            .into();
            (&mut tx_out_ref.e_memo[..]).copy_from_slice(memo.encrypt(shared_secret).as_slice());
            tx_out = tx_out_ref.clone();
        }
        Ok((tx_out, conf_num))
    }

    /// Add a standard change output to the transaction.
    ///
    /// The change output is meant to send any value in the inputs not already
    /// sent via outputs or fee, back to the sender's address.
    /// The caller should ensure that the math adds up, and that
    /// change_value + total_outlays + fee = total_input_value
    ///
    /// (Here, outlay means a non-change output).
    ///
    /// A change output should be sent to the dedicated change subaddress of the
    /// sender.
    ///
    /// If provided, a Destination memo is attached to this output, which allows
    /// for recoverable transaction history.
    ///
    /// The use of dedicated change subaddress for change outputs allows to
    /// authenticate the contents of destination memos, which are otherwise
    /// unauthenticated.
    ///
    /// # Arguments
    /// * `value` - The value of this change output.
    /// * `change_destination` - An object including both a primary address and
    ///   a change subaddress to use to create this change output. The primary
    ///   address is used for the fog hint, the change subaddress owns the
    ///   change output. These can both be obtained from an account key, but
    ///   this API does not require the account key.
    /// * `destination_memo` - The destination memo which will be attached to
    ///   the TxOut in order to create recoverable transaction history. If
    ///   omitted, the unused memo type is used instead.
    /// * `rng` - RNG used to generate blinding for commitment
    pub fn add_change_output<RNG: CryptoRng + RngCore>(
        &mut self,
        value: u64,
        change_destination: &ChangeDestination,
        destination_memo: Option<DestinationMemo>,
        rng: &mut RNG,
    ) -> Result<(TxOut, TxOutConfirmationNumber), TxBuilderError> {
        let memo: MemoPayload = destination_memo.map(|memo| memo.into()).unwrap_or_default();
        self.add_output_with_fog_hint_address(
            value,
            &change_destination.primary_address,
            &change_destination.change_subaddress,
            memo,
            rng,
        )
    }

    /// Add an output to the transaction, using `fog_hint_address` to construct
    /// the fog hint.
    ///
    /// Caution: This method should not be used without fully understanding the
    /// implications.
    ///
    /// Receiving a `TxOut` addressed to a different recipient than what's
    /// contained in the fog hint is normally considered to be a violation
    /// of convention and is likely to be filtered out silently by the
    /// client, except in special circumstances where the recipient is expressly
    /// expecting it.
    ///
    /// # Arguments
    /// * `value` - The value of this output, in picoMOB.
    /// * `recipient` - The recipient's public address
    /// * `fog_hint_address` - The public address used to create the fog hint
    /// * `memo` - The memo payload to attach to this TxOut
    /// * `rng` - RNG used to generate blinding for commitment
    pub fn add_output_with_fog_hint_address<RNG: CryptoRng + RngCore>(
        &mut self,
        value: u64,
        recipient: &PublicAddress,
        fog_hint_address: &PublicAddress,
        memo: MemoPayload,
        rng: &mut RNG,
    ) -> Result<(TxOut, TxOutConfirmationNumber), TxBuilderError> {
        let (hint, pubkey_expiry) = create_fog_hint(fog_hint_address, &self.fog_resolver, rng)?;
        let (tx_out, shared_secret) =
            create_output_with_fog_hint(value, recipient, hint, memo, rng)?;

        self.impose_tombstone_block_limit(pubkey_expiry);

        self.outputs_and_shared_secrets
            .push((tx_out.clone(), shared_secret));

        let confirmation = TxOutConfirmationNumber::from(&shared_secret);

        Ok((tx_out, confirmation))
    }

    /// Add a change output to the transaction, using the fog-

    /// Sets the tombstone block, clamping to smallest pubkey expiry value.
    ///
    /// # Arguments
    /// * `tombstone_block` - Tombstone block number.
    pub fn set_tombstone_block(&mut self, tombstone_block: u64) -> u64 {
        self.tombstone_block = min(tombstone_block, self.fog_tombstone_block_limit);
        self.tombstone_block
    }

    /// Reduce the fog_tombstone_block_limit value by the amount specified,
    /// and propagate this constraint to self.tombstone_block
    fn impose_tombstone_block_limit(&mut self, pubkey_expiry: u64) {
        // Reduce fog tombstone block limit value if necessary
        self.fog_tombstone_block_limit = min(self.fog_tombstone_block_limit, pubkey_expiry);
        // Reduce tombstone_block value if necessary
        self.tombstone_block = min(self.fog_tombstone_block_limit, self.tombstone_block);
    }

    /// Sets the transaction fee.
    ///
    /// # Arguments
    /// * `fee` - Transaction fee, in picoMOB.
    pub fn set_fee(&mut self, fee: u64) {
        self.fee = fee;
    }

    /// Gets the transaction fee.
    pub fn get_fee(&self) -> u64 {
        self.fee
    }

    /// Consume the builder and return the transaction.
    pub fn build<RNG: CryptoRng + RngCore>(mut self, rng: &mut RNG) -> Result<Tx, TxBuilderError> {
        if self.input_credentials.is_empty() {
            return Err(TxBuilderError::NoInputs);
        }

        // All inputs must have rings of the same size.
        if self
            .input_credentials
            .windows(2)
            .any(|win| win[0].ring.len() != win[1].ring.len())
        {
            return Err(TxBuilderError::InvalidRingSize);
        }

        // Construct a list of sorted inputs.
        // Inputs are sorted by the first ring element's public key. Note that each ring
        // is also sorted.
        self.input_credentials
            .sort_by(|a, b| a.ring[0].public_key.cmp(&b.ring[0].public_key));

        let inputs: Vec<TxIn> = self
            .input_credentials
            .iter()
            .map(|input_credential| TxIn {
                ring: input_credential.ring.clone(),
                proofs: input_credential.membership_proofs.clone(),
            })
            .collect();

        // Sort outputs by public key.
        self.outputs_and_shared_secrets
            .sort_by(|(a, _), (b, _)| a.public_key.cmp(&b.public_key));

        let output_values_and_blindings: Vec<(u64, Scalar)> = self
            .outputs_and_shared_secrets
            .iter()
            .map(|(tx_out, shared_secret)| {
                let amount = &tx_out.amount;
                let (value, blinding) = amount
                    .get_value(shared_secret)
                    .expect("TransactionBuilder created an invalid Amount");
                (value, blinding)
            })
            .collect();

        let (outputs, _shared_serets): (Vec<TxOut>, Vec<_>) =
            self.outputs_and_shared_secrets.into_iter().unzip();

        let tx_prefix = TxPrefix::new(inputs, outputs, self.fee, self.tombstone_block);

        let mut rings: Vec<Vec<(CompressedRistrettoPublic, CompressedCommitment)>> = Vec::new();
        for input in &tx_prefix.inputs {
            let ring: Vec<(CompressedRistrettoPublic, CompressedCommitment)> = input
                .ring
                .iter()
                .map(|tx_out| (tx_out.target_key, tx_out.amount.commitment))
                .collect();
            rings.push(ring);
        }

        let real_input_indices: Vec<usize> = self
            .input_credentials
            .iter()
            .map(|input_credential| input_credential.real_index)
            .collect();

        // One-time private key, amount value, and amount blinding for each real input.
        let mut input_secrets: Vec<(RistrettoPrivate, u64, Scalar)> = Vec::new();
        for input_credential in &self.input_credentials {
            let onetime_private_key = input_credential.onetime_private_key;
            let amount = &input_credential.ring[input_credential.real_index].amount;
            let shared_secret = create_shared_secret(
                &input_credential.real_output_public_key,
                &input_credential.view_private_key,
            );
            let (value, blinding) = amount.get_value(&shared_secret)?;
            input_secrets.push((onetime_private_key, value, blinding));
        }

        let message = tx_prefix.hash().0;
        let signature = SignatureRctBulletproofs::sign(
            &message,
            &rings,
            &real_input_indices,
            &input_secrets,
            &output_values_and_blindings,
            self.fee,
            rng,
        )?;

        Ok(Tx {
            prefix: tx_prefix,
            signature,
        })
    }
}

/// Creates a TxOut that sends `value` to `recipient` using the provided
/// `fog_hint`.
///
/// # Arguments
/// * `value` - Value of the output, in picoMOB.
/// * `recipient` - Recipient's address.
/// * `fog_hint` - The encrypted fog hint to use
/// * `rng` -
fn create_output_with_fog_hint<RNG: CryptoRng + RngCore>(
    value: u64,
    recipient: &PublicAddress,
    fog_hint: EncryptedFogHint,
    memo: MemoPayload,
    rng: &mut RNG,
) -> Result<(TxOut, RistrettoPublic), TxBuilderError> {
    let private_key = RistrettoPrivate::from_random(rng);
    let tx_out = TxOut::new(value, recipient, &private_key, fog_hint, memo)?;
    let shared_secret = create_shared_secret(recipient.view_public_key(), &private_key);
    Ok((tx_out, shared_secret))
}

/// Create a fog hint, using the fog_resolver collection in self.
///
/// # Arguments
/// * `recipient` - Recipient's address.
/// * `fog_resolver` - Set of validated fog pubkey data
/// * `rng` - Entropy for the encryption.
///
/// # Returns
/// * `encrypted_fog_hint` - The fog hint to use for a TxOut.
/// * `pubkey_expiry` - The block at which this fog pubkey expires, or
///   u64::max_value() Imposes a limit on tombstone block for the transaction
fn create_fog_hint<RNG: RngCore + CryptoRng, FPR: FogPubkeyResolver>(
    recipient: &PublicAddress,
    fog_resolver: &FPR,
    rng: &mut RNG,
) -> Result<(EncryptedFogHint, u64), TxBuilderError> {
    if recipient.fog_report_url().is_none() {
        return Ok((EncryptedFogHint::fake_onetime_hint(rng), u64::max_value()));
    }

    // Find fog pubkey from set of pre-fetched fog pubkeys
    let validated_fog_pubkey = fog_resolver.get_fog_pubkey(recipient)?;

    Ok((
        FogHint::from(recipient).encrypt(&validated_fog_pubkey.pubkey, rng),
        validated_fog_pubkey.pubkey_expiry,
    ))
}

#[cfg(test)]
pub mod transaction_builder_tests {
    use super::*;
    use maplit::btreemap;
    use mc_account_keys::{AccountKey, DEFAULT_SUBADDRESS_INDEX};
    use mc_fog_report_validation_test_utils::{FullyValidatedFogPubkey, MockFogResolver};
    use mc_transaction_core::{
        constants::{MAX_INPUTS, MAX_OUTPUTS, MILLIMOB_TO_PICOMOB},
        onetime_keys::*,
        ring_signature::KeyImage,
        tx::TxOutMembershipProof,
        validation::validate_signature,
    };
    use rand::{rngs::StdRng, SeedableRng};
    use std::convert::TryFrom;

    /// Creates a TxOut that sends `value` to `recipient`.
    ///
    /// Note: This is only used in test code
    ///
    /// # Arguments
    /// * `value` - Value of the output, in picoMOB.
    /// * `recipient` - Recipient's address.
    /// * `fog_resolver` - Set of prefetched fog public keys to choose from
    /// * `rng` - Entropy for the encryption.
    ///
    /// # Returns
    /// * A transaction output, and the shared secret for this TxOut.
    fn create_output<RNG: CryptoRng + RngCore, FPR: FogPubkeyResolver>(
        value: u64,
        recipient: &PublicAddress,
        fog_resolver: &FPR,
        rng: &mut RNG,
    ) -> Result<(TxOut, RistrettoPublic), TxBuilderError> {
        let (hint, _pubkey_expiry) = create_fog_hint(recipient, fog_resolver, rng)?;
        create_output_with_fog_hint(value, recipient, hint, MemoPayload::default(), rng)
    }

    /// Creates a ring of of TxOuts.
    ///
    /// # Arguments
    /// * `ring_size` - Number of elements in the ring.
    /// * `account` - Owner of one of the ring elements.
    /// * `value` - Value of the real element.
    /// * `rng` - Randomness.
    ///
    /// Returns (ring, real_index)
    fn get_ring<RNG: CryptoRng + RngCore>(
        ring_size: usize,
        account: &AccountKey,
        value: u64,
        rng: &mut RNG,
    ) -> (Vec<TxOut>, usize) {
        let mut ring: Vec<TxOut> = Vec::new();

        // Create ring_size - 1 mixins.
        for _i in 0..ring_size - 1 {
            let address = AccountKey::random(rng).default_subaddress();
            let (tx_out, _) =
                create_output(value, &address, &MockFogResolver::default(), rng).unwrap();
            ring.push(tx_out);
        }

        // Insert the real element.
        let real_index = (rng.next_u64() % ring_size as u64) as usize;
        let (tx_out, _) = create_output(
            value,
            &account.default_subaddress(),
            &MockFogResolver(Default::default()),
            rng,
        )
        .unwrap();
        ring.insert(real_index, tx_out);
        assert_eq!(ring.len(), ring_size);

        (ring, real_index)
    }

    /// Creates an `InputCredentials` for an account.
    ///
    /// # Arguments
    /// * `account` - Owner of one of the ring elements.
    /// * `value` - Value of the real element.
    /// * `rng` - Randomness.
    ///
    /// Returns (input_credentials)
    fn get_input_credentials<RNG: CryptoRng + RngCore>(
        account: &AccountKey,
        value: u64,
        rng: &mut RNG,
    ) -> InputCredentials {
        let (ring, real_index) = get_ring(3, account, value, rng);
        let real_output = ring[real_index].clone();

        let onetime_private_key = recover_onetime_private_key(
            &RistrettoPublic::try_from(&real_output.public_key).unwrap(),
            &account.view_private_key(),
            &account.subaddress_spend_private(DEFAULT_SUBADDRESS_INDEX),
        );

        let membership_proofs: Vec<TxOutMembershipProof> = ring
            .iter()
            .map(|_tx_out| {
                // TransactionBuilder does not validate membership proofs, but does require one
                // for each ring member.
                TxOutMembershipProof::default()
            })
            .collect();

        InputCredentials::new(
            ring,
            membership_proofs,
            real_index,
            onetime_private_key,
            *account.view_private_key(),
        )
        .unwrap()
    }

    // Uses TransactionBuilder to build a transaction.
    fn get_transaction<RNG: RngCore + CryptoRng>(
        num_inputs: usize,
        num_outputs: usize,
        sender: &AccountKey,
        recipient: &AccountKey,
        rng: &mut RNG,
    ) -> Result<Tx, TxBuilderError> {
        let mut transaction_builder = TransactionBuilder::new(MockFogResolver::default());
        let input_value = 1000;
        let output_value = 10;

        // Inputs
        for _i in 0..num_inputs {
            let input_credentials = get_input_credentials(sender, input_value, rng);
            transaction_builder.add_input(input_credentials);
        }

        // Outputs
        for _i in 0..num_outputs {
            transaction_builder
                .add_output(output_value, &recipient.default_subaddress(), rng)
                .unwrap();
        }

        // Set the fee so that sum(inputs) = sum(outputs) + fee.
        let fee = num_inputs as u64 * input_value - num_outputs as u64 * output_value;
        transaction_builder.set_fee(fee);

        transaction_builder.build(rng)
    }

    #[test]
    // Spend a single input and send its full value to a single recipient.
    fn test_simple_transaction() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let sender = AccountKey::random(&mut rng);
        let recipient = AccountKey::random(&mut rng);
        let value = 1475 * MILLIMOB_TO_PICOMOB;

        // Mint an initial collection of outputs, including one belonging to Alice.
        let input_credentials = get_input_credentials(&sender, value, &mut rng);

        let membership_proofs = input_credentials.membership_proofs.clone();
        let key_image = KeyImage::from(&input_credentials.onetime_private_key);

        let mut transaction_builder = TransactionBuilder::new(MockFogResolver::default());

        transaction_builder.add_input(input_credentials);
        let (_txout, confirmation) = transaction_builder
            .add_output(
                value - MINIMUM_FEE,
                &recipient.default_subaddress(),
                &mut rng,
            )
            .unwrap();

        let tx = transaction_builder.build(&mut rng).unwrap();

        // The transaction should have a single input.
        assert_eq!(tx.prefix.inputs.len(), 1);

        assert_eq!(tx.prefix.inputs[0].proofs.len(), membership_proofs.len());

        let expected_key_images = vec![key_image];
        assert_eq!(tx.key_images(), expected_key_images);

        // The transaction should have one output.
        assert_eq!(tx.prefix.outputs.len(), 1);

        let output: &TxOut = tx.prefix.outputs.get(0).unwrap();

        // The output should belong to the correct recipient.
        {
            assert!(view_key_matches_output(
                &recipient.view_key(),
                &RistrettoPublic::try_from(&output.target_key).unwrap(),
                &RistrettoPublic::try_from(&output.public_key).unwrap()
            ));
        }

        // The output should have the correct value and confirmation number
        {
            let public_key = RistrettoPublic::try_from(&output.public_key).unwrap();
            assert!(confirmation.validate(&public_key, &recipient.view_private_key()));
        }

        // The transaction should have a valid signature.
        assert!(validate_signature(&tx, &mut rng).is_ok());
    }

    #[test]
    // Spend a single input and send its full value to a single fog recipient.
    fn test_simple_fog_transaction() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let sender = AccountKey::random(&mut rng);
        let recipient = AccountKey::random_with_fog(&mut rng);
        let ingest_private_key = RistrettoPrivate::from_random(&mut rng);
        let value = 1475 * MILLIMOB_TO_PICOMOB;

        let input_credentials = get_input_credentials(&sender, value, &mut rng);

        let membership_proofs = input_credentials.membership_proofs.clone();
        let key_image = KeyImage::from(&input_credentials.onetime_private_key);

        let fog_resolver = MockFogResolver(btreemap! {
                            recipient
                    .default_subaddress()
                    .fog_report_url()
                    .unwrap()
                    .to_string()
            =>
                FullyValidatedFogPubkey {
                    pubkey: RistrettoPublic::from(&ingest_private_key),
                    pubkey_expiry: 1000,
                },
        });

        let mut transaction_builder = TransactionBuilder::new(fog_resolver);

        transaction_builder.add_input(input_credentials);
        let (_txout, confirmation) = transaction_builder
            .add_output(
                value - MINIMUM_FEE,
                &recipient.default_subaddress(),
                &mut rng,
            )
            .unwrap();

        let tx = transaction_builder.build(&mut rng).unwrap();

        // The transaction should have a single input.
        assert_eq!(tx.prefix.inputs.len(), 1);

        assert_eq!(tx.prefix.inputs[0].proofs.len(), membership_proofs.len());

        let expected_key_images = vec![key_image];
        assert_eq!(tx.key_images(), expected_key_images);

        // The transaction should have one output.
        assert_eq!(tx.prefix.outputs.len(), 1);

        let output: &TxOut = tx.prefix.outputs.get(0).unwrap();

        // The output should belong to the correct recipient.
        {
            assert!(view_key_matches_output(
                &recipient.view_key(),
                &RistrettoPublic::try_from(&output.target_key).unwrap(),
                &RistrettoPublic::try_from(&output.public_key).unwrap()
            ));
        }

        // The output should have the correct value and confirmation number
        {
            let public_key = RistrettoPublic::try_from(&output.public_key).unwrap();
            assert!(confirmation.validate(&public_key, &recipient.view_private_key()));
        }

        // The output's fog hint should contain the correct public key.
        {
            let mut output_fog_hint = FogHint::new(RistrettoPublic::from_random(&mut rng));
            assert!(bool::from(FogHint::ct_decrypt(
                &ingest_private_key,
                &output.e_fog_hint,
                &mut output_fog_hint
            )));
            assert_eq!(
                output_fog_hint.get_view_pubkey(),
                &CompressedRistrettoPublic::from(recipient.default_subaddress().view_public_key())
            );
        }

        // The transaction should have a valid signature.
        assert!(validate_signature(&tx, &mut rng).is_ok());
    }

    #[test]
    // Use a custom PublicAddress to create the fog hint.
    fn test_custom_fog_hint_address() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let sender = AccountKey::random(&mut rng);
        let recipient = AccountKey::random(&mut rng);
        let fog_hint_address = AccountKey::random_with_fog(&mut rng).default_subaddress();
        let ingest_private_key = RistrettoPrivate::from_random(&mut rng);
        let value = 1475 * MILLIMOB_TO_PICOMOB;

        let fog_resolver = MockFogResolver(btreemap! {
                            fog_hint_address
                    .fog_report_url()
                    .unwrap()
                    .to_string()
            =>
                FullyValidatedFogPubkey {
                    pubkey: RistrettoPublic::from(&ingest_private_key),
                    pubkey_expiry: 1000,
                },
        });

        let mut transaction_builder = TransactionBuilder::new(fog_resolver);

        let input_credentials = get_input_credentials(&sender, value, &mut rng);
        transaction_builder.add_input(input_credentials);

        let (_txout, _confirmation) = transaction_builder
            .add_output_with_fog_hint_address(
                value - MINIMUM_FEE,
                &recipient.default_subaddress(),
                &fog_hint_address,
                Default::default(),
                &mut rng,
            )
            .unwrap();

        let tx = transaction_builder.build(&mut rng).unwrap();

        // The transaction should have one output.
        assert_eq!(tx.prefix.outputs.len(), 1);

        let output: &TxOut = tx.prefix.outputs.get(0).unwrap();

        // The output should belong to the correct recipient.
        {
            assert!(view_key_matches_output(
                &recipient.view_key(),
                &RistrettoPublic::try_from(&output.target_key).unwrap(),
                &RistrettoPublic::try_from(&output.public_key).unwrap()
            ));
        }

        // The output's fog hint should contain the correct public key.
        {
            let mut output_fog_hint = FogHint::new(RistrettoPublic::from_random(&mut rng));
            assert!(bool::from(FogHint::ct_decrypt(
                &ingest_private_key,
                &output.e_fog_hint,
                &mut output_fog_hint
            )));
            assert_eq!(
                output_fog_hint.get_view_pubkey(),
                &CompressedRistrettoPublic::from(fog_hint_address.view_public_key())
            );
        }
    }

    #[test]
    #[ignore]
    // `build` should return an error if the inputs contain rings of different
    // sizes.
    fn test_inputs_with_different_ring_sizes() {
        unimplemented!()
    }

    #[test]
    // `build` should return an error if the sum of inputs does not equal the sum of
    // outputs and the fee.
    fn test_inputs_do_not_equal_outputs() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let alice = AccountKey::random(&mut rng);
        let bob = AccountKey::random(&mut rng);
        let value = 1475;

        // Mint an initial collection of outputs, including one belonging to Alice.
        let (ring, real_index) = get_ring(3, &alice, value, &mut rng);
        let real_output = ring[real_index].clone();

        let onetime_private_key = recover_onetime_private_key(
            &RistrettoPublic::try_from(&real_output.public_key).unwrap(),
            &alice.view_private_key(),
            &alice.subaddress_spend_private(DEFAULT_SUBADDRESS_INDEX),
        );

        let membership_proofs: Vec<TxOutMembershipProof> = ring
            .iter()
            .map(|_tx_out| {
                // TransactionBuilder does not validate membership proofs, but does require one
                // for each ring member.
                TxOutMembershipProof::default()
            })
            .collect();

        let input_credentials = InputCredentials::new(
            ring,
            membership_proofs,
            real_index,
            onetime_private_key,
            *alice.view_private_key(),
        )
        .unwrap();

        let mut transaction_builder = TransactionBuilder::new(MockFogResolver::default());
        transaction_builder.add_input(input_credentials);

        let wrong_value = 999;
        transaction_builder
            .add_output(wrong_value, &bob.default_subaddress(), &mut rng)
            .unwrap();

        let result = transaction_builder.build(&mut rng);
        // Signing should fail if value is not conserved.
        match result {
            Err(TxBuilderError::RingSignatureFailed) => {} // Expected.
            _ => panic!("Unexpected result {:?}", result),
        }
    }

    #[test]
    // `build` should succeed with MAX_INPUTS and MAX_OUTPUTS.
    fn test_max_transaction_size() {
        let mut rng: StdRng = SeedableRng::from_seed([18u8; 32]);
        let sender = AccountKey::random(&mut rng);
        let recipient = AccountKey::random(&mut rng);
        let tx = get_transaction(
            MAX_INPUTS as usize,
            MAX_OUTPUTS as usize,
            &sender,
            &recipient,
            &mut rng,
        )
        .unwrap();
        assert_eq!(tx.prefix.inputs.len(), MAX_INPUTS as usize);
        assert_eq!(tx.prefix.outputs.len(), MAX_OUTPUTS as usize);
    }

    #[test]
    // Ring elements should be sorted by tx_out.public_key
    fn test_ring_elements_are_sorted() {
        let mut rng: StdRng = SeedableRng::from_seed([97u8; 32]);
        let sender = AccountKey::random(&mut rng);
        let recipient = AccountKey::random(&mut rng);
        let num_inputs = 3;
        let num_outputs = 11;
        let tx = get_transaction(num_inputs, num_outputs, &sender, &recipient, &mut rng).unwrap();

        for tx_in in &tx.prefix.inputs {
            assert!(tx_in
                .ring
                .windows(2)
                .all(|w| w[0].public_key < w[1].public_key));
        }
    }

    #[test]
    // Transaction outputs should be sorted by public key.
    fn test_outputs_are_sorted() {
        let mut rng: StdRng = SeedableRng::from_seed([92u8; 32]);
        let sender = AccountKey::random(&mut rng);
        let recipient = AccountKey::random(&mut rng);
        let num_inputs = 3;
        let num_outputs = 11;
        let tx = get_transaction(num_inputs, num_outputs, &sender, &recipient, &mut rng).unwrap();

        let outputs = tx.prefix.outputs;
        let mut expected_outputs = outputs.clone();
        expected_outputs.sort_by(|a, b| a.public_key.cmp(&b.public_key));
        assert_eq!(outputs, expected_outputs);
    }

    #[test]
    // Transaction inputs should be sorted by the public key of the first ring
    // element.
    fn test_inputs_are_sorted() {
        let mut rng: StdRng = SeedableRng::from_seed([92u8; 32]);
        let sender = AccountKey::random(&mut rng);
        let recipient = AccountKey::random(&mut rng);
        let num_inputs = 3;
        let num_outputs = 11;
        let tx = get_transaction(num_inputs, num_outputs, &sender, &recipient, &mut rng).unwrap();

        let inputs = tx.prefix.inputs;
        let mut expected_inputs = inputs.clone();
        expected_inputs.sort_by(|a, b| a.ring[0].public_key.cmp(&b.ring[0].public_key));
        assert_eq!(inputs, expected_inputs);
    }
}
