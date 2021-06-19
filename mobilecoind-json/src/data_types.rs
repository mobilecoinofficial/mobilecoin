// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Serializeable data types that wrap the mobilecoind API.

use mc_api::external::{
    Amount, CompressedRistretto, EncryptedFogHint, KeyImage, PublicAddress, RingMLSAG,
    SignatureRctBulletproofs, Tx, TxIn, TxOutMembershipElement, TxOutMembershipHash,
    TxOutMembershipProof, TxPrefix,
};
use protobuf::RepeatedField;
use serde_derive::{Deserialize, Serialize};
use std::convert::TryFrom;

#[derive(Deserialize, Default, Debug)]
pub struct JsonPasswordRequest {
    pub password: String,
}

#[derive(Serialize, Default, Debug)]
pub struct JsonPasswordResponse {
    pub success: bool,
}

#[derive(Deserialize, Default, Debug)]
pub struct JsonUnlockDbRequest {
    pub password: String,
}

#[derive(Serialize, Default, Debug)]
pub struct JsonUnlockDbResponse {
    pub success: bool,
}

#[derive(Serialize, Default, Debug)]
pub struct JsonRootEntropyResponse {
    pub entropy: String,
}

impl From<&mc_mobilecoind_api::GenerateRootEntropyResponse> for JsonRootEntropyResponse {
    fn from(src: &mc_mobilecoind_api::GenerateRootEntropyResponse) -> Self {
        Self {
            entropy: hex::encode(&src.root_entropy),
        }
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonMnemonicResponse {
    pub mnemonic: String,
}

impl From<&mc_mobilecoind_api::GenerateMnemonicResponse> for JsonMnemonicResponse {
    fn from(src: &mc_mobilecoind_api::GenerateMnemonicResponse) -> Self {
        Self {
            mnemonic: src.mnemonic.clone(),
        }
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonAccountKeyResponse {
    pub view_private_key: String,
    pub spend_private_key: String,
}

impl From<&mc_mobilecoind_api::GetAccountKeyResponse> for JsonAccountKeyResponse {
    fn from(src: &mc_mobilecoind_api::GetAccountKeyResponse) -> Self {
        Self {
            view_private_key: hex::encode(&src.get_account_key().get_view_private_key().get_data()),
            spend_private_key: hex::encode(
                &src.get_account_key().get_spend_private_key().get_data(),
            ),
        }
    }
}

#[derive(Deserialize, Default, Debug)]
pub struct JsonMonitorRequest {
    pub account_key: JsonAccountKeyResponse,
    pub first_subaddress: u64,
    pub num_subaddresses: u64,
}

#[derive(Serialize, Default, Debug)]
pub struct JsonMonitorResponse {
    pub monitor_id: String,
    pub is_new: bool,
}

impl From<&mc_mobilecoind_api::AddMonitorResponse> for JsonMonitorResponse {
    fn from(src: &mc_mobilecoind_api::AddMonitorResponse) -> Self {
        Self {
            monitor_id: hex::encode(&src.monitor_id),
            is_new: src.is_new,
        }
    }
}

#[derive(Serialize, Default, Debug)]
pub struct JsonMonitorListResponse {
    pub monitor_ids: Vec<String>,
}

impl From<&mc_mobilecoind_api::GetMonitorListResponse> for JsonMonitorListResponse {
    fn from(src: &mc_mobilecoind_api::GetMonitorListResponse) -> Self {
        Self {
            monitor_ids: src.get_monitor_id_list().iter().map(hex::encode).collect(),
        }
    }
}

#[derive(Serialize, Default, Debug)]
pub struct JsonMonitorStatusResponse {
    pub first_subaddress: u64,
    pub num_subaddresses: u64,
    pub first_block: u64,
    pub next_block: u64,
}

impl From<&mc_mobilecoind_api::GetMonitorStatusResponse> for JsonMonitorStatusResponse {
    fn from(src: &mc_mobilecoind_api::GetMonitorStatusResponse) -> Self {
        let status = src.get_status();

        Self {
            first_subaddress: status.get_first_subaddress(),
            num_subaddresses: status.get_num_subaddresses(),
            first_block: status.get_first_block(),
            next_block: status.get_next_block(),
        }
    }
}

#[derive(Serialize, Default, Debug)]
pub struct JsonBalanceResponse {
    pub balance: String,
}

impl From<&mc_mobilecoind_api::GetBalanceResponse> for JsonBalanceResponse {
    fn from(src: &mc_mobilecoind_api::GetBalanceResponse) -> Self {
        Self {
            balance: src.balance.to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct JsonUnspentTxOut {
    pub tx_out: JsonTxOut,
    pub subaddress_index: u64,
    pub key_image: String,
    pub value: String, // Needs to be String since Javascript ints are not 64 bit.
    pub attempted_spend_height: u64,
    pub attempted_spend_tombstone: u64,
    pub monitor_id: String,
}

impl From<&mc_mobilecoind_api::UnspentTxOut> for JsonUnspentTxOut {
    fn from(src: &mc_mobilecoind_api::UnspentTxOut) -> Self {
        Self {
            tx_out: src.get_tx_out().into(),
            subaddress_index: src.get_subaddress_index(),
            key_image: hex::encode(&src.get_key_image().get_data()),
            value: src.value.to_string(),
            attempted_spend_height: src.get_attempted_spend_height(),
            attempted_spend_tombstone: src.get_attempted_spend_tombstone(),
            monitor_id: hex::encode(&src.get_monitor_id()),
        }
    }
}

// Helper conversion between json and protobuf
impl TryFrom<&JsonUnspentTxOut> for mc_mobilecoind_api::UnspentTxOut {
    type Error = String;

    fn try_from(src: &JsonUnspentTxOut) -> Result<mc_mobilecoind_api::UnspentTxOut, String> {
        let mut key_image = KeyImage::new();
        key_image.set_data(
            hex::decode(&src.key_image)
                .map_err(|err| format!("Failed to decode key image hex: {}", err))?,
        );

        // Reconstruct the public address as a protobuf
        let mut utxo = mc_mobilecoind_api::UnspentTxOut::new();
        utxo.set_tx_out(
            mc_api::external::TxOut::try_from(&src.tx_out)
                .map_err(|err| format!("Failed to get TxOut: {}", err))?,
        );
        utxo.set_subaddress_index(src.subaddress_index);
        utxo.set_key_image(key_image);
        utxo.set_value(
            src.value
                .parse::<u64>()
                .map_err(|err| format!("Failed to parse u64 from value: {}", err))?,
        );
        utxo.set_attempted_spend_height(src.attempted_spend_height);
        utxo.set_attempted_spend_tombstone(src.attempted_spend_tombstone);
        utxo.set_monitor_id(
            hex::decode(&src.monitor_id)
                .map_err(|err| format!("Failed to decode monitor id hex: {}", err))?,
        );

        Ok(utxo)
    }
}

#[derive(Serialize, Default, Debug)]
pub struct JsonUtxosResponse {
    pub output_list: Vec<JsonUnspentTxOut>,
}

impl From<&mc_mobilecoind_api::GetUnspentTxOutListResponse> for JsonUtxosResponse {
    fn from(src: &mc_mobilecoind_api::GetUnspentTxOutListResponse) -> Self {
        Self {
            output_list: src
                .get_output_list()
                .iter()
                .map(JsonUnspentTxOut::from)
                .collect(),
        }
    }
}

#[derive(Deserialize, Default, Debug)]
pub struct JsonCreateRequestCodeRequest {
    pub receiver: JsonPublicAddress,
    pub value: Option<String>,
    pub memo: Option<String>,
}

#[derive(Serialize, Default, Debug)]
pub struct JsonCreateRequestCodeResponse {
    pub b58_request_code: String,
}

impl From<&mc_mobilecoind_api::CreateRequestCodeResponse> for JsonCreateRequestCodeResponse {
    fn from(src: &mc_mobilecoind_api::CreateRequestCodeResponse) -> Self {
        Self {
            b58_request_code: String::from(src.get_b58_code()),
        }
    }
}

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct JsonPublicAddress {
    /// Hex encoded compressed ristretto bytes
    pub view_public_key: String,

    /// Hex encoded compressed ristretto bytes
    pub spend_public_key: String,

    /// Fog Report Server Url
    pub fog_report_url: String,

    /// Hex encoded signature bytes
    pub fog_authority_sig: String,

    /// String label for fog reports
    pub fog_report_id: String,
}

impl From<&PublicAddress> for JsonPublicAddress {
    fn from(src: &PublicAddress) -> Self {
        Self {
            view_public_key: hex::encode(&src.get_view_public_key().get_data()),
            spend_public_key: hex::encode(&src.get_spend_public_key().get_data()),
            fog_report_url: String::from(src.get_fog_report_url()),
            fog_report_id: String::from(src.get_fog_report_id()),
            fog_authority_sig: hex::encode(&src.get_fog_authority_sig()),
        }
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonPublicAddressResponse {
    /// Hex encoded compressed ristretto bytes
    pub view_public_key: String,

    /// Hex encoded compressed ristretto bytes
    pub spend_public_key: String,

    /// Fog Report Server Url
    pub fog_report_url: String,

    /// Hex encoded signature bytes
    pub fog_authority_sig: String,

    /// String label for fog reports
    pub fog_report_id: String,

    /// b58-encoded public address
    pub b58_address_code: String,
}

impl From<&mc_mobilecoind_api::GetPublicAddressResponse> for JsonPublicAddressResponse {
    fn from(src: &mc_mobilecoind_api::GetPublicAddressResponse) -> Self {
        let public_address = src.get_public_address();
        Self {
            view_public_key: hex::encode(&public_address.get_view_public_key().get_data()),
            spend_public_key: hex::encode(&public_address.get_spend_public_key().get_data()),
            fog_report_url: String::from(public_address.get_fog_report_url()),
            fog_report_id: String::from(public_address.get_fog_report_id()),
            fog_authority_sig: hex::encode(&public_address.get_fog_authority_sig()),
            b58_address_code: src.get_b58_code().to_string(),
        }
    }
}

// Helper conversion between json and protobuf
impl TryFrom<&JsonPublicAddress> for PublicAddress {
    type Error = String;

    fn try_from(src: &JsonPublicAddress) -> Result<PublicAddress, String> {
        // Decode the keys
        let mut view_public_key = CompressedRistretto::new();
        view_public_key.set_data(
            hex::decode(&src.view_public_key)
                .map_err(|err| format!("Failed to decode view key hex: {}", err))?,
        );
        let mut spend_public_key = CompressedRistretto::new();
        spend_public_key.set_data(
            hex::decode(&src.spend_public_key)
                .map_err(|err| format!("Failed to decode spend key hex: {}", err))?,
        );

        // Reconstruct the public address as a protobuf
        let mut public_address = PublicAddress::new();
        public_address.set_view_public_key(view_public_key);
        public_address.set_spend_public_key(spend_public_key);
        public_address.set_fog_report_url(src.fog_report_url.clone());
        public_address.set_fog_report_id(src.fog_report_id.clone());
        public_address.set_fog_authority_sig(
            hex::decode(&src.fog_authority_sig)
                .map_err(|err| format!("Failed to decode fog authority sig hex: {}", err))?,
        );

        Ok(public_address)
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonParseRequestCodeResponse {
    pub receiver: JsonPublicAddress,
    pub value: String,
    pub memo: String,
}

impl From<&mc_mobilecoind_api::ParseRequestCodeResponse> for JsonParseRequestCodeResponse {
    fn from(src: &mc_mobilecoind_api::ParseRequestCodeResponse) -> Self {
        Self {
            receiver: JsonPublicAddress::from(src.get_receiver()),
            value: src.get_value().to_string(),
            memo: src.get_memo().to_string(),
        }
    }
}

#[derive(Deserialize, Default, Debug)]
pub struct JsonCreateAddressCodeRequest {
    pub receiver: JsonPublicAddress,
}

#[derive(Serialize, Default, Debug)]
pub struct JsonCreateAddressCodeResponse {
    pub b58_code: String,
}

impl From<&mc_mobilecoind_api::CreateAddressCodeResponse> for JsonCreateAddressCodeResponse {
    fn from(src: &mc_mobilecoind_api::CreateAddressCodeResponse) -> Self {
        Self {
            b58_code: String::from(src.get_b58_code()),
        }
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonParseAddressCodeResponse {
    pub receiver: JsonPublicAddress,
}

impl From<&mc_mobilecoind_api::ParseAddressCodeResponse> for JsonParseAddressCodeResponse {
    fn from(src: &mc_mobilecoind_api::ParseAddressCodeResponse) -> Self {
        Self {
            receiver: JsonPublicAddress::from(src.get_receiver()),
        }
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonSenderTxReceipt {
    pub key_images: Vec<String>,
    pub tombstone: u64,
}

impl From<&mc_mobilecoind_api::SenderTxReceipt> for JsonSenderTxReceipt {
    fn from(src: &mc_mobilecoind_api::SenderTxReceipt) -> Self {
        Self {
            key_images: src
                .get_key_image_list()
                .iter()
                .map(|key_image| hex::encode(key_image.get_data()))
                .collect(),
            tombstone: src.get_tombstone(),
        }
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonReceiverTxReceipt {
    pub recipient: JsonPublicAddress,
    pub tx_public_key: String,
    pub tx_out_hash: String,
    pub tombstone: u64,
    pub confirmation_number: String,
}

impl From<&mc_mobilecoind_api::ReceiverTxReceipt> for JsonReceiverTxReceipt {
    fn from(src: &mc_mobilecoind_api::ReceiverTxReceipt) -> Self {
        Self {
            recipient: JsonPublicAddress::from(src.get_recipient()),
            tx_public_key: hex::encode(&src.get_tx_public_key().get_data()),
            tx_out_hash: hex::encode(&src.get_tx_out_hash()),
            tombstone: src.get_tombstone(),
            confirmation_number: hex::encode(&src.get_tx_out_hash()),
        }
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonSendPaymentRequest {
    pub request_data: JsonParseRequestCodeResponse,
    pub max_input_utxo_value: Option<String>, // String due to u64 limitation.
    pub change_subaddress: Option<String>,
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonSendPaymentResponse {
    pub sender_tx_receipt: JsonSenderTxReceipt,
    pub receiver_tx_receipt_list: Vec<JsonReceiverTxReceipt>,
}

impl From<&mc_mobilecoind_api::SendPaymentResponse> for JsonSendPaymentResponse {
    fn from(src: &mc_mobilecoind_api::SendPaymentResponse) -> Self {
        Self {
            sender_tx_receipt: JsonSenderTxReceipt::from(src.get_sender_tx_receipt()),
            receiver_tx_receipt_list: src
                .get_receiver_tx_receipt_list()
                .iter()
                .map(JsonReceiverTxReceipt::from)
                .collect(),
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct JsonPayAddressCodeRequest {
    pub receiver_b58_address_code: String,
    pub value: String,
    pub max_input_utxo_value: Option<String>,
    pub change_subaddress: Option<String>,
}

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct JsonOutlay {
    pub value: String,
    pub receiver: JsonPublicAddress,
}

impl From<&mc_mobilecoind_api::Outlay> for JsonOutlay {
    fn from(src: &mc_mobilecoind_api::Outlay) -> Self {
        Self {
            value: src.get_value().to_string(),
            receiver: src.get_receiver().into(),
        }
    }
}

impl TryFrom<&JsonOutlay> for mc_mobilecoind_api::Outlay {
    type Error = String;

    fn try_from(src: &JsonOutlay) -> Result<mc_mobilecoind_api::Outlay, String> {
        let mut outlay = mc_mobilecoind_api::Outlay::new();
        outlay.set_value(
            src.value
                .parse::<u64>()
                .map_err(|err| format!("Failed to parse u64 from value: {}", err))?,
        );
        outlay.set_receiver(
            PublicAddress::try_from(&src.receiver)
                .map_err(|err| format!("Could not convert receiver: {}", err))?,
        );

        Ok(outlay)
    }
}

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct JsonAmount {
    pub commitment: String,
    pub masked_value: String,
}

impl From<&Amount> for JsonAmount {
    fn from(src: &Amount) -> Self {
        Self {
            commitment: hex::encode(src.get_commitment().get_data()),
            masked_value: src.get_masked_value().to_string(),
        }
    }
}

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct JsonTxOut {
    pub amount: JsonAmount,
    pub target_key: String,
    pub public_key: String,
    pub e_fog_hint: String,
    pub e_memo: String,
}

impl From<&mc_api::external::TxOut> for JsonTxOut {
    fn from(src: &mc_api::external::TxOut) -> Self {
        Self {
            amount: src.get_amount().into(),
            target_key: hex::encode(src.get_target_key().get_data()),
            public_key: hex::encode(src.get_public_key().get_data()),
            e_fog_hint: hex::encode(src.get_e_fog_hint().get_data()),
            e_memo: hex::encode(src.get_e_memo()),
        }
    }
}

// Helper conversion between json and protobuf
impl TryFrom<&JsonTxOut> for mc_api::external::TxOut {
    type Error = String;

    fn try_from(src: &JsonTxOut) -> Result<mc_api::external::TxOut, String> {
        let mut commitment = CompressedRistretto::new();
        commitment.set_data(
            hex::decode(&src.amount.commitment)
                .map_err(|err| format!("Failed to decode commitment hex: {}", err))?,
        );
        let mut amount = Amount::new();
        amount.set_commitment(commitment);
        amount.set_masked_value(
            src.amount
                .masked_value
                .parse::<u64>()
                .map_err(|err| format!("Failed to parse u64 from value: {}", err))?,
        );
        let mut target_key = CompressedRistretto::new();
        target_key.set_data(
            hex::decode(&src.target_key)
                .map_err(|err| format!("Failed to decode target key hex: {}", err))?,
        );
        let mut public_key = CompressedRistretto::new();
        public_key.set_data(
            hex::decode(&src.public_key)
                .map_err(|err| format!("Failed to decode public key hex: {}", err))?,
        );
        let mut e_fog_hint = EncryptedFogHint::new();
        e_fog_hint.set_data(
            hex::decode(&src.e_fog_hint)
                .map_err(|err| format!("Failed to decode e_fog_hint hex: {}", err))?,
        );
        let e_memo = hex::decode(&src.e_memo)
            .map_err(|err| format!("Failed to decode e_memo hex: {}", err))?;

        let mut txo = mc_api::external::TxOut::new();
        txo.set_amount(amount);
        txo.set_target_key(target_key);
        txo.set_public_key(public_key);
        txo.set_e_fog_hint(e_fog_hint);
        txo.set_e_memo(e_memo);

        Ok(txo)
    }
}

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct JsonRange {
    pub from: String,
    pub to: String,
}

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct JsonTxOutMembershipElement {
    pub range: JsonRange,
    pub hash: String,
}

impl From<&TxOutMembershipElement> for JsonTxOutMembershipElement {
    fn from(src: &TxOutMembershipElement) -> Self {
        Self {
            range: JsonRange {
                from: src.get_range().get_from().to_string(),
                to: src.get_range().get_to().to_string(),
            },
            hash: hex::encode(src.get_hash().get_data()),
        }
    }
}

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct JsonTxOutMembershipProof {
    pub index: String,
    pub highest_index: String,
    pub elements: Vec<JsonTxOutMembershipElement>,
}

impl From<&TxOutMembershipProof> for JsonTxOutMembershipProof {
    fn from(src: &TxOutMembershipProof) -> Self {
        Self {
            index: src.get_index().to_string(),
            highest_index: src.get_highest_index().to_string(),
            elements: src
                .get_elements()
                .iter()
                .map(JsonTxOutMembershipElement::from)
                .collect(),
        }
    }
}

impl TryFrom<&JsonTxOutMembershipProof> for TxOutMembershipProof {
    type Error = String;

    fn try_from(src: &JsonTxOutMembershipProof) -> Result<TxOutMembershipProof, String> {
        let mut elements: Vec<TxOutMembershipElement> = Vec::new();
        for element in &src.elements {
            let mut range = mc_api::external::Range::new();
            range.set_from(
                element
                    .range
                    .from
                    .parse::<u64>()
                    .map_err(|err| format!("Failed to parse u64 from range.from: {}", err))?,
            );
            range.set_to(
                element
                    .range
                    .to
                    .parse::<u64>()
                    .map_err(|err| format!("Failed to parse u64 from range.to: {}", err))?,
            );

            let mut hash = TxOutMembershipHash::new();
            hash.set_data(
                hex::decode(&element.hash)
                    .map_err(|err| format!("Could not decode elem hash: {}", err))?,
            );

            let mut elem = TxOutMembershipElement::new();
            elem.set_range(range);
            elem.set_hash(hash);
            elements.push(elem);
        }

        let mut proof = TxOutMembershipProof::new();
        proof.set_index(
            src.index
                .parse::<u64>()
                .map_err(|err| format!("Failed to parse u64 from index: {}", err))?,
        );
        proof.set_highest_index(
            src.highest_index
                .parse::<u64>()
                .map_err(|err| format!("Failed to parse u64 from highest_index: {}", err))?,
        );
        proof.set_elements(RepeatedField::from_vec(elements));

        Ok(proof)
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
/// A request for randomly sampled TxOuts for use as mixins.
pub struct JsonMixinRequest {
    /// Number of mixins requested.
    pub num_mixins: u64,
    /// Outputs that should be excluded from the result.
    pub excluded: Vec<JsonTxOut>,
}

#[derive(Deserialize, Serialize, Default, Debug)]
/// Randomly sampled TxOuts for use as mixins, with membership proofs.
pub struct JsonMixinResponse {
    /// TxOuts to use as mixins.
    pub mixins: Vec<JsonTxOut>,
    /// Corresponding membership proofs.
    pub membership_proofs: Vec<JsonTxOutMembershipProof>,
}

#[derive(Deserialize, Serialize, Default, Debug)]
/// Requests Merkle proof-of-membership for each queried TxOut
pub struct JsonMembershipProofRequest {
    pub outputs: Vec<JsonTxOut>,
}

#[derive(Deserialize, Serialize, Default, Debug)]
/// Outputs and their corresponding proofs of membership.
pub struct JsonMembershipProofResponse {
    /// Queried outputs.
    pub outputs: Vec<JsonTxOut>,
    /// Corresponding membership proofs.
    pub membership_proofs: Vec<JsonTxOutMembershipProof>,
}

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct JsonTxIn {
    pub ring: Vec<JsonTxOut>,
    pub proofs: Vec<JsonTxOutMembershipProof>,
}

impl From<&TxIn> for JsonTxIn {
    fn from(src: &TxIn) -> Self {
        Self {
            ring: src.get_ring().iter().map(JsonTxOut::from).collect(),
            proofs: src
                .get_proofs()
                .iter()
                .map(JsonTxOutMembershipProof::from)
                .collect(),
        }
    }
}

impl TryFrom<&JsonTxIn> for TxIn {
    type Error = String;

    fn try_from(src: &JsonTxIn) -> Result<TxIn, String> {
        let mut outputs: Vec<mc_api::external::TxOut> = Vec::new();
        for output in &src.ring {
            let p_output = mc_api::external::TxOut::try_from(output)
                .map_err(|err| format!("Could not get TxOut: {}", err))?;
            outputs.push(p_output);
        }

        let mut proofs: Vec<TxOutMembershipProof> = Vec::new();
        for proof in &src.proofs {
            let p_proof = TxOutMembershipProof::try_from(proof)
                .map_err(|err| format!("Could not get proof: {}", err))?;
            proofs.push(p_proof);
        }

        let mut txin = TxIn::new();
        txin.set_ring(RepeatedField::from_vec(outputs));
        txin.set_proofs(RepeatedField::from_vec(proofs));

        Ok(txin)
    }
}

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct JsonTxPrefix {
    pub inputs: Vec<JsonTxIn>,
    pub outputs: Vec<JsonTxOut>,
    pub fee: String,
    tombstone_block: String,
}

impl From<&TxPrefix> for JsonTxPrefix {
    fn from(src: &TxPrefix) -> Self {
        Self {
            inputs: src.get_inputs().iter().map(JsonTxIn::from).collect(),
            outputs: src.get_outputs().iter().map(JsonTxOut::from).collect(),
            fee: src.get_fee().to_string(),
            tombstone_block: src.get_tombstone_block().to_string(),
        }
    }
}

impl TryFrom<&JsonTxPrefix> for TxPrefix {
    type Error = String;

    fn try_from(src: &JsonTxPrefix) -> Result<TxPrefix, String> {
        let mut inputs: Vec<TxIn> = Vec::new();
        for input in &src.inputs {
            let p_input =
                TxIn::try_from(input).map_err(|err| format!("Could not get TxIn: {}", err))?;
            inputs.push(p_input);
        }

        let mut outputs: Vec<mc_api::external::TxOut> = Vec::new();
        for output in &src.outputs {
            let p_output = mc_api::external::TxOut::try_from(output)
                .map_err(|err| format!("Could not get TxOut: {}", err))?;
            outputs.push(p_output);
        }

        let mut prefix = TxPrefix::new();
        prefix.set_inputs(RepeatedField::from_vec(inputs));
        prefix.set_outputs(RepeatedField::from_vec(outputs));
        prefix.set_fee(
            src.fee
                .parse::<u64>()
                .map_err(|err| format!("Failed to parse u64 from fee: {}", err))?,
        );
        prefix.set_tombstone_block(
            src.tombstone_block
                .parse::<u64>()
                .map_err(|err| format!("Failed to parse u64 from tombstone_block: {}", err))?,
        );

        Ok(prefix)
    }
}

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct JsonRingMLSAG {
    pub c_zero: String,
    pub responses: Vec<String>,
    pub key_image: String,
}

impl From<&RingMLSAG> for JsonRingMLSAG {
    fn from(src: &RingMLSAG) -> Self {
        Self {
            c_zero: hex::encode(src.get_c_zero().get_data()),
            responses: src
                .get_responses()
                .iter()
                .map(|x| hex::encode(x.get_data()))
                .collect(),
            key_image: hex::encode(src.get_key_image().get_data()),
        }
    }
}

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct JsonSignatureRctBulletproofs {
    pub ring_signatures: Vec<JsonRingMLSAG>,
    pub pseudo_output_commitments: Vec<String>,
    range_proofs: String,
}

impl From<&SignatureRctBulletproofs> for JsonSignatureRctBulletproofs {
    fn from(src: &SignatureRctBulletproofs) -> Self {
        Self {
            ring_signatures: src
                .get_ring_signatures()
                .iter()
                .map(JsonRingMLSAG::from)
                .collect(),
            pseudo_output_commitments: src
                .get_pseudo_output_commitments()
                .iter()
                .map(|x| hex::encode(x.get_data()))
                .collect(),
            range_proofs: hex::encode(src.get_range_proofs().to_vec()),
        }
    }
}

impl TryFrom<&JsonSignatureRctBulletproofs> for SignatureRctBulletproofs {
    type Error = String;

    fn try_from(src: &JsonSignatureRctBulletproofs) -> Result<SignatureRctBulletproofs, String> {
        let mut ring_sigs: Vec<RingMLSAG> = Vec::new();
        for sig in &src.ring_signatures {
            let mut c_zero = mc_api::external::CurveScalar::new();
            c_zero.set_data(
                hex::decode(&sig.c_zero)
                    .map_err(|err| format!("Could not decode from hex: {}", err))?,
            );

            let mut responses: Vec<mc_api::external::CurveScalar> = Vec::new();
            for resp in &sig.responses {
                let mut response = mc_api::external::CurveScalar::new();
                response.set_data(
                    hex::decode(resp)
                        .map_err(|err| format!("Could not decode from hex: {}", err))?,
                );
                responses.push(response);
            }

            let mut key_image = KeyImage::new();
            key_image.set_data(
                hex::decode(&sig.key_image)
                    .map_err(|err| format!("Could not decode from hex: {}", err))?,
            );

            let mut ring_sig = RingMLSAG::new();
            ring_sig.set_c_zero(c_zero);
            ring_sig.set_responses(RepeatedField::from_vec(responses));
            ring_sig.set_key_image(key_image);

            ring_sigs.push(ring_sig);
        }

        let mut commitments: Vec<CompressedRistretto> = Vec::new();
        for comm in &src.pseudo_output_commitments {
            let mut compressed = CompressedRistretto::new();
            compressed.set_data(
                hex::decode(&comm).map_err(|err| format!("Could not decode from hex: {}", err))?,
            );
            commitments.push(compressed);
        }

        let mut signature = SignatureRctBulletproofs::new();
        signature.set_ring_signatures(RepeatedField::from_vec(ring_sigs));
        signature.set_pseudo_output_commitments(RepeatedField::from_vec(commitments));
        let proofs_bytes = hex::decode(&src.range_proofs)
            .map_err(|err| format!("Could not decode from hex: {}", err))?;
        signature.set_range_proofs(proofs_bytes);

        Ok(signature)
    }
}

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct JsonTx {
    pub prefix: JsonTxPrefix,
    pub signature: JsonSignatureRctBulletproofs,
}

impl From<&Tx> for JsonTx {
    fn from(src: &Tx) -> Self {
        Self {
            prefix: src.get_prefix().into(),
            signature: src.get_signature().into(),
        }
    }
}

impl TryFrom<&JsonTx> for Tx {
    type Error = String;

    fn try_from(src: &JsonTx) -> Result<Tx, String> {
        let mut tx = Tx::new();

        tx.set_prefix(
            TxPrefix::try_from(&src.prefix)
                .map_err(|err| format!("Could not convert TxPrefix: {}", err))?,
        );
        tx.set_signature(
            SignatureRctBulletproofs::try_from(&src.signature)
                .map_err(|err| format!("Could not convert signature: {}", err))?,
        );

        Ok(tx)
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonTxProposal {
    pub input_list: Vec<JsonUnspentTxOut>,
    pub outlay_list: Vec<JsonOutlay>,
    pub tx: JsonTx,
    pub fee: u64,
    pub outlay_index_to_tx_out_index: Vec<(usize, usize)>,
    pub outlay_confirmation_numbers: Vec<Vec<u8>>,
}

impl From<&mc_mobilecoind_api::TxProposal> for JsonTxProposal {
    fn from(src: &mc_mobilecoind_api::TxProposal) -> Self {
        let outlay_map: Vec<(usize, usize)> = src
            .get_outlay_index_to_tx_out_index()
            .iter()
            .map(|(key, val)| (*key as usize, *val as usize))
            .collect();
        Self {
            input_list: src
                .get_input_list()
                .iter()
                .map(JsonUnspentTxOut::from)
                .collect(),
            outlay_list: src.get_outlay_list().iter().map(JsonOutlay::from).collect(),
            tx: src.get_tx().into(),
            fee: src.get_fee(),
            outlay_index_to_tx_out_index: outlay_map,
            outlay_confirmation_numbers: src.get_outlay_confirmation_numbers().to_vec(),
        }
    }
}

// Helper conversion between json and protobuf
impl TryFrom<&JsonTxProposal> for mc_mobilecoind_api::TxProposal {
    type Error = String;

    fn try_from(src: &JsonTxProposal) -> Result<mc_mobilecoind_api::TxProposal, String> {
        let mut inputs: Vec<mc_mobilecoind_api::UnspentTxOut> = Vec::new();
        for input in src.input_list.iter() {
            let utxo = mc_mobilecoind_api::UnspentTxOut::try_from(input)
                .map_err(|err| format!("Failed to convert input: {}", err))?;
            inputs.push(utxo);
        }

        let mut outlays: Vec<mc_mobilecoind_api::Outlay> = Vec::new();
        for outlay in src.outlay_list.iter() {
            let out = mc_mobilecoind_api::Outlay::try_from(outlay)
                .map_err(|err| format!("Failed to convert outlay: {}", err))?;
            outlays.push(out);
        }

        // Reconstruct the public address as a protobuf
        let mut proposal = mc_mobilecoind_api::TxProposal::new();
        proposal.set_input_list(RepeatedField::from_vec(inputs));
        proposal.set_outlay_list(RepeatedField::from_vec(outlays));
        proposal
            .set_tx(Tx::try_from(&src.tx).map_err(|err| format!("Could not convert tx: {}", err))?);
        proposal.set_fee(src.fee);
        proposal.set_outlay_index_to_tx_out_index(
            src.outlay_index_to_tx_out_index
                .iter()
                .map(|(key, val)| (*key as u64, *val as u64))
                .collect(),
        );
        proposal.set_outlay_confirmation_numbers(RepeatedField::from_vec(
            src.outlay_confirmation_numbers.clone(),
        ));

        Ok(proposal)
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonCreateTxProposalRequest {
    pub input_list: Vec<JsonUnspentTxOut>,
    pub transfer: JsonParseRequestCodeResponse,
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonCreateTxProposalResponse {
    pub tx_proposal: JsonTxProposal,
}

impl From<&mc_mobilecoind_api::GenerateTxResponse> for JsonCreateTxProposalResponse {
    fn from(src: &mc_mobilecoind_api::GenerateTxResponse) -> Self {
        Self {
            tx_proposal: src.get_tx_proposal().into(),
        }
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonTxProposalRequest {
    pub tx_proposal: JsonTxProposal,
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonSubmitTxResponse {
    pub sender_tx_receipt: JsonSenderTxReceipt,
    pub receiver_tx_receipt_list: Vec<JsonReceiverTxReceipt>,
}

impl From<&mc_mobilecoind_api::SubmitTxResponse> for JsonSubmitTxResponse {
    fn from(src: &mc_mobilecoind_api::SubmitTxResponse) -> Self {
        Self {
            sender_tx_receipt: src.get_sender_tx_receipt().into(),
            receiver_tx_receipt_list: src
                .get_receiver_tx_receipt_list()
                .iter()
                .map(JsonReceiverTxReceipt::from)
                .collect(),
        }
    }
}

impl TryFrom<&JsonSubmitTxResponse> for mc_mobilecoind_api::SubmitTxResponse {
    type Error = String;

    fn try_from(src: &JsonSubmitTxResponse) -> Result<Self, String> {
        let mut sender_receipt = mc_mobilecoind_api::SenderTxReceipt::new();

        let key_images: Vec<KeyImage> = src
            .sender_tx_receipt
            .key_images
            .iter()
            .map(|k| {
                hex::decode(&k).map(KeyImage::from).map_err(|err| {
                    format!(
                        "Failed to decode hex for sender_tx_receipt.key_images: {}",
                        err
                    )
                })
            })
            .collect::<Result<Vec<KeyImage>, String>>()?;

        sender_receipt.set_key_image_list(RepeatedField::from_vec(key_images));
        sender_receipt.set_tombstone(src.sender_tx_receipt.tombstone);

        let mut receiver_receipts = Vec::new();
        for r in src.receiver_tx_receipt_list.iter() {
            let mut receiver_receipt = mc_mobilecoind_api::ReceiverTxReceipt::new();
            receiver_receipt.set_recipient(
                PublicAddress::try_from(&r.recipient)
                    .map_err(|err| format!("Failed to convert recipient: {}", err))?,
            );
            let mut pubkey = mc_api::external::CompressedRistretto::new();
            pubkey.set_data(
                hex::decode(&r.tx_public_key)
                    .map_err(|err| format!("Failed to decode hex for tx_public_key: {}", err))?,
            );
            receiver_receipt.set_tx_public_key(pubkey);
            receiver_receipt.set_tx_out_hash(
                hex::decode(&r.tx_out_hash)
                    .map_err(|err| format!("Failed to decode hex for tx_out_hash: {}", err))?,
            );
            receiver_receipt.set_tombstone(r.tombstone);
            receiver_receipt.set_confirmation_number(
                hex::decode(&r.confirmation_number).map_err(|err| {
                    format!("Failed to decode hex for confirmation_number: {}", err)
                })?,
            );
            receiver_receipts.push(receiver_receipt);
        }

        let mut resp = mc_mobilecoind_api::SubmitTxResponse::new();
        resp.set_sender_tx_receipt(sender_receipt);
        resp.set_receiver_tx_receipt_list(RepeatedField::from_vec(receiver_receipts));

        Ok(resp)
    }
}

#[derive(Serialize, Default, Debug)]
pub struct JsonStatusResponse {
    pub status: String,
}

impl From<&mc_mobilecoind_api::GetTxStatusAsSenderResponse> for JsonStatusResponse {
    fn from(src: &mc_mobilecoind_api::GetTxStatusAsSenderResponse) -> Self {
        let status_str = match src.get_status() {
            mc_mobilecoind_api::TxStatus::Unknown => "unknown",
            mc_mobilecoind_api::TxStatus::Verified => "verified",
            mc_mobilecoind_api::TxStatus::TombstoneBlockExceeded => "failed",
            mc_mobilecoind_api::TxStatus::InvalidConfirmationNumber => "invalid_confirmation",
            mc_mobilecoind_api::TxStatus::PublicKeysInDifferentBlocks => {
                "public_keys_in_different_blocks"
            }
            mc_mobilecoind_api::TxStatus::TransactionFailureKeyImageBlockMismatch => {
                "transaction_failure_key_image_block_mismatch"
            }
            mc_mobilecoind_api::TxStatus::TransactionFailureKeyImageAlreadySpent => {
                "transaction_failure_key_image_already_spent"
            }
        };

        Self {
            status: String::from(status_str),
        }
    }
}

impl From<&mc_mobilecoind_api::GetTxStatusAsReceiverResponse> for JsonStatusResponse {
    fn from(src: &mc_mobilecoind_api::GetTxStatusAsReceiverResponse) -> Self {
        let status_str = match src.get_status() {
            mc_mobilecoind_api::TxStatus::Unknown => "unknown",
            mc_mobilecoind_api::TxStatus::Verified => "verified",
            mc_mobilecoind_api::TxStatus::TombstoneBlockExceeded => "failed",
            mc_mobilecoind_api::TxStatus::InvalidConfirmationNumber => "invalid_confirmation",
            mc_mobilecoind_api::TxStatus::PublicKeysInDifferentBlocks => {
                "public_keys_in_different_blocks"
            }
            mc_mobilecoind_api::TxStatus::TransactionFailureKeyImageBlockMismatch => {
                "transaction_failure_key_image_block_mismatch"
            }
            mc_mobilecoind_api::TxStatus::TransactionFailureKeyImageAlreadySpent => {
                "transaction_failure_key_image_already_spent"
            }
        };

        Self {
            status: String::from(status_str),
        }
    }
}

#[derive(Serialize, Default, Debug)]
pub struct JsonLedgerInfoResponse {
    pub block_count: String,
    pub txo_count: String,
}

impl From<&mc_mobilecoind_api::GetLedgerInfoResponse> for JsonLedgerInfoResponse {
    fn from(src: &mc_mobilecoind_api::GetLedgerInfoResponse) -> Self {
        Self {
            block_count: src.block_count.to_string(),
            txo_count: src.txo_count.to_string(),
        }
    }
}

#[derive(Serialize, Default, Debug)]
pub struct JsonBlockInfoResponse {
    pub key_image_count: String,
    pub txo_count: String,
}

impl From<&mc_mobilecoind_api::GetBlockInfoResponse> for JsonBlockInfoResponse {
    fn from(src: &mc_mobilecoind_api::GetBlockInfoResponse) -> Self {
        Self {
            key_image_count: src.key_image_count.to_string(),
            txo_count: src.txo_count.to_string(),
        }
    }
}

#[derive(Serialize, Default, Debug)]
pub struct JsonBlockDetailsResponse {
    pub block_id: String,
    pub version: u32,
    pub parent_id: String,
    pub index: String,
    pub cumulative_txo_count: String,
    pub contents_hash: String,
    pub key_images: Vec<String>,
    pub txos: Vec<JsonTxOut>,
}

impl From<&mc_mobilecoind_api::GetBlockResponse> for JsonBlockDetailsResponse {
    fn from(src: &mc_mobilecoind_api::GetBlockResponse) -> Self {
        let block = src.get_block();

        Self {
            block_id: hex::encode(&block.get_id().get_data()),
            version: block.get_version(),
            parent_id: hex::encode(&block.get_parent_id().get_data()),
            index: block.get_index().to_string(),
            cumulative_txo_count: block.get_cumulative_txo_count().to_string(),
            contents_hash: hex::encode(&block.get_contents_hash().get_data()),
            key_images: src
                .get_key_images()
                .iter()
                .map(|k| hex::encode(k.get_data()))
                .collect(),
            txos: src.get_txos().iter().map(JsonTxOut::from).collect(),
        }
    }
}

#[derive(Serialize, Default, Debug)]
pub struct JsonProcessedTxOut {
    pub monitor_id: String,
    pub subaddress_index: u64,
    pub public_key: String,
    pub key_image: String,
    pub value: String, // Needs to be String since Javascript ints are not 64 bit.
    pub direction: String,
}

impl From<&mc_mobilecoind_api::ProcessedTxOut> for JsonProcessedTxOut {
    fn from(src: &mc_mobilecoind_api::ProcessedTxOut) -> Self {
        let direction_str = match src.direction {
            mc_mobilecoind_api::ProcessedTxOutDirection::Invalid => "invalid",
            mc_mobilecoind_api::ProcessedTxOutDirection::Received => "received",
            mc_mobilecoind_api::ProcessedTxOutDirection::Spent => "spent",
        };

        Self {
            monitor_id: hex::encode(&src.get_monitor_id()),
            subaddress_index: src.subaddress_index,
            public_key: hex::encode(&src.get_public_key().get_data()),
            key_image: hex::encode(&src.get_key_image().get_data()),
            value: src.value.to_string(),
            direction: direction_str.to_owned(),
        }
    }
}

#[derive(Serialize, Default, Debug)]
pub struct JsonProcessedBlockResponse {
    pub tx_outs: Vec<JsonProcessedTxOut>,
}

impl From<&mc_mobilecoind_api::GetProcessedBlockResponse> for JsonProcessedBlockResponse {
    fn from(src: &mc_mobilecoind_api::GetProcessedBlockResponse) -> Self {
        Self {
            tx_outs: src
                .get_tx_outs()
                .iter()
                .map(JsonProcessedTxOut::from)
                .collect(),
        }
    }
}

#[derive(Serialize, Default, Debug)]
pub struct JsonBlockIndexByTxPubKeyResponse {
    pub block_index: String,
}

impl From<&mc_mobilecoind_api::GetBlockIndexByTxPubKeyResponse>
    for JsonBlockIndexByTxPubKeyResponse
{
    fn from(src: &mc_mobilecoind_api::GetBlockIndexByTxPubKeyResponse) -> Self {
        Self {
            block_index: src.block.to_string(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_crypto_keys::RistrettoPublic;
    use mc_ledger_db::Ledger;
    use mc_transaction_core::{encrypted_fog_hint::ENCRYPTED_FOG_HINT_LEN, Amount};
    use mc_transaction_core_test_utils::{
        create_ledger, create_transaction, initialize_ledger, AccountKey,
    };
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};
    use std::{collections::HashMap, iter::FromIterator};

    /// Test conversion of TxProposal
    #[test]
    fn test_tx_proposal_conversion() {
        // First, go from rust -> proto
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let tx = {
            let mut ledger = create_ledger();
            let sender = AccountKey::random(&mut rng);
            let recipient = AccountKey::random(&mut rng);
            initialize_ledger(&mut ledger, 1, &sender, &mut rng);

            let block_contents = ledger.get_block_contents(0).unwrap();
            let tx_out = block_contents.outputs[0].clone();

            create_transaction(
                &mut ledger,
                &tx_out,
                &sender,
                &recipient.default_subaddress(),
                10,
                &mut rng,
            )
        };

        let utxo = {
            let tx_out = mc_transaction_core::tx::TxOut {
                amount: Amount::new(1u64 << 13, &RistrettoPublic::from_random(&mut rng)).unwrap(),
                target_key: RistrettoPublic::from_random(&mut rng).into(),
                public_key: RistrettoPublic::from_random(&mut rng).into(),
                e_fog_hint: (&[0u8; ENCRYPTED_FOG_HINT_LEN]).into(),
                e_memo: vec![0u8; 34],
            };

            let subaddress_index = 123;
            let key_image = mc_transaction_core::ring_signature::KeyImage::from(456);
            let value = 789;
            let attempted_spend_height = 1000;
            let attempted_spend_tombstone = 1234;

            // make proto UnspentTxOut
            let mut unspent = mc_mobilecoind_api::UnspentTxOut::new();
            unspent.set_tx_out(mc_api::external::TxOut::from(&tx_out));
            unspent.set_subaddress_index(subaddress_index);
            unspent.set_key_image(mc_api::external::KeyImage::from(&key_image));
            unspent.set_value(value);
            unspent.set_attempted_spend_height(attempted_spend_height);
            unspent.set_attempted_spend_tombstone(attempted_spend_tombstone);
            unspent
        };

        // Make proto outlay
        let mut outlay = mc_mobilecoind_api::Outlay::new();
        let public_addr = AccountKey::random(&mut rng).default_subaddress();
        outlay.set_receiver(mc_api::external::PublicAddress::from(&public_addr));
        outlay.set_value(1234);

        let outlay_index_to_tx_out_index = HashMap::from_iter(vec![(0, 0)]);
        let outlay_confirmation_numbers =
            vec![mc_transaction_core::tx::TxOutConfirmationNumber::from(
                [0u8; 32],
            )];

        // Make proto TxProposal
        let mut proto_proposal = mc_mobilecoind_api::TxProposal::new();
        proto_proposal.set_input_list(RepeatedField::from_vec(vec![utxo]));
        proto_proposal.set_outlay_list(RepeatedField::from_vec(vec![outlay]));
        proto_proposal.set_tx(mc_api::external::Tx::from(&tx));
        proto_proposal.set_outlay_index_to_tx_out_index(outlay_index_to_tx_out_index);
        proto_proposal.set_outlay_confirmation_numbers(RepeatedField::from_vec(
            outlay_confirmation_numbers
                .iter()
                .map(|x| x.to_vec())
                .collect(),
        ));

        // Proto -> Json
        let json_proposal = JsonTxProposal::from(&proto_proposal);

        // Json -> Proto
        let proto2 = mc_mobilecoind_api::TxProposal::try_from(&json_proposal).unwrap();

        // Assert each field, then the whole thing
        assert_eq!(proto_proposal.input_list, proto2.input_list);
        assert_eq!(proto_proposal.outlay_list, proto2.outlay_list);

        // The tx is complicated, so check each field of the tx
        assert_eq!(proto_proposal.get_tx().prefix, proto2.get_tx().prefix);
        assert_eq!(
            proto_proposal
                .get_tx()
                .get_signature()
                .get_ring_signatures()[0]
                .c_zero,
            proto2.get_tx().get_signature().get_ring_signatures()[0].c_zero
        );
        assert_eq!(
            proto_proposal
                .get_tx()
                .get_signature()
                .get_ring_signatures()[0]
                .responses,
            proto2.get_tx().get_signature().get_ring_signatures()[0].responses
        );
        assert_eq!(
            proto_proposal
                .get_tx()
                .get_signature()
                .get_ring_signatures()[0]
                .key_image,
            proto2.get_tx().get_signature().get_ring_signatures()[0].key_image
        );
        assert_eq!(
            proto_proposal.get_tx().get_signature().ring_signatures,
            proto2.get_tx().get_signature().ring_signatures
        );
        assert_eq!(
            proto_proposal
                .get_tx()
                .get_signature()
                .pseudo_output_commitments,
            proto2.get_tx().get_signature().pseudo_output_commitments
        );
        assert_eq!(
            proto_proposal.get_tx().get_signature().range_proofs,
            proto2.get_tx().get_signature().range_proofs
        );

        assert_eq!(proto_proposal.get_tx().signature, proto2.get_tx().signature);
        assert_eq!(proto_proposal.tx, proto2.tx);

        // Check the rest of the fields
        assert_eq!(proto_proposal.fee, proto2.fee);
        assert_eq!(
            proto_proposal.outlay_index_to_tx_out_index,
            proto2.outlay_index_to_tx_out_index
        );
        assert_eq!(
            proto_proposal.outlay_confirmation_numbers,
            proto2.outlay_confirmation_numbers
        );
        assert_eq!(proto_proposal, proto2);
    }
}
