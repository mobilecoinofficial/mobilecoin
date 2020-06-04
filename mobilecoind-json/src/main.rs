#![feature(proc_macro_hygiene, decl_macro)]

use grpcio::{ChannelBuilder, ChannelCredentialsBuilder};
use protobuf::RepeatedField;

use mc_api::external::KeyImage;
use mc_common::logger::{create_app_logger, log, o};
use mc_mobilecoind_api::mobilecoind_api_grpc::MobilecoindApiClient;
use rocket::{get, post, routes};
use rocket_contrib::json::Json;
use serde_derive::{Deserialize, Serialize};
use std::sync::Arc;
use structopt::StructOpt;

/// Command line config, set with defaults that will work with
/// a standard mobilecoind instance
#[derive(Clone, Debug, StructOpt)]
#[structopt(
    name = "mobilecoind-rest-gateway",
    about = "A REST frontend for mobilecoind"
)]
pub struct Config {
    /// Host to listen on.
    #[structopt(long, default_value = "127.0.0.1")]
    pub listen_host: String,

    /// Port to start webserver on.
    #[structopt(long, default_value = "9090")]
    pub listen_port: u16,

    /// MobileCoinD URI.
    #[structopt(long, default_value = "127.0.0.1:4444")]
    pub mobilecoind_host: String,

    /// SSL
    #[structopt(long)]
    pub use_ssl: bool,
}

/// Connection to the mobilecoind client
struct State {
    pub mobilecoind_api_client: MobilecoindApiClient,
}

#[derive(Serialize, Default)]
struct JsonEntropyResponse {
    entropy: String,
}

/// Requests a new root entropy from mobilecoind
#[get("/entropy")]
fn entropy(state: rocket::State<State>) -> Result<Json<JsonEntropyResponse>, String> {
    let resp = state
        .mobilecoind_api_client
        .generate_entropy(&mc_mobilecoind_api::Empty::new())
        .map_err(|err| format!("Failed getting entropy: {}", err))?;
    Ok(Json(JsonEntropyResponse {
        entropy: hex::encode(resp.entropy),
    }))
}

#[derive(Deserialize, Default)]
struct JsonMonitorRequest {
    entropy: String,
    first_subaddress: u64,
    num_subaddresses: u64,
}

#[derive(Serialize, Default)]
struct JsonMonitorResponse {
    monitor_id: String,
}

/// Creates a monitor. Data for the key and range is POSTed using the struct above.
#[post("/monitors", format = "json", data = "<monitor>")]
fn create_monitor(
    state: rocket::State<State>,
    monitor: Json<JsonMonitorRequest>,
) -> Result<Json<JsonMonitorResponse>, String> {
    let entropy = hex::decode(&monitor.entropy)
        .map_err(|err| format!("Failed to decode hex key: {}", err))?;

    let mut req = mc_mobilecoind_api::GetAccountKeyRequest::new();
    req.set_entropy(entropy.to_vec());

    let mut resp = state
        .mobilecoind_api_client
        .get_account_key(&req)
        .map_err(|err| format!("Failed getting account key for entropy: {}", err))?;

    let account_key = resp.take_account_key();

    let mut req = mc_mobilecoind_api::AddMonitorRequest::new();
    req.set_account_key(account_key);
    req.set_first_subaddress(monitor.first_subaddress);
    req.set_num_subaddresses(monitor.num_subaddresses);
    req.set_first_block(0);

    let monitor_response = state
        .mobilecoind_api_client
        .add_monitor(&req)
        .map_err(|err| format!("Failed adding monitor: {}", err))?;

    Ok(Json(JsonMonitorResponse {
        monitor_id: hex::encode(monitor_response.monitor_id),
    }))
}

#[derive(Serialize, Default)]
struct JsonMonitorStatusResponse {
    first_subaddress: u64,
    num_subaddresses: u64,
    first_block: u64,
    next_block: u64,
}

/// Get the current status of a created monitor
#[get("/monitors/<monitor_hex>")]
fn monitor_status(
    state: rocket::State<State>,
    monitor_hex: String,
) -> Result<Json<JsonMonitorStatusResponse>, String> {
    let monitor_id =
        hex::decode(monitor_hex).map_err(|err| format!("Failed to decode monitor hex: {}", err))?;

    let mut req = mc_mobilecoind_api::GetMonitorStatusRequest::new();
    req.set_monitor_id(monitor_id);

    let resp = state
        .mobilecoind_api_client
        .get_monitor_status(&req)
        .map_err(|err| format!("Failed getting monitor status: {}", err))?;

    let status = resp.get_status();

    Ok(Json(JsonMonitorStatusResponse {
        first_subaddress: status.get_first_subaddress(),
        num_subaddresses: status.get_num_subaddresses(),
        first_block: status.get_first_block(),
        next_block: status.get_next_block(),
    }))
}

#[derive(Serialize, Default)]
struct JsonBalanceResponse {
    balance: String,
}

/// Balance check using a created monitor and subaddress index
#[get("/monitors/<monitor_hex>/<subaddress_index>/balance")]
fn balance(
    state: rocket::State<State>,
    monitor_hex: String,
    subaddress_index: u64,
) -> Result<Json<JsonBalanceResponse>, String> {
    let monitor_id =
        hex::decode(monitor_hex).map_err(|err| format!("Failed to decode monitor hex: {}", err))?;

    let mut req = mc_mobilecoind_api::GetBalanceRequest::new();
    req.set_monitor_id(monitor_id);
    req.set_subaddress_index(subaddress_index);

    let resp = state
        .mobilecoind_api_client
        .get_balance(&req)
        .map_err(|err| format!("Failed getting balance: {}", err))?;
    let balance = resp.get_balance();
    Ok(Json(JsonBalanceResponse {
        balance: balance.to_string(),
    }))
}

#[derive(Deserialize)]
struct JsonRequestCodeRequest {
    value: Option<u64>,
    memo: Option<String>,
}

#[derive(Serialize, Default)]
struct JsonRequestCodeResponse {
    request_code: String,
}

/// Generates a request code with an optional value and memo
#[post(
    "/monitors/<monitor_hex>/<subaddress_index>/request-code",
    format = "json",
    data = "<extra>"
)]
fn request_code(
    state: rocket::State<State>,
    monitor_hex: String,
    subaddress_index: u64,
    extra: Json<JsonRequestCodeRequest>,
) -> Result<Json<JsonRequestCodeResponse>, String> {
    let monitor_id =
        hex::decode(monitor_hex).map_err(|err| format!("Failed to decode monitor hex: {}", err))?;

    // Get our public address.
    let mut req = mc_mobilecoind_api::GetPublicAddressRequest::new();
    req.set_monitor_id(monitor_id);
    req.set_subaddress_index(subaddress_index);

    let resp = state
        .mobilecoind_api_client
        .get_public_address(&req)
        .map_err(|err| format!("Failed getting public address: {}", err))?;

    let public_address = resp.get_public_address().clone();

    // Generate b58 code
    let mut req = mc_mobilecoind_api::GetRequestCodeRequest::new();
    req.set_receiver(public_address);
    if let Some(value) = extra.value {
        req.set_value(value);
    }
    if let Some(memo) = extra.memo.clone() {
        req.set_memo(memo);
    }

    let resp = state
        .mobilecoind_api_client
        .get_request_code(&req)
        .map_err(|err| format!("Failed getting request code: {}", err))?;

    Ok(Json(JsonRequestCodeResponse {
        request_code: String::from(resp.get_b58_code()),
    }))
}

#[derive(Serialize, Default)]
struct JsonReadRequestResponse {
    value: String,
    memo: String,
}

/// Retrieves the metadata in a request code
#[get("/read-request/<request_code>")]
fn read_request(
    state: rocket::State<State>,
    request_code: String,
) -> Result<Json<JsonReadRequestResponse>, String> {
    let mut req = mc_mobilecoind_api::ReadRequestCodeRequest::new();
    req.set_b58_code(request_code.clone());
    let resp = state
        .mobilecoind_api_client
        .read_request_code(&req)
        .map_err(|err| format!("Failed reading request code: {}", err))?;

    Ok(Json(JsonReadRequestResponse {
        value: resp.get_value().to_string(),
        memo: resp.get_memo().to_string(),
    }))
}

#[derive(Deserialize)]
struct JsonTransferRequest {
    request_code: String,
    amount: u64,
}
#[derive(Deserialize, Serialize)]
struct JsonTransferResponse {
    key_image: String,
    tombstone: u64,
}

/// Performs a transfer from a monitor and subaddress. The target and amount are in the POST data.
#[post(
    "/monitors/<monitor_hex>/<subaddress_index>/transfer",
    format = "json",
    data = "<transfer>"
)]
fn transfer(
    state: rocket::State<State>,
    monitor_hex: String,
    subaddress_index: u64,
    transfer: Json<JsonTransferRequest>,
) -> Result<Json<JsonTransferResponse>, String> {
    let monitor_id =
        hex::decode(monitor_hex).map_err(|err| format!("Failed to decode monitor hex: {}", err))?;

    let mut req = mc_mobilecoind_api::ReadRequestCodeRequest::new();
    req.set_b58_code(transfer.request_code.clone());
    let resp = state
        .mobilecoind_api_client
        .read_request_code(&req)
        .map_err(|err| format!("Failed reading request code: {}", err))?;
    let public_address = resp.get_receiver();

    let mut outlay = mc_mobilecoind_api::Outlay::new();
    outlay.set_receiver(public_address.clone());
    outlay.set_value(transfer.amount);

    let mut req = mc_mobilecoind_api::SendPaymentRequest::new();
    req.set_sender_monitor_id(monitor_id);
    req.set_sender_subaddress(subaddress_index);
    req.set_outlay_list(RepeatedField::from_vec(vec![outlay]));

    let resp = state
        .mobilecoind_api_client
        .send_payment(&req)
        .map_err(|err| format!("Failed to send payment: {}", err))?;

    let receipt = resp.get_sender_tx_receipt();
    Ok(Json(JsonTransferResponse {
        key_image: hex::encode(receipt.get_key_image_list()[0].get_data()),
        tombstone: receipt.get_tombstone(),
    }))
}

#[derive(Serialize, Default)]
struct JsonStatusResponse {
    status: String,
}

/// Checks the status of a transfer given a key image and tombstone block
#[post("/check-transfer-status", format="json", data="<receipt>")]
fn status(
    state: rocket::State<State>,
    receipt: Json<JsonTransferResponse>,
) -> Result<Json<JsonStatusResponse>, String> {
    let mut sender_receipt = mc_mobilecoind_api::SenderTxReceipt::new();
    let mut key_image = KeyImage::new();
    key_image.set_data(
        hex::decode(&receipt.key_image).map_err(|err| format!("Failed to decode key image hex: {}", err))?,
    );
    sender_receipt.set_key_image_list(RepeatedField::from_vec(vec![key_image]));
    sender_receipt.set_tombstone(receipt.tombstone);

    let mut req = mc_mobilecoind_api::GetTxStatusAsSenderRequest::new();
    req.set_receipt(sender_receipt);

    let resp = state
        .mobilecoind_api_client
        .get_tx_status_as_sender(&req)
        .map_err(|err| format!("Failed getting status: {}", err))?;
    let status = resp.get_status();
    match status {
        mc_mobilecoind_api::TxStatus::Unknown => Ok(Json(JsonStatusResponse {
            status: String::from("unknown"),
        })),
        mc_mobilecoind_api::TxStatus::Verified => Ok(Json(JsonStatusResponse {
            status: String::from("verified"),
        })),
        mc_mobilecoind_api::TxStatus::TombstoneBlockExceeded => Ok(Json(JsonStatusResponse {
            status: String::from("failed"),
        })),
    }
}

fn main() {
    mc_common::setup_panic_handler();
    let _sentry_guard = mc_common::sentry::init();

    let config = Config::from_args();

    let (logger, _global_logger_guard) = create_app_logger(o!());
    log::info!(
        logger,
        "Starting mobilecoind HTTP gateway on {}:{}, connecting to {}",
        config.listen_host,
        config.listen_port,
        config.mobilecoind_host
    );

    // Set up the gRPC connection to the mobilecoind client
    let env = Arc::new(grpcio::EnvBuilder::new().build());
    let ch_builder = ChannelBuilder::new(env)
        .max_receive_message_len(std::i32::MAX)
        .max_send_message_len(std::i32::MAX);

    let ch = if config.use_ssl {
        let creds = ChannelCredentialsBuilder::new().build();
        ch_builder.secure_connect(&config.mobilecoind_host, creds)
    } else {
        ch_builder.connect(&config.mobilecoind_host)
    };

    let mobilecoind_api_client = MobilecoindApiClient::new(ch);

    let rocket_config = rocket::Config::build(rocket::config::Environment::Production)
        .address(&config.listen_host)
        .port(config.listen_port)
        .unwrap();

    rocket::custom(rocket_config)
        .mount(
            "/",
            routes![
                entropy,
                create_monitor,
                balance,
                request_code,
                transfer,
                status
            ],
        )
        .manage(State {
            mobilecoind_api_client,
        })
        .launch();
}
