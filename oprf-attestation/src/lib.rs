use aws_nitro_enclaves_nsm_api::{api::Request, driver};
use serde_bytes::ByteBuf;

use axum::{Router, body::Bytes, extract::Path, response::IntoResponse, routing::get};

// use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn get_attestation(nonce: Bytes) -> eyre::Result<Vec<u8>> {
    println!("Initializing NSM connection...");
    let nsm_fd = driver::nsm_init();

    let public_key = ByteBuf::from("my super secret key");
    let hello = ByteBuf::from("hello, world!");

    let request = Request::Attestation {
        public_key: Some(public_key),
        user_data: Some(hello),
        nonce: Some(ByteBuf::from(nonce)),
    };
    println!("Sending attestation request to NSM...");
    let response = driver::nsm_process_request(nsm_fd, request);
    println!("Received response from NSM, exiting NSM connection...");

    driver::nsm_exit(nsm_fd);
    match response {
        aws_nitro_enclaves_nsm_api::api::Response::Attestation { document } => Ok(document),
        _ => {
            println!("didnt get attestation document, got {response:?}");
            Err(eyre::eyre!("Unexpected response: {:?}", response))
        }
    }
}

pub async fn handle_attestation_request(Path(nonce): Path<u64>) -> impl IntoResponse {
    println!("Received attestation request with nonce: {nonce}");
    let document = get_attestation(Bytes::from(nonce.to_be_bytes().to_vec()));
    match document {
        Ok(doc) => (axum::http::StatusCode::OK, doc),
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            e.to_string().into_bytes(),
        ),
    }
}

pub fn get_attestation_router() -> Router {
    let router = Router::new().route("/attest/{nonce}", get(handle_attestation_request));
    return router;
}
