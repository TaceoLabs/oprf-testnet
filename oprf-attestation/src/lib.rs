use aws_nitro_enclaves_nsm_api::{api::Request, driver};
use serde_bytes::ByteBuf;

use axum::{Router, body::Bytes, extract::Path, response::IntoResponse, routing::get};

use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use base64::Engine;
use futures_util::StreamExt;
use serde_cbor::Value;
use std::collections::BTreeMap;
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

pub fn handle_attestation_doc(doc: Bytes) -> eyre::Result<()> {
    let cose_sign1: Value = serde_cbor::from_slice(&doc)
        .map_err(|e| eyre::eyre!("Failed to parse COSE_Sign1: {:?}", e))
        .unwrap();

    // Step 2: Extract the payload (index 2 in the COSE_Sign1 array)
    let payload = match &cose_sign1 {
        Value::Array(arr) if arr.len() == 4 => match &arr[2] {
            Value::Bytes(b) => b.clone(),
            _ => return Err(eyre::eyre!("COSE_Sign1 payload is not bytes")),
        },
        _ => return Err(eyre::eyre!("Invalid COSE_Sign1 structure")),
    };

    let signature = match &cose_sign1 {
        Value::Array(arr) if arr.len() == 4 => match &arr[3] {
            Value::Bytes(b) => b.clone(),
            _ => return Err(eyre::eyre!("COSE_Sign1 payload is not bytes")),
        },
        _ => return Err(eyre::eyre!("Invalid COSE_Sign1 structure")),
    };

    // Step 3: Decode the actual AttestationDoc from the payload
    let attest_doc: AttestationDoc = serde_cbor::from_slice(&payload)
        .map_err(|e| eyre::eyre!("Failed to decode AttestationDoc: {:?}", e))?;

    // println!("Decoded attestation document: {:?}", doc);

    println!("Nonce in doc: {:?}", attest_doc.nonce);

    let vec: &[u8] = doc.as_ref();
    println!("Validating...");
    let attest_res = attestation_doc_validation::validate_attestation_doc(&vec)
        .expect("Failed to validate attestation doc");
    let existing_nonce = base64::prelude::BASE64_STANDARD.encode("44");
    let nonce_attest_result =
        attestation_doc_validation::validate_expected_nonce(&attest_doc, &existing_nonce);
    println!("finished validation");
    println!("Attestation doc validation result: {attest_res:?}");
    println!("Nonce validation result: {nonce_attest_result:?}");

    println!("Verifying pcrs..");
    let encoded_measurements = attest_doc
        .pcrs
        .iter()
        .map(|(&index, buf)| (index, hex::encode(&buf[..])))
        .collect::<BTreeMap<_, _>>();
    let pcr4 = "8ac3842529db0edb729e855f909b546500284f0b561dc496f37bbf49f004eee4b22922adb4bebabcbce11fe54f16f283";
    let pcr4_valid = encoded_measurements
        .get(&4)
        .map(|v| v == pcr4)
        .unwrap_or(false);
    println!("PCR 4 valid: {pcr4_valid}");
    println!(
        "PCR 4 value:          {}",
        encoded_measurements
            .get(&4)
            .unwrap_or(&"missing".to_string())
    );
    println!("PCR 4 expected value: {pcr4}");
    println!(
        "PCR 3 value:          {}",
        encoded_measurements
            .get(&3)
            .unwrap_or(&"missing".to_string())
    );
    println!(
        "PCR 8 value:          {}",
        encoded_measurements
            .get(&8)
            .unwrap_or(&"missing".to_string())
    );

    println!("Attestation document {:?}", attest_doc.module_id);

    // Ok(doc)
    Ok(())
}
