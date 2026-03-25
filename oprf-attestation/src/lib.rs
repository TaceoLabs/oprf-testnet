use aws_nitro_enclaves_nsm_api::{api::Request, driver};
use eyre::{Context, OptionExt, bail};
use serde_bytes::ByteBuf;

use axum::{Router, body::Bytes, extract::Path, response::IntoResponse, routing::get};

use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use base64::Engine;
use serde_cbor::Value;
use std::collections::BTreeMap;

pub struct AttestationValues {
    pub nonce: usize,
    pub pcrs: BTreeMap<usize, String>,
    pub public_key: Vec<u8>,
    pub user_data: Vec<u8>,
}

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

pub fn handle_attestation_doc(doc: Bytes, expected_values: &AttestationValues) -> eyre::Result<()> {
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

    let _signature = match &cose_sign1 {
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

    let vec: &[u8] = doc.as_ref();
    attestation_doc_validation::validate_attestation_doc(&vec)
        .context("Attestation document validation failed")?;
    let expected_nonce =
        base64::prelude::BASE64_STANDARD.encode(expected_values.nonce.to_be_bytes());

    attestation_doc_validation::validate_expected_nonce(&attest_doc, &expected_nonce)
        .context("Nonce validation failed")?;

    tracing::info!("Verifying pcrs..");

    // println!("PCR values in attestation document: {:?}", attest_doc.pcrs);
    // println!("Expected PCR values: {:?}", expected_values.pcrs);

    expected_values
        .pcrs
        .iter()
        .for_each(|(index, expected_value)| {
            let actual_value = attest_doc
                .pcrs
                .get(index)
                .map(|buf| hex::encode(&buf[..]))
                .unwrap_or_else(|| "missing".to_string());
            println!("PCR {index} value:          {actual_value}");
            println!("PCR {index} expected value: {expected_value}");
        });

    // let encoded_measurements = attest_doc
    //     .pcrs
    //     .iter()
    //     .map(|(&index, buf)| (index, hex::encode(&buf[..])))
    //     .collect::<BTreeMap<_, _>>();
    //
    // let pcr4 = expected_values
    //     .pcrs
    //     .get(&4)
    //     .unwrap_or(&"missing".to_string())
    //     .to_string();
    // eyre::ensure!(
    //     encoded_measurements
    //         .get(&4)
    //         .map(|v| *v == pcr4)
    //         .unwrap_or(false),
    //     "PCR 4 value does not match expected value"
    // );
    // println!(
    //     "PCR 4 value:          {}",
    //     encoded_measurements
    //         .get(&4)
    //         .unwrap_or(&"missing".to_string())
    // );
    // println!("PCR 4 expected value: {pcr4}");
    //
    // let pcr3 = expected_values
    //     .pcrs
    //     .get(&3)
    //     .unwrap_or(&"missing".to_string())
    //     .to_string();
    // eyre::ensure!(
    //     encoded_measurements
    //         .get(&3)
    //         .map(|v| *v == pcr3)
    //         .unwrap_or(false),
    //     "PCR 3 value does not match expected value"
    // );
    // println!(
    //     "PCR 3 value:          {}",
    //     encoded_measurements
    //         .get(&3)
    //         .unwrap_or(&"missing".to_string())
    // );
    // println!(
    //     "PCR 8 value:          {}",
    //     encoded_measurements
    //         .get(&8)
    //         .unwrap_or(&"missing".to_string())
    // );

    println!("Attestation document {:?}", attest_doc.module_id);

    // Ok(doc)
    Ok(())
}
