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
    pub pcr4s: Vec<String>,
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

    for i in 0..3 {
        let expected = expected_values.pcrs[&i].clone();
        let actual_value = attest_doc
            .pcrs
            .get(&i)
            .map(|buf| hex::encode(&buf[..]))
            .unwrap_or_else(|| "missing".to_string());
        eyre::ensure!(
            actual_value == *expected,
            "PCR {i} value does not match expected value"
        );
    }

    //Check if PCR 4 values is in allowed pcr4 list
    eyre::ensure!(
        expected_values.pcr4s.iter().any(|expected_value| {
            let expected_value_hex = expected_value.to_lowercase();
            let actual_value_hex = hex::encode(
                &attest_doc
                    .pcrs
                    .get(&4)
                    .map(|buf| &buf[..])
                    .unwrap_or_else(|| b"missing"),
            );
            if actual_value_hex == expected_value_hex {
                return true;
            }
            false
        }),
        "PCR 4 value does not match any expected value"
    );

    // for (index, expected_value) in &expected_values.pcrs {
    //     let actual_value = attest_doc
    //         .pcrs
    //         .get(index)
    //         .map(|buf| hex::encode(&buf[..]))
    //         .unwrap_or_else(|| "missing".to_string());
    //     eyre::ensure!(
    //         actual_value == *expected_value,
    //         "PCR {index} value does not match expected value"
    //     );
    // }

    // println!("Attestation document {:?}", attest_doc.pcrs);

    // Ok(doc)
    tracing::info!("Attestation document validated successfully");
    Ok(())
}
