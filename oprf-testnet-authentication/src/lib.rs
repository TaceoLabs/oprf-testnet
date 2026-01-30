use std::{fs, process::Command};

use async_trait::async_trait;
use axum::response::IntoResponse;
use eyre::{Context, eyre};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use taceo_oprf::types::api::{OprfRequest, OprfRequestAuthenticator};
use uuid::Uuid;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnkeyRespRoot {
    pub data: UnkeyData,
    pub meta: UnkeyMeta,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnkeyData {
    pub valid: bool,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnkeyMeta {
    pub request_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TestNetRequestAuth {
    pub proof_input: ProofInput,
    pub api_key: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ProofInput {
    pub public_inputs: Vec<u8>,
    pub proof: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum TestNetRequestAuthError {
    #[error(transparent)]
    ProofInvalid(#[from] eyre::Report),
    #[error(transparent)]
    ApiRequestFailed(#[from] reqwest::Error),
    #[error("Request to Unkey failed")]
    ApiResponseWrong(String),
    #[error("API Key not valid")]
    ApiVerificationFailed,
}

impl IntoResponse for TestNetRequestAuthError {
    fn into_response(self) -> axum::response::Response {
        tracing::debug!("{self:?}");
        match self {
            TestNetRequestAuthError::ProofInvalid(_) => {
                (StatusCode::BAD_REQUEST, "Verification of proof failed").into_response()
            }
            TestNetRequestAuthError::ApiRequestFailed(_)
            | TestNetRequestAuthError::ApiResponseWrong(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
            }
            TestNetRequestAuthError::ApiVerificationFailed => {
                (StatusCode::UNAUTHORIZED, "API Key not valid").into_response()
            }
        }
    }
}

pub struct TestNetRequestAuthenticator {
    client: reqwest::Client,
    root_api_key: String,
}

impl TestNetRequestAuthenticator {
    pub async fn init(root_api_key: String) -> eyre::Result<Self> {
        let client = reqwest::Client::new();
        Ok(Self {
            client,
            root_api_key,
        })
    }
}

#[async_trait]
impl OprfRequestAuthenticator for TestNetRequestAuthenticator {
    type RequestAuth = TestNetRequestAuth;
    type RequestAuthError = TestNetRequestAuthError;

    async fn verify(
        &self,
        request_auth: &OprfRequest<Self::RequestAuth>,
    ) -> Result<(), Self::RequestAuthError> {
        // verify ZK
        let file_prefix = Uuid::new_v4();
        let proof_path = format!("/tmp/{}_proof_input", file_prefix);
        let public_inputs_path = format!("/tmp/{}_public_inputs", file_prefix);
        let vk_path = "circuits/einfallswinkel_ist_gleich_ausfallswinkel/out/vk";
        let _ = fs::write(
            &public_inputs_path,
            &request_auth.auth.proof_input.public_inputs,
        );
        let _ = fs::write(&proof_path, &request_auth.auth.proof_input.proof);

        let bb_verify_status = Command::new("bb")
            .arg("verify")
            .arg("-t")
            .arg("noir-recursive")
            .arg("-p")
            .arg(proof_path)
            .arg("-i")
            .arg(public_inputs_path)
            .arg("-k")
            .arg(vk_path)
            .status();

        if bb_verify_status.is_err() {
            return Err(eyre::eyre!("Proof verification failed").into());
        }
        if !bb_verify_status.unwrap().success() {
            return Err(eyre::eyre!("Proof did not verify").into());
        }
        #[derive(serde::Serialize)]
        struct Key {
            key: String,
        }
        let key_to_verify = Key {
            key: request_auth.auth.api_key.clone(),
        };

        //verify API
        let client = self.client.clone();
        let result = client
            .post("https://api.unkey.com/v2/keys.verifyKey")
            .bearer_auth(self.root_api_key.clone())
            .json(&key_to_verify)
            .send()
            .await?;

        match result.json::<UnkeyRespRoot>().await {
            Ok(resp_data) => {
                if !resp_data.data.valid {
                    return Err(TestNetRequestAuthError::ApiVerificationFailed);
                }
                return Ok(());
            }
            Err(err) => {
                tracing::debug!("Unkey response parse error: {}", err);
                return Err(TestNetRequestAuthError::ApiResponseWrong(err.to_string()));
            }
        }
    }
}
