use async_trait::async_trait;
use axum::response::IntoResponse;
use reqwest::StatusCode;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::process::Command;
use taceo_oprf::types::api::{OprfRequest, OprfRequestAuthenticator};
use tempfile::NamedTempFile;

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
    pub public_inputs: Vec<u8>,
    pub proof: Vec<u8>,
    pub api_key: String,
}

#[derive(Debug, thiserror::Error)]
pub enum TestNetRequestAuthError {
    #[error("Proof invalid")]
    ProofInvalid,
    #[error("Proof verification failed")]
    ProofVerificationFailed,
    #[error(transparent)]
    ApiRequestFailed(#[from] reqwest::Error),
    #[error("Internal Server Error")]
    InternalServerError(String),
    #[error("API Key not valid")]
    ApiVerificationFailed,
}

impl IntoResponse for TestNetRequestAuthError {
    fn into_response(self) -> axum::response::Response {
        tracing::debug!("{self:?}");
        match self {
            TestNetRequestAuthError::ProofInvalid => {
                (StatusCode::BAD_REQUEST, "Proof is invalid").into_response()
            }
            TestNetRequestAuthError::ApiRequestFailed(_)
            | TestNetRequestAuthError::InternalServerError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
            }
            TestNetRequestAuthError::ApiVerificationFailed => {
                (StatusCode::UNAUTHORIZED, "API Key not valid").into_response()
            }
            TestNetRequestAuthError::ProofVerificationFailed => {
                (StatusCode::BAD_REQUEST, "Could not verify proof").into_response()
            }
        }
    }
}

pub struct TestNetRequestAuthenticator {
    client: reqwest::Client,
    root_api_key: SecretString,
}

impl TestNetRequestAuthenticator {
    pub async fn init(root_api_key: SecretString) -> eyre::Result<Self> {
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
        let vk_path = "noir/prototype_oprf/out/vk";
        let mut public_inputs = NamedTempFile::new().unwrap();
        let mut proof = NamedTempFile::new().unwrap();
        let _ = public_inputs.write_all(&request_auth.auth.public_inputs);
        let _ = proof.write_all(&request_auth.auth.proof);

        let bb_verify_status = Command::new("bb")
            .arg("verify")
            .arg("-t")
            .arg("noir-recursive")
            .arg("-p")
            .arg(proof.path())
            .arg("-i")
            .arg(public_inputs.path())
            .arg("-k")
            .arg(vk_path)
            .status();

        if bb_verify_status.is_err() {
            return Err(TestNetRequestAuthError::ProofInvalid);
        }
        if !bb_verify_status.unwrap().success() {
            return Err(TestNetRequestAuthError::ProofVerificationFailed);
        }

        //verify API
        let client = self.client.clone();
        let result = client
            .post("https://api.unkey.com/v2/keys.verifyKey")
            .bearer_auth(self.root_api_key.expose_secret())
            .json(&serde_json::json!({"key": request_auth.auth.api_key}))
            .send()
            .await?;

        match result.json::<UnkeyRespRoot>().await {
            Ok(resp_data) => {
                if !resp_data.data.valid {
                    return Err(TestNetRequestAuthError::ApiVerificationFailed);
                }
                Ok(())
            }
            Err(err) => {
                tracing::debug!("Unkey response parse error: {}", err);
                Err(TestNetRequestAuthError::InternalServerError(
                    "Failed to parse Unkey response".to_string(),
                ))
            }
        }
    }
}
