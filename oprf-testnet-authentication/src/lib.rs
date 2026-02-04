use async_trait::async_trait;
use axum::response::IntoResponse;
use reqwest::StatusCode;
use secrecy::ExposeSecret as _;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::io::Write as _;
use std::process::Command;
use taceo_oprf::types::api::{OprfRequest, OprfRequestAuthenticator};
use tempfile::NamedTempFile;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnkeyRespRoot {
    pub data: UnkeyData,
    pub meta: UnkeyMeta,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnkeyData {
    pub valid: bool,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnkeyMeta {
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
            Self::ProofInvalid => (StatusCode::BAD_REQUEST, "Proof is invalid").into_response(),
            Self::ApiRequestFailed(_) | Self::InternalServerError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
            }
            Self::ApiVerificationFailed => {
                (StatusCode::UNAUTHORIZED, "API Key not valid").into_response()
            }
            Self::ProofVerificationFailed => {
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
    pub fn init(root_api_key: SecretString) -> eyre::Result<Self> {
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
        req: &OprfRequest<Self::RequestAuth>,
    ) -> Result<(), Self::RequestAuthError> {
        // verify ZK
        let vk_path = "noir/prototype_oprf/out/vk";
        let mut public_inputs = NamedTempFile::new().expect("NamedTempFile creation should work");
        let mut proof = NamedTempFile::new().expect("NamedTempFile creation should work");
        public_inputs
            .write_all(&req.auth.public_inputs)
            .expect("TempFile write for public_inputs should work");
        proof
            .write_all(&req.auth.proof)
            .expect("TempFile write for proof should work");

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

        match bb_verify_status {
            Ok(status) => {
                if !status.success() {
                    tracing::error!(
                        "'bb verify' failed with status code: {}",
                        status.code().expect("'bb verify' not terminated by signal")
                    );
                    return Err(TestNetRequestAuthError::ProofVerificationFailed);
                }
            }
            Err(_) => {
                return Err(TestNetRequestAuthError::ProofInvalid);
            }
        }

        //verify API
        let client = self.client.clone();
        let result = client
            .post("https://api.unkey.com/v2/keys.verifyKey")
            .bearer_auth(self.root_api_key.expose_secret())
            .json(&serde_json::json!({"key": req.auth.api_key}))
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
                    "Failed to parse Unkey response".to_owned(),
                ))
            }
        }
    }
}
