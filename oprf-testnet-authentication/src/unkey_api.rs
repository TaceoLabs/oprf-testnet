use eyre::Context;
use reqwest::Client;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use taceo_oprf::{service::Environment, types::api::OprfRequestAuthenticatorError};

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
    pub code: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnkeyMeta {
    pub request_id: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ApiVerificationError {
    #[error("API Key not valid")]
    ApiVerificationFailed,
    #[error("API Key rate limit exceeded")]
    ApiRateLimitExceeded,
    #[error(transparent)]
    InternalServerError(#[from] eyre::Report),
    #[error("unknown_error_{0}")]
    Unknown(u16),
}

pub mod api_error_codes {
    pub const API_VERIFICATION_FAILED: u16 = 4500;
    pub const API_RATE_LIMIT_EXCEEDED: u16 = 4501;
    pub const INTERNAL: u16 = 1011;
}

impl From<u16> for ApiVerificationError {
    fn from(value: u16) -> Self {
        match value {
            api_error_codes::API_VERIFICATION_FAILED => ApiVerificationError::ApiVerificationFailed,
            api_error_codes::API_RATE_LIMIT_EXCEEDED => ApiVerificationError::ApiRateLimitExceeded,
            api_error_codes::INTERNAL => {
                ApiVerificationError::InternalServerError(eyre::eyre!("Internal Server Error"))
            }
            other => Self::Unknown(other),
        }
    }
}

impl From<&ApiVerificationError> for u16 {
    fn from(value: &ApiVerificationError) -> Self {
        match value {
            ApiVerificationError::ApiVerificationFailed => api_error_codes::API_VERIFICATION_FAILED,
            ApiVerificationError::ApiRateLimitExceeded => api_error_codes::API_RATE_LIMIT_EXCEEDED,
            ApiVerificationError::InternalServerError(_) => api_error_codes::INTERNAL,
            ApiVerificationError::Unknown(other) => *other,
        }
    }
}

impl From<ApiVerificationError> for OprfRequestAuthenticatorError {
    fn from(value: ApiVerificationError) -> Self {
        let code = u16::from(&value);
        let msg = match value {
            ApiVerificationError::ApiVerificationFailed => {
                taceo_oprf::types::close_frame_message!("API Key not valid")
            }
            ApiVerificationError::ApiRateLimitExceeded => {
                taceo_oprf::types::close_frame_message!("API Key rate limit exceeded")
            }
            ApiVerificationError::InternalServerError(err) => {
                tracing::error!("Internal server error: {err:?}");
                taceo_oprf::types::close_frame_message!("Internal Server Error")
            }
            ApiVerificationError::Unknown(other) => {
                tracing::error!("Unknown API verification error with code: {other}");
                taceo_oprf::types::close_frame_message!("unknown")
            }
        };
        Self::with_message(code, msg)
    }
}

pub async fn verify_api_key(
    client: Client,
    verify_key: SecretString,
    api_key: String,
    env: Environment,
) -> Result<(), ApiVerificationError> {
    if matches!(env, Environment::Dev) {
        tracing::info!("Skipping API key verification in dev environment");
        return Ok(());
    }

    tracing::debug!("Verifying API");
    let result = client
        .post("https://api.unkey.com/v2/keys.verifyKey")
        .bearer_auth(verify_key.expose_secret())
        .json(&serde_json::json!({"key": api_key}))
        .send()
        .await
        .context("Unkey API request error")?
        .error_for_status()
        .context("Unkey API status code error")?;

    // parse API response
    tracing::debug!("Parsing API response");
    let unkey_response = result
        .json::<UnkeyRespRoot>()
        .await
        .context("Unkey response parse error")?;

    if !unkey_response.data.valid {
        if unkey_response.data.code == "RATE_LIMITED" {
            return Err(ApiVerificationError::ApiRateLimitExceeded);
        }
        return Err(ApiVerificationError::ApiVerificationFailed);
    }
    Ok(())
}
