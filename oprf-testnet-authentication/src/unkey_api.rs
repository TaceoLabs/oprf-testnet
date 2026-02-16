use axum::{response, response::IntoResponse};
use eyre::Context;
use reqwest::{Client, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use taceo_oprf::service::config::Environment;

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
}

impl IntoResponse for ApiVerificationError {
    fn into_response(self) -> response::Response {
        tracing::debug!("{self:?}");
        match self {
            Self::ApiVerificationFailed => {
                (StatusCode::UNAUTHORIZED, "API Key not valid").into_response()
            }
            Self::ApiRateLimitExceeded => {
                (StatusCode::TOO_MANY_REQUESTS, "API Key rate limit exceeded").into_response()
            }
            Self::InternalServerError(err) => {
                tracing::error!("Internal server error: {err:?}");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
            }
        }
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
