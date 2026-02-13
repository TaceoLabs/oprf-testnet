use async_trait::async_trait;
use axum::response::{self, IntoResponse};
use reqwest::StatusCode;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use taceo_oprf::{
    service::config::Environment,
    types::{
        OprfKeyId,
        api::{OprfRequest, OprfRequestAuthenticator},
    },
};

use crate::unkey_api::{self, ApiVerificationError};

#[derive(Clone, Serialize, Deserialize)]
pub struct TestNetApiOnlyRequestAuth {
    pub api_key: String,
    pub oprf_key_id: OprfKeyId,
}

#[derive(Debug, thiserror::Error)]
pub enum TestNetApiOnlyRequestAuthError {
    #[error(transparent)]
    ApiVerificationError(#[from] ApiVerificationError),
    #[error(transparent)]
    InternalServerError(#[from] eyre::Report),
}

impl IntoResponse for TestNetApiOnlyRequestAuthError {
    fn into_response(self) -> response::Response {
        tracing::debug!("{self:?}");
        match self {
            Self::InternalServerError(err) => {
                tracing::error!("Internal server error: {err:?}");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
            }
            Self::ApiVerificationError(err) => err.into_response(),
        }
    }
}

pub struct BasicTestNetRequestAuthenticator {
    client: reqwest::Client,
    root_api_key: SecretString,
    env: Environment,
}

impl BasicTestNetRequestAuthenticator {
    pub fn init(root_api_key: SecretString, env: Environment) -> Self {
        let client = reqwest::Client::new();
        Self {
            client,
            root_api_key,
            env,
        }
    }
}

#[async_trait]
impl OprfRequestAuthenticator for BasicTestNetRequestAuthenticator {
    type RequestAuth = TestNetApiOnlyRequestAuth;
    type RequestAuthError = TestNetApiOnlyRequestAuthError;

    async fn authenticate(
        &self,
        req: &OprfRequest<Self::RequestAuth>,
    ) -> Result<OprfKeyId, Self::RequestAuthError> {
        tracing::debug!("Authenticating with only API");

        //call API
        unkey_api::verify_api_key(
            self.client.clone(),
            self.root_api_key.clone(),
            req.auth.api_key.clone(),
            self.env,
        )
        .await?;
        tracing::debug!("Authentication successful");
        Ok(req.auth.oprf_key_id)
    }
}
