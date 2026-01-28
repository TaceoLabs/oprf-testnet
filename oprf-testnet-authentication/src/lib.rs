use async_trait::async_trait;
use axum::response::IntoResponse;
use eyre::Context;
use oprf_service::OprfRequestAuthenticator;
use oprf_types::api::v1::OprfRequest;
use reqwest::{ClientBuilder, StatusCode};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct TestNetRequestAuth;

#[derive(Debug, thiserror::Error)]
pub enum TestNetRequestAuthError {
    #[error(transparent)]
    NotSupported(#[from] eyre::Report),
}

impl IntoResponse for TestNetRequestAuthError {
    fn into_response(self) -> axum::response::Response {
        tracing::debug!("{self:?}");
        match self {
            TestNetRequestAuthError::NotSupported(_) => (
                StatusCode::NOT_IMPLEMENTED,
                "This operation is not supported on the test network.",
            )
                .into_response(),
        }
    }
}

pub struct TestNetRequestAuthenticator {
    client: reqwest::Client,
    api_key: String,
}

impl TestNetRequestAuthenticator {
    pub async fn init(api_key: String) -> eyre::Result<Self> {
        let client = ClientBuilder::new()
            .build()
            .context("while building reqwest client")?;

        Ok(Self { client, api_key })
    }
}

#[async_trait]
impl OprfRequestAuthenticator for TestNetRequestAuthenticator {
    type RequestAuth = TestNetRequestAuth;
    type RequestAuthError = TestNetRequestAuthError;

    async fn verify(
        &self,
        _request: &OprfRequest<Self::RequestAuth>,
    ) -> Result<(), Self::RequestAuthError> {
        Ok(())
    }
}
