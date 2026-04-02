//! This module implements a basic request authenticator for the testnet environment that only verifies the API key.
//!
//! It is intended as a very basic example of how to implement a request authenticator.
use async_trait::async_trait;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use taceo_oprf::{
    service::Environment,
    types::{
        OprfKeyId,
        api::{OprfRequest, OprfRequestAuthenticator, OprfRequestAuthenticatorError},
    },
};

use crate::{
    AuthModule,
    unkey_api::{self},
};

/// The authentication information that is sent alongside the OPRF request in the basic module.
#[derive(Clone, Serialize, Deserialize)]
pub struct BasicTestNetRequestAuth {
    /// The API key to verify against the unkey API.
    pub api_key: String,
}

/// The server side implementation of the basic authentication module.
pub struct BasicTestNetRequestAuthenticator {
    client: reqwest::Client,
    root_api_key: SecretString,
    env: Environment,
}

impl BasicTestNetRequestAuthenticator {
    /// Initializes the basic request authenticator with the given root API key and environment.
    ///
    /// The root API key is used to grant this service permission to verify incoming API keys with the unkey API.
    /// The `env` is used to determin if we go to the API at all, if it is set to `Environment::Dev` we skip the API call and just verify that the API key is not empty.
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
    type RequestAuth = BasicTestNetRequestAuth;

    async fn authenticate(
        &self,
        req: &OprfRequest<Self::RequestAuth>,
    ) -> Result<OprfKeyId, OprfRequestAuthenticatorError> {
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
        Ok(AuthModule::Basic.oprf_key_id())
    }
}
