use alloy::primitives::FixedBytes;
use async_trait::async_trait;
use axum::response;
use axum::response::IntoResponse;
use eyre::Context as _;
use reqwest::Client;
use reqwest::StatusCode;
use secrecy::ExposeSecret as _;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::fs::File;
use std::io::Write as _;
use std::process;
use std::process::Command;
use std::str::FromStr;
use taceo_oprf::client::VerifiableOprfOutput;
use taceo_oprf::core::oprf::BlindingFactor;
use taceo_oprf::service::config::Environment;
use taceo_oprf::types::OprfKeyId;
use taceo_oprf::types::api::{OprfRequest, OprfRequestAuthenticator};
use tempfile::NamedTempFile;

#[derive(Debug, Clone)]
pub enum AuthModule {
    TestNet,
    TestNetApiOnly,
}

impl AuthModule {
    pub fn to_path(&self) -> String {
        format!("/{self}")
    }
}

impl fmt::Display for AuthModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::TestNet => "testnet",
            Self::TestNetApiOnly => "testnet-api-only",
        };
        write!(f, "{s}")
    }
}

impl FromStr for AuthModule {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "testnet" => Ok(AuthModule::TestNet),
            "testnet-api-only" => Ok(AuthModule::TestNetApiOnly),
            _ => Err(format!("Unknown AuthModule: {s}")),
        }
    }
}

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
    pub oprf_key_id: OprfKeyId,
    pub api_key: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TestNetApiOnlyRequestAuth {
    pub api_key: String,
    pub oprf_key_id: OprfKeyId,
}

#[derive(Debug, thiserror::Error)]
pub enum ApiVerificationError {
    #[error("API Key not valid")]
    ApiVerificationFailed,
    #[error(transparent)]
    InternalServerError(#[from] eyre::Report),
}

#[derive(Debug, thiserror::Error)]
pub enum TestNetApiOnlyRequestAuthError {
    #[error(transparent)]
    ApiVerificationError(#[from] ApiVerificationError),
    #[error(transparent)]
    InternalServerError(#[from] eyre::Report),
}

#[derive(Debug, thiserror::Error)]
pub enum TestNetRequestAuthError {
    #[error("Proof invalid")]
    ProofInvalid,
    #[error(transparent)]
    ApiVerificationError(#[from] ApiVerificationError),
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
            Self::InternalServerError(err) => {
                tracing::error!("Internal server error: {err:?}");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
            }
        }
    }
}

impl IntoResponse for TestNetRequestAuthError {
    fn into_response(self) -> response::Response {
        tracing::debug!("{self:?}");
        match self {
            Self::ProofInvalid => (StatusCode::BAD_REQUEST, "Proof is invalid").into_response(),
            Self::InternalServerError(err) => {
                tracing::error!("Internal server error: {err:?}");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
            }
            Self::ApiVerificationError(err) => err.into_response(),
        }
    }
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

pub struct TestNetRequestAuthenticator {
    client: reqwest::Client,
    root_api_key: SecretString,
    env: Environment,
}

pub struct TestNetApiOnlyRequestAuthenticator {
    client: reqwest::Client,
    root_api_key: SecretString,
    env: Environment,
}

impl TestNetRequestAuthenticator {
    pub fn init(root_api_key: SecretString, env: Environment) -> Self {
        let client = reqwest::Client::new();
        Self {
            client,
            root_api_key,
            env,
        }
    }
}

impl TestNetApiOnlyRequestAuthenticator {
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
impl OprfRequestAuthenticator for TestNetRequestAuthenticator {
    type RequestAuth = TestNetRequestAuth;
    type RequestAuthError = TestNetRequestAuthError;

    async fn authenticate(
        &self,
        req: &OprfRequest<Self::RequestAuth>,
    ) -> Result<OprfKeyId, Self::RequestAuthError> {
        tracing::debug!("Authenticating with API Key and Proof");
        //call API
        let api_valid = tokio::task::spawn({
            let client = self.client.clone();
            let root_api_key = self.root_api_key.clone();
            let api_key = req.auth.api_key.clone();
            let env = self.env;
            async move { verify_api_key(client, root_api_key, api_key, env).await }
        });

        verify_proof(
            &req.auth.public_inputs,
            &req.auth.proof,
            VerificationType::BlindedQueryVerification,
        )?;
        api_valid.await.context("awaiting api verification")??;
        tracing::debug!("Authentication successful");
        Ok(req.auth.oprf_key_id)
    }
}

#[async_trait]
impl OprfRequestAuthenticator for TestNetApiOnlyRequestAuthenticator {
    type RequestAuth = TestNetApiOnlyRequestAuth;
    type RequestAuthError = TestNetApiOnlyRequestAuthError;

    async fn authenticate(
        &self,
        req: &OprfRequest<Self::RequestAuth>,
    ) -> Result<OprfKeyId, Self::RequestAuthError> {
        tracing::debug!("Authenticating with only API");

        //call API
        verify_api_key(
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

async fn verify_api_key(
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
        return Err(ApiVerificationError::ApiVerificationFailed);
    }
    Ok(())
}

pub fn compute_nullifier_proof(
    verifiable_oprf_output: VerifiableOprfOutput,
    signature: Vec<u8>,
    msg_hash: FixedBytes<32>,
    beta: &BlindingFactor,
    pubkey_x: Vec<u8>,
    pubkey_y: Vec<u8>,
) -> eyre::Result<(Vec<u8>, Vec<u8>)> {
    let name_of_proof = "verified_oprf_proof";
    let directory = format!("noir/{}", name_of_proof);
    let input_file_path = format!("{}/Prover.toml", directory);
    let witness_path = format!("target/{}.gz", name_of_proof);
    let bytecode_path = format!("target/{}.json", name_of_proof);
    let mut prover_toml_file = File::create(input_file_path)?;

    write!(
        prover_toml_file,
        "signature = {:?}
        beta = \"{:?}\"
        dlog_e = \"{:?}\"
        dlog_s = \"{:?}\"
        hashed_message = {:?}
        pub_key_x = {:?}
        pub_key_y = {:?}

        [oprf_pk]
        x = \"{:?}\"
        y = \"{:?}\"

        [oprf_response]
        x = \"{:?}\"
        y = \"{:?}\"

        [oprf_response_blinded]
        x = \"{:?}\"
        y = \"{:?}\"",
        signature,
        beta.beta(),
        verifiable_oprf_output.dlog_proof.e,
        verifiable_oprf_output.dlog_proof.s,
        msg_hash.to_vec(),
        pubkey_x,
        pubkey_y,
        verifiable_oprf_output.oprf_public_key.inner().x,
        verifiable_oprf_output.oprf_public_key.inner().y,
        verifiable_oprf_output.unblinded_response.x,
        verifiable_oprf_output.unblinded_response.y,
        verifiable_oprf_output.blinded_response.x,
        verifiable_oprf_output.blinded_response.y
    )?;

    let nargo_exec_status = Command::new("nargo")
        .arg("execute")
        .current_dir(&directory)
        // .stdout(process::Stdio::null())
        // .stderr(process::Stdio::null())
        .status()
        .context("while spawning nargo execute")?;

    eyre::ensure!(
        nargo_exec_status.success(),
        "'nargo execute' failed with status code: {:?}",
        nargo_exec_status.code()
    );

    let bb_write_vk_status = Command::new("bb")
        .arg("write_vk")
        .arg("-b")
        .arg(&bytecode_path)
        .current_dir(&directory)
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .status()
        .context("while spawning bb write_vk")?;

    eyre::ensure!(
        bb_write_vk_status.success(),
        "'bb write_vk' failed with status code: {:?}",
        bb_write_vk_status.code()
    );

    let bb_prove_status = Command::new("bb")
        .arg("prove")
        .arg("-b")
        .arg(&bytecode_path)
        .arg("-k")
        .arg("out/vk")
        .arg("-w")
        .arg(witness_path)
        .current_dir(&directory)
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .status()
        .context("while spawning bb prove")?;

    eyre::ensure!(
        bb_prove_status.success(),
        "'bb prove' failed with status code: {:?}",
        bb_prove_status.code()
    );

    let public_inputs = fs::read(format!("{}/out/public_inputs", &directory))?;
    let proof = fs::read(format!("{}/out/proof", &directory))?;
    Ok((public_inputs, proof))
}

#[derive(Debug, Copy, Clone)]
pub enum VerificationType {
    BlindedQueryVerification,
    NullifierVerification,
}
pub fn verify_proof(
    public_inputs: &[u8],
    proof: &[u8],
    verification_type: VerificationType,
) -> eyre::Result<(), TestNetRequestAuthError> {
    let vk_path = match verification_type {
        VerificationType::BlindedQueryVerification => "noir/blinded_query_proof/out/vk",
        VerificationType::NullifierVerification => "noir/verified_oprf_proof/out/vk",
    };

    let mut public_input_file =
        NamedTempFile::new().context("creating public inputs NameTempFile")?;

    let mut proof_file = NamedTempFile::new().context("creating proof NameTempFile")?;

    public_input_file
        .write_all(public_inputs)
        .context("writing public inputs to temp file")?;

    proof_file
        .write_all(proof)
        .context("writing proof to temp file")?;

    tracing::debug!("Verifying proof with bb");
    let bb_verify_status = Command::new("bb")
        .arg("verify")
        .arg("-t")
        .arg("noir-recursive")
        .arg("-p")
        .arg(proof_file.path())
        .arg("-i")
        .arg(public_input_file.path())
        .arg("-k")
        .arg(vk_path)
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .status()
        .context("while spawning bb verify")?;

    if !bb_verify_status.success() {
        tracing::error!(
            "Proof verification failed with status code: {:?}",
            bb_verify_status.code()
        );
        return Err(TestNetRequestAuthError::ProofInvalid);
    }

    Ok(())
}

pub fn compute_wallet_ownership_proof(
    beta: &BlindingFactor,
    pubkey_x: &[u8],
    pubkey_y: &[u8],
    signature: &[u8],
    hashed_msg: &[u8],
) -> eyre::Result<(Vec<u8>, Vec<u8>)> {
    let name_of_proof = "blinded_query_proof";
    let directory = format!("noir/{}", name_of_proof);
    let input_file_path = format!("{}/Prover.toml", directory);
    let witness_path = format!("target/{}.gz", name_of_proof);
    let bytecode_path = format!("target/{}.json", name_of_proof);
    let mut prover_toml_file = File::create(input_file_path)?;

    write!(
        prover_toml_file,
        "beta = \"{:?}\"\npub_key_x = {:?}\npub_key_y = {:?}\nsignature = {:?}\nhashed_message = {:?}",
        beta.beta(),
        pubkey_x,
        pubkey_y,
        signature,
        hashed_msg
    )?;

    let nargo_exec_status = Command::new("nargo")
        .arg("execute")
        .current_dir(&directory)
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .status()
        .context("while spawning nargo execute")?;

    eyre::ensure!(
        nargo_exec_status.success(),
        "'nargo execute' failed with status code: {:?}",
        nargo_exec_status.code()
    );

    let bb_write_vk_status = Command::new("bb")
        .arg("write_vk")
        .arg("-b")
        .arg(&bytecode_path)
        .current_dir(&directory)
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .status()
        .context("while spawning bb write_vk")?;

    eyre::ensure!(
        bb_write_vk_status.success(),
        "'bb write_vk' failed with status code: {:?}",
        bb_write_vk_status.code()
    );

    let bb_prove_status = Command::new("bb")
        .arg("prove")
        .arg("-b")
        .arg(&bytecode_path)
        .arg("-k")
        .arg("out/vk")
        .arg("-w")
        .arg(witness_path)
        .current_dir(&directory)
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .status()
        .context("while spawning bb prove")?;

    eyre::ensure!(
        bb_prove_status.success(),
        "'bb prove' failed with status code: {:?}",
        bb_prove_status.code()
    );

    let public_inputs = fs::read(format!("{}/out/public_inputs", &directory))?;
    let proof = fs::read(format!("{}/out/proof", &directory))?;
    Ok((public_inputs, proof))
}
