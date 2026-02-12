use alloy::primitives::FixedBytes;
use alloy::primitives::U160;
use async_trait::async_trait;
use axum::response;
use axum::response::IntoResponse;
use bn254_blackbox_solver::Bn254BlackBoxSolver;
use eyre::Context as _;
use nargo::foreign_calls::DefaultForeignCallBuilder;
use noir_artifact_cli::Artifact;
use noirc_artifacts::program::CompiledProgram;
use reqwest::Client;
use reqwest::StatusCode;
use secrecy::ExposeSecret as _;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::Write as _;
use std::path::Path;
use std::path::PathBuf;
use std::process;
use std::process::Command;
use taceo_oprf::client::VerifiableOprfOutput;
use taceo_oprf::core::oprf::BlindingFactor;
use taceo_oprf::service::config::Environment;
use taceo_oprf::types::OprfKeyId;
use taceo_oprf::types::api::{OprfRequest, OprfRequestAuthenticator};
use tempfile::NamedTempFile;
use tempfile::TempDir;

const BLINDED_QUERY_PROOF_PROGRAM_ARTIFACT: &[u8] = include_bytes!("../blinded_query_proof.json");
const BLINDED_QUERY_PROOF_VK: &[u8] = include_bytes!("../blinded_query_proof.vk");
const VERIFIED_OPRF_PROOF_PROGRAM_ARTIFACT: &[u8] = include_bytes!("../verified_oprf_proof.json");
pub const VERIFIED_OPRF_PROOF_VK: &[u8] = include_bytes!("../verified_oprf_proof.vk");

#[derive(Debug, Clone)]
pub enum AuthModule {
    Basic,
    WalletOwnership,
}

impl AuthModule {
    pub fn to_path(&self) -> String {
        format!("/{self}")
    }

    pub fn oprf_key_id(&self) -> OprfKeyId {
        match self {
            Self::Basic => OprfKeyId::new(U160::from(1)),
            Self::WalletOwnership => OprfKeyId::new(U160::from(2)),
        }
    }
}

impl fmt::Display for AuthModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Basic => "basic",
            Self::WalletOwnership => "wallet-ownership",
        };
        write!(f, "{s}")
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

pub struct WalletOwnershipTestNetRequestAuthenticator {
    client: reqwest::Client,
    root_api_key: SecretString,
    env: Environment,
    vk_path: PathBuf,
}

pub struct BasicTestNetRequestAuthenticator {
    client: reqwest::Client,
    root_api_key: SecretString,
    env: Environment,
}

impl WalletOwnershipTestNetRequestAuthenticator {
    pub fn init(root_api_key: SecretString, env: Environment, vk_path: PathBuf) -> Self {
        let client = reqwest::Client::new();
        Self {
            client,
            root_api_key,
            env,
            vk_path,
        }
    }
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
impl OprfRequestAuthenticator for WalletOwnershipTestNetRequestAuthenticator {
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

        verify_proof(&req.auth.public_inputs, &req.auth.proof, &self.vk_path)?;
        api_valid.await.context("awaiting api verification")??;
        tracing::debug!("Authentication successful");
        Ok(req.auth.oprf_key_id)
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
    let temp_dir = TempDir::new().context("creating temporary directory for proof generation")?;
    let path = temp_dir.path();
    let program_artifact = path.join("program_artifact.json");
    let vk = path.join("vk");
    let input = path.join("Prover.toml");
    let witness = path.join("witness.gz");

    std::fs::write(&program_artifact, VERIFIED_OPRF_PROOF_PROGRAM_ARTIFACT)?;

    std::fs::write(&vk, VERIFIED_OPRF_PROOF_VK)?;

    std::fs::write(
        &input,
        format!(
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
        ),
    )?;

    generate_witness(&program_artifact, &input, &witness)?;

    generate_proof(path, &program_artifact, &witness, &vk)
}

pub fn compute_wallet_ownership_proof(
    beta: &BlindingFactor,
    pubkey_x: &[u8],
    pubkey_y: &[u8],
    signature: &[u8],
    hashed_msg: &[u8],
) -> eyre::Result<(Vec<u8>, Vec<u8>)> {
    let temp_dir = TempDir::new().context("creating temporary directory for proof generation")?;
    let path = temp_dir.path();
    let program_artifact = path.join("program_artifact.json");
    let vk = path.join("vk");
    let input = path.join("Prover.toml");
    let witness = path.join("witness.gz");

    std::fs::write(&program_artifact, BLINDED_QUERY_PROOF_PROGRAM_ARTIFACT)?;

    std::fs::write(&vk, BLINDED_QUERY_PROOF_VK)?;

    std::fs::write(
        &input,
        format!(
            "beta = \"{:?}\"\npub_key_x = {:?}\npub_key_y = {:?}\nsignature = {:?}\nhashed_message = {:?}",
            beta.beta(),
            pubkey_x,
            pubkey_y,
            signature,
            hashed_msg
        ),
    )?;

    generate_witness(&program_artifact, &input, &witness)?;

    generate_proof(path, &program_artifact, &witness, &vk)
}

pub fn generate_witness(
    artifact_path: &Path,
    prover_file: &Path,
    witness_path: &Path,
) -> eyre::Result<()> {
    let artifact = Artifact::read_from_file(artifact_path)?;

    let circuit: CompiledProgram = match artifact {
        Artifact::Program(program) => program.into(),
        _ => eyre::bail!("Expected a program artifact"),
    };

    let transcript_executor = nargo::foreign_calls::layers::Empty;
    let mut foreign_call_executor = DefaultForeignCallBuilder {
        output: std::io::stdout(),
        enable_mocks: false,
        resolver_url: None,
        root_path: None,
        package_name: None,
    }
    .build_with_base(transcript_executor);

    let blackbox_solver = Bn254BlackBoxSolver(false);

    let execution_res = noir_artifact_cli::execution::execute(
        &circuit,
        &blackbox_solver,
        &mut foreign_call_executor,
        prover_file,
    )?;

    std::fs::write(witness_path, execution_res.witness_stack.serialize()?)?;

    Ok(())
}

fn generate_proof(
    path: &Path,
    program_artifact: &Path,
    witness: &Path,
    vk: &Path,
) -> eyre::Result<(Vec<u8>, Vec<u8>)> {
    let bb_prove_status = Command::new("bb")
        .arg("prove")
        .arg("-b")
        .arg(program_artifact)
        .arg("-k")
        .arg(vk)
        .arg("-w")
        .arg(witness)
        .current_dir(path)
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .status()
        .context("while spawning bb prove")?;

    eyre::ensure!(
        bb_prove_status.success(),
        "'bb prove' failed with status code: {:?}",
        bb_prove_status.code()
    );

    let public_inputs = std::fs::read(path.join("out/public_inputs"))?;
    let proof = std::fs::read(path.join("out/proof"))?;

    Ok((public_inputs, proof))
}

pub fn verify_proof(
    public_inputs: &[u8],
    proof: &[u8],
    vk_path: &Path,
) -> Result<(), TestNetRequestAuthError> {
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
