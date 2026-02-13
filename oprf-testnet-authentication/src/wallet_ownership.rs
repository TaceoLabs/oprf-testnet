//! This module implements a more complex request authenticator for the testnet environment that additionally verifies a zero-knowledge proof.
//!
//! It is intended to show how a more complex authentication flow can look like.
use std::path::PathBuf;

use async_trait::async_trait;
use axum::response::{self, IntoResponse};
use eyre::Context;
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

use crate::{
    AuthModule,
    unkey_api::{self, ApiVerificationError},
};

/// The authentication information that is sent alongside the OPRF request in the `wallet_ownership` module.
#[derive(Clone, Serialize, Deserialize)]
pub struct TestNetRequestAuth {
    /// The public inputs to the proof
    pub public_inputs: Vec<u8>,
    /// The proof that the client owns the wallet corresponding to the public key that was used to generate the OPRF request
    pub proof: Vec<u8>,
    /// The API key to verify against the unkey API.
    pub api_key: String,
}

/// The possible errors that can occur during authentication of an OPRF request in the `wallet_ownership` module.
#[derive(Debug, thiserror::Error)]
pub enum TestNetRequestAuthError {
    /// The proof provided by the client is invalid.
    #[error("Proof invalid")]
    ProofInvalid,
    /// An error occurred while verifying the API key with the unkey API.
    #[error(transparent)]
    ApiVerificationError(#[from] ApiVerificationError),
    /// Generic internal server error.
    #[error(transparent)]
    InternalServerError(#[from] eyre::Report),
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

/// The server side implementation of the `wallet_ownership` authentication module.
pub struct WalletOwnershipTestNetRequestAuthenticator {
    client: reqwest::Client,
    root_api_key: SecretString,
    env: Environment,
    vk_path: PathBuf,
}

impl WalletOwnershipTestNetRequestAuthenticator {
    /// Initializes the basic request authenticator with the given root API key and environment.
    ///
    /// The root API key is used to grant this service permission to verify incoming API keys with the unkey API.
    /// The `env` is used to determin if we go to the API at all, if it is set to `Environment::Dev` we skip the API call and just verify that the API key is not empty.
    /// The `vk_path` is the path to the verification key used to verify the zero-knowledge proofs sent by the client.
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
            async move { unkey_api::verify_api_key(client, root_api_key, api_key, env).await }
        });

        zk::verify_proof(&req.auth.public_inputs, &req.auth.proof, &self.vk_path)?;
        api_valid.await.context("awaiting api verification")??;
        tracing::debug!("Authentication successful");
        Ok(AuthModule::WalletOwnership.oprf_key_id())
    }
}

///  Module for handling zero-knowledge proof generation and verification using the `bb` CLI tool.
pub mod zk {
    use std::{
        io::Write,
        path::Path,
        process::{self, Command},
    };

    use alloy::primitives::FixedBytes;
    use bn254_blackbox_solver::Bn254BlackBoxSolver;
    use eyre::Context;
    use nargo::foreign_calls::DefaultForeignCallBuilder;
    use noir_artifact_cli::Artifact;
    use noirc_artifacts::program::CompiledProgram;
    use taceo_oprf::{client::VerifiableOprfOutput, core::oprf::BlindingFactor};
    use tempfile::{NamedTempFile, TempDir};

    use crate::wallet_ownership::TestNetRequestAuthError;

    const BLINDED_QUERY_PROOF_PROGRAM_ARTIFACT: &[u8] =
        include_bytes!("../blinded_query_proof.json");
    const BLINDED_QUERY_PROOF_VK: &[u8] = include_bytes!("../blinded_query_proof.vk");
    const VERIFIED_OPRF_PROOF_PROGRAM_ARTIFACT: &[u8] =
        include_bytes!("../verified_oprf_proof.json");
    /// The verification key for the proof that verifies the OPRF output and wallet ownership.
    pub const VERIFIED_OPRF_PROOF_VK: &[u8] = include_bytes!("../verified_oprf_proof.vk");

    /// Computes a zero-knowledge proof that the client owns the wallet corresponding to the public key used in the OPRF request and that the OPRF output was correctly computed.
    pub fn compute_nullifier_proof(
        verifiable_oprf_output: VerifiableOprfOutput,
        signature: Vec<u8>,
        msg_hash: FixedBytes<32>,
        beta: &BlindingFactor,
        pubkey_x: Vec<u8>,
        pubkey_y: Vec<u8>,
    ) -> eyre::Result<(Vec<u8>, Vec<u8>)> {
        let temp_dir =
            TempDir::new().context("creating temporary directory for proof generation")?;
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

    /// Computes a zero-knowledge proof that the client owns the wallet corresponding to the public key used in the OPRF request.
    ///
    /// This is used as the query authorization proof in the `wallet_ownership` module.
    pub fn compute_wallet_ownership_proof(
        beta: &BlindingFactor,
        pubkey_x: &[u8],
        pubkey_y: &[u8],
        signature: &[u8],
        hashed_msg: &[u8],
    ) -> eyre::Result<(Vec<u8>, Vec<u8>)> {
        let temp_dir =
            TempDir::new().context("creating temporary directory for proof generation")?;
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

    /// Generates a witness file for the given program artifact and Prover.toml file using the bundled Noir and writes it to the given witness path.
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

    /// Verifies a proof using the `bb` CLI tool. The given public inputs and proof file are written to tempfiles and verified against the passed verification key.
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
}
