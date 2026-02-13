use std::str::FromStr;

use alloy::{hex, signers::k256::ecdsa::SigningKey};
use clap::Parser;
use eyre::Context;
use oprf_testnet_authentication::AuthModule;
use rustls::{ClientConfig, RootCertStore};
use secrecy::{ExposeSecret, SecretString};
use std::{path::PathBuf, sync::Arc};
use taceo_oprf::client::Connector;

const BB_VERSION: &str = "3.0.0-nightly.20260102";

#[derive(Parser, Debug, Clone)]
pub struct BasicConfig {
    /// The input (field element) for the OPRF evaluation, represented as a string.
    #[clap(long)]
    pub input: String,
}

#[derive(Parser, Debug, Clone)]
pub struct WalletOwnershipConfig {
    /// The wallet private key, represented as a hex string
    #[clap(long)]
    pub private_key: Option<SecretString>,

    /// The directory to write the nullifier prove and public inputs to.
    #[clap(long, default_value = ".")]
    pub output_path: PathBuf,
}

#[derive(Parser, Debug, Clone)]
pub enum AuthModuleArg {
    Basic(BasicConfig),
    WalletOwnership(WalletOwnershipConfig),
}

/// The configuration for the OPRF client.
///
/// It can be configured via environment variables or command line arguments using `clap`.
#[derive(Parser, Debug)]
pub struct OprfClientConfig {
    /// The URLs to all OPRF nodes
    #[clap(
        long,
        env = "OPRF_CLIENT_NODES",
        value_delimiter = ',',
        default_value = "https://node0.eu.test.oprf.taceo.network,https://node1.eu.test.oprf.taceo.network,https://node2.eu.test.oprf.taceo.network"
    )]
    pub nodes: Vec<String>,

    /// The threshold of services that need to respond
    #[clap(long, env = "OPRF_CLIENT_THRESHOLD", default_value = "2")]
    pub threshold: usize,

    /// The API Key
    #[clap(long, env = "OPRF_CLIENT_API_KEY")]
    pub api_key: String,

    #[clap(subcommand)]
    pub module: AuthModuleArg,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    nodes_observability::install_tracing("info");
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");
    let mut rng = rand::thread_rng();
    let config = OprfClientConfig::parse();
    tracing::info!("starting oprf-testnet-client with config: {config:#?}");

    // setup TLS config - even if we are http
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let rustls_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = Connector::Rustls(Arc::new(rustls_config));

    match config.module {
        AuthModuleArg::Basic(BasicConfig { input }) => {
            tracing::info!("Running basic verifiable OPRF...");
            let input_str = input.clone();
            let input = ark_babyjubjub::Fq::from_str(&input)
                .map_err(|_| eyre::eyre!("Invalid input, must be a field element"))?;
            eyre::ensure!(
                input_str == input.to_string(),
                "Parsed input does not match original string, this can happen if there are leading zeros, leading signs, or if the number is larger than the field modulus",
            );
            let verifiable_oprf_output = taceo_oprf_testnet_client::basic_verifiable_oprf(
                &config.nodes,
                config.threshold,
                AuthModule::Basic.oprf_key_id(),
                config.api_key,
                input,
                connector,
                &mut rng,
            )
            .await?;
            tracing::info!("OPRF output: {}", verifiable_oprf_output.output);
        }
        AuthModuleArg::WalletOwnership(WalletOwnershipConfig {
            output_path,
            private_key,
        }) => {
            check_bb_version()?;
            tracing::info!("Running wallet ownership verifiable OPRF...");
            let private_key = if let Some(private_key) = private_key {
                let private_key_bytes = hex::decode(private_key.expose_secret())
                    .context("Invalid private key hex string, must be a 32-byte hex string optionally prefixed with 0x")?;
                SigningKey::from_slice(&private_key_bytes)
                    .context("Invalid private key, must be a valid secp256k1 private key")?
            } else {
                let private_key = SigningKey::random(&mut rng);
                tracing::info!(
                    "Generated random wallet with private key 0x{}",
                    hex::encode(private_key.to_bytes())
                );
                private_key
            };
            let (verifiable_oprf_output, pulic_inputs, proof) =
                taceo_oprf_testnet_client::wallet_ownership_verifiable_oprf(
                    &config.nodes,
                    config.threshold,
                    AuthModule::WalletOwnership.oprf_key_id(),
                    config.api_key,
                    private_key,
                    connector,
                    &mut rng,
                )
                .await?;
            std::fs::write(output_path.join("proof"), &proof)?;
            std::fs::write(output_path.join("public_inputs"), &pulic_inputs)?;
            tracing::info!("Nullifier: {}", verifiable_oprf_output.output);
        }
    }

    Ok(())
}

fn check_bb_version() -> eyre::Result<()> {
    tracing::debug!("Checking if 'bb' version {BB_VERSION} is installed..");
    let bb_output = std::process::Command::new("bb")
        .arg("--version")
        .output()
        .context("The 'bb' binary is not installed or not found in PATH. Please install Barretenberg to get 'bb' from from https://barretenberg.aztec.network/docs/getting_started/")?;
    let version = String::from_utf8(bb_output.stdout)?;
    let version = version.trim();
    eyre::ensure!(
        version == BB_VERSION,
        "The 'bb' binary version is {version}, but version {BB_VERSION} is required. Please install the correct version using 'bbup -nv 1.0.0-beta.18'"
    );
    Ok(())
}
