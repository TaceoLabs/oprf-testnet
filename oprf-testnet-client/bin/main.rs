use std::str::FromStr;

use alloy::signers::k256::ecdsa::SigningKey;
use clap::Parser;
use eyre::Context;
use oprf_testnet_authentication::AuthModule;
use rustls::{ClientConfig, RootCertStore};
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
    /// The directory to write the nullifier prove and public inputs to.
    #[clap(long, default_value = ".")]
    pub out: PathBuf,
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
    #[clap(long, env = "OPRF_CLIENT_NODES", value_delimiter = ',')]
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
        AuthModuleArg::WalletOwnership(WalletOwnershipConfig { out }) => {
            check_bb_version()?;
            tracing::info!("Running wallet ownership verifiable OPRF...");
            let private_key = SigningKey::random(&mut rng);
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
            tracing::info!("Writing nullifier proof and public inputs to {out:?}");
            std::fs::write(out.join("proof"), &proof)?;
            std::fs::write(out.join("public_inputs"), &pulic_inputs)?;
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
        "The 'bb' binary version is {version}, but version {BB_VERSION} is required. Please install the correct version using 'bbup -nv 1.0.0-beta.18 "
    );
    Ok(())
}
