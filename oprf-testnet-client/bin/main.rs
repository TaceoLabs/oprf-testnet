use alloy::signers::k256::ecdsa::SigningKey;
use ark_ff::UniformRand as _;
use clap::Parser;
use eyre::Context;
use oprf_testnet_authentication::AuthModule;
use rustls::{ClientConfig, RootCertStore};
use std::{path::PathBuf, process, sync::Arc};
use taceo_oprf::client::Connector;

#[derive(Parser, Debug, Clone)]
pub struct WalletOwnershipConfig {
    /// The directory to write the nullifier prove and public inputs to.
    #[clap(long, default_value = ".")]
    pub out: PathBuf,
}

#[derive(Parser, Debug, Clone)]
pub enum AuthModuleArg {
    Basic,
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
        AuthModuleArg::Basic => {
            tracing::info!("Running basic verifiable OPRF...");
            let action = ark_babyjubjub::Fq::rand(&mut rng);
            let verifiable_oprf_output = taceo_oprf_testnet_client::basic_verifiable_oprf(
                &config.nodes,
                config.threshold,
                AuthModule::Basic.oprf_key_id(),
                config.api_key,
                action,
                connector,
                &mut rng,
            )
            .await?;
            tracing::info!("OPRF output: {}", verifiable_oprf_output.output);
        }
        AuthModuleArg::WalletOwnership(WalletOwnershipConfig { out }) => {
            check_noir_and_bb_installed()?;
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

fn check_noir_and_bb_installed() -> eyre::Result<()> {
    tracing::debug!("Checking if Noir and BB are installed...");
    let nargo_output = std::process::Command::new("nargo")
        .arg("--version")
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .output()
        .context("The 'nargo' binary is not installed or not found in PATH. Please install Noir to get 'nargo' from https://noir-lang.org/docs/getting_started/quick_start")?;

    eyre::ensure!(
        nargo_output.status.success(),
        "The 'nargo' binary is not installed or not found in PATH. Please install Noir to get 'nargo' from https://noir-lang.org/docs/getting_started/quick_start"
    );

    let bb_output = std::process::Command::new("bb")
        .arg("--version")
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .output()
        .context("The 'bb' binary is not installed or not found in PATH. Please install Barretenberg to get 'bb' from from https://barretenberg.aztec.network/docs/getting_started/")?;
    eyre::ensure!(
        bb_output.status.success(),
        "The 'bb' binary is not installed or not found in PATH. Please install Barretenberg to get 'bb' from from https://barretenberg.aztec.network/docs/getting_started/"
    );
    Ok(())
}
