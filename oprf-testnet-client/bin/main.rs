use alloy::primitives::U160;
use ark_ff::UniformRand as _;
use clap::Parser;
use oprf_testnet_authentication::AuthModule;
use rand::SeedableRng as _;
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;
use taceo_oprf::{client::Connector, types::OprfKeyId};
use taceo_oprf_testnet_client::{DistributedOprfArgs, distributed_oprf};

/// The configuration for the OPRF client.
///
/// It can be configured via environment variables or command line arguments using `clap`.
#[derive(Parser, Debug)]
pub struct OprfDevClientConfig {
    /// The URLs to all OPRF nodes
    #[clap(long, env = "OPRF_CLIENT_NODES", value_delimiter = ',')]
    pub nodes: Vec<String>,

    /// The threshold of services that need to respond
    #[clap(long, env = "OPRF_CLIENT_THRESHOLD", default_value = "2")]
    pub threshold: usize,

    /// rp id of already registered rp
    #[clap(long, env = "OPRF_CLIENT_OPRF_KEY_ID")]
    pub oprf_key_id: U160,

    /// The API Key
    #[clap(long, env = "OPRF_CLIENT_API_KEY")]
    pub api_key: String,

    /// If we use the API only use-case
    #[clap(long, env = "OPRF_DEV_CLIENT_API_ONLY", default_value = "false")]
    pub api_only: bool,
}

async fn run_oprf(
    nodes: &[String],
    threshold: usize,
    api_key: String,
    module: AuthModule,
    oprf_key_id: OprfKeyId,
    connector: Connector,
) -> eyre::Result<()> {
    let mut rng = rand_chacha::ChaCha12Rng::from_entropy();

    let action = ark_babyjubjub::Fq::rand(&mut rng);

    // the client example internally checks the DLog equality
    let _verifiable_oprf = distributed_oprf(
        DistributedOprfArgs {
            services: nodes,
            threshold,
            api_key,
            module,
            oprf_key_id,
            action,
            connector,
        },
        &mut rng,
    )
    .await?;
    Ok(())
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");
    let config = OprfDevClientConfig::parse();
    tracing::info!("starting oprf-dev-client with config: {config:#?}");

    // setup TLS config - even if we are http
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let rustls_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = Connector::Rustls(Arc::new(rustls_config));
    let module = match config.api_only {
        true => AuthModule::TestNetApiOnly,
        false => AuthModule::TestNet,
    };

    run_oprf(
        &config.nodes,
        config.threshold,
        config.api_key,
        module,
        config.oprf_key_id.into(),
        connector,
    )
    .await?;
    tracing::info!("oprf-test successful");

    Ok(())
}
