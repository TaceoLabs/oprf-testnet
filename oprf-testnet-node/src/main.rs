//! OPRF Service Binary
//!
//! This is the main entry point for the OPRF node service.
//! It initializes tracing, metrics, and starts the service with configuration
//! from command-line arguments or environment variables.

use std::{process::ExitCode, sync::Arc};

use eyre::Context;
use taceo_oprf::service::secret_manager::postgres::PostgresSecretManager;
use taceo_oprf_testnet_node::config::load_oprf_testnet_config;

#[tokio::main]
async fn main() -> eyre::Result<ExitCode> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");
    let tracing_config = nodes_observability::TracingConfig::try_from_env()?;
    let _tracing_handle = nodes_observability::initialize_tracing(&tracing_config)?;
    taceo_oprf::service::metrics::describe_metrics();

    tracing::info!("{}", nodes_common::version_info!());

    let config = load_oprf_testnet_config().context("while loading config")?;

    // Load the AWS secret manager.
    let secret_manager = Arc::new(
        PostgresSecretManager::init(&config.postgres_config)
            .await
            .context("while starting postgres secret-manager")?,
    );

    let result = taceo_oprf_testnet_node::start(
        config,
        secret_manager,
        nodes_common::default_shutdown_signal(),
    )
    .await;
    match result {
        Ok(()) => {
            tracing::info!("good night!");
            Ok(ExitCode::SUCCESS)
        }
        Err(err) => {
            // we don't want to double print the error therefore we just return FAILURE
            tracing::error!("{err:?}");
            Ok(ExitCode::FAILURE)
        }
    }
}
