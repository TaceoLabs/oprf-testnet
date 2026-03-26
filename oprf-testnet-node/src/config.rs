//! Configuration types and CLI/environment parsing for the OPRF service.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use config::{Config, Environment};
use eyre::Context;
use nodes_common::postgres::PostgresConfig;
use secrecy::SecretString;
use serde::Deserialize;
use taceo_oprf::service::config::OprfNodeServiceConfig;

/// The configuration for the OPRF node.
///
/// It can be configured via environment variables or command line arguments using `clap`.
#[derive(Debug, Clone, Deserialize)]
pub struct TestNetNodeConfig {
    /// The bind addr of the AXUM server
    #[serde(default = "default_bind_addr")]
    pub bind_addr: SocketAddr,
    /// Max wait time the service waits for its workers during shutdown.
    #[serde(default = "default_max_wait_shutdown")]
    #[serde(with = "humantime_serde")]
    pub max_wait_time_shutdown: Duration,

    /// The Unkey root key
    pub unkey_verify_key: SecretString,

    /// The path to the wallet ownership verification key
    pub vk_path: PathBuf,

    /// The OPRF service config
    #[serde(rename = "service")]
    pub node_config: OprfNodeServiceConfig,

    /// The postgres config for the secret-manager
    #[serde(rename = "postgres")]
    pub postgres_config: PostgresConfig,
}

/// Loads the OPRF testnet node configuration from environment variables.
pub fn load_oprf_testnet_config() -> eyre::Result<TestNetNodeConfig> {
    let cfg =
        Config::builder().add_source(Environment::with_prefix("TACEO_OPRF_NODE").separator("__"));

    cfg.build()
        .context("while building from config")?
        .try_deserialize()
        .context("while parsing config")
}

fn default_bind_addr() -> SocketAddr {
    "0.0.0.0:4321".parse().expect("valid SocketAddr")
}

const fn default_max_wait_shutdown() -> Duration {
    Duration::from_secs(10)
}
