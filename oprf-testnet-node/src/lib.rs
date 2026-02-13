//! This example project shows the structure of a TACEO:OPRF node.
//!
//! It initializes the OPRF service with two authentication modules (basic and wallet ownership) and starts an axum server to handle incoming requests.
#![deny(missing_docs)]
use std::sync::{Arc, atomic::Ordering};

use oprf_testnet_authentication::{
    AuthModule, basic::BasicTestNetRequestAuthenticator,
    wallet_ownership::WalletOwnershipTestNetRequestAuthenticator,
};
use taceo_oprf::service::{
    OprfServiceBuilder, StartedServices, secret_manager::SecretManagerService,
};

use crate::config::TestNetNodeConfig;

pub mod config;

/// Starts the OPRF testnet node with the given configuration and secret manager. The node will run until the provided shutdown signal is triggered, at which point it will attempt to gracefully shut down all services within the specified maximum wait time.
pub async fn start(
    config: TestNetNodeConfig,
    secret_manager: SecretManagerService,
    shutdown_signal: impl std::future::Future<Output = ()> + Send + 'static,
) -> eyre::Result<()> {
    tracing::info!("starting oprf-testnet-node with config: {config:#?}");
    let service_config = config.service_config;
    let (cancellation_token, is_graceful_shutdown) =
        nodes_common::spawn_shutdown_task(shutdown_signal);

    tracing::info!("init basic oprf request auth service..");
    let basic_oprf_req_auth_service = Arc::new(BasicTestNetRequestAuthenticator::init(
        config.unkey_verify_key.clone(),
        service_config.environment,
    ));

    tracing::info!("init wallet ownership oprf request auth service..");
    let wallet_ownership_oprf_req_auth_service =
        Arc::new(WalletOwnershipTestNetRequestAuthenticator::init(
            config.unkey_verify_key.clone(),
            service_config.environment,
            config.vk_path,
        ));

    tracing::info!("init oprf service..");
    let (oprf_service_router, key_event_watcher) = OprfServiceBuilder::init(
        service_config,
        secret_manager,
        StartedServices::default(),
        cancellation_token.clone(),
    )
    .await?
    .module(&AuthModule::Basic.to_path(), basic_oprf_req_auth_service)
    .module(
        &AuthModule::WalletOwnership.to_path(),
        wallet_ownership_oprf_req_auth_service,
    )
    .build();

    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    let axum_cancel_token = cancellation_token.clone();
    let server = tokio::spawn(async move {
        tracing::info!(
            "starting axum server on {}",
            listener
                .local_addr()
                .map(|x| x.to_string())
                .unwrap_or(String::from("invalid addr"))
        );
        let axum_shutdown_signal = axum_cancel_token.clone();
        let axum_result = axum::serve(listener, oprf_service_router)
            .with_graceful_shutdown(async move { axum_shutdown_signal.cancelled().await })
            .await;
        tracing::info!("axum server shutdown");
        if let Err(err) = axum_result {
            tracing::error!("got error from axum: {err:?}");
        }
        // we cancel the token in case axum encountered an error to shutdown the service
        axum_cancel_token.cancel();
    });

    tracing::info!("everything started successfully - now waiting for shutdown...");
    cancellation_token.cancelled().await;

    tracing::info!(
        "waiting for shutdown of services (max wait time {:?})..",
        config.max_wait_time_shutdown
    );
    match tokio::time::timeout(config.max_wait_time_shutdown, async move {
        tokio::join!(server, key_event_watcher)
    })
    .await
    {
        Ok(_) => tracing::info!("successfully finished shutdown in time"),
        Err(_) => tracing::warn!("could not finish shutdown in time"),
    }
    if is_graceful_shutdown.load(Ordering::Relaxed) {
        Ok(())
    } else {
        eyre::bail!("Unexpected shutdown - check error logs")
    }
}
