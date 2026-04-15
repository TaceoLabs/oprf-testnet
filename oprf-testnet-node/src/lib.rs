//! This example project shows the structure of a TACEO:OPRF node.
//!
//! It initializes the OPRF service with two authentication modules (basic and wallet ownership) and starts an axum server to handle incoming requests.
#![deny(missing_docs)]
use std::sync::{Arc, atomic::Ordering};

use crate::config::TestNetNodeConfig;
use alloy_primitives::address;
use axum::{
    Router,
    extract::Request,
    http::StatusCode,
    middleware::{Next, from_fn},
    response::Response,
    routing::get,
};
use oprf_testnet_authentication::{
    AuthModule, basic::BasicTestNetRequestAuthenticator,
    wallet_ownership::WalletOwnershipTestNetRequestAuthenticator,
};
use taceo_oprf::service::{
    OprfServiceBuilder, StartedServices, secret_manager::SecretManagerService,
};
use x402_axum::X402Middleware;
use x402_chain_eip155::{KnownNetworkEip155, V2Eip155Exact};
use x402_types::networks::USDC;

pub mod config;

async fn log_x402_request(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let has_x_payment = req.headers().contains_key("X-Payment");
    let has_payment_signature = req.headers().contains_key("Payment-Signature");

    tracing::info!(
        %method,
        %uri,
        has_x_payment,
        has_payment_signature,
        "x402 request received"
    );

    let response = next.run(req).await;
    let status = response.status();
    let has_payment_required = response.headers().contains_key("Payment-Required");
    let has_payment_response = response.headers().contains_key("Payment-Response");

    tracing::info!(
        %method,
        %uri,
        %status,
        has_payment_required,
        has_payment_response,
        "x402 request completed"
    );

    response
}

/// Starts the OPRF testnet node with the given configuration and secret manager. The node will run until the provided shutdown signal is triggered, at which point it will attempt to gracefully shut down all services within the specified maximum wait time.
pub async fn start(
    config: TestNetNodeConfig,
    secret_manager: SecretManagerService,
    shutdown_signal: impl std::future::Future<Output = ()> + Send + 'static,
) -> eyre::Result<()> {
    tracing::info!("starting oprf-testnet-node with config: {config:#?}");
    let service_config = config.node_config.clone();
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
    let rpc_provider =
        nodes_common::web3::RpcProviderBuilder::with_config(&config.rpc_provider_config)
            .build()
            .await?;
    let (oprf_service_router, key_event_watcher) = OprfServiceBuilder::init(
        service_config,
        secret_manager,
        rpc_provider,
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

    let new_health_router: Router = Router::new().route(
        "/health1",
        get(|| async move { (StatusCode::OK, "healthy") }),
    );

    let x402 = X402Middleware::try_from("https://facilitator.x402.rs")
        .expect("valid x402 facilitator url");
    tracing::info!(
        facilitator = "https://facilitator.x402.rs",
        settlement = "before_execution",
        network = "base-sepolia",
        amount = 10u64,
        asset = "USDC",
        recipient = "0xC8549f30Ec22EebD0977eE495E5EC2e01ca436f9",
        "configured x402 middleware for paid routes"
    );
    let app = oprf_service_router
        .layer(x402.with_price_tag(V2Eip155Exact::price_tag(
            address!("0xC8549f30Ec22EebD0977eE495E5EC2e01ca436f9"),
            USDC::base_sepolia().amount(10u64),
        )))
        .layer(from_fn(log_x402_request));

    let app = app.merge(new_health_router);

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
        let axum_result = axum::serve(listener, app)
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
