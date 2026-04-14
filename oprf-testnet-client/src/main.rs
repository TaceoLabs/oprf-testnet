use alloy::{
    hex,
    signers::{k256::ecdsa::SigningKey, local::PrivateKeySigner},
};

use clap::Parser;
use eyre::Context;
use futures_util::future::try_join_all;
use reqwest::Client;
use reqwest::{StatusCode, Url};
use rustls::{ClientConfig, RootCertStore};
use secrecy::{ExposeSecret, SecretString};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use taceo_oprf::client::Connector;
use x402_chain_eip155::V1Eip155ExactClient;
use x402_chain_eip155::V2Eip155ExactClient;
use x402_reqwest::{ReqwestWithPayments, ReqwestWithPaymentsBuild, X402Client};
use x402_types::{
    proto::{self, OriginalJson},
    scheme::client::X402SchemeClient,
    util::Base64Bytes,
};

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

    /// Optional private key used to sign x402 payment challenges during the websocket handshake.
    #[clap(long, env = "OPRF_CLIENT_PAYMENT_PRIVATE_KEY")]
    pub payment_private_key: SecretString,

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
    tracing::debug!("starting oprf-testnet-client with config: {config:#?}");

    // setup TLS config - even if we are http
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let rustls_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = Connector::Rustls(Arc::new(rustls_config));
    let payment_private_key = parse_signing_key(&config.payment_private_key).context(
        "Invalid payment private key hex string, must be a 32-byte hex string optionally prefixed with 0x",
    )?;

    check_node_health_endpoints(&config.nodes, Some(&payment_private_key)).await?;
    tracing::info!("All node health checks succeeded");
    match config.module {
        AuthModuleArg::Basic(BasicConfig { input }) => {
            tracing::info!("Running basic verifiable OPRF...");
            // check_node_health_endpoints(&config.nodes, payment_private_key.as_ref()).await?;
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
                config.api_key,
                input,
                Some(payment_private_key),
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
                parse_signing_key(&private_key).context(
                    "Invalid private key hex string, must be a 32-byte hex string optionally prefixed with 0x",
                )?
            } else {
                let private_key = SigningKey::random(&mut rng);
                tracing::info!(
                    "Generated random wallet with private key 0x{}",
                    hex::encode(private_key.to_bytes())
                );
                private_key
            };
            // payment_private_key.as_ref().unwrap_or(&private_key);
            // check_node_health_endpoints(&config.nodes, Some(effective_payment_signing_key)).await?;
            let (verifiable_oprf_output, pulic_inputs, proof) =
                taceo_oprf_testnet_client::wallet_ownership_verifiable_oprf(
                    &config.nodes,
                    config.threshold,
                    config.api_key,
                    private_key,
                    Some(payment_private_key),
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

fn parse_signing_key(private_key: &SecretString) -> eyre::Result<SigningKey> {
    let private_key_bytes =
        hex::decode(private_key.expose_secret()).context("private key must be valid hex")?;
    SigningKey::from_slice(&private_key_bytes)
        .context("private key must be a valid secp256k1 scalar")
}

async fn check_node_health_endpoints(
    nodes: &[String],
    payment_signing_key: Option<&SigningKey>,
) -> eyre::Result<()> {
    let payment_signing_key = payment_signing_key.ok_or_else(|| {
        eyre::eyre!(
            "health checks against priced routes require a payment signer; provide --payment-private-key"
        )
    })?;
    let signer = Arc::new(PrivateKeySigner::from_signing_key(
        payment_signing_key.clone(),
    ));
    try_join_all(
        nodes
            .iter()
            .map(|node| check_node_health_endpoint(node, signer.clone())),
    )
    .await?;

    Ok(())
}

async fn check_node_health_endpoint(node: &str, signer: Arc<PrivateKeySigner>) -> eyre::Result<()> {
    let healthcheck_url = healthcheck_url(node)?;
    tracing::debug!("Checking HTTP health endpoint for {node} at {healthcheck_url}");
    let x402_client = X402Client::new()
        .register(V1Eip155ExactClient::new(signer.clone()))
        .register(V2Eip155ExactClient::new(signer));
    let client = Client::new().with_payments(x402_client).build();

    let response = client
        .get(healthcheck_url.clone())
        .send()
        .await
        .with_context(|| format!("sending health check request to {healthcheck_url}"))?;

    let status = response.status();
    eyre::ensure!(
        status.is_success(),
        "Node {node} health check at {healthcheck_url} failed with HTTP status {status}",
    );
    Ok(())
}

async fn maybe_pay_x402(
    client: &reqwest::Client,
    response: reqwest::Response,
    healthcheck_url: Url,
    payment_signing_key: Option<&SigningKey>,
) -> eyre::Result<reqwest::Response> {
    if response.status() != StatusCode::PAYMENT_REQUIRED {
        return Ok(response);
    }

    tracing::info!("Received 402 Payment Required for {healthcheck_url}");
    let payment_required = deserialize_payment_required(response).await?;
    let (header_name, header_value) = sign_payment_required(&payment_required, payment_signing_key)
        .await
        .context("signing x402 payment for node health check")?;

    client
        .get(healthcheck_url.clone())
        .header(header_name, header_value)
        .send()
        .await
        .with_context(|| format!("retrying health check with x402 payment for {healthcheck_url}"))
}

fn healthcheck_url(node: &str) -> eyre::Result<Url> {
    let mut url = Url::parse(node).with_context(|| format!("invalid node URL: {node}"))?;
    let scheme = match url.scheme() {
        "ws" => "http",
        "wss" => "https",
        scheme => scheme,
    }
    .to_owned();
    url.set_scheme(&scheme)
        .map_err(|_| eyre::eyre!("invalid URL scheme in node URL: {node}"))?;
    url.set_path("/health");
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

async fn sign_payment_required(
    payment_required: &proto::PaymentRequired,
    payment_signing_key: Option<&SigningKey>,
) -> eyre::Result<(&'static str, String)> {
    let payment_signing_key = payment_signing_key.ok_or_else(|| {
        eyre::eyre!(
            "received 402 Payment Required during node health check, but no payment signer is configured; provide --payment-private-key"
        )
    })?;

    let signer = Arc::new(PrivateKeySigner::from_signing_key(
        payment_signing_key.clone(),
    ));
    let signed_payload = match payment_required {
        proto::PaymentRequired::V1(_) => {
            let client = V1Eip155ExactClient::new(signer);
            let candidate = client
                .accept(payment_required)
                .into_iter()
                .next()
                .ok_or_else(|| eyre::eyre!("no supported x402 V1 payment option was offered"))?;
            candidate.sign().await.map_err(|err| eyre::eyre!(err))?
        }
        proto::PaymentRequired::V2(_) => {
            let client = V2Eip155ExactClient::new(signer);
            let candidate = client
                .accept(payment_required)
                .into_iter()
                .next()
                .ok_or_else(|| eyre::eyre!("no supported x402 V2 payment option was offered"))?;
            candidate.sign().await.map_err(|err| eyre::eyre!(err))?
        }
    };

    let header_name = match payment_required {
        proto::PaymentRequired::V1(_) => "X-Payment",
        proto::PaymentRequired::V2(_) => "Payment-Signature",
    };
    Ok((header_name, signed_payload))
}

async fn deserialize_payment_required(
    response: reqwest::Response,
) -> eyre::Result<proto::PaymentRequired> {
    if let Some(header) = response.headers().get("Payment-Required") {
        let bytes = Base64Bytes::from(header.as_bytes())
            .decode()
            .map_err(|err| eyre::eyre!("failed to decode Payment-Required header: {err}"))?;
        let payment_required =
            serde_json::from_slice::<proto::v2::PaymentRequired<OriginalJson>>(&bytes)
                .context("failed to deserialize Payment-Required header as x402 V2")?;
        return Ok(proto::PaymentRequired::V2(payment_required));
    }

    let body = response
        .bytes()
        .await
        .context("missing HTTP response body for PaymentRequired")?;

    serde_json::from_slice::<proto::v1::PaymentRequired<OriginalJson>>(&body)
        .map(proto::PaymentRequired::V1)
        .or_else(|v1_err| {
            serde_json::from_slice::<proto::v2::PaymentRequired<OriginalJson>>(&body)
                .map(proto::PaymentRequired::V2)
                .map_err(|v2_err| {
                    eyre::eyre!(
                        "failed to deserialize HTTP response as PaymentRequired: v1 error: {v1_err}; v2 error: {v2_err}"
                    )
                })
        })
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
