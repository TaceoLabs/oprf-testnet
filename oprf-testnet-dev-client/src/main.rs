use std::{
    collections::HashMap,
    str::FromStr as _,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy::{
    network::EthereumWallet,
    primitives::{Address, U160, eip191_hash_message},
    providers::{DynProvider, Provider as _, ProviderBuilder},
    signers::{
        SignerSync,
        k256::{ecdsa::SigningKey, elliptic_curve::sec1::ToEncodedPoint},
        local::PrivateKeySigner,
    },
};
use ark_ff::{PrimeField, UniformRand as _};
use clap::Parser;
use eyre::Context as _;
use oprf_testnet_authentication::{AuthModule, TestNetRequestAuth};
use oprf_testnet_client::{DistributedOprfArgs, compute_proof};
use rand::SeedableRng as _;
use rustls::{ClientConfig, RootCertStore};
use secrecy::{ExposeSecret as _, SecretString};
use taceo_oprf::{
    client::Connector,
    core::oprf::{BlindedOprfRequest, BlindingFactor},
    dev_client::{
        Command, StressTestKeyGenCommand, StressTestOprfCommand,
        oprf_test_utils::{self, health_checks},
    },
    types::{OprfKeyId, ShareEpoch, api::OprfRequest, crypto::OprfPublicKey},
};
use tokio::{sync::mpsc, task::JoinSet};
use uuid::Uuid;

/// The configuration for the OPRF client.
///
/// It can be configured via environment variables or command line arguments using `clap`.
#[derive(Parser, Debug)]
pub struct OprfDevClientConfig {
    /// The URLs to all OPRF nodes
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_NODES",
        value_delimiter = ',',
        default_value = "http://127.0.0.1:10000,http://127.0.0.1:10001,http://127.0.0.1:10002"
    )]
    pub nodes: Vec<String>,

    /// The threshold of services that need to respond
    #[clap(long, env = "OPRF_DEV_CLIENT_THRESHOLD", default_value = "2")]
    pub threshold: usize,

    /// The Address of the OprfKeyRegistry contract.
    #[clap(long, env = "OPRF_DEV_CLIENT_OPRF_KEY_REGISTRY_CONTRACT")]
    pub oprf_key_registry_contract: Address,

    /// The RPC for chain communication
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_CHAIN_RPC_URL",
        default_value = "http://localhost:8545"
    )]
    pub chain_rpc_url: SecretString,

    /// The PRIVATE_KEY of the TACEO admin wallet - used to register the OPRF nodes
    ///
    /// Default is anvil wallet 0
    #[clap(
        long,
        env = "TACEO_ADMIN_PRIVATE_KEY",
        default_value = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    )]
    pub taceo_private_key: SecretString,

    /// rp id of already registered rp
    #[clap(long, env = "OPRF_DEV_CLIENT_OPRF_KEY_ID")]
    pub oprf_key_id: Option<U160>,

    /// The share epoch. Will be ignored if `oprf_key_id` is `None`.
    #[clap(long, env = "OPRF_DEV_CLIENT_SHARE_EPOCH", default_value = "0")]
    pub share_epoch: u32,

    /// max wait time for init key-gen/reshare to succeed.
    #[clap(long, env = "OPRF_DEV_CLIENT_WAIT_TIME", default_value="2min", value_parser=humantime::parse_duration)]
    pub max_wait_time: Duration,

    /// The API Key
    #[clap(long, env = "OPRF_DEV_CLIENT_API_KEY")]
    pub api_key: String,

    /// If we use the API only use-case
    #[clap(long, env = "OPRF_DEV_CLIENT_API_ONLY", default_value = "false")]
    pub api_only: bool,

    /// Command
    #[command(subcommand)]
    pub command: Command,
}

async fn run_oprf(
    nodes: &[String],
    threshold: usize,
    api_key: String,
    module: AuthModule,
    oprf_key_id: OprfKeyId,
    connector: Connector,
) -> eyre::Result<ShareEpoch> {
    let mut rng = rand_chacha::ChaCha12Rng::from_entropy();

    let action = ark_babyjubjub::Fq::rand(&mut rng);

    // the client example internally checks the DLog equality
    let verifiable_oprf = oprf_testnet_client::distributed_oprf(
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
    tracing::debug!("OPRF output: {:?}", verifiable_oprf);
    Ok(verifiable_oprf.epoch)
}

async fn prepare_oprf_stress_test_oprf_request(
    oprf_key_id: OprfKeyId,
    api_key: String,
) -> eyre::Result<(Uuid, BlindedOprfRequest, OprfRequest<TestNetRequestAuth>)> {
    let mut rng = rand_chacha::ChaCha12Rng::from_entropy();

    let request_id = Uuid::new_v4();
    let blinding_factor = BlindingFactor::rand(&mut rng);

    let private_key = SigningKey::random(&mut rand::thread_rng());
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();
    let encoded_pubkey = private_key
        .verifying_key()
        .as_affine()
        .to_encoded_point(false);
    let x_affine = encoded_pubkey
        .x()
        .expect("should be possible to get x from publickey")
        .to_vec();
    let y_affine = encoded_pubkey
        .y()
        .expect("should be possible to get y from publickey")
        .to_vec();

    let signer = PrivateKeySigner::from_signing_key(private_key);
    let msg = format!("TACEO Oprf Input: {ts}");
    let msg_hash = eip191_hash_message(msg.as_bytes());
    let mut signature = signer.sign_hash_sync(&msg_hash)?.as_bytes().to_vec();
    //Remove recovery id
    _ = signature.pop();
    let action = ark_babyjubjub::Fq::from_be_bytes_mod_order(signer.address().as_ref());
    let (public_inputs, proof) = compute_proof(
        blinding_factor.clone(),
        x_affine,
        y_affine,
        signature,
        msg_hash.to_vec(),
    )
    .await?;

    let auth = TestNetRequestAuth {
        public_inputs,
        proof,
        api_key,
        oprf_key_id,
    };
    let query = action;
    let blinded_request = taceo_oprf::core::oprf::client::blind_query(query, blinding_factor);
    let oprf_req = OprfRequest {
        request_id,
        blinded_query: blinded_request.blinded_query(),
        auth,
    };

    Ok((request_id, blinded_request, oprf_req))
}

#[allow(clippy::too_many_arguments)]
async fn stress_test_oprf(
    cmd: StressTestOprfCommand,
    nodes: &[String],
    threshold: usize,
    api_key: String,
    module: AuthModule,
    oprf_key_id: OprfKeyId,
    oprf_public_key: OprfPublicKey,
    connector: Connector,
) -> eyre::Result<()> {
    let mut blinded_requests = HashMap::with_capacity(cmd.runs);
    let mut init_requests = HashMap::with_capacity(cmd.runs);

    tracing::info!("preparing requests..");
    for _ in 0..cmd.runs {
        let (request_id, blinded_req, req) =
            prepare_oprf_stress_test_oprf_request(oprf_key_id, api_key.clone()).await?;
        blinded_requests.insert(request_id, blinded_req);
        init_requests.insert(request_id, req);
    }

    tracing::info!("sending init requests..");
    let (sessions, finish_requests) = taceo_oprf::dev_client::send_init_requests(
        nodes,
        &module.to_string(),
        threshold,
        connector,
        cmd.sequential,
        init_requests,
    )
    .await?;

    tracing::info!("sending finish requests..");
    let responses = taceo_oprf::dev_client::send_finish_requests(
        sessions,
        cmd.sequential,
        finish_requests.clone(),
    )
    .await?;

    if !cmd.skip_checks {
        tracing::info!("checking OPRF + proofs");
        for (id, res) in responses {
            let blinded_req = blinded_requests.get(&id).expect("is there").to_owned();
            let finish_req = finish_requests.get(&id).expect("is there").to_owned();
            let _dlog_proof = taceo_oprf::client::verify_dlog_equality(
                id,
                oprf_public_key,
                &blinded_req,
                res,
                finish_req,
            )?;
        }
    }

    Ok(())
}

async fn stress_test_key_gen(
    cmd: StressTestKeyGenCommand,
    nodes: &[String],
    oprf_key_registry: Address,
    provider: DynProvider,
    max_wait_time: Duration,
) -> eyre::Result<()> {
    // initiate key-gens and reshares
    let mut key_gens = JoinSet::new();
    for _ in 0..cmd.runs {
        let oprf_key_id_u32: u32 = rand::random();
        let oprf_key_id = OprfKeyId::new(U160::from(oprf_key_id_u32));
        tracing::debug!("init OPRF key gen with: {oprf_key_id}");
        oprf_test_utils::init_key_gen(provider.clone(), oprf_key_registry, oprf_key_id).await?;
        key_gens.spawn({
            let nodes = nodes.to_vec();
            async move {
                health_checks::oprf_public_key_from_services(
                    oprf_key_id,
                    ShareEpoch::default(),
                    &nodes,
                    max_wait_time,
                )
                .await?;
                eyre::Ok(oprf_key_id)
            }
        });
    }
    tracing::info!("finished init key-gens, now starting reshares");
    let mut reshares = JoinSet::new();
    while let Some(key_gen_result) = key_gens.join_next().await {
        let key_id = key_gen_result
            .expect("Can join")
            .context("Could not fetch oprf-key-gen")?;
        tracing::debug!("init OPRF reshare for {key_id}");
        oprf_test_utils::init_reshare(provider.clone(), oprf_key_registry, key_id).await?;
        // do an oprf to check if correct
        reshares.spawn({
            let nodes = nodes.to_vec();
            async move {
                health_checks::oprf_public_key_from_services(
                    key_id,
                    ShareEpoch::default().next(),
                    &nodes,
                    max_wait_time,
                )
                .await?;
                eyre::Ok(())
            }
        });
    }
    tracing::info!(
        "started {} key-gens + reshare - waiting to finish",
        cmd.runs
    );
    reshares
        .join_all()
        .await
        .into_iter()
        .collect::<eyre::Result<Vec<_>>>()
        .context("cannot finish reshares")?;
    Ok(())
}

#[expect(clippy::too_many_arguments)]
async fn reshare_test(
    nodes: &[String],
    threshold: usize,
    api_key: String,
    module: AuthModule,
    oprf_key_registry: Address,
    oprf_key_id: OprfKeyId,
    connector: Connector,
    provider: DynProvider,
    acceptance_num: usize,
    max_wait_time: Duration,
) -> eyre::Result<()> {
    tracing::info!("running OPRF to get current epoch..");
    let current_epoch = run_oprf(
        nodes,
        threshold,
        api_key.clone(),
        module.clone(),
        oprf_key_id,
        connector.clone(),
    )
    .await?;
    tracing::info!("current epoch: {current_epoch}");

    tracing::info!("start OPRF client task");
    let (tx, mut rx) = mpsc::channel(32);
    // we need this so that we don't get random warnings when we kill the task abruptly
    let shutdown_signal = Arc::new(AtomicBool::new(false));
    let oprf_client_task = tokio::task::spawn({
        let nodes = nodes.to_vec();
        let connector = connector.clone();
        let shutdown_signal = Arc::clone(&shutdown_signal);
        let module = module.clone();
        async move {
            let nodes = nodes.to_vec();
            let mut counter = 0;
            loop {
                if shutdown_signal.load(Ordering::Relaxed) {
                    break;
                }
                let result = run_oprf(
                    &nodes,
                    threshold,
                    api_key.clone(),
                    module.clone(),
                    oprf_key_id,
                    connector.clone(),
                )
                .await;
                counter += 1;
                if counter % 50 == 0 {
                    tracing::debug!("send OPRF: {}", counter);
                }
                if tx.send(result).await.is_err() {
                    break;
                }
            }
        }
    });

    tracing::info!("Doing reshare!");
    oprf_test_utils::init_reshare(provider.clone(), oprf_key_registry, oprf_key_id).await?;
    tokio::time::timeout(
        max_wait_time,
        wait_for_epoch(&mut rx, acceptance_num, current_epoch.next()),
    )
    .await??;

    tracing::info!("Doing reshare!");
    oprf_test_utils::init_reshare(provider.clone(), oprf_key_registry, oprf_key_id).await?;
    tokio::time::timeout(
        max_wait_time,
        wait_for_epoch(&mut rx, acceptance_num, current_epoch.next().next()),
    )
    .await??;
    shutdown_signal.store(true, Ordering::Relaxed);

    if tokio::time::timeout(Duration::from_secs(5), oprf_client_task)
        .await
        .is_err()
    {
        tracing::warn!("test succeeded but could not finish client tasks in 5 seconds?")
    };
    Ok(())
}
async fn wait_for_epoch(
    rx: &mut mpsc::Receiver<Result<ShareEpoch, eyre::Report>>,
    acceptance_num: usize,
    target_epoch: ShareEpoch,
) -> eyre::Result<()> {
    let mut new_epoch_found = 0;
    while let Some(result) = rx.recv().await {
        match result {
            Ok(epoch) if epoch == target_epoch => {
                new_epoch_found += 1;
                if new_epoch_found == acceptance_num {
                    tracing::info!(
                        "successfully used new epoch {} {acceptance_num} times!",
                        target_epoch
                    );
                    return Ok(());
                }
            }
            Ok(_) => continue,
            Err(err) => {
                return Err(err);
            }
        }
    }
    eyre::bail!("Channel closed without getting {acceptance_num}");
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    nodes_observability::install_tracing(
        "taceo_oprf=info,taceo_oprf_testnet_dev_client=info,taceo_oprf_testnet_client=info",
    );
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");
    let config = OprfDevClientConfig::parse();
    tracing::info!("starting oprf-dev-client with config: {config:#?}");

    tracing::info!("health check for all nodes...");
    health_checks::services_health_check(&config.nodes, Duration::from_secs(5))
        .await
        .context("while doing health checks")?;
    tracing::info!("everyone online..");

    let private_key = PrivateKeySigner::from_str(config.taceo_private_key.expose_secret())?;
    let wallet = EthereumWallet::from(private_key.clone());

    tracing::info!("init rpc provider..");
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect(config.chain_rpc_url.expose_secret())
        .await
        .context("while connecting to RPC")?
        .erased();

    let (oprf_key_id, oprf_public_key) = if let Some(oprf_key_id) = config.oprf_key_id {
        let oprf_key_id = OprfKeyId::new(oprf_key_id);
        let share_epoch = ShareEpoch::from(config.share_epoch);
        let oprf_public_key = health_checks::oprf_public_key_from_services(
            oprf_key_id,
            share_epoch,
            &config.nodes,
            config.max_wait_time,
        )
        .await?;
        (oprf_key_id, oprf_public_key)
    } else {
        let (oprf_key_id, oprf_public_key) = taceo_oprf::dev_client::init_key_gen(
            &config.nodes,
            config.oprf_key_registry_contract,
            provider.clone(),
            config.max_wait_time,
        )
        .await?;
        (oprf_key_id, oprf_public_key)
    };

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

    match config.command.clone() {
        Command::Test => {
            tracing::info!("running oprf-test");
            run_oprf(
                &config.nodes,
                config.threshold,
                config.api_key,
                module,
                oprf_key_id,
                connector,
            )
            .await?;
            tracing::info!("oprf-test successful");
        }
        Command::StressTestOprf(cmd) => {
            tracing::info!("running stress-test");
            stress_test_oprf(
                cmd,
                &config.nodes,
                config.threshold,
                config.api_key,
                module,
                oprf_key_id,
                oprf_public_key,
                connector,
            )
            .await?;
            tracing::info!("stress-test successful");
        }
        Command::StressTestKeyGen(cmd) => {
            tracing::info!("running key-gen stress-test");
            stress_test_key_gen(
                cmd,
                &config.nodes,
                config.oprf_key_registry_contract,
                provider,
                config.max_wait_time,
            )
            .await?;
            tracing::info!("stress-test successful");
        }
        Command::ReshareTest(cmd) => {
            tracing::info!("running reshare-test");
            reshare_test(
                &config.nodes,
                config.threshold,
                config.api_key,
                module,
                config.oprf_key_registry_contract,
                oprf_key_id,
                connector,
                provider,
                cmd.acceptance_num,
                config.max_wait_time,
            )
            .await?;
            tracing::info!("reshare-test successful");
        }
    }

    Ok(())
}
