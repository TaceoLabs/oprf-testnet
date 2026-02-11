use alloy::primitives::eip191_hash_message;
use alloy::signers::SignerSync;
use alloy::signers::k256::ecdsa::SigningKey;
use alloy::signers::k256::elliptic_curve::sec1::ToEncodedPoint;
use alloy::signers::local::PrivateKeySigner;
use ark_ff::PrimeField as _;
use eyre::Context;
use oprf_testnet_authentication::{
    AuthModule, TestNetApiOnlyRequestAuth, TestNetRequestAuth, compute_nullifier_proof,
    compute_wallet_ownership_proof, verify_proof,
};
use rand::{CryptoRng, Rng};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use taceo_oprf::client::VerifiableOprfOutput;
use taceo_oprf::{client::Connector, core::oprf::BlindingFactor, types::OprfKeyId};
use tracing::instrument;

pub struct DistributedOprfArgs<'a> {
    pub services: &'a [String],
    pub threshold: usize,
    pub api_key: String,
    pub module: AuthModule,
    pub oprf_key_id: OprfKeyId,
    pub action: ark_babyjubjub::Fq,
    pub connector: Connector,
}

pub async fn distributed_oprf<R: Rng + CryptoRng>(
    distributed_oprf_args: DistributedOprfArgs<'_>,
    rng: &mut R,
) -> eyre::Result<VerifiableOprfOutput> {
    tracing::debug!(
        "Starting distributed OPRF with args: {}",
        distributed_oprf_args.module
    );
    match distributed_oprf_args.module {
        AuthModule::TestNet => distributed_oprf_api_and_proof(distributed_oprf_args, rng).await,
        AuthModule::TestNetApiOnly => distributed_oprf_api_only(distributed_oprf_args, rng).await,
    }
}

#[instrument(level = "debug", skip_all)]
pub async fn distributed_oprf_api_only<R: Rng + CryptoRng>(
    distributed_oprf_args: DistributedOprfArgs<'_>,
    rng: &mut R,
) -> eyre::Result<VerifiableOprfOutput> {
    tracing::info!("Running distributed OPRF with API only authentication");
    let start = Instant::now();
    let blinding_factor = BlindingFactor::rand(rng);
    let domain_separator = ark_babyjubjub::Fq::from_be_bytes_mod_order(b"OPRF TestNet");

    let auth = TestNetApiOnlyRequestAuth {
        api_key: distributed_oprf_args.api_key,
        oprf_key_id: distributed_oprf_args.oprf_key_id,
    };

    let verifiable_oprf_output = taceo_oprf::client::distributed_oprf(
        distributed_oprf_args.services,
        &distributed_oprf_args.module.to_string(),
        distributed_oprf_args.threshold,
        distributed_oprf_args.action,
        blinding_factor,
        domain_separator,
        auth,
        distributed_oprf_args.connector,
    )
    .await
    .context("cannot get verifiable oprf output")?;
    let elapsed = start.elapsed();
    tracing::info!("Total time taken for distributed OPRF with only API: {elapsed:?}",);

    Ok(verifiable_oprf_output)
}

#[instrument(level = "debug", skip_all)]
pub async fn distributed_oprf_api_and_proof<R: Rng + CryptoRng>(
    distributed_oprf_args: DistributedOprfArgs<'_>,
    rng: &mut R,
) -> eyre::Result<VerifiableOprfOutput> {
    let start = Instant::now();
    tracing::info!("Running distributed OPRF with API and Proof authentication");
    let blinding_factor = BlindingFactor::rand(rng);
    let domain_separator = ark_babyjubjub::Fq::from_be_bytes_mod_order(b"OPRF TestNet");

    let private_key = SigningKey::random(&mut rand::thread_rng());
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

    // Instantiate a signer
    let signer = PrivateKeySigner::from_signing_key(private_key);
    let query = ark_babyjubjub::Fq::from_be_bytes_mod_order(signer.address().as_ref());

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    let msg = format!("TACEO Oprf Input: {ts}");
    let msg_hash = eip191_hash_message(msg.as_bytes());
    let mut signature = signer.sign_hash_sync(&msg_hash)?.as_bytes().to_vec();

    //Remove recovery id
    _ = signature.pop();

    let (public_inputs, proof) = compute_wallet_ownership_proof(
        &blinding_factor,
        &x_affine,
        &y_affine,
        &signature,
        msg_hash.as_ref(),
    )?;

    let auth = TestNetRequestAuth {
        public_inputs,
        proof,
        oprf_key_id: distributed_oprf_args.oprf_key_id,
        api_key: distributed_oprf_args.api_key,
    };

    let verifiable_oprf_output = taceo_oprf::client::distributed_oprf(
        distributed_oprf_args.services,
        &distributed_oprf_args.module.to_string(),
        distributed_oprf_args.threshold,
        query,
        blinding_factor.clone(),
        domain_separator,
        auth,
        distributed_oprf_args.connector,
    )
    .await
    .context("cannot get verifiable oprf output")?;

    tracing::debug!("Computing proof for the verifiable OPRF output..");
    let (public_inputs, proof) = compute_nullifier_proof(
        verifiable_oprf_output.clone(),
        signature,
        msg_hash,
        &blinding_factor,
        x_affine,
        y_affine,
    )?;

    verify_proof(
        &public_inputs,
        &proof,
        oprf_testnet_authentication::VerificationType::NullifierVerification,
    )?;

    let elapsed = start.elapsed();
    tracing::info!(
        "Total time taken for distributed OPRF with API and Proof authentication: {elapsed:?}",
    );
    Ok(verifiable_oprf_output)
}
