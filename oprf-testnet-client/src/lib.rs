use alloy::primitives::eip191_hash_message;
use alloy::signers::SignerSync;
use alloy::signers::k256::ecdsa::SigningKey;
use alloy::signers::k256::elliptic_curve::sec1::ToEncodedPoint;
use alloy::signers::local::PrivateKeySigner;
use ark_ff::PrimeField as _;
use eyre::Context;
use oprf_testnet_authentication::{
    AuthModule, basic::BasicTestNetRequestAuth, wallet_ownership::TestNetRequestAuth,
    wallet_ownership::zk,
};
use rand::{CryptoRng, Rng};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use taceo_oprf::client::VerifiableOprfOutput;
use taceo_oprf::{client::Connector, core::oprf::BlindingFactor};
use tempfile::NamedTempFile;
use tracing::instrument;

#[instrument(level = "debug", skip_all)]
pub async fn basic_verifiable_oprf<R: Rng + CryptoRng>(
    nodes: &[String],
    threshold: usize,
    api_key: String,
    action: ark_babyjubjub::Fq,
    connector: Connector,
    rng: &mut R,
) -> eyre::Result<VerifiableOprfOutput> {
    tracing::info!("Running distributed OPRF with API only authentication");
    let start = Instant::now();
    let blinding_factor = BlindingFactor::rand(rng);
    let domain_separator = ark_babyjubjub::Fq::from_be_bytes_mod_order(b"OPRF TestNet");

    let auth = BasicTestNetRequestAuth { api_key };

    let verifiable_oprf_output = taceo_oprf::client::distributed_oprf(
        nodes,
        &AuthModule::Basic.to_string(),
        threshold,
        action,
        blinding_factor,
        domain_separator,
        auth,
        connector,
    )
    .await
    .context("cannot get verifiable oprf output")?;

    let elapsed = start.elapsed();
    tracing::info!("Total time taken for distributed OPRF with only API: {elapsed:?}",);

    Ok(verifiable_oprf_output)
}

#[instrument(level = "debug", skip_all)]
pub async fn wallet_ownership_verifiable_oprf<R: Rng + CryptoRng>(
    nodes: &[String],
    threshold: usize,
    api_key: String,
    private_key: SigningKey,
    connector: Connector,
    rng: &mut R,
) -> eyre::Result<(VerifiableOprfOutput, Vec<u8>, Vec<u8>)> {
    tracing::info!("Running distributed OPRF with API and Proof authentication");
    let start = Instant::now();
    let blinding_factor = BlindingFactor::rand(rng);
    let domain_separator = ark_babyjubjub::Fq::from_be_bytes_mod_order(b"OPRF TestNet");

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

    let (public_inputs, proof) = zk::compute_wallet_ownership_proof(
        &blinding_factor,
        &x_affine,
        &y_affine,
        &signature,
        msg_hash.as_ref(),
    )?;

    let auth = TestNetRequestAuth {
        public_inputs,
        proof,
        api_key,
    };

    let verifiable_oprf_output = taceo_oprf::client::distributed_oprf(
        nodes,
        &AuthModule::WalletOwnership.to_string(),
        threshold,
        query,
        blinding_factor.clone(),
        domain_separator,
        auth,
        connector,
    )
    .await
    .context("cannot get verifiable oprf output")?;

    tracing::debug!("Computing proof for the verifiable OPRF output..");
    let (public_inputs, proof) = zk::compute_nullifier_proof(
        verifiable_oprf_output.clone(),
        signature,
        msg_hash,
        &blinding_factor,
        x_affine,
        y_affine,
    )?;

    let vk = NamedTempFile::new().context("creating NamedTempFile for vk")?;
    std::fs::write(vk.path(), zk::VERIFIED_OPRF_PROOF_VK).context("writing VK to temp file")?;
    zk::verify_proof(&public_inputs, &proof, vk.path())?;

    let elapsed = start.elapsed();
    tracing::info!(
        "Total time taken for distributed OPRF with API and Proof authentication: {elapsed:?}",
    );

    Ok((verifiable_oprf_output, public_inputs, proof))
}
