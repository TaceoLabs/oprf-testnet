use std::fs;
use std::hash::Hasher;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{fs::File, process::Command};

use alloy::network::EthereumWallet;
use alloy::primitives::eip191_hash_message;
use alloy::signers::SignerSync;
use alloy::signers::k256::ecdsa::SigningKey;
use alloy::signers::k256::elliptic_curve::point::AffineCoordinates;
use alloy::signers::k256::elliptic_curve::sec1::ToEncodedPoint;
use alloy::signers::local::{LocalSigner, PrivateKeySigner};
use ark_ff::PrimeField as _;
use eyre::Context;
use oprf_testnet_authentication::{ProofInput, TestNetRequestAuth};
use rand::{CryptoRng, Rng};
use sha2::{Digest, Sha256};
use taceo_oprf::{
    client::Connector,
    core::oprf::BlindingFactor,
    types::{OprfKeyId, ShareEpoch},
};

// /// A signer instantiated with a locally stored private key.
// pub type PrivateKeySigner = LocalSigner<k256::ecdsa::SigningKey>;

// #[instrument(level = "debug", skip_all)]
pub async fn distributed_oprf<R: Rng + CryptoRng>(
    services: &[String],
    threshold: usize,
    api_key: String,
    oprf_key_id: OprfKeyId,
    share_epoch: ShareEpoch,
    action: ark_babyjubjub::Fq,
    connector: Connector,
    rng: &mut R,
) -> eyre::Result<()> {
    let query = action;
    let blinding_factor = BlindingFactor::rand(rng);
    let domain_separator = ark_babyjubjub::Fq::from_be_bytes_mod_order(b"OPRF TestNet");

    let private_key = SigningKey::random(&mut rand::thread_rng());
    let encoded_pubkey = private_key
        .verifying_key()
        .as_affine()
        .to_encoded_point(false);
    let y_affine = encoded_pubkey.y().unwrap().to_vec();
    let x_affine = encoded_pubkey.x().unwrap().to_vec();

    // Instantiate a signer
    let signer = PrivateKeySigner::from_signing_key(private_key);

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
        .to_string();

    let msg = "TACEO Oprf Input: ".to_string() + &ts;
    let msg_hash = eip191_hash_message(msg.as_bytes());
    let mut signature = signer.sign_hash_sync(&msg_hash)?.as_bytes().to_vec();
    //Remove recovery id
    _ = signature.pop();

    let proof_input = compute_proof(
        blinding_factor.clone(),
        x_affine,
        y_affine,
        signature,
        msg_hash.to_vec(),
    )
    .await?;
    let auth = TestNetRequestAuth {
        proof_input,
        api_key,
    };

    let _verifiable_oprf_output = taceo_oprf::client::distributed_oprf(
        services,
        "testnet",
        threshold,
        oprf_key_id,
        share_epoch,
        query,
        blinding_factor,
        domain_separator,
        auth,
        connector,
    )
    .await
    .context("cannot get verifiable oprf output")?;
    Ok(())
}

pub async fn compute_proof(
    beta: BlindingFactor,
    pubkey_x: Vec<u8>,
    pubkey_y: Vec<u8>,
    signature: Vec<u8>,
    hashed_msg: Vec<u8>,
) -> eyre::Result<ProofInput> {
    let name_of_proof = "prototype_oprf";
    let directory = format!("noir/{}", name_of_proof);
    let input_file_path = format!("{}/Prover.toml", directory);
    let witness_path = format!("target/{}.gz", name_of_proof);
    let bytecode_path = format!("target/{}.json", name_of_proof);
    let mut prover_toml_file = File::create(input_file_path)?;

    let _ = write!(
        prover_toml_file,
        "beta = \"{}\"\npub_key_x = {}\npub_key_y = {}\nsignature = {}\nhashed_message = {}",
        beta.beta().to_string(),
        format!("{:?}", pubkey_x),
        format!("{:?}", pubkey_y),
        format!("{:?}", signature),
        format!("{:?}", hashed_msg)
    );

    let nargo_exec_status = Command::new("nargo")
        .arg("execute")
        .current_dir(&directory)
        .status();

    if nargo_exec_status.is_err() || !nargo_exec_status.unwrap().success() {
        return Err(eyre::eyre!("nargo execute failed"));
    }

    let bb_write_vk_status = Command::new("bb")
        .arg("write_vk")
        .arg("-b")
        .arg(&bytecode_path)
        .current_dir(&directory)
        .status();

    if bb_write_vk_status.is_err() || !bb_write_vk_status.unwrap().success() {
        return Err(eyre::eyre!("bb write_vk failed"));
    }

    let bb_prove_status = Command::new("bb")
        .arg("prove")
        .arg("-b")
        .arg(&bytecode_path)
        .arg("-k")
        .arg("out/vk")
        .arg("-w")
        .arg(witness_path)
        .current_dir(&directory)
        .status();

    if bb_prove_status.is_err() || !bb_prove_status.unwrap().success() {
        return Err(eyre::eyre!("bb prove failed"));
    }

    let public_inputs = fs::read(format!("{}/out/public_inputs", &directory))?;
    let proof = fs::read(format!("{}/out/proof", &directory))?;
    Ok(ProofInput {
        public_inputs,
        proof,
    })
}
