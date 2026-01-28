use ark_ec::AffineRepr as _;
use ark_ff::PrimeField as _;
use eyre::Context;
use rand::{CryptoRng, Rng};
use taceo_oprf::{
    client::Connector,
    core::oprf::BlindingFactor,
    types::{OprfKeyId, ShareEpoch},
};
use tracing::instrument;

// #[instrument(level = "debug", skip_all)]
pub async fn distributed_oprf<R: Rng + CryptoRng>(
    services: &[String],
    threshold: usize,
    oprf_key_id: OprfKeyId,
    share_epoch: ShareEpoch,
    action: ark_babyjubjub::Fq,
    connector: Connector,
    rng: &mut R,
) -> eyre::Result<()> {
    let query = action;
    let blinding_factor = BlindingFactor::rand(rng);
    let domain_separator = ark_babyjubjub::Fq::from_be_bytes_mod_order(b"OPRF TestNet");
    let auth = ();
    tracing::info!("here 111");
    let _verifiable_oprf_output = taceo_oprf::client::distributed_oprf(
        services,
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

    // dlog_proof
    //     .verify(
    //         oprf_public_key.inner(),
    //         blinded_request,
    //         blinded_response,
    //         ark_babyjubjub::EdwardsAffine::generator(),
    //     )
    //     .context("cannot verify dlog proof")?;
    //
    Ok(())
}
