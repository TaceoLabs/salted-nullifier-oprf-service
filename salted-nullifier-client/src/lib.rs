use ark_ff::PrimeField as _;
use oprf_client::{BlindingFactor, Connector};
use oprf_types::{OprfKeyId, ShareEpoch};
use rand::{CryptoRng, Rng};
use salted_nullifier_authentication::SaltedNullifierRequestAuth;

const UNSALTED_NULLIFIER_DS: &[u8] = b"TACEO Unsalted Nullifier Auth";

fn compute_encrypted_unsalted_nullifier() -> (SaltedNullifierRequestAuth, ark_babyjubjub::Fq) {
    // TODO
    // compute the face-match proof(or provide it from non-rust land)
    // compute the blinded query (the unsalted encrypted nullifier)
    todo!()
}

pub async fn salted_nullifier<R: Rng + CryptoRng>(
    services: &[String],
    threshold: usize,
    oprf_key_id: OprfKeyId,
    share_epoch: ShareEpoch,
    connector: Connector,
    rng: &mut R,
) {
    let (oprf_request_auth, query_hash) = compute_encrypted_unsalted_nullifier();
    let blinding_factor = BlindingFactor::rand(rng);
    let ds = ark_babyjubjub::Fq::from_be_bytes_mod_order(UNSALTED_NULLIFIER_DS);

    let _verifiable_oprf_output = oprf_client::distributed_oprf(
        services,
        threshold,
        oprf_key_id,
        share_epoch,
        query_hash,
        blinding_factor,
        ds,
        oprf_request_auth,
        connector,
    )
    .await
    .expect("TODO handle error case");

    // TODO
    // post processing of verifiable oprf-output
    // potentially won't happen in rust land, therefore maybe we don't really need anything here
}
