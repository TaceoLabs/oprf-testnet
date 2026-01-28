pub mod constants;
pub mod types;
pub mod dlog;
pub mod commitment;
pub mod query;
pub mod nullifier;
pub mod merkle_proof;
pub mod credential_signature;

// use commitment::generate_nullifier;
// use constants::{MAX_DEPTH, NUM_KEYS};
// use nullifier::oprf_nullifier;
// use types::{OprfNullifierInputs, OprfNullifierOutputs, PublicKey};

// pub fn main(
//     cred_pk: pub PublicKey,
//     current_timestamp: pub u64,
//     cred_genesis_issued_at_min: pub u64,
//     root: pub Field,
//     depth: pub Field,
//     rp_id: pub Field,
//     action: pub Field,
//     oprf_pk: pub PublicKey,
//     signal_hash: pub Field,
//     nonce: pub Field,
//     inputs: OprfNullifierInputs<MAX_DEPTH, NUM_KEYS>,
// ) -> pub OprfNullifierOutputs {
//     oprf_nullifier(
//         cred_pk,
//         current_timestamp,
//         cred_genesis_issued_at_min,
//         root,
//         depth,
//         rp_id,
//         action,
//         oprf_pk,
//         signal_hash,
//         nonce,
//         inputs,
//     )
// }
