pub(crate) mod query_proof;
pub(crate) mod nullifier_proof;

use crate::query_proof::query_proof;
use babyjubjub::BabyJubJubPoint;

pub fn main(
    hashed_message: pub [u8; 32],
    pub_key_x: [u8; 32],
    pub_key_y: [u8; 32],
    signature: [u8; 64],
    beta: Field,
) -> pub BabyJubJubPoint {
    query_proof(hashed_message, pub_key_x, pub_key_y, signature, beta)
}
