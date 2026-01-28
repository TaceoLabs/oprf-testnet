use babyjubjub::{BabyJubJubPoint, hash_to_curve::encode};
use ecrecover::ecrecover;

pub fn query_proof(
    hashed_message: [u8; 32],
    pub_key_x: [u8; 32],
    pub_key_y: [u8; 32],
    signature: [u8; 64],
    beta: Field,
) -> BabyJubJubPoint {
    let addr = ecrecover(pub_key_x, pub_key_y, signature, hashed_message);

    let beta_bits = BabyJubJubPoint::validate_scalar_field_with_bits(beta);

    // Encode query to curve point and perform scalar multiplication
    let (px, py) = encode(addr);
    let p = BabyJubJubPoint::new(px, py);
    // Precondition: encode returns a valid point on the BabyJubJub curve in the prime order subgroup
    let b_q = p.scalar_mul_bits(beta_bits);

    b_q
}
