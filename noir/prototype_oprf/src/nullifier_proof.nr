use babyjubjub::BabyJubJubPoint;
use oprf::{commitment::generate_nullifier, dlog::verify_dlog_equality, query::verify_unblinding};
//WIP:
pub fn nullifier_proof(
    oprf_pk: BabyJubJubPoint,
    dlog_e: Field,
    dlog_s: Field,
    oprf_response_blinded: BabyJubJubPoint,
    oprf_response: BabyJubJubPoint,
    query: Field,
    beta: Field,
) -> Field {
    verify_dlog_equality(
        dlog_e,
        dlog_s,
        oprf_pk,
        oprf_response,
        oprf_response_blinded,
    );

    verify_unblinding(
        oprf_response,
        oprf_response_blinded,
        BabyJubJubPoint::validate_scalar_field_with_bits(beta),
    );

    generate_nullifier(query, oprf_response)
}
