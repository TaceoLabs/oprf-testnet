use babyjubjub::{BabyJubJubPoint, BabyJubJubPointInSubgroup};
use oprf::oprf_output::verified_oprf;
use wallet_ownership::wallet_address;
pub global DS_N: Field = 24546418369108709687614662004; // b"OPRF TestNet"
pub global DS_DLOG: Field = 1523098184080632582082867317389990410064981862; // b"DLOG Equality Proof"

fn main(
    // These are the inputs needed for the first part of the OPRF protocol, the query proof.
    pub_key_x: [u8; 32],
    pub_key_y: [u8; 32],
    signature: [u8; 64],
    beta: Field,
    // These are the inputs needed for the second part of the OPRF protocol, the verified OPRF output.
    // The OPRF public key is a public input, and it must be verified outside the circuit that it is a valid point in the prime order subgroup of the BabyJubJub curve.
    oprf_pk: pub BabyJubJubPointInSubgroup,
    dlog_e: Field,
    dlog_s: Field,
    oprf_response_x: Field,
    oprf_response_y: Field,
) -> pub Field {
    // Similar to the blinded query proof, we first recover the user input (address) from the signature over the fixed message.
    let address = wallet_address(pub_key_x, pub_key_y, signature);
    // Construct the unblinded OPRF response point, checking it is on the curve.
    let oprf_response = BabyJubJubPoint::new(oprf_response_x, oprf_response_y);
    // Inside the verified_oprf function, we recompute the blinded query proof to check that the original query was computed correctly, verify the dlog equality proof, verify the unblinding was done correctly, and then generate the final verified OPRF output.
    verified_oprf(
        beta,
        oprf_pk,
        dlog_e,
        dlog_s,
        oprf_response,
        address,
        DS_DLOG,
        DS_N,
    )
}

mod tests {
    use super::main;
    use babyjubjub::BabyJubJubPointInSubgroup;
    use wallet_ownership::{TEST_PUB_KEY_X, TEST_PUB_KEY_Y, TEST_SIGNATURE};

    struct Kat {
        signature: [u8; 64],
        beta: Field,
        oprf_pk: BabyJubJubPointInSubgroup,
        dlog_e: Field,
        dlog_s: Field,
        oprf_response_x: Field,
        oprf_response_y: Field,
        expected_output: Field,
    }

    // OPRF secret key 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd.
    fn kat() -> Kat {
        Kat {
            signature: TEST_SIGNATURE,
            beta: 1498760273557913456370459222027449040163634869948415528344868600761947487523,
            oprf_pk: BabyJubJubPointInSubgroup::new(
                0x0f4583e516f077314fb7c7b8a87fae07166068e3dddb4200fff32bf399b2349d,
                0x1a289edfe55dabcc66eb07a2e53d7683afe0d6dcb27ac72dfbdd76bba9b949a8,
            ),
            dlog_e: 0x040e6bf380b2cf23744c604ecea4ce8b060bdcfac33e4aabfe67cfcb53066f82,
            dlog_s: 0xb89a7e66ea91835b3d6841734ee7a766cac8606c5dce26006a68f2629b761a,
            oprf_response_x: 0x19e48cf0f614b50f0656d25f9b742fb8660a8e56fef9ecf64f3a625b69374670,
            oprf_response_y: 0x1211ac4fca68ebc215dfdb62f679637e0c4bb46b07555702d27ed0f446b5d766,
            expected_output: 0x3026ff285fe4388e1b9c62361f23ef502c4fb6e411356cbe753bb7a9d672c572,
        }
    }

    fn run(k: Kat) -> Field {
        main(
            TEST_PUB_KEY_X,
            TEST_PUB_KEY_Y,
            k.signature,
            k.beta,
            k.oprf_pk,
            k.dlog_e,
            k.dlog_s,
            k.oprf_response_x,
            k.oprf_response_y,
        )
    }

    #[test]
    fn test_main() {
        let k = kat();
        let expected = k.expected_output;
        assert(run(k) == expected, "OPRF output does not match expected value");
    }

    #[test(should_fail_with = "Beta cannot be zero")]
    fn test_zero_beta_rejected() {
        let mut k = kat();
        k.beta = 0;
        let _ = run(k);
    }

    #[test(should_fail_with = "Point is not on the BabyJubJub curve")]
    fn test_off_curve_response_rejected() {
        let mut k = kat();
        k.oprf_response_x += 1;
        let _ = run(k);
    }

    #[test(should_fail_with = "OPRF response must be in prime order subgroup")]
    fn test_off_subgroup_response_rejected() {
        // (-x, -y) = P + (0, -1), i.e. P plus a 2-torsion point: on the curve, outside the prime order subgroup.
        let mut k = kat();
        k.oprf_response_x = -k.oprf_response_x;
        k.oprf_response_y = -k.oprf_response_y;
        let _ = run(k);
    }

    #[test(should_fail)]
    fn test_invalid_signature_rejected() {
        let mut k = kat();
        k.signature[0] += 1;
        let _ = run(k);
    }

    #[test(should_fail_with = "Challenge verification failed")]
    fn test_wrong_dlog_proof_rejected() {
        let mut k = kat();
        k.dlog_s += 1;
        let _ = run(k);
    }

    #[test(should_fail_with = "Challenge verification failed")]
    fn test_wrong_oprf_pk_rejected() {
        let mut k = kat();
        k.oprf_pk = BabyJubJubPointInSubgroup::generator();
        let _ = run(k);
    }
}
