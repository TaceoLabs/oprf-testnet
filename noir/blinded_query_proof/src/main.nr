use babyjubjub::BabyJubJubPointInSubgroup;
use oprf::blinded_query::blinded_query;
use wallet_ownership::wallet_address;

/// This directory contains an implementation of the proof flow for the blinded query for the OPRF-based service,
/// using a Noir implementation of [ECRecover](https://github.com/colinnielsen/ecrecover-noir)
/// which derives an address from the public key and verifies the given signature.
/// The general idea is that only a client who controls the private key corresponding to the public key
/// can produce a valid signature for the fixed message, and thus only such a client can derive the correct proof for their address.
///
/// 1. **Client message signing (wallet)**
///    - The client signs a fixed message with their wallet.
///    - The hash of that message is fixed by the circuit. It must not be a prover-chosen input,
///      as ECDSA signatures over an arbitrary hash can be forged from the public key alone.
///
/// 2. **In-circuit verification**
///    - The client provides the following as **private inputs**:
///      - public key
///      - signature
///      - random field element `beta` (blinding factor)
///    - The circuit verifies the signature against the public key and recovers/derives
///      the wallet address.
///
/// 3. **Encode, blind, and query OPRF**
///    - The recovered address is **encoded to the curve** (BabyJubJub here).
///    - The encoded point is **blinded** using `beta` to get `b_q`.
///    - The blinded point is sent to the OPRF nodes as the client's query input.
///
fn main(
    pub_key_x: [u8; 32],
    pub_key_y: [u8; 32],
    signature: [u8; 64],
    beta: Field,
) -> pub BabyJubJubPointInSubgroup {
    // Verify the signature over the fixed message and derive the ETH address, which is used as the input to the OPRF protocol.
    let address = wallet_address(pub_key_x, pub_key_y, signature);

    // Generate the query proof point.
    blinded_query(beta, address)
}

mod tests {
    use super::main;
    use babyjubjub::BabyJubJubPointInSubgroup;
    use wallet_ownership::{TEST_PUB_KEY_X, TEST_PUB_KEY_Y, TEST_SIGNATURE};

    global BETA: Field =
        1498760273557913456370459222027449040163634869948415528344868600761947487523;

    #[test]
    fn test_main() {
        let result = main(TEST_PUB_KEY_X, TEST_PUB_KEY_Y, TEST_SIGNATURE, BETA);
        let expected = BabyJubJubPointInSubgroup::new(
            0x1a23b1caeed85a20e60abfba9cea870446bd1131dac30411eeb57f2ab73b3078,
            0x05958ac48b134c390ea7a12bccebb854299bb45e60d914be081e29c6d8b830a4,
        );
        assert(result.equals(expected), "Query request point does not match expected value");
    }

    #[test(should_fail)]
    fn test_invalid_signature_rejected() {
        let mut signature = TEST_SIGNATURE;
        signature[0] += 1;
        let _ = main(TEST_PUB_KEY_X, TEST_PUB_KEY_Y, signature, BETA);
    }

    #[test(should_fail_with = "Beta cannot be zero")]
    fn test_zero_beta_rejected() {
        let _ = main(TEST_PUB_KEY_X, TEST_PUB_KEY_Y, TEST_SIGNATURE, 0);
    }
}
