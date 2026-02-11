use babyjubjub::BabyJubJubPoint;
use ecrecover::ecrecover;
use oprf::blinded_query::blinded_query;

/// This directory contains an implementation of the proof flow for the blinded query for the OPRF-based service,
/// using a Noir implementation of [ECRecover](https://github.com/colinnielsen/ecrecover-noir)
/// which derives an address from the public key and verifies the given signature.
/// The general idea is that only a client who controls the private key corresponding to the public key
/// can produce a valid signature for the fixed message, and thus only such a client can derive the correct proof for their address.
///
/// 1. **Client message signing (wallet)**
///    - The client signs a fixed message with their wallet.
///    - The hashed message is provided to the circuit as a **public input**.
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
    hashed_message: pub [u8; 32],
    pub_key_x: [u8; 32],
    pub_key_y: [u8; 32],
    signature: [u8; 64],
    beta: Field,
) -> pub BabyJubJubPoint {
    // The function ecrecover takes in a hashed message, a public key (x and y coordinates) and a signature, verifies the signature and returns the recovered ETH address, which is used as the input to the OPRF protocol.
    let address = ecrecover(pub_key_x, pub_key_y, signature, hashed_message);

    // Generate the query proof point.
    blinded_query(beta, address)
}

#[test]
fn test_main() {
    let signature = [
        34, 94, 125, 19, 113, 129, 1, 254, 222, 37, 77, 59, 21, 235, 106, 193, 166, 124, 104, 4,
        118, 162, 234, 211, 115, 66, 94, 150, 59, 199, 57, 183, 59, 250, 14, 152, 118, 130, 19, 3,
        212, 55, 92, 127, 128, 188, 84, 190, 85, 212, 225, 151, 89, 155, 47, 162, 87, 134, 208, 226,
        7, 161, 5, 168,
    ];
    let beta = 1498760273557913456370459222027449040163634869948415528344868600761947487523;
    let hashed_message = [
        218, 239, 222, 213, 190, 193, 112, 62, 182, 226, 19, 202, 51, 169, 222, 157, 155, 222, 83,
        32, 18, 31, 187, 249, 49, 128, 244, 131, 204, 206, 107, 226,
    ];
    let pub_key_x = [
        158, 30, 136, 123, 120, 204, 6, 226, 64, 216, 96, 95, 238, 120, 20, 91, 44, 2, 181, 15, 171,
        210, 100, 74, 243, 208, 255, 91, 222, 248, 18, 190,
    ];
    let pub_key_y = [
        151, 145, 124, 206, 255, 36, 241, 99, 254, 200, 250, 151, 236, 57, 81, 36, 165, 7, 139, 205,
        215, 77, 194, 49, 9, 177, 21, 157, 90, 29, 26, 7,
    ];

    let expected_query_request = BabyJubJubPoint::new(
        20769343801606875644580992560767002733477266146250829360177308891153456763932,
        717924508062895681512301498190527672768108096190869247123342479357366276555,
    );

    let result = main(hashed_message, pub_key_x, pub_key_y, signature, beta);
    assert(
        (result.x == expected_query_request.x) & (result.y == expected_query_request.y),
        "Query request point does not match expected value",
    );
}
