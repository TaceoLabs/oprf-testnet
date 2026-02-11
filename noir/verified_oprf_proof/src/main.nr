use babyjubjub::BabyJubJubPoint;
use ecrecover::ecrecover;
use oprf::oprf_output::verified_oprf;
pub global DS_N: Field = 24546418369108709687614662004; // b"OPRF TestNet"
pub global DS_DLOG: Field = 1523098184080632582082867317389990410064981862; // b"DLOG Equality Proof"

fn main(
    // These are the inputs needed for the first part of the OPRF protocol, the query proof.
    hashed_message: pub [u8; 32],
    pub_key_x: [u8; 32],
    pub_key_y: [u8; 32],
    signature: [u8; 64],
    beta: Field,
    // These are the inputs needed for the second part of the OPRF protocol, the verified OPRF output.
    oprf_pk: pub BabyJubJubPoint,
    dlog_e: Field,
    dlog_s: Field,
    oprf_response_blinded: BabyJubJubPoint,
    oprf_response: BabyJubJubPoint,
) -> pub Field {
    // Similar to the blinded query proof, we first recover the user input (address) from the signature.
    let address = ecrecover(pub_key_x, pub_key_y, signature, hashed_message);
    // Inside the verified_oprf function, we recompute the blinded query proof to check that the original query was computed correctly, verify the dlog equality proof, verify the unblinding was done correctly, and then generate the final verified OPRF output.
    verified_oprf(
        beta,
        oprf_pk,
        dlog_e,
        dlog_s,
        oprf_response_blinded,
        oprf_response,
        address,
        DS_DLOG,
        DS_N,
    )
}

#[test]
fn test_main() {
    let oprf_pk = BabyJubJubPoint::new(
        15003657924788399520423800501973962387080403835278072811641574091656004606719,
        14529415343323015636900366522580262473735574267701282924026299349812458958307,
    );

    let oprf_response = BabyJubJubPoint::new(
        1065949620655181774308101197704033100236194646567058021926722685606992436847,
        14787959160106034745010522499467846959920195067540224472248153986015143882065,
    );

    let oprf_response_blinded = BabyJubJubPoint::new(
        4412395052256565047298638251655830431466984686274840433808703772709569110803,
        20256127588343150090186757350315422452391433342385468273813865055940593724572,
    );

    let signature = [
        34, 94, 125, 19, 113, 129, 1, 254, 222, 37, 77, 59, 21, 235, 106, 193, 166, 124, 104, 4,
        118, 162, 234, 211, 115, 66, 94, 150, 59, 199, 57, 183, 59, 250, 14, 152, 118, 130, 19, 3,
        212, 55, 92, 127, 128, 188, 84, 190, 85, 212, 225, 151, 89, 155, 47, 162, 87, 134, 208, 226,
        7, 161, 5, 168,
    ];
    let beta = 1498760273557913456370459222027449040163634869948415528344868600761947487523;
    let dlog_e = 2815834045141047248296014764766921370888833365641393041932225141550944894751;
    let dlog_s = 1023284613684976434280267589564951651741782634037934709388634324034792989992;
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

    let expected_output =
        4950770752664949154430470844859569966167289863513636892677190123059944174158;

    let result = main(
        hashed_message,
        pub_key_x,
        pub_key_y,
        signature,
        beta,
        oprf_pk,
        dlog_e,
        dlog_s,
        oprf_response_blinded,
        oprf_response,
    );
    assert(result == expected_output, "OPRF output does not match expected value");
}
