use ecrecover::ecrecover;

/// EIP-191 (`personal_sign`) hash of the fixed message "TACEO Oprf Input".
///
/// The hash must be fixed by the circuit: ECDSA signatures over a prover-chosen hash can be forged from the public key alone.
/// As the message is fixed, the signature is not protected against replay attacks: it never expires and whoever obtains it can prove ownership of the wallet.
pub fn signed_message_hash() -> [u8; 32] {
    let body = "Ethereum Signed Message:\n16TACEO Oprf Input".as_bytes();
    let mut msg = [0x19; 44];
    for i in 0..43 {
        msg[i + 1] = body[i];
    }
    keccak256::keccak256(msg, 44)
}

/// Verifies the signature over the fixed message and returns the ETH address of the signer.
pub fn wallet_address(pub_key_x: [u8; 32], pub_key_y: [u8; 32], signature: [u8; 64]) -> Field {
    ecrecover(pub_key_x, pub_key_y, signature, signed_message_hash())
}

// Signature of the anvil default account 0 (0xf39f...2266) over the fixed message.
pub global TEST_PUB_KEY_X: [u8; 32] = [
    131, 24, 83, 91, 84, 16, 93, 74, 122, 174, 96, 192, 143, 196, 95, 150, 135, 24, 27, 79, 223,
    198, 37, 189, 26, 117, 63, 167, 57, 127, 237, 117,
];
pub global TEST_PUB_KEY_Y: [u8; 32] = [
    53, 71, 241, 28, 168, 105, 102, 70, 242, 243, 172, 176, 142, 49, 1, 106, 250, 194, 62, 99, 12,
    93, 17, 245, 159, 97, 254, 245, 123, 13, 42, 165,
];
pub global TEST_SIGNATURE: [u8; 64] = [
    172, 33, 178, 134, 120, 81, 97, 201, 98, 197, 81, 228, 95, 5, 236, 171, 21, 247, 79, 143, 99,
    48, 23, 83, 220, 206, 88, 140, 199, 44, 104, 1, 53, 73, 159, 198, 170, 237, 176, 60, 11, 64,
    247, 223, 114, 255, 167, 167, 191, 26, 76, 167, 166, 245, 201, 113, 105, 149, 95, 116, 82, 107,
    17, 179,
];

#[test]
fn test_signed_message_hash() {
    // cast keccak "$(printf '\x19Ethereum Signed Message:\n16TACEO Oprf Input')"
    let expected = [
        0x2b, 0xe0, 0x80, 0xcd, 0x95, 0x3c, 0xe4, 0x44, 0x16, 0x69, 0x18, 0x13, 0xe4, 0x77, 0x56,
        0xca, 0x6c, 0x87, 0x2e, 0x5f, 0x41, 0xbd, 0xd7, 0xad, 0x3f, 0x29, 0x4d, 0x12, 0x0b, 0xbc,
        0x6a, 0x37,
    ];
    assert(signed_message_hash() == expected);
}

#[test]
fn test_wallet_address() {
    let addr = wallet_address(TEST_PUB_KEY_X, TEST_PUB_KEY_Y, TEST_SIGNATURE);
    assert(addr == 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266);
}

#[test(should_fail)]
fn test_invalid_signature_rejected() {
    let mut signature = TEST_SIGNATURE;
    signature[0] += 1;
    let _ = wallet_address(TEST_PUB_KEY_X, TEST_PUB_KEY_Y, signature);
}
