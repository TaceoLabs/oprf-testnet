pub fn u8_32_to_u8_64(arr_a: [u8; 32], arr_b: [u8; 32]) -> [u8; 64] {
    let mut combined: [u8; 64] = [0; 64];

    for i in 0..32 {
        combined[i] = arr_a[i];
    }
    for i in 0..32 {
        combined[i + 32] = arr_b[i];
    }

    combined
}

pub fn split_u8_64(arr: [u8; 64]) -> ([u8; 32], [u8; 32]) {
    let mut arr_a: [u8; 32] = [0; 32];
    let mut arr_b: [u8; 32] = [0; 32];

    for i in 0..32 {
        arr_a[i] = arr[i];
        arr_b[i] = arr[i + 32];
    }

    (arr_a, arr_b)
}

#[test]
fn test_split_u8_64() {
    let u8_64 = [
        193, 255, 211, 207, 238, 45, 158, 92, 214, 118, 67, 248, 243, 159, 214, 229, 26, 173, 136,
        246, 244, 206, 106, 184, 130, 114, 121, 207, 255, 185, 34, 102, 193, 255, 211, 207, 238, 45,
        158, 92, 214, 118, 67, 248, 243, 159, 214, 229, 26, 173, 136, 246, 244, 206, 106, 184, 130,
        114, 121, 207, 255, 185, 34, 102,
    ];

    let (arr_a, arr_b) = split_u8_64(u8_64);

    for i in 0..32 {
        assert(arr_a[i] == u8_64[i]);
        assert(arr_b[i] == u8_64[i + 32]);
    }
}
