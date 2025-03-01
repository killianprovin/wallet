pub fn vec_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

pub fn hex_to_vec(hex: &str) -> Vec<u8> {
    hex.as_bytes().chunks(2).map(|chunk| {
        u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap()
    }).collect()
}