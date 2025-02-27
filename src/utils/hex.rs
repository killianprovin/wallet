pub fn vec_to_hex(bytes: Vec<u8>) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}