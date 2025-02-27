use crate::utils::base58_encode;
use crate::hash::{hash160, double_sha256};

pub fn p2pkh_address(pubkey: &[u8]) -> String {
    let hash160_val = hash160(pubkey);

    let mut payload = Vec::with_capacity(1 + 20);
    payload.push(0x00);
    payload.extend_from_slice(&hash160_val);

    let check = double_sha256(&payload);
    let checksum = &check[..4];

    payload.extend_from_slice(checksum);

    base58_encode(&payload)
}