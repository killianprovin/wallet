use crate::utils::base58_encode;
use crate::hash::{hash160, double_sha256};
use crate::utils::encode_bech32;
use crate::utils::bech32::{convert_bits, Bech32Variant};

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

pub fn p2sh_p2wpkh_address(pubkey: &[u8]) -> String {
    let pubkey_hash = hash160(pubkey);

    let mut redeem_script = Vec::with_capacity(1 + 1 + 20);
    redeem_script.push(0x00);
    redeem_script.push(0x14);
    redeem_script.extend_from_slice(&pubkey_hash);

    let redeem_script_hash = hash160(&redeem_script);

    let mut payload = Vec::with_capacity(1 + 20);
    payload.push(0x05);
    payload.extend_from_slice(&redeem_script_hash);
    let checksum = &double_sha256(&payload)[..4];
    payload.extend_from_slice(checksum);

    base58_encode(&payload)
}

pub fn p2wpkh_address(pubkey: &[u8]) -> String {
    let ripemd160_hash = hash160(pubkey);

    let mut data = vec![0x00];
    data.extend_from_slice(&convert_bits(&ripemd160_hash, 8, 5, true).unwrap());

    encode_bech32("bc", &data, Bech32Variant::Bech32)
}