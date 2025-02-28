use crate::bip32::{generate_master_prv, derive_child_prv, derive_child_pub, prv_to_pub};
use crate::address::p2wpkh_address;

const ZPUB_VERSION: [u8; 4] = [0x04, 0xB2, 0x47, 0x46];
const ZPRV_VERSION: [u8; 4] = [0x04, 0xB2, 0x43, 0x0C];

pub fn generate_master_zprv(mnemonic: &str, passphrase: &str) -> Vec<u8> {
    generate_master_prv(mnemonic, passphrase, &ZPRV_VERSION)
}

pub fn derive_child_zprv(parent_zprv: &[u8], index: u32) -> Vec<u8> {
    derive_child_prv(parent_zprv, index, &ZPRV_VERSION)
}

pub fn derive_child_zpub(parent_zpub: &[u8], index: u32) -> Vec<u8> {
    derive_child_pub(parent_zpub, index, &ZPUB_VERSION)
}

pub fn zprv_to_zpub(prv: &[u8]) -> Vec<u8> {
    prv_to_pub(prv, &ZPUB_VERSION)
}

pub fn p2wpkh_address_from_zpub(parent_zpub: &[u8], index: u32) -> String {
    let child_zpub = derive_child_zpub(parent_zpub, index);
    let pubkey_bytes = &child_zpub[45..78];
    assert_eq!(pubkey_bytes.len(), 33, "La clé publique compressée doit faire 33 octets");
    p2wpkh_address(pubkey_bytes)
}