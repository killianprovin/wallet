use crate::bip::bip32::{generate_master_prv, derive_child_prv, derive_child_pub, prv_to_pub};

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