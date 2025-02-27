use crate::bip32::{generate_master_prv, derive_child_prv, derive_child_pub, prv_to_pub};

const YPUB_VERSION: [u8; 4] = [0x04, 0x9D, 0x7C, 0xB2];
const YPRV_VERSION: [u8; 4] = [0x04, 0x9D, 0x78, 0x78];

pub fn generate_master_yprv(mnemonic: &str, passphrase: &str) -> Vec<u8> {
    generate_master_prv(mnemonic, passphrase, &YPRV_VERSION)
}

pub fn derive_child_yprv(parent_yprv: &[u8], index: u32) -> Vec<u8> {
    derive_child_prv(parent_yprv, index, &YPRV_VERSION)
}

pub fn derive_child_ypub(parent_ypub: &[u8], index: u32) -> Vec<u8> {
    derive_child_pub(parent_ypub, index, &YPUB_VERSION)
}

pub fn yprv_to_ypub(yprv: &[u8]) -> Vec<u8> {
    prv_to_pub(yprv, &YPUB_VERSION)
}