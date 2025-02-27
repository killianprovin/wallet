use crate::bip32::{generate_master_prv, derive_child_prv, derive_child_pub, prv_to_pub};
use crate::address::p2pkh_address;

const XPUB_VERSION: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];
const XPRV_VERSION: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4];

pub fn generate_master_xprv(mnemonic: &str, passphrase: &str) -> Vec<u8> {
    generate_master_prv(mnemonic, passphrase, &XPRV_VERSION)
}

pub fn derive_child_xprv(parent_xprv: &[u8], index: u32) -> Vec<u8> {
    derive_child_prv(parent_xprv, index, &XPRV_VERSION)
}

pub fn derive_child_xpub(parent_xpub: &[u8], index: u32) -> Vec<u8> {
    derive_child_pub(parent_xpub, index, &XPUB_VERSION)
}

pub fn xprv_to_xpub(prv: &[u8]) -> Vec<u8> {
    prv_to_pub(prv, &XPUB_VERSION)
}

pub fn p2pkh_address_from_xpub(parent_xpub: &[u8], index: u32) -> String {
    let child_xpub = derive_child_pub(parent_xpub, index, &XPUB_VERSION);
    let pubkey_bytes = &child_xpub[45..78];
    assert_eq!(pubkey_bytes.len(), 33, "La clé publique compressée doit faire 33 octets");
    p2pkh_address(pubkey_bytes)
}