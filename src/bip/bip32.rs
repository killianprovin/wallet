use crate::bip::bip39::generate_seed;
use crate::hash::{hmac_sha512, double_sha256, hash160};
use secp256k1::{Secp256k1, SecretKey, PublicKey, Scalar};

pub fn generate_master_prv(mnemonic: &str, passphrase: &str, version: &[u8; 4]) -> Vec<u8> {
    let seed = generate_seed(mnemonic, passphrase);

    let hmac_key = b"Bitcoin seed";
    let hmac_result = hmac_sha512(hmac_key, &seed);

    let master_private_key = &hmac_result[..32];
    let master_chain_code = &hmac_result[32..];

    let mut extended_key = Vec::new();

    extended_key.extend_from_slice(version);
    extended_key.push(0x00);
    extended_key.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    extended_key.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    extended_key.extend_from_slice(master_chain_code);
    extended_key.push(0x00);
    extended_key.extend_from_slice(master_private_key);
    let checksum = &double_sha256(&extended_key)[..4];
    extended_key.extend_from_slice(checksum);

    extended_key
}

pub fn prv_to_pub(prv: &[u8], version: &[u8; 4]) -> Vec<u8> {
    let ext_data = &prv[..78];

    let chain_code = &ext_data[13..45];
    let key_data = &ext_data[45..78];
    let priv_key_bytes = &key_data[1..];

    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(priv_key_bytes).expect("La clé privée doit être sur 32 octets et dans l'ordre de courbe");
    let pk = PublicKey::from_secret_key(&secp, &sk);
    let pk_serialized = pk.serialize();

    let mut extended_pub = Vec::new();
    extended_pub.extend_from_slice(version);
    extended_pub.push(ext_data[4]);
    extended_pub.extend_from_slice(&ext_data[5..9]);
    extended_pub.extend_from_slice(&ext_data[9..13]);
    extended_pub.extend_from_slice(chain_code);
    extended_pub.extend_from_slice(&pk_serialized);
    let checksum = &double_sha256(&extended_pub)[..4];
    extended_pub.extend_from_slice(checksum);

    extended_pub
}

fn ser32(i: u32) -> [u8; 4] {
    i.to_be_bytes()
}

pub fn derive_child_prv(parent_prv: &[u8], index: u32, version: &[u8; 4]) -> Vec<u8> {
    assert!(parent_prv.len() == 82, "Le prv parent doit être sur 82 octets.");
    let parent_data = &parent_prv[..78];

    let parent_depth = parent_data[4];
    let parent_chain_code = &parent_data[13..45];
    let parent_privkey_bytes = &parent_data[46..78];

    let secp = Secp256k1::new();
    let parent_sk = SecretKey::from_slice(parent_privkey_bytes)
        .expect("Clé privée parent invalide");
    let parent_pk = PublicKey::from_secret_key(&secp, &parent_sk);
    let parent_pk_ser = parent_pk.serialize();
    let parent_fingerprint = &hash160(&parent_pk_ser)[..4];

    let mut data = Vec::with_capacity(1 + 32 + 4);
    if index >= 0x80000000 {
        data.push(0x00);
        data.extend_from_slice(parent_privkey_bytes);
    } else {
        data.extend_from_slice(&parent_pk_ser);
    }
    data.extend_from_slice(&ser32(index));

    let i = hmac_sha512(parent_chain_code, &data);
    let il = &i[..32];
    let ir = &i[32..];

    let il_array: [u8; 32] = il.try_into().expect("IL doit contenir exactement 32 octets");

    let tweak_scalar = Scalar::from_be_bytes(il_array)
        .expect("Impossible de convertir il en Scalar");

    let child_sk = parent_sk
        .add_tweak(&tweak_scalar)
        .expect("La dérivation de la clé enfant a échoué");

    let mut child_extended = Vec::with_capacity(78);
    child_extended.extend_from_slice(version);
    child_extended.push(parent_depth.wrapping_add(1));
    child_extended.extend_from_slice(parent_fingerprint);
    child_extended.extend_from_slice(&ser32(index));
    child_extended.extend_from_slice(ir);
    child_extended.push(0x00);
    child_extended.extend_from_slice(&child_sk[..]);

    let checksum = &double_sha256(&child_extended)[..4];
    child_extended.extend_from_slice(checksum);

    child_extended
}


pub fn derive_child_pub(parent_pub: &[u8], index: u32, version: &[u8; 4]) -> Vec<u8> {
    assert!(index < 0x80000000, "On ne peut pas dériver un enfant renforcé à partir d'un xpub.");
    assert!(parent_pub.len() == 82, "Le xpub parent doit être sur 82 octets.");

    let parent_data = &parent_pub[..78];

    let parent_depth = parent_data[4];
    let parent_chain_code = &parent_data[13..45];
    let parent_pk_ser = &parent_data[45..78];

    let parent_fingerprint = &hash160(parent_pk_ser)[..4];

    let mut data = Vec::with_capacity(33 + 4);
    data.extend_from_slice(parent_pk_ser);
    data.extend_from_slice(&ser32(index));

    let i = hmac_sha512(parent_chain_code, &data);
    let il = &i[..32];
    let ir = &i[32..];

    let secp = Secp256k1::new();
    let il_sk = SecretKey::from_slice(il)
        .expect("IL n'est pas une clé privée valide");
    let il_pk = PublicKey::from_secret_key(&secp, &il_sk);
    let parent_pk = PublicKey::from_slice(parent_pk_ser)
        .expect("Clé publique parent invalide");
    let child_pk = parent_pk.combine(&il_pk)
        .expect("La dérivation de la clé publique enfant a échoué");
    let child_pk_ser = child_pk.serialize();

    let mut child_extended = Vec::with_capacity(78);
    child_extended.extend_from_slice(version);
    child_extended.push(parent_depth.wrapping_add(1));
    child_extended.extend_from_slice(parent_fingerprint);
    child_extended.extend_from_slice(&ser32(index));
    child_extended.extend_from_slice(ir);
    child_extended.extend_from_slice(&child_pk_ser);

    let checksum = &double_sha256(&child_extended)[..4];
    child_extended.extend_from_slice(checksum);

    child_extended
}