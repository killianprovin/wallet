use secp256k1::{Secp256k1, SecretKey, PublicKey, Scalar};
use crate::hash::{hmac_sha512, double_sha256, hash160};
use crate::bip39::generate_seed;

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
    let sk = SecretKey::from_slice(priv_key_bytes).expect("Invalid private key");
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

pub fn derive_child_prv(parent_prv: &[u8], index: u32, version: &[u8; 4]) -> Vec<u8> {
    assert!(parent_prv.len() == 82, "Invalid parent xprv length");
    let parent_data = &parent_prv[..78];

    let parent_depth = parent_data[4];
    let parent_chain_code = &parent_data[13..45];
    let parent_privkey_bytes = &parent_data[46..78];

    let secp = Secp256k1::new();
    let parent_sk = SecretKey::from_slice(parent_privkey_bytes)
        .expect("Invalid parent private key");
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
    data.extend_from_slice(&index.to_be_bytes());

    let i = hmac_sha512(parent_chain_code, &data);
    let il = &i[..32];
    let ir = &i[32..];

    let il_array: [u8; 32] = il.try_into().expect("il must be 32 bytes");

    let tweak_scalar = Scalar::from_be_bytes(il_array)
        .expect("Impossible to convert tweak scalar");

    let child_sk = parent_sk
        .add_tweak(&tweak_scalar)
        .expect("Derivation failed");

    let mut child_extended = Vec::with_capacity(78);
    child_extended.extend_from_slice(version);
    child_extended.push(parent_depth.wrapping_add(1));
    child_extended.extend_from_slice(parent_fingerprint);
    child_extended.extend_from_slice(&index.to_be_bytes());
    child_extended.extend_from_slice(ir);
    child_extended.push(0x00);
    child_extended.extend_from_slice(&child_sk[..]);

    let checksum = &double_sha256(&child_extended)[..4];
    child_extended.extend_from_slice(checksum);

    child_extended
}


pub fn derive_child_pub(parent_pub: &[u8], index: u32, version: &[u8; 4]) -> Vec<u8> {
    assert!(index < 0x80000000, "Impossible to derive hardened child from public key");
    assert!(parent_pub.len() == 82, "xpub length must be 82 bytes");

    let parent_data = &parent_pub[..78];

    let parent_depth = parent_data[4];
    let parent_chain_code = &parent_data[13..45];
    let parent_pk_ser = &parent_data[45..78];

    let parent_fingerprint = &hash160(parent_pk_ser)[..4];

    let mut data = Vec::with_capacity(33 + 4);
    data.extend_from_slice(parent_pk_ser);
    data.extend_from_slice(&index.to_be_bytes());

    let i = hmac_sha512(parent_chain_code, &data);
    let il = &i[..32];
    let ir = &i[32..];

    let secp = Secp256k1::new();
    let il_sk = SecretKey::from_slice(il)
        .expect("il is not a valid private key");
    let il_pk = PublicKey::from_secret_key(&secp, &il_sk);
    let parent_pk = PublicKey::from_slice(parent_pk_ser)
        .expect("Impossible to convert parent public key");
    let child_pk = parent_pk.combine(&il_pk)
        .expect("Impossible to combine public keys");
    let child_pk_ser = child_pk.serialize();

    let mut child_extended = Vec::with_capacity(78);
    child_extended.extend_from_slice(version);
    child_extended.push(parent_depth.wrapping_add(1));
    child_extended.extend_from_slice(parent_fingerprint);
    child_extended.extend_from_slice(&index.to_be_bytes());
    child_extended.extend_from_slice(ir);
    child_extended.extend_from_slice(&child_pk_ser);

    let checksum = &double_sha256(&child_extended)[..4];
    child_extended.extend_from_slice(checksum);

    child_extended
}

pub fn prv_to_secret_key(xprv: &[u8]) -> SecretKey {
    let key_data = &xprv[46..78];
    SecretKey::from_slice(key_data)
        .expect("key_data must be 32 bytes and valid private key")
}

pub fn pub_to_public_key(xpub: &[u8]) -> PublicKey {
    let key_data = &xpub[45..78];
    PublicKey::from_slice(key_data)
        .expect("key_data must be 33 bytes and valid pub key")
}