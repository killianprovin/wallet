use crate::hash::pbkdf2_hmac_sha512;

pub fn generate_seed(mnemonic: &str, passphrase: &str) -> Vec<u8> {
    let salt = format!("mnemonic{}", passphrase);
    pbkdf2_hmac_sha512(
        mnemonic.as_bytes(),
        salt.as_bytes(),
        2048,
        64,
    )
}