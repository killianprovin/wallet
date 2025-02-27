use crate::hash::sha512;

pub fn hmac_sha512(key: &[u8], message: &[u8]) -> Vec<u8> {
    const BLOCK_SIZE: usize = 128;

    let mut key = if key.len() > BLOCK_SIZE {
        sha512(key)
    } else {
        key.to_vec()
    };

    if key.len() < BLOCK_SIZE {
        key.resize(BLOCK_SIZE, 0x00);
    }

    let mut ipad = vec![0x36; BLOCK_SIZE];
    let mut opad = vec![0x5c; BLOCK_SIZE];

    for i in 0..BLOCK_SIZE {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }

    let mut inner_hash_input = ipad;
    inner_hash_input.extend_from_slice(message);
    let inner_hash = sha512(&inner_hash_input);

    let mut outer_hash_input = opad;
    outer_hash_input.extend_from_slice(&inner_hash);
    sha512(&outer_hash_input)
}
