use crate::hash::hmac_sha512;

pub fn pbkdf2_hmac_sha512(password: &[u8],  salt: &[u8], iterations: u32, dk_len: usize,) -> Vec<u8> {
    let mut dk = Vec::with_capacity(dk_len);
    let mut block_num: u32 = 1;

    while dk.len() < dk_len {
        let mut salt_block = Vec::with_capacity(salt.len() + 4);
        salt_block.extend_from_slice(salt);
        salt_block.extend_from_slice(&block_num.to_be_bytes());

        let mut u = hmac_sha512(password, &salt_block);
        let mut t = u.clone();

        for _ in 1..iterations {
            u = hmac_sha512(password, &u);
            for (t_byte, u_byte) in t.iter_mut().zip(u.iter()) {
                *t_byte ^= u_byte;
            }
        }

        dk.extend_from_slice(&t);
        block_num += 1;
    }

    dk.truncate(dk_len);
    dk
}
