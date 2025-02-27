pub mod sha256;
pub mod sha512;
pub mod hmac;
pub mod pbkdf2;
pub mod ripemd160;

pub use sha256::sha256;
pub use sha256::double_sha256;

pub use sha512::sha512;

pub use hmac::hmac_sha512;

pub use pbkdf2::pbkdf2_hmac_sha512;

pub use ripemd160::ripemd160;

pub fn hash160(input: &[u8]) -> Vec<u8> {
    ripemd160(&sha256(input))
}