use secp256k1::{Secp256k1, Message, SecretKey, ecdsa::{RecoverableSignature, RecoveryId}, PublicKey};
use crate::hash::{double_sha256, hash160};
use crate::utils::{base64_encode, base64_decode, base58_encode, write_varint};

pub fn sign_bitcoin_message(message: &str, secret_key: &SecretKey, compressed: bool) -> String {
    let prefix = "Bitcoin Signed Message:\n";
    
    let mut data = Vec::new();
    write_varint(prefix.len(), &mut data);
    data.extend_from_slice(prefix.as_bytes());
    write_varint(message.len(), &mut data);
    data.extend_from_slice(message.as_bytes());

    let hash: [u8; 32] = double_sha256(&data).try_into().expect("Hash must be 32 bytes");
    let msg = Message::from_digest(hash);
    
    let secp = Secp256k1::new();
    let rec_sig = secp.sign_ecdsa_recoverable(&msg, secret_key);
    
    let (rec_id, sig_bytes) = rec_sig.serialize_compact();
    let rec_id_val: i32 = rec_id.try_into().expect("id must be 1 byte");
    
    let header: u8 = if compressed {
        (rec_id_val + 31).try_into().unwrap()
    } else {
        (rec_id_val + 27).try_into().unwrap()
    };
    
    let mut compact_sig= Vec::with_capacity(65);
    compact_sig.push(header);
    compact_sig.extend_from_slice(&sig_bytes);
    
    base64_encode(&compact_sig)
}

pub fn verify_bitcoin_message(message: &str, signature: &str, public_key: &PublicKey) -> bool {
    let prefix = "Bitcoin Signed Message:\n";
    
    let mut data = Vec::new();
    write_varint(prefix.len(), &mut data);
    data.extend_from_slice(prefix.as_bytes());
    write_varint(message.len(), &mut data);
    data.extend_from_slice(message.as_bytes());

    let hash: [u8; 32] = double_sha256(&data).try_into().expect("Hash must be 32 bytes");
    let msg = Message::from_digest(hash);
    
    let secp = Secp256k1::new();
    let sig_bytes = base64_decode(signature);
    let rec_id : i32 = if sig_bytes[0] >= 31 {
        (sig_bytes[0] - 31).try_into().unwrap()
    } else {
        (sig_bytes[0] - 27).try_into().unwrap()
    };
    
    let rec_sig = RecoverableSignature::from_compact(&sig_bytes[1..], rec_id.try_into().expect("id must be 1 byte")).expect("Unable to reconstruct signature");
    let sig = rec_sig.to_standard();
    
    secp.verify_ecdsa(&msg, &sig, public_key).is_ok()
}

pub fn verify_bitcoin_message_with_address(message: &str, address: &str, signature_b64: &str) -> bool {
    let prefix = "Bitcoin Signed Message:\n";
    
    let mut data = Vec::new();
    write_varint(prefix.len(), &mut data);
    data.extend_from_slice(prefix.as_bytes());
    write_varint(message.len(), &mut data);
    data.extend_from_slice(message.as_bytes());

    let hash: [u8; 32] = double_sha256(&data).try_into().expect("Hash must be 32 bytes");
    let msg = Message::from_digest(hash);

    let sig_data = base64_decode(signature_b64);
    if sig_data.len() != 65 {
        println!("Invalid signature length");
        return false;
    }

    let rec_id_byte: i32 = sig_data[0].try_into().expect("Invalid RecoveryId");
    let rec_id = match rec_id_byte {
        27..=30 => RecoveryId::from((rec_id_byte - 27).try_into().expect("Invalid RecoveryId")),
        
        31..=34 => RecoveryId::from((rec_id_byte - 31).try_into().expect("Invalid RecoveryId")),
        _ => {
            println!("Invalid RecoveryId");
            return false;
        }
    };

    let secp = Secp256k1::new();

    let rec_sig = RecoverableSignature::from_compact(&sig_data[1..], rec_id)
        .expect("Unable to reconstruct signature");

    let pubkey = secp.recover_ecdsa(&msg, &rec_sig)
        .expect("Unable to recover public key");

    let pubkey_bytes = pubkey.serialize();
    let pubkey_hash = hash160(&pubkey_bytes);

    let mut address_bytes = vec![0x00];
    address_bytes.extend_from_slice(&pubkey_hash);

    let checksum = &double_sha256(&address_bytes)[..4];
    address_bytes.extend_from_slice(checksum);

    let derived_address = base58_encode(&address_bytes);

    derived_address == address
}