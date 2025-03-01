use wallet::utils::{base58_encode};
use wallet::bip32::{prv_to_secret_key, pub_to_public_key};
use wallet::bip44::{generate_master_xprv, derive_child_xprv, xprv_to_xpub, p2pkh_address_from_xpub};
use wallet::bip49::{generate_master_yprv, derive_child_yprv, yprv_to_ypub, p2sh_address_from_ypub};
use wallet::bip84::{generate_master_zprv, derive_child_zprv, zprv_to_zpub, p2wpkh_address_from_zpub};
use wallet::signature::{sign_bitcoin_message, verify_bitcoin_message, verify_bitcoin_message_with_address};

fn main() {
    let mnemonic = "consider cry bomb sniff party pattern pool horse skirt damage dawn wagon excess slab snow abstract series dad worth frequent lemon imitate nest chicken";
    let passphrase = "";
    
    // Test BIP44: m/44'/0'/0'/0
    println!("--- BIP44 (xprv/xpub) ---");
    let master_xprv = generate_master_xprv(mnemonic, passphrase);
    let xprv_44 = derive_child_xprv(&master_xprv, 0x8000002C);  // m/44'
    let xprv_44_0 = derive_child_xprv(&xprv_44, 0x80000000);      // m/44'/0'
    let xprv_44_0_0 = derive_child_xprv(&xprv_44_0, 0x80000000);    // m/44'/0'/0'
    let xprv_44_0_0_0 = derive_child_xprv(&xprv_44_0_0, 0);          // m/44'/0'/0'/0
    let xpub_44_0_0_0 = xprv_to_xpub(&xprv_44_0_0_0);
    println!("m/44'/0'/0'/0 xprv: {}", base58_encode(&xprv_44_0_0_0));
    println!("m/44'/0'/0'/0 xpub: {}", base58_encode(&xpub_44_0_0_0));

    // Test BIP49: m/49'/0'/0'/0
    println!("\n--- BIP49 (yprv/ypub) ---");
    let master_yprv = generate_master_yprv(mnemonic, passphrase);
    let yprv_49 = derive_child_yprv(&master_yprv, 0x80000031);  // m/49'
    let yprv_49_0 = derive_child_yprv(&yprv_49, 0x80000000);      // m/49'/0'
    let yprv_49_0_0 = derive_child_yprv(&yprv_49_0, 0x80000000);    // m/49'/0'/0'
    let yprv_49_0_0_0 = derive_child_yprv(&yprv_49_0_0, 0);          // m/49'/0'/0'/0
    let ypub_49_0_0_0 = yprv_to_ypub(&yprv_49_0_0_0);
    println!("m/49'/0'/0'/0 yprv: {}", base58_encode(&yprv_49_0_0_0));
    println!("m/49'/0'/0'/0 ypub: {}", base58_encode(&ypub_49_0_0_0));

    // Test BIP84: m/84'/0'/0'/0
    println!("\n--- BIP84 (zprv/zpub) ---");
    let master_zprv = generate_master_zprv(mnemonic, passphrase);
    let zprv_84 = derive_child_zprv(&master_zprv, 0x80000054);  // m/84'
    let zprv_84_0 = derive_child_zprv(&zprv_84, 0x80000000);      // m/84'/0'
    let zprv_84_0_0 = derive_child_zprv(&zprv_84_0, 0x80000000);    // m/84'/0'/0'
    let zprv_84_0_0_0 = derive_child_zprv(&zprv_84_0_0, 0);          // m/84'/0'/0'/0
    let zpub_84_0_0_0 = zprv_to_zpub(&zprv_84_0_0_0);
    println!("m/84'/0'/0'/0 zprv: {}", base58_encode(&zprv_84_0_0_0));
    println!("m/84'/0'/0'/0 zpub: {}", base58_encode(&zpub_84_0_0_0));

    // Test derivation normal de xprv puis prv_to_pub egale de xpub
    let xpub_44_0_0_0_derived = derive_child_xprv(&xprv_44_0_0, 0);
    let xpub_44_0_0_0_derived = xprv_to_xpub(&xpub_44_0_0_0_derived);
    assert_eq!(xpub_44_0_0_0, xpub_44_0_0_0_derived);

    // Génération de 3 adresses P2PKH à partir de la clé publique compressée
    let address0 = p2pkh_address_from_xpub(&xpub_44_0_0_0, 0);
    let address1 = p2pkh_address_from_xpub(&xpub_44_0_0_0, 1);
    let address2 = p2pkh_address_from_xpub(&xpub_44_0_0_0, 2);

    println!("\n--- P2PKH addresses ---");
    println!("Address 0: {}", address0);
    println!("Address 1: {}", address1);
    println!("Address 2: {}", address2);

    // Génération de 3 adresses P2SH-P2WPKH à partir de la clé publique compressée
    let address0 = p2sh_address_from_ypub(&ypub_49_0_0_0, 0);
    let address1 = p2sh_address_from_ypub(&ypub_49_0_0_0, 1);
    let address2 = p2sh_address_from_ypub(&ypub_49_0_0_0, 2);

    println!("\n--- P2SH-P2WPKH addresses ---");
    println!("Address 0: {}", address0);
    println!("Address 1: {}", address1);
    println!("Address 2: {}", address2);

    // Génération de 3 adresses P2WPKH à partir de la clé publique compressée
    let address0 = p2wpkh_address_from_zpub(&zpub_84_0_0_0, 0);
    let address1 = p2wpkh_address_from_zpub(&zpub_84_0_0_0, 1);
    let address2 = p2wpkh_address_from_zpub(&zpub_84_0_0_0, 2);

    println!("\n--- P2WPKH addresses ---");
    println!("Address 0: {}", address0);
    println!("Address 1: {}", address1);
    println!("Address 2: {}", address2);

    // Signature d'un message avec la clé privée
    println!("\n--- Signature ---");
    let message = "Hello World\nI want to sign this message!";

    let prvkey = derive_child_xprv(&xprv_44_0_0_0, 0);
    let pubkey = xprv_to_xpub(&prvkey);
    let address = p2pkh_address_from_xpub(&xpub_44_0_0_0, 0);
    let secret_key = prv_to_secret_key(&prvkey);

    let signature = sign_bitcoin_message(message, &secret_key, true);
    println!("Message: {}", message);
    println!("address: {}", address);
    println!("Signature: {}", signature);

    // Vérification de la signature
    let pubkey = pub_to_public_key(&pubkey);
    let is_valid = verify_bitcoin_message(message, &signature, &pubkey);
    println!("Signature is valid: {}", is_valid);

    // Vérification de la signature avec l'adresse
    let is_valid = verify_bitcoin_message_with_address(message, &address, &signature);
    println!("Signature is valid: {}", is_valid);

    // Verification de la signature avec une adresse
    let address = "18FgxNdGSemUZNybpdrgdr1rbdRFbuAwL9";

    let message = "Esta es una prueba de firma de mensaje usando una dirección de Bitcoin, para Bit2Me Academy.";

    let signature = "IJQ9jOGl5ZdjmsUNDYmAwUlFqfjp/FfAi5dzdgiQTfjheDYmBxfBq40URLPOoggonqRYtGydTdwmiRn8ZElcSjc=";

    let is_valid = verify_bitcoin_message_with_address(&message, &address, &signature);
    println!("Signature is valid: {}", is_valid);
}











/* 0.00015426 BTC on testnet4

Tx : ae20ce9931fc9ed1c1e65e785510c2b58d75ac831fb92ab2925be4f295ff0883

Address : tb1qrazrspgm7enyw0hcsl90jzcsj6hp0qv4hdd65v
Privkey : zprvAhD3JhutQGPN3pgBZgG2uEkznsAuSWgAgWRFWKYDvh5PiJU3MtP6QqfzbUkeYGGQ6Vu5Aj9HCJ6GWCV9GWFGZoM2dmks4KMnEFDc1m8DhkN
Pubkey : zpub6vCPiDSnEdwfGJkefho3GNhjLu1PqyQ23jLrJhwqV2cNb6oBuRhLxdzUSkyqbGE7NoGxpMbbNNeCpnbXZ939DPzrNkQBsLoTgAQ5PaTExrt

*/