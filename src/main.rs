use wallet::utils::{base58_encode};
use wallet::bip44::{generate_master_xprv, derive_child_xprv, xprv_to_xpub, p2pkh_address_from_xpub};
use wallet::bip49::{generate_master_yprv, derive_child_yprv, yprv_to_ypub};
use wallet::bip84::{generate_master_zprv, derive_child_zprv, zprv_to_zpub};

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

}
