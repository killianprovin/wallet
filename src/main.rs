use wallet::utils::{vec_to_hex, hex_to_vec};
use wallet::bip84::{generate_master_zprv, derive_child_zprv, zprv_to_zpub, p2wpkh_address_from_zpub};

use wallet::tx::{Tx, TxIn, TxOut, OutPoint, serialize_transaction, calculate_txid, create_script_pubkey};

fn main() {
    let mnemonic = "consider cry bomb sniff party pattern pool horse skirt damage dawn wagon excess slab snow abstract series dad worth frequent lemon imitate nest chicken";
    let passphrase = "";
    
    // Test BIP84: m/84'/0'/0'/0
    println!("\n--- BIP84 (zprv/zpub) ---");
    let master_zprv = generate_master_zprv(mnemonic, passphrase);
    let zprv_84 = derive_child_zprv(&master_zprv, 0x80000054);  // m/84'
    let zprv_84_0 = derive_child_zprv(&zprv_84, 0x80000000);      // m/84'/0'
    let zprv_84_0_0 = derive_child_zprv(&zprv_84_0, 0x80000000);    // m/84'/0'/0'
    let zprv_84_0_0_0 = derive_child_zprv(&zprv_84_0_0, 0);          // m/84'/0'/0'/0
    let zpub_84_0_0_0 = zprv_to_zpub(&zprv_84_0_0_0);


    // Génération de 3 adresses P2WPKH à partir de la clé publique compressée
    let address0 = p2wpkh_address_from_zpub(&zpub_84_0_0_0, 0);
    let address1 = p2wpkh_address_from_zpub(&zpub_84_0_0_0, 1);

    println!("\n--- P2WPKH addresses ---");
    println!("Address 0: {}", address0);
    println!("Address 1: {}", address1);

    let script_pubkey1 = create_script_pubkey("tb1qrazrspgm7enyw0hcsl90jzcsj6hp0qv4hdd65v")
        .expect("Invalid script pubkey");
    let script_pubkey2 = create_script_pubkey("tb1qhzkw7r54krcr3te57dwpq779ygcx8g396ke97g")
        .expect("Invalid script pubkey");

    let tx = Tx {
        version: 2,
        flag: Some(0x0100),
        inputs: vec![
            TxIn {
                previous_output: OutPoint {
                    txid: hex_to_vec("ae20ce9931fc9ed1c1e65e785510c2b58d75ac831fb92ab2925be4f295ff0883")
                        .try_into()
                        .expect("Invalid txid"),
                    vout: 1,
                },
                script_sig: vec![],
                sequence: 0xFFFFFFFF,
            }
        ],
        outputs: vec![
            TxOut {
                value: 10_000,
                script_pubkey: script_pubkey1.clone(),
            },
            TxOut {
                value: 5_000,
                script_pubkey: script_pubkey2.clone(),
            },
        ],
        witnesses: Some(vec![]),
        lock_time: 0,
    };

    let txid = calculate_txid(&tx);
    println!("Txid: {}", vec_to_hex(&txid));

    let raw_tx = serialize_transaction(&tx, true);
    println!("Raw tx: {}", vec_to_hex(&raw_tx));
}











/* 0.00015426 BTC on testnet4

Tx : ae20ce9931fc9ed1c1e65e785510c2b58d75ac831fb92ab2925be4f295ff0883
Address : tb1qrazrspgm7enyw0hcsl90jzcsj6hp0qv4hdd65v
Privkey : zprvAhD3JhutQGPN3pgBZgG2uEkznsAuSWgAgWRFWKYDvh5PiJU3MtP6QqfzbUkeYGGQ6Vu5Aj9HCJ6GWCV9GWFGZoM2dmks4KMnEFDc1m8DhkN
Pubkey : zpub6vCPiDSnEdwfGJkefho3GNhjLu1PqyQ23jLrJhwqV2cNb6oBuRhLxdzUSkyqbGE7NoGxpMbbNNeCpnbXZ939DPzrNkQBsLoTgAQ5PaTExrt

*/

//02000000000101d0edf061023a1edc36fd887e4ba6c660cbdb3ada9d3456baec55c4ab682497980000000000fdffffff02b05b7e030000000016001464d7c3134e71393f900108bccf43f18eee02faea423c0000000000001600141f4438051bf666473ef887caf90b1096ae178195014073d3c41947ba2092e471045e6174516128cfb97c753ce81baf8453517c82deafec61af5913d0a17d241558552cd8d5d4638c731c888d7c2b751004acacf2807881190100
