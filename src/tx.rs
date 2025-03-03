use crate::hash::double_sha256;
use crate::utils::{write_varint, read_varint, decode_bech32, bech32::convert_bits, hex_to_vec};

#[derive(Debug, Clone)]
pub struct Tx {
    pub version: u32,
    pub flag: Option<u16>,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub witnesses: Option<Vec<Witness>>,
    pub lock_time: u32,
}

#[derive(Debug, Clone)]
pub struct TxIn {
    pub previous_output: OutPoint,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

#[derive(Debug, Clone)]
pub struct TxOut {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct OutPoint {
    pub txid: [u8; 32],
    pub vout: u32,
}

#[derive(Debug, Clone)]
pub struct Witness {
    pub items: Vec<Vec<u8>>,
}

pub fn create_script_pubkey(bech32_address: &str) -> Result<Vec<u8>, String> {
    let (hrp, data) = decode_bech32(bech32_address)
        .map_err(|e| format!("Erreur lors du décodage de l'adresse Bech32: {}", e))?;
    if hrp != "bc" && hrp != "tb" {
        return Err("HRP invalide pour une adresse Bitcoin.".to_string());
    }
    if data.is_empty() {
        return Err("Données vides dans l'adresse Bech32.".to_string());
    }
    let witness_version = data[0];
    let witness_program = convert_bits(&data[1..], 5, 8, false)
        .map_err(|e| format!("Erreur lors de la conversion des bits: {}", e))?;
    if witness_program.len() != 20 && witness_program.len() != 32 {
        return Err("Longueur du programme témoin invalide.".to_string());
    }
    let mut script_pubkey = Vec::new();
    script_pubkey.push(witness_version);
    script_pubkey.push(witness_program.len() as u8);
    script_pubkey.extend(witness_program);

    Ok(script_pubkey)
}

pub fn serialize_transaction(tx: &Tx, include_witness: bool) -> Vec<u8> {
    let mut raw = Vec::new();
    raw.extend_from_slice(&tx.version.to_le_bytes());
    let has_witness = include_witness && tx.witnesses.is_some();
    if has_witness {
        raw.push(0x00);
        raw.push(0x01);
    }

    write_varint(tx.inputs.len(), &mut raw);
    for input in &tx.inputs {
        let mut reversed_txid = input.previous_output.txid;
        reversed_txid.reverse();
        raw.extend_from_slice(&reversed_txid);
        raw.extend_from_slice(&input.previous_output.vout.to_le_bytes());
        write_varint(input.script_sig.len(), &mut raw);
        raw.extend_from_slice(&input.script_sig);
        raw.extend_from_slice(&input.sequence.to_le_bytes());
    }

    write_varint(tx.outputs.len(), &mut raw);
    for output in &tx.outputs {
        raw.extend_from_slice(&output.value.to_le_bytes());
        write_varint(output.script_pubkey.len(), &mut raw);
        raw.extend_from_slice(&output.script_pubkey);
    }

    if has_witness {
        if let Some(witnesses) = &tx.witnesses {
            for witness in witnesses {
                write_varint(witness.items.len(), &mut raw);
                for item in &witness.items {
                    write_varint(item.len(), &mut raw);
                    raw.extend_from_slice(item);
                }
            }
        }
    }

    raw.extend_from_slice(&tx.lock_time.to_le_bytes());

    raw
}


pub fn calculate_txid(tx: &Tx) -> [u8; 32] {
    let raw = serialize_transaction(tx, false);
    let mut hash = double_sha256(&raw);
    hash.reverse();
    hash.try_into().expect("Hash must be 32 bytes")
}

fn read_bytes(data: &[u8], len: usize, index: &mut usize) -> Vec<u8> {
    let result = data[*index..*index + len].to_vec();
    *index += len;
    result
}

fn read_u32(data: &[u8], index: &mut usize) -> u32 {
    let result = u32::from_le_bytes(data[*index..*index + 4].try_into().unwrap());
    *index += 4;
    result
}

fn read_u64(data: &[u8], index: &mut usize) -> u64 {
    let result = u64::from_le_bytes(data[*index..*index + 8].try_into().unwrap());
    *index += 8;
    result
}

fn read_txid(data: &[u8], index: &mut usize) -> [u8; 32] {
    let mut txid : [u8; 32] = read_bytes(data, 32, index).try_into().expect("Invalid TXID length");
    txid.reverse();
    txid
}


pub fn deserialize_transaction(hex: &str) -> Result<Tx, String> {
    let raw = hex_to_vec(hex);
    let mut index = 0;

    let version = read_u32(&raw, &mut index);
    let mut flag = None;

    if raw.len() >= index + 2 && raw[index] == 0x00 && raw[index + 1] == 0x01 {
        flag = Some(0x0100);
        index += 2;
    }

    let input_count = read_varint(&raw, &mut index);
    let mut inputs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        let txid = read_txid(&raw, &mut index);
        let vout = read_u32(&raw, &mut index);
        let script_sig_len = read_varint(&raw, &mut index);
        let script_sig = read_bytes(&raw, script_sig_len, &mut index);
        let sequence = read_u32(&raw, &mut index);

        inputs.push(TxIn {
            previous_output: OutPoint { txid, vout },
            script_sig,
            sequence,
        });
    }

    let output_count = read_varint(&raw, &mut index);
    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        let value = read_u64(&raw, &mut index);
        let script_pubkey_len = read_varint(&raw, &mut index);
        let script_pubkey = read_bytes(&raw, script_pubkey_len, &mut index);

        outputs.push(TxOut {
            value,
            script_pubkey,
        });
    }
    
    let witnesses = if flag.is_some() {
        let mut witnesses = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            let item_count = read_varint(&raw, &mut index);
            let mut items = Vec::with_capacity(item_count);
            for _ in 0..item_count {
                let item_len = read_varint(&raw, &mut index);
                items.push(read_bytes(&raw, item_len, &mut index));
            }
            witnesses.push(Witness { items });
        }
        Some(witnesses)
    } else {
        None
    };

    let lock_time = read_u32(&raw, &mut index);

    Ok(Tx {
        version,
        flag,
        inputs,
        outputs,
        witnesses,
        lock_time,
    })
}