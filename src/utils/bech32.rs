const CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

pub enum Bech32Variant {
    Bech32,
    Bech32m,
}

fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for v in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ (*v as u32);
        for (i, &gen) in [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
            .iter()
            .enumerate()
        {
            if (top >> i) & 1 != 0 {
                chk ^= gen;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut ret = Vec::new();
    for b in hrp.bytes() {
        ret.push(b >> 5);
    }
    ret.push(0);
    for b in hrp.bytes() {
        ret.push(b & 31);
    }
    ret
}

fn create_checksum(hrp: &str, data: &[u8], variant: Bech32Variant) -> Vec<u8> {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0u8; 6]);
    let polymod_result = polymod(&values)
        ^ match variant {
            Bech32Variant::Bech32 => 1,
            Bech32Variant::Bech32m => 0x2bc830a3,
        };
    let mut checksum = Vec::new();
    for i in 0..6 {
        checksum.push(((polymod_result >> (5 * (5 - i))) & 31) as u8);
    }
    checksum
}

pub fn encode_bech32(hrp: &str, data: &[u8], variant: Bech32Variant) -> String {
    let checksum = create_checksum(hrp, data, variant);
    let mut combined = Vec::new();
    combined.extend_from_slice(data);
    combined.extend_from_slice(&checksum);

    let mut result = hrp.to_string();
    result.push('1');
    for d in combined {
        result.push(CHARSET.chars().nth(d as usize).unwrap());
    }
    result
}

pub fn convert_bits(data: &[u8], from_bits: u32, to_bits: u32, pad: bool) -> Result<Vec<u8>, &'static str> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut ret: Vec<u8> = Vec::new();
    let maxv: u32 = (1 << to_bits) - 1;
    for value in data {
        let v = *value as u32;
        if (v >> from_bits) != 0 {
            return Err("Invalid data range: value exceeds from_bits size");
        }
        acc = (acc << from_bits) | v;
        bits += from_bits;
        while bits >= to_bits {
            bits -= to_bits;
            ret.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            ret.push(((acc << (to_bits - bits)) & maxv) as u8);
        }
    } else if bits >= from_bits || ((acc << (to_bits - bits)) & maxv) != 0 {
        return Err("Invalid padding");
    }
    Ok(ret)
}