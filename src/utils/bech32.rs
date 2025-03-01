const CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const CHARSET_REV: [i8; 128] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
];

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

fn verify_checksum(hrp: &str, data: &[u8]) -> bool {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    polymod(&values) == 1
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

pub fn decode_bech32(bech32: &str) -> Result<(String, Vec<u8>), &'static str> {
    if bech32.len() < 8 || bech32.len() > 90 {
        return Err("Invalid Bech32 string length");
    }

    let (hrp, data) = match bech32.rfind('1') {
        Some(pos) => (&bech32[..pos], &bech32[pos + 1..]),
        None => return Err("Invalid Bech32 format: missing separator '1'"),
    };

    if hrp.is_empty() || data.len() < 6 {
        return Err("Invalid Bech32 format: HRP or data part too short");
    }

    let mut data_values = Vec::with_capacity(data.len());
    for c in data.chars() {
        if c as usize >= 128 || CHARSET_REV[c as usize] == -1 {
            return Err("Invalid character in Bech32 string");
        }
        data_values.push(CHARSET_REV[c as usize] as u8);
    }

    if !verify_checksum(hrp, &data_values) {
        return Err("Invalid checksum");
    }

    Ok((hrp.to_string(), data_values[..data_values.len() - 6].to_vec()))
}