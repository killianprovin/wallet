pub fn base58_encode(data: &[u8]) -> String {
    const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    let mut leading_zeros = 0;
    for &byte in data {
        if byte == 0 {
            leading_zeros += 1;
        } else {
            break;
        }
    }

    let mut encoded = Vec::new();
    let mut num = data.to_vec();

    while !num.is_empty() {
        let mut remainder = 0u16;
        let mut new_num = Vec::new();

        for &byte in &num {
            let temp = (remainder << 8) + byte as u16;
            let quotient = temp / 58;
            remainder = temp % 58;

            if !new_num.is_empty() || quotient != 0 {
                new_num.push(quotient as u8);
            }
        }

        encoded.push(BASE58_ALPHABET[remainder as usize]);
        num = new_num;
    }

    for _ in 0..leading_zeros {
        encoded.push(b'1');
    }

    encoded.reverse();

    String::from_utf8(encoded).expect("Encodage UTF-8 valide")
}