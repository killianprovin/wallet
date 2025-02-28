pub fn base64_encode(data: &[u8]) -> String {
    let base64_chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut encoded = String::new();
    let mut buffer: u32;
    let mut padding = 0;

    let mut i = 0;
    while i < data.len() {
        buffer = (data[i] as u32) << 16;

        if i + 1 < data.len() {
            buffer |= (data[i + 1] as u32) << 8;
        } else {
            padding += 1;
        }

        if i + 2 < data.len() {
            buffer |= data[i + 2] as u32;
        } else {
            padding += 1;
        }

        encoded.push(base64_chars[((buffer >> 18) & 0x3F) as usize] as char);
        encoded.push(base64_chars[((buffer >> 12) & 0x3F) as usize] as char);

        if padding < 2 {
            encoded.push(base64_chars[((buffer >> 6) & 0x3F) as usize] as char);
        } else {
            encoded.push('=');
        }

        if padding < 1 {
            encoded.push(base64_chars[(buffer & 0x3F) as usize] as char);
        } else {
            encoded.push('=');
        }

        i += 3;
    }

    encoded
}

pub fn base64_decode(input: &str) -> Vec<u8> {
    let base64_chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = Vec::new();
    let mut buffer = 0u32;
    let mut bits_collected = 0;

    for byte in input.bytes() {
        if byte == b'\n' || byte == b'\r' || byte == b' ' {
            continue;
        }

        if byte == b'=' {
            break;
        }

        let val = base64_chars.iter().position(|&c| c == byte)
            .expect("Invalid Base64 character");

        buffer = (buffer << 6) | (val as u32);
        bits_collected += 6;

        if bits_collected >= 8 {
            bits_collected -= 8;
            let byte = (buffer >> bits_collected) as u8;
            output.push(byte);
        }
    }

    output
}