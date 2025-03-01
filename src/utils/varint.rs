pub fn write_varint(value: usize, buffer: &mut Vec<u8>) {
    if value < 0xFD {
        buffer.push(value as u8);
    } else if value <= 0xFFFF {
        buffer.push(0xFD);
        buffer.push((value & 0xFF) as u8);
        buffer.push((value >> 8) as u8);
    } else if value <= 0xFFFFFFFF {
        buffer.push(0xFE);
        buffer.push((value & 0xFF) as u8);
        buffer.push(((value >> 8) & 0xFF) as u8);
        buffer.push(((value >> 16) & 0xFF) as u8);
        buffer.push(((value >> 24) & 0xFF) as u8);
    } else {
        buffer.push(0xFF);
        buffer.push((value & 0xFF) as u8);
        buffer.push(((value >> 8) & 0xFF) as u8);
        buffer.push(((value >> 16) & 0xFF) as u8);
        buffer.push(((value >> 24) & 0xFF) as u8);
        buffer.push(((value >> 32) & 0xFF) as u8);
        buffer.push(((value >> 40) & 0xFF) as u8);
        buffer.push(((value >> 48) & 0xFF) as u8);
        buffer.push(((value >> 56) & 0xFF) as u8);
    }
}

pub fn read_varint(data: &[u8], index: &mut usize) -> usize {
    let first = data[*index];
    *index += 1;

    match first {
        0xFD => {
            let val = (data[*index] as u16) | ((data[*index + 1] as u16) << 8);
            *index += 2;
            val as usize
        }
        0xFE => {
            let val = (data[*index] as u32)
                | ((data[*index + 1] as u32) << 8)
                | ((data[*index + 2] as u32) << 16)
                | ((data[*index + 3] as u32) << 24);
            *index += 4;
            val as usize
        }
        0xFF => {
            let val = (data[*index] as u64)
                | ((data[*index + 1] as u64) << 8)
                | ((data[*index + 2] as u64) << 16)
                | ((data[*index + 3] as u64) << 24)
                | ((data[*index + 4] as u64) << 32)
                | ((data[*index + 5] as u64) << 40)
                | ((data[*index + 6] as u64) << 48)
                | ((data[*index + 7] as u64) << 56);
            *index += 8;
            val as usize
        }
        _ => first as usize,
    }
}
