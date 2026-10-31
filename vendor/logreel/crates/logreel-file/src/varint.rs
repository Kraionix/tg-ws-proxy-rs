//! Unsigned LEB128.

/// Append a varint.
#[cfg(test)]
pub(crate) fn put(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}

/// Read a varint, rejecting overlong encodings and overflow.
pub(crate) fn read(bytes: &[u8], pos: &mut usize, max_bytes: usize) -> Result<u64, &'static str> {
    let mut value = 0u64;
    for shift in 0..max_bytes {
        let byte = *bytes.get(*pos).ok_or("unexpected end of record")?;
        *pos += 1;
        let part = u64::from(byte & 0x7F);
        if shift == 9 && part > 1 {
            return Err("varint overflows u64");
        }
        value |= part << (shift * 7);
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err("varint is too long")
}
