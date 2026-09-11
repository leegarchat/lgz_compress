//! ARM64 / x86 branch normalization.
//!
//! Direct port of `arm64_branch_normalize/denormalize` and
//! `x86_branch_normalize/denormalize` from lgzv3.c.
//! Relative branch addresses become absolute (and back), which makes code
//! more compressible. Arithmetic uses explicit `wrapping_*`, matching
//! `uint32_t`/`int32_t` overflow semantics in C.

/// ARM64: relative B/BL and ADRP addresses -> absolute.
///
/// Processes 4-byte little-endian instructions:
/// `B`/`BL` (opcode_top 0x05/0x25), `ADRP` (mask 0x9F000000 == 0x90000000).
#[cfg(any(feature = "compress", test))]
pub fn arm64_normalize(data: &mut [u8]) {
    let size = data.len();
    let mut i = 0;
    while i + 3 < size {
        let instr = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let opcode_top = instr >> 26;
        let mut new_instr = instr;
        let mut modified = false;

        if opcode_top == 0x05 || opcode_top == 0x25 {
            // B / BL: signed imm26.
            let mut imm26 = instr & 0x03FF_FFFF;
            if imm26 & 0x0200_0000 != 0 {
                imm26 |= 0xFC00_0000;
            }
            let abs_addr = ((i / 4) as i32).wrapping_add(imm26 as i32) as u32;
            new_instr = (instr & 0xFC00_0000) | (abs_addr & 0x03FF_FFFF);
            modified = true;
        } else if instr & 0x9F00_0000 == 0x9000_0000 {
            // ADRP: signed immhi:immlo (4K pages).
            let immhi = (instr >> 5) & 0x7_FFFF;
            let immlo = (instr >> 29) & 0x3;
            let mut imm21 = (immhi << 2) | immlo;
            if imm21 & 0x10_0000 != 0 {
                imm21 |= 0xFFE0_0000;
            }
            let page = ((i >> 12) as i32).wrapping_add(imm21 as i32) as u32;
            let new_immhi = (page >> 2) & 0x7_FFFF;
            let new_immlo = page & 0x3;
            new_instr = (instr & 0x9F00_001F) | (new_immhi << 5) | (new_immlo << 29);
            modified = true;
        }

        if modified {
            data[i..i + 4].copy_from_slice(&new_instr.to_le_bytes());
        }
        i += 4;
    }
}

/// ARM64: absolute B/BL and ADRP addresses -> relative (inverse operation).
pub fn arm64_denormalize(data: &mut [u8]) {
    let size = data.len();
    let mut i = 0;
    while i + 3 < size {
        let instr = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let opcode_top = instr >> 26;
        let mut new_instr = instr;
        let mut modified = false;

        if opcode_top == 0x05 || opcode_top == 0x25 {
            let mut abs_addr = instr & 0x03FF_FFFF;
            if abs_addr & 0x0200_0000 != 0 {
                abs_addr |= 0xFC00_0000;
            }
            let rel = (abs_addr as i32).wrapping_sub((i / 4) as i32) as u32;
            new_instr = (instr & 0xFC00_0000) | (rel & 0x03FF_FFFF);
            modified = true;
        } else if instr & 0x9F00_0000 == 0x9000_0000 {
            let immhi = (instr >> 5) & 0x7_FFFF;
            let immlo = (instr >> 29) & 0x3;
            let mut page = (immhi << 2) | immlo;
            if page & 0x10_0000 != 0 {
                page |= 0xFFE0_0000;
            }
            let rel = (page as i32).wrapping_sub((i >> 12) as i32) as u32;
            let new_immhi = (rel >> 2) & 0x7_FFFF;
            let new_immlo = rel & 0x3;
            new_instr = (instr & 0x9F00_001F) | (new_immhi << 5) | (new_immlo << 29);
            modified = true;
        }

        if modified {
            data[i..i + 4].copy_from_slice(&new_instr.to_le_bytes());
        }
        i += 4;
    }
}

/// x86: `E8`/`E9 rel32` -> absolute target address.
#[cfg(any(feature = "compress", test))]
pub fn x86_normalize(data: &mut [u8]) {
    let size = data.len();
    let mut i = 0;
    while i + 5 <= size {
        if data[i] == 0xE8 || data[i] == 0xE9 {
            let rel = u32::from_le_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]]);
            let abs_addr = rel.wrapping_add((i + 5) as u32);
            data[i + 1..i + 5].copy_from_slice(&abs_addr.to_le_bytes());
            i += 4;
        }
        i += 1;
    }
}

/// x86: absolute target address -> `E8`/`E9 rel32` (inverse operation).
pub fn x86_denormalize(data: &mut [u8]) {
    let size = data.len();
    let mut i = 0;
    while i + 5 <= size {
        if data[i] == 0xE8 || data[i] == 0xE9 {
            let abs_addr =
                u32::from_le_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]]);
            let rel = abs_addr.wrapping_sub((i + 5) as u32);
            data[i + 1..i + 5].copy_from_slice(&rel.to_le_bytes());
            i += 4;
        }
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Involution holds for arbitrary bytes (mask hits are self-inverse).
    #[test]
    fn arm64_involution_pseudo_random() {
        let mut x: u64 = 0x1234_5678_9ABC_DEF0;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x & 0xFF) as u8
        };
        for len in [0, 1, 3, 4, 5, 31, 64, 1000] {
            let mut data: Vec<u8> = (0..len).map(|_| next()).collect();
            let orig = data.clone();
            arm64_normalize(&mut data);
            arm64_denormalize(&mut data);
            assert_eq!(data, orig, "len={len}");
        }
    }

    #[test]
    fn x86_involution_pseudo_random() {
        let mut x: u64 = 0xDEAD_BEEF_CAFE_1234;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x & 0xFF) as u8
        };
        // Bias towards E8/E9 so the transform actually engages.
        for len in [0, 4, 5, 100, 1000] {
            let mut data: Vec<u8> = (0..len)
                .map(|i| if i % 7 == 0 { 0xE8 } else { next() })
                .collect();
            let orig = data.clone();
            x86_normalize(&mut data);
            x86_denormalize(&mut data);
            assert_eq!(data, orig, "len={len}");
        }
    }
}
