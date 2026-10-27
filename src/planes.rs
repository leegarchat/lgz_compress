//! ARM64 instruction byte-plane splitting (stride = 4).
//!
//! Direct port of `arm64_planes_encode/decode` from lgzv3.c.
//! Planes are stored in reverse byte order: [b3][b2][b1][b0].
//! A tail that is not a multiple of 4 is copied as is.

/// Pack instructions into 4 planes (+ tail).
#[cfg(feature = "compress")]
pub fn encode(data: &[u8]) -> Vec<u8> {
    let size = data.len();
    let n_instr = size / 4;
    let remainder = size % 4;
    let mut out = vec![0u8; size];
    for i in 0..n_instr {
        out[i] = data[i * 4 + 3];
        out[n_instr + i] = data[i * 4 + 2];
        out[2 * n_instr + i] = data[i * 4 + 1];
        out[3 * n_instr + i] = data[i * 4];
    }
    out[4 * n_instr..].copy_from_slice(&data[n_instr * 4..n_instr * 4 + remainder]);
    out
}

/// Unpack planes back into instructions.
///
/// Split-based (no bounds checks): LLVM autovectorizes the interleave
/// (NEON `ZIP1`/`ZIP2` on ARM64, shuffles on x86).
pub fn decode(data: &[u8]) -> Vec<u8> {
    let size = data.len();
    let n_instr = size / 4;
    let mut out = vec![0u8; size];
    let (p3, rest) = data.split_at(n_instr);
    let (p2, rest) = rest.split_at(n_instr);
    let (p1, rest) = rest.split_at(n_instr);
    let (p0, tail) = rest.split_at(n_instr);

    let (out_body, out_tail) = out.split_at_mut(n_instr * 4);
    for (dst, (((&b3, &b2), &b1), &b0)) in out_body
        .chunks_exact_mut(4)
        .zip(p3.iter().zip(p2.iter()).zip(p1.iter()).zip(p0.iter()))
    {
        dst[0] = b0;
        dst[1] = b1;
        dst[2] = b2;
        dst[3] = b3;
    }
    out_tail.copy_from_slice(tail);
    out
}

#[cfg(all(test, feature = "compress"))]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_lengths() {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x & 0xFF) as u8
        };
        for len in [0, 1, 2, 3, 4, 5, 7, 8, 31, 64, 100, 1000] {
            let data: Vec<u8> = (0..len).map(|_| next()).collect();
            assert_eq!(decode(&encode(&data)), data, "len={len}");
        }
    }
}
