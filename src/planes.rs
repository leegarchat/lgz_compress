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
pub fn decode(data: &[u8]) -> Vec<u8> {
    let size = data.len();
    let n_instr = size / 4;
    let remainder = size % 4;
    let mut out = vec![0u8; size];
    for i in 0..n_instr {
        out[i * 4 + 3] = data[i];
        out[i * 4 + 2] = data[n_instr + i];
        out[i * 4 + 1] = data[2 * n_instr + i];
        out[i * 4] = data[3 * n_instr + i];
    }
    out[n_instr * 4..].copy_from_slice(&data[4 * n_instr..4 * n_instr + remainder]);
    out
}
