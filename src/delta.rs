//! Delta encoding.
//!
//! Direct port of `delta_encode/decode` from lgzv3.c.
//! Arithmetic uses `wrapping_*`, matching unsigned `uint8_t` arithmetic in C.

/// Forward delta encoding: `data[i] -= data[i-1]`, from the end.
pub fn encode(data: &mut [u8]) {
    if data.len() < 2 {
        return;
    }
    for i in (1..data.len()).rev() {
        data[i] = data[i].wrapping_sub(data[i - 1]);
    }
}

/// Inverse delta decoding: `data[i] += data[i-1]`, from the start.
pub fn decode(data: &mut [u8]) {
    for i in 1..data.len() {
        data[i] = data[i].wrapping_add(data[i - 1]);
    }
}
