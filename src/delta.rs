//! Delta encoding.
//!
//! Direct port of `delta_encode/decode` from lgzv3.c.
//! Arithmetic uses `wrapping_*`, matching unsigned `uint8_t` arithmetic in C.

/// Forward delta encoding: `data[i] -= data[i-1]`, from the end.
# [cfg(feature = "compress")]
# [cfg(feature = "compress")]
pub fn encode(data: &mut [u8]) {
    if data.len() < 2 {
        return;
    }
    for i in (1..data.len()).rev() {
        data[i] = data[i].wrapping_sub(data[i - 1]);
    }
}

/// Inverse delta decoding: `data[i] += data[i-1]`, from the start.
/// The accumulator stays in a register: no re-read of `data[i - 1]`
/// from memory, no bounds checks — LLVM emits a tight loop.
pub fn decode(data: &mut [u8]) {
    if let Some((&mut first, rest)) = data.split_first_mut() {
        let mut acc = first;
        for b in rest {
            acc = acc.wrapping_add(*b);
            *b = acc;
        }
    }
}

#[cfg(all(test, feature = "compress"))]
mod tests {
    use super::*;

    #[test]
    fn decode_inverts_encode_and_handles_edges() {
        for len in [0, 1, 2, 3, 100, 1000] {
            let mut data: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
            let orig = data.clone();
            encode(&mut data);
            decode(&mut data);
            assert_eq!(data, orig, "len={len}");
            // Idempotent on empty/single: no panic, no change.
            if len < 2 {
                let mut d = orig.clone();
                decode(&mut d);
                assert_eq!(d, orig);
            }
        }
    }
}
