//! LZMA2 backend (pure Rust, `lzma-rust2`).
//!
//! Replaces `lzma_compress_buf` / `lzma_decompress_buf` from lgzv3.c, which
//! used the XZ Embedded SDK (`Lzma2Enc_Encode2` / `Lzma2Decode`).
//!
//! Wire format is kept byte-compatible with the C version: every payload is
//! `[1 byte dict props][raw LZMA2 stream]` (single chunk + end marker).
//! The dict props byte uses the standard LZMA2 encoding, so files written
//! by the C tool decode here and vice versa.
//!
//! Encoder mapping (C -> Rust):
//! - `dictSize` = `optimal_dict_size` (ported 1:1), `lc`/`lp`/`pb` passed
//!   through from the brute-force tables;
//! - C `level = 9, algo = 1 (normal), btMode = 1, numHashBytes = 4, fb = 273`
//!   map to `Normal` mode, `Bt4` matcher, `nice_len = 273`;
//! - C `mc` (match search limit 48/256/4096/500000) maps to `depth_limit`
//!   (32/128/2048/auto). Exact search behavior differs between the two
//!   match finders, so ratios are compared empirically, not bit-by-bit.

use std::io::Read;
#[cfg(feature = "compress")]
use std::io::Write;

use lzma_rust2::Lzma2Reader;
#[cfg(feature = "compress")]
use lzma_rust2::{EncodeMode, Lzma2Options, Lzma2Writer, LzmaOptions, MfType};

use crate::error::Error;

/// Max dictionary: 16 MiB normally, 32 MiB on level 3, and 64 MiB on
/// level 3 for inputs over 32 MiB (ramdisk-scale solids on modern devices
/// with 8-16 GB RAM). Mirrors `get_optimal_dict_size` in lgzv3.c, extended.
/// Encode-only (`compress` feature): the decompress-only ramdisk build
/// never sizes dictionaries.
#[cfg(feature = "compress")]
pub fn optimal_dict_size(in_size: u64, opt_level: u8) -> u32 {
    let max_dict: u64 = if opt_level >= 3 {
        if in_size > 32 * 1024 * 1024 {
            64 * 1024 * 1024
        } else {
            32 * 1024 * 1024
        }
    } else {
        16 * 1024 * 1024
    };
    let mut dict: u64 = 4096;
    while dict < in_size && dict < max_dict {
        dict <<= 1;
    }
    dict as u32
}

/// Match-finder depth limit per optimization level.
///
/// Heuristic mapping of C's `mc` (48/256/4096/500000). `0` means automatic
/// (derived from `nice_len`), used for the extreme level.
/// Encode-only.
#[cfg(feature = "compress")]
fn depth_limit(opt_level: u8) -> i32 {
    match opt_level {
        0 => 32,
        1 => 128,
        2 => 2048,
        _ => 0,
    }
}

/// Raw standard LZMA2 props decoding (valid for props 0..=40).
fn decode_props(prop: u8) -> u32 {
    (2u32 | (prop as u32 & 1)) << (prop as u32 / 2 + 11)
}

/// Encode a dictionary size as a standard LZMA2 props byte.
///
/// For props 0..=39 the decoded size is `(2 | (prop & 1)) << (prop / 2 + 11)`.
/// Returns the smallest props byte whose decoded size fits `dict_size`.
/// Encode-only.
#[cfg(feature = "compress")]
pub fn dict_props_byte(dict_size: u32) -> u8 {
    for prop in 0..40u8 {
        if decode_props(prop) >= dict_size {
            return prop;
        }
    }
    40
}

/// Decode a standard LZMA2 props byte to a dictionary size.
///
/// Returns `None` for reserved values (> 40). Props 40 means "any size"
/// (up to 4 GiB); it is rejected here because the decoder would have to
/// allocate that much memory (the C version fails the same way).
pub fn dict_size_from_props(prop: u8) -> Option<u32> {
    if prop > 40 {
        return None;
    }
    if prop == 40 {
        return None;
    }
    Some(decode_props(prop))
}

/// Build encoder options for the given brute-force parameters.
/// Encode-only.
#[cfg(feature = "compress")]
fn make_options(in_size: u64, lc: u32, lp: u32, pb: u32, opt_level: u8) -> Lzma2Options {
    let dict_size = optimal_dict_size(in_size, opt_level);
    let lzma_options = LzmaOptions::new(
        dict_size,
        lc,
        lp,
        pb,
        EncodeMode::Normal,
        LzmaOptions::NICE_LEN_MAX,
        MfType::Bt4,
        depth_limit(opt_level),
    );
    Lzma2Options {
        lzma_options,
        chunk_size: None,
    }
}

/// Compress a buffer: `[dict props byte][raw LZMA2 stream]`.
///
/// Port of `lzma_compress_buf`. The returned length already includes the
/// leading props byte, matching C's `*out_size = 1 + comp_size`.
/// Encode-only (`compress` feature).
#[cfg(feature = "compress")]
pub fn compress_buf(
    input: &[u8],
    lc: u32,
    lp: u32,
    pb: u32,
    opt_level: u8,
) -> Result<Vec<u8>, Error> {
    if lc > 8 || lp > 4 || pb > 4 || lc + lp > 4 {
        return Err(Error::Lzma(format!("invalid lc/lp/pb: {lc}/{lp}/{pb}")));
    }
    let options = make_options(input.len() as u64, lc, lp, pb, opt_level);
    let dict_size = options.lzma_options.dict_size;
    let mut writer = Lzma2Writer::new(Vec::new(), options);
    writer
        .write_all(input)
        .map_err(|e| Error::Lzma(format!("encode: {e}")))?;
    let mut stream = writer
        .finish()
        .map_err(|e| Error::Lzma(format!("finish: {e}")))?;
    let mut out = Vec::with_capacity(stream.len() + 1);
    out.push(dict_props_byte(dict_size));
    out.append(&mut stream);
    Ok(out)
}

/// Decompress a `[dict props byte][raw LZMA2 stream]` payload.
///
/// Port of `lzma_decompress_buf`. The output length must match `orig_size`
/// exactly, otherwise the archive is rejected.
pub fn decompress_buf(input: &[u8], orig_size: usize) -> Result<Vec<u8>, Error> {
    if input.is_empty() {
        return Err(Error::Lzma("empty payload".to_string()));
    }
    if orig_size > 256 * 1024 * 1024 {
        return Err(Error::TooLarge("output exceeds 256 MiB".to_string()));
    }
    let prop = input[0];
    let dict_size = dict_size_from_props(prop)
        .ok_or_else(|| Error::Lzma(format!("bad dict props byte: {prop}")))?;
    let mut reader = Lzma2Reader::new(&input[1..], dict_size, None);
    let mut out = Vec::with_capacity(orig_size);
    reader
        .read_to_end(&mut out)
        .map_err(|e| Error::Lzma(format!("decode: {e}")))?;
    if out.len() != orig_size {
        return Err(Error::Lzma(format!(
            "size mismatch: got {}, expected {orig_size}",
            out.len()
        )));
    }
    Ok(out)
}
