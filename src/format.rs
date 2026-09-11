//! Archive container format.
//!
//! Byte-compatible with lgzv3.c:
//! ```text
//! [8 bytes] magic "UCOMP01\0"
//! [8 bytes] original file size (LE)
//! [4 bytes] chunk count (LE u32)
//! per chunk:
//!   [1 byte ] preprocessing type
//!   [4 bytes] original chunk size (LE u32)
//!   [4 bytes] compressed chunk size, incl. 1 LZMA2 props byte (LE u32)
//!   [N bytes] compressed payload
//! ```
//!
//! Preprocessing types:
//! - 0 = plain LZMA2
//! - 1 = chunk: arm64 planes + delta
//! - 2 = chunk: delta only
//! - 3 = blob: branch normalize (ARM64 or x86_64)
//! - 4 = blob: branch normalize + in-place planes + delta
//! - 5 = blob: whole-file delta
//! - 6 = blob: branch normalize + whole-file delta

use crate::error::Error;

/// Archive magic, `MAGIC "UCOMP01"` + NUL, 8 bytes total.
pub const MAGIC: &[u8; 8] = b"UCOMP01\0";

/// Short human-readable name of a preprocessing type (for `list` output).
pub fn preproc_name(t: u8) -> &'static str {
    match t {
        0 => "raw",
        1 => "arm64-planes+delta",
        2 => "delta",
        3 => "branch-norm",
        4 => "branch-norm+planes+delta",
        5 => "file-delta",
        6 => "branch-norm+file-delta",
        _ => "unknown",
    }
}/// Header length: magic (8) + original size (8) + chunk count (4).
pub const HEADER_LEN: usize = 20;
/// Per-chunk header length: type (1) + orig size (4) + comp size (4).
pub const CHUNK_HDR_LEN: usize = 9;
/// Same 256 MiB output cap as the C decoder.
pub const MAX_OUTPUT: u64 = 256 * 1024 * 1024;

#[cfg(feature = "compress")]
pub fn write_u32le(buf: &mut [u8], v: u32) {
    buf[0..4].copy_from_slice(&v.to_le_bytes());
}

#[cfg(feature = "compress")]
pub fn write_u64le(buf: &mut [u8], v: u64) {
    buf[0..8].copy_from_slice(&v.to_le_bytes());
}

pub fn read_u32le(buf: &[u8]) -> u32 {
    u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
}

pub fn read_u64le(buf: &[u8]) -> u64 {
    u64::from_le_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ])
}

/// One chunk descriptor from the archive header.
#[derive(Debug, Clone, Copy)]
pub struct ChunkMeta {
    /// Preprocessing type (0..=6).
    pub preproc: u8,
    /// Original chunk size.
    pub orig_size: u32,
    /// Compressed payload size (incl. props byte).
    pub comp_size: u32,
}

/// Parsed archive header: original size + chunk table with payload ranges.
#[derive(Debug)]
pub struct ArchiveHeader {
    pub orig_size: u64,
    pub chunks: Vec<(ChunkMeta, std::ops::Range<usize>)>,
}

/// Serialize the archive header (magic + sizes + per-chunk records).
#[cfg(feature = "compress")]
pub fn encode_header(orig_size: u64, metas: &[ChunkMeta]) -> Vec<u8> {
    let mut hdr = vec![0u8; HEADER_LEN + metas.len() * CHUNK_HDR_LEN];
    hdr[0..8].copy_from_slice(MAGIC);
    write_u64le(&mut hdr[8..16], orig_size);
    write_u32le(
        &mut hdr[16..20],
        metas.len() as u32,
    );
    for (i, m) in metas.iter().enumerate() {
        let base = HEADER_LEN + i * CHUNK_HDR_LEN;
        hdr[base] = m.preproc;
        write_u32le(&mut hdr[base + 1..base + 5], m.orig_size);
        write_u32le(&mut hdr[base + 5..base + 9], m.comp_size);
    }
    hdr
}

/// Parse and validate the archive header.
///
/// Unlike C (which trusts the header), all offsets and sizes are
/// bounds-checked and cross-checked against the original size.
pub fn parse_header(data: &[u8]) -> Result<ArchiveHeader, Error> {
    if data.len() < HEADER_LEN || &data[0..8] != MAGIC {
        return Err(Error::BadArchive(
            "magic mismatch (expected UCOMP01)".to_string(),
        ));
    }
    let orig_size = read_u64le(&data[8..16]);
    if orig_size > MAX_OUTPUT {
        return Err(Error::TooLarge("original size exceeds 256 MiB".to_string()));
    }
    let n_chunks = read_u32le(&data[16..20]);
    if n_chunks == 0 || n_chunks > 1_000_000 {
        return Err(Error::BadArchive(format!("bad chunk count: {n_chunks}")));
    }
    let n_chunks = n_chunks as usize;
    let table_end = HEADER_LEN
        .checked_add(n_chunks.checked_mul(CHUNK_HDR_LEN).ok_or_else(|| {
            Error::BadArchive("chunk table too large".to_string())
        })?)
        .ok_or_else(|| Error::BadArchive("chunk table too large".to_string()))?;
    if data.len() < table_end {
        return Err(Error::BadArchive("truncated chunk table".to_string()));
    }

    let mut chunks = Vec::with_capacity(n_chunks);
    let mut pos = table_end;
    let mut out_pos: u64 = 0;
    for i in 0..n_chunks {
        let base = HEADER_LEN + i * CHUNK_HDR_LEN;
        let preproc = data[base];
        if preproc > 6 {
            return Err(Error::BadArchive(format!(
                "chunk {i}: bad preproc type {preproc}"
            )));
        }
        let orig_size_c = read_u32le(&data[base + 1..base + 5]);
        let comp_size = read_u32le(&data[base + 5..base + 9]);
        if comp_size == 0 {
            return Err(Error::BadArchive(format!("chunk {i}: empty payload")));
        }
        let end = pos.checked_add(comp_size as usize).ok_or_else(|| {
            Error::BadArchive(format!("chunk {i}: payload range overflow"))
        })?;
        if end > data.len() {
            return Err(Error::BadArchive(format!("chunk {i}: truncated payload")));
        }
        out_pos = out_pos.checked_add(orig_size_c as u64).ok_or_else(|| {
            Error::BadArchive("chunk sizes overflow original size".to_string())
        })?;
        if out_pos > orig_size {
            return Err(Error::BadArchive(
                "chunk sizes exceed original size".to_string(),
            ));
        }
        chunks.push((
            ChunkMeta {
                preproc,
                orig_size: orig_size_c,
                comp_size,
            },
            pos..end,
        ));
        pos = end;
    }
    if out_pos != orig_size {
        return Err(Error::BadArchive(format!(
            "chunk sizes sum to {out_pos}, header says {orig_size}"
        )));
    }
    Ok(ArchiveHeader { orig_size, chunks })
}
