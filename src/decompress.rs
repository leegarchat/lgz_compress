//! Archive decompression (UCOMP01 single-blob files).
//!
//! Direct port of `decompress_file` from lgzv3.c, including the per-type
//! post-processing (types 1-6 invert the matching preprocessing).
//! For blob types 3/4/6 the ELF section table is re-parsed from the
//! decompressed data to locate code ranges — exactly like C.
//!
//! [`decompress_bytes`] is shared with the multi-file unpacker, which
//! decodes the solid UCOMP01 payload of a UCOMP02 container.

use std::fs;

use crate::elf::{self, Arch};
use crate::error::Error;
use crate::format;
use crate::{delta, lzma, normalize, planes};

/// Undo preprocessing of type 1: per-plane delta decode, un-plane,
/// then ARM64 branch denormalization.
fn undo_type1(payload: Vec<u8>) -> Result<Vec<u8>, Error> {
    let n_instr = payload.len() / 4;
    let mut buf = payload;
    if n_instr > 1 {
        for p in 0..4 {
            delta::decode(&mut buf[p * n_instr..(p + 1) * n_instr]);
        }
    }
    let mut out = planes::decode(&buf);
    normalize::arm64_denormalize(&mut out);
    Ok(out)
}

/// Undo preprocessing of type 4 on one code section: per-plane delta
/// decode, un-plane (in place), then branch denormalization.
/// On x86 it is a plain branch denormalization.
fn undo_type4_section(buf: &mut [u8], arch: Arch) {
    match arch {
        Arch::Arm64 => {
            let n_instr = buf.len() / 4;
            if n_instr > 1 {
                for p in 0..4 {
                    delta::decode(&mut buf[p * n_instr..(p + 1) * n_instr]);
                }
            }
            let unplaned = planes::decode(buf);
            buf.copy_from_slice(&unplaned);
            normalize::arm64_denormalize(buf);
        }
        Arch::X86 => normalize::x86_denormalize(buf),
    }
}

/// Denormalize branch targets inside code sections of a blob.
fn denormalize_blob_sections(buf: &mut [u8]) {
    if let Some(info) = elf::parse(buf) {
        for s in &info.sections {
            if s.is_code {
                let (off, size) = (s.offset as usize, s.size as usize);
                if off + size <= buf.len() {
                    match info.arch {
                        Arch::Arm64 => normalize::arm64_denormalize(&mut buf[off..off + size]),
                        Arch::X86 => normalize::x86_denormalize(&mut buf[off..off + size]),
                    }
                }
            }
        }
    }
}

/// Invert the preprocessing of a single decompressed chunk.
fn undo_preproc(mut payload: Vec<u8>, preproc: u8) -> Result<Vec<u8>, Error> {
    match preproc {
        0 => Ok(payload),
        1 => undo_type1(payload),
        2 | 5 => {
            delta::decode(&mut payload);
            Ok(payload)
        }
        3 => {
            denormalize_blob_sections(&mut payload);
            Ok(payload)
        }
        4 => {
            if let Some(info) = elf::parse(&payload) {
                // Collect ranges first: `elf::parse` borrows `payload`.
                let ranges: Vec<(usize, usize, Arch)> = info
                    .sections
                    .iter()
                    .filter(|s| s.is_code)
                    .map(|s| (s.offset as usize, s.size as usize, info.arch))
                    .collect();
                for (off, size, arch) in ranges {
                    if off + size <= payload.len() {
                        undo_type4_section(&mut payload[off..off + size], arch);
                    }
                }
            }
            Ok(payload)
        }
        6 => {
            delta::decode(&mut payload);
            denormalize_blob_sections(&mut payload);
            Ok(payload)
        }
        _ => Err(Error::BadArchive(format!(
            "unsupported preproc type {preproc}"
        ))),
    }
}

/// Decompress a UCOMP01 archive image into raw bytes.
pub fn decompress_bytes(data: &[u8]) -> Result<Vec<u8>, Error> {
    let header = format::parse_header(data)?;
    let mut output = Vec::with_capacity(header.orig_size as usize);
    for (i, (meta, range)) in header.chunks.iter().enumerate() {
        let payload = lzma::decompress_buf(&data[range.clone()], meta.orig_size as usize)
            .map_err(|e| Error::Lzma(format!("block {i}: {e}")))?;
        let plain = undo_preproc(payload, meta.preproc)?;
        if plain.len() != meta.orig_size as usize {
            return Err(Error::BadArchive(format!(
                "block {i}: postproc size mismatch"
            )));
        }
        output.extend_from_slice(&plain);
    }
    if output.len() as u64 != header.orig_size {
        return Err(Error::BadArchive("output size mismatch".to_string()));
    }
    Ok(output)
}

/// Decompress a UCOMP01 archive file into `out_path`.
pub fn decompress_file(in_path: &str, out_path: &str) -> Result<(), Error> {
    let data = fs::read(in_path)?;
    if data.len() < 8 || &data[0..8] != format::MAGIC {
        return Err(Error::BadArchive(
            "not a single-file archive (magic mismatch)".to_string(),
        ));
    }
    let output = decompress_bytes(&data)?;
    println!(
        "[*] Decompressing: {} bytes of original data",
        output.len()
    );
    fs::write(out_path, &output)?;
    println!("[+] Decompressed OK: {} bytes", output.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity: a plain (type 0) chunk round-trips through the header codec.
    #[test]
    fn plain_chunk_roundtrip() {
        let orig: Vec<u8> = (0..256).map(|i| (i * 7 + 3) as u8).collect();
        let comp = lzma::compress_buf(&orig, 3, 0, 2, 1).unwrap();
        let meta = crate::format::ChunkMeta {
            preproc: 0,
            orig_size: orig.len() as u32,
            comp_size: comp.len() as u32,
        };
        let mut img = format::encode_header(orig.len() as u64, &[meta]);
        img.extend_from_slice(&comp);
        assert_eq!(decompress_bytes(&img).unwrap(), orig);
    }
}
