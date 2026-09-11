//! Per-chunk best-of preprocessing selection.
//!
//! Direct port of `compress_chunk_best` from lgzv3.c, plus one extra
//! candidate the C version lacks: ARM64 planes WITHOUT delta (type 7).
//! Delta coding breaks opcode periodicity in machine code, so on heavy
//! .so/.text sections pure plane splitting can win 1-2% over planes+delta.
//! Every candidate is LZMA2-compressed and the smallest payload wins
//! (strictly smaller keeps the earlier candidate, as in C):
//! - (lc=3, lp=0, pb=2) on raw data, always;
//! - (lc=2, lp=2, pb=2) on raw data, unless level 0;
//! - ARM64 code chunks >= 16 bytes: branch normalize -> planes ->
//!   per-plane delta -> (lc=0, lp=0, pb=0) [type 1];
//! - ARM64 code chunks >= 16 bytes: branch normalize -> planes,
//!   no delta -> (lc=0, lp=0, pb=0) [type 7];
//! - chunks >= 4 bytes: whole-buffer delta -> (lc=0, lp=0, pb=0) [type 2].

use crate::elf::Arch;
use crate::error::Error;
use crate::{delta, lzma, normalize, planes};

/// Winner of the per-chunk brute force.
#[derive(Debug)]
pub struct ChunkResult {
    /// Preprocessing type (0, 1 or 2 for single chunks).
    pub preproc_type: u8,
    /// Compressed payload (`[props][LZMA2 stream]`).
    pub compressed: Vec<u8>,
    /// Original chunk size.
    pub orig_size: usize,
}

impl ChunkResult {
    pub fn comp_size(&self) -> usize {
        self.compressed.len()
    }
}

/// Compress one chunk with every applicable preprocessing and keep the best.
pub fn compress_chunk_best(
    data: &[u8],
    is_code: bool,
    arch: Option<Arch>,
    opt_level: u8,
) -> Result<ChunkResult, Error> {
    let mut best: Option<ChunkResult> = None;

    let mut consider = |preproc_type: u8, payload: Vec<u8>| {
        if best.as_ref().is_none_or(|b: &ChunkResult| payload.len() < b.comp_size()) {
            best = Some(ChunkResult {
                preproc_type,
                compressed: payload,
                orig_size: data.len(),
            });
        }
    };

    // Candidate 1: raw with (3, 0, 2).
    let c = lzma::compress_buf(data, 3, 0, 2, opt_level)?;
    consider(0, c);

    if opt_level == 0 {
        return best.ok_or_else(|| Error::Lzma("all candidates failed".to_string()));
    }

    // Candidate 2: raw with (2, 2, 2).
    let c = lzma::compress_buf(data, 2, 2, 2, opt_level)?;
    consider(0, c);

    // Candidate 3: ARM64 code -> normalize + planes + per-plane delta.
    // Candidate 4: ARM64 code -> normalize + planes, no delta (type 7).
    if is_code && arch == Some(Arch::Arm64) && data.len() >= 16 {
        let mut tmp = data.to_vec();
        normalize::arm64_normalize(&mut tmp);
        let planed = planes::encode(&tmp);

        let mut planed_delta = planed.clone();
        let n_instr = data.len() / 4;
        if n_instr > 1 {
            for p in 0..4 {
                delta::encode(&mut planed_delta[p * n_instr..(p + 1) * n_instr]);
            }
        }
        let c = lzma::compress_buf(&planed_delta, 0, 0, 0, opt_level)?;
        consider(1, c);

        let c = lzma::compress_buf(&planed, 0, 0, 0, opt_level)?;
        consider(7, c);
    }

    // Candidate 5: whole-buffer delta.
    if data.len() >= 4 {
        let mut tmp = data.to_vec();
        delta::encode(&mut tmp);
        let c = lzma::compress_buf(&tmp, 0, 0, 0, opt_level)?;
        consider(2, c);
    }

    best.ok_or_else(|| Error::Lzma("all candidates failed".to_string()))
}
