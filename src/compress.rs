//! Whole-file compression pipeline.
//!
//! Direct port of `compress_file` from lgzv3.c: ELF-aware chunking, parallel
//! multi-block compression, parallel single-blob brute force over
//! (preprocessing x lc/lp/pb), then the smaller of the two layouts wins.
//! `rayon` thread pools replace OpenMP.
//!
//! The `if (0 && ...)` shortlist block from C never executes and is not
//! ported. Inputs larger than 4 GiB are rejected (C silently truncated them
//! to 32 bits in chunk headers).
//!
//! [`compress_data`] is also used by the multi-file packer: it compresses
//! an opaque solid blob (per-file normalization already applied by the
//! caller) as one plain chunk plus the single-blob brute force.

use std::fs;
use std::io::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use rayon::prelude::*;

use crate::chunk::{compress_chunk_best, ChunkResult};
use crate::elf::{self, Arch};
use crate::error::Error;
use crate::format::{self, ChunkMeta};
use crate::{delta, lzma, normalize, planes};

/// One file region handed to the multi-block path.
#[derive(Debug, Clone, Copy)]
pub struct Chunk {
    pub off: usize,
    pub size: usize,
    pub is_code: bool,
}

/// Smart (lc, lp, pb) table for level 2. Port of `smart_combos`.
const SMART_COMBOS: [[u32; 3]; 19] = [
    [3, 0, 2],
    [4, 0, 2],
    [2, 0, 2],
    [3, 1, 2],
    [2, 2, 2],
    [1, 3, 2],
    [0, 4, 2],
    [4, 0, 1],
    [3, 1, 1],
    [2, 2, 1],
    [1, 3, 1],
    [0, 4, 1],
    [4, 0, 0],
    [3, 1, 0],
    [2, 2, 0],
    [1, 3, 0],
    [0, 4, 0],
    [0, 0, 2],
    [0, 1, 2],
];

const LCS: [u32; 5] = [3, 0, 1, 2, 4];
const LPS: [u32; 3] = [0, 1, 2];
const PBS: [u32; 3] = [2, 0, 1];

/// Number of worker threads to use by default (all online cores).
pub fn hw_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// Job settings shared by single-file compression and the solid packer.
#[derive(Debug, Clone, Copy)]
pub struct CompressOpts {
    /// Optimization level 0-3.
    pub level: u8,
    /// Worker thread count (already resolved, >= 1).
    pub threads: usize,
    /// Suppress progress lines (the packer prints its own summary).
    pub quiet: bool,
}

/// Split the file into chunks along ELF PROGBITS sections.
///
/// Gaps between sections become plain chunks; without ELF (or without
/// sections) the whole file is a single plain chunk.
pub fn build_chunks(data: &[u8]) -> (Vec<Chunk>, Option<Arch>) {
    let Some(info) = elf::parse(data) else {
        return (
            vec![Chunk {
                off: 0,
                size: data.len(),
                is_code: false,
            }],
            None,
        );
    };
    if info.sections.is_empty() {
        return (
            vec![Chunk {
                off: 0,
                size: data.len(),
                is_code: false,
            }],
            Some(info.arch),
        );
    }
    let mut chunks = Vec::new();
    let mut pos: u64 = 0;
    for s in &info.sections {
        if s.offset > pos {
            chunks.push(Chunk {
                off: pos as usize,
                size: (s.offset - pos) as usize,
                is_code: false,
            });
        }
        chunks.push(Chunk {
            off: s.offset as usize,
            size: s.size as usize,
            is_code: s.is_code,
        });
        pos = s.offset + s.size;
    }
    if pos < data.len() as u64 {
        chunks.push(Chunk {
            off: pos as usize,
            size: data.len() - pos as usize,
            is_code: false,
        });
    }
    (chunks, Some(info.arch))
}

fn chunk_thread_count(opt_level: u8, file_size: usize, threads: usize) -> usize {
    // NOTE: unlike the C version (which capped workers at 3/8), all cores
    // are used: pass results are picked deterministically, so the thread
    // count affects speed, never the output bytes.
    let mut ct = match opt_level {
        0 => 1,
        _ => threads,
    };
    if opt_level == 2 && file_size < (1 << 20) && ct > 4 {
        ct = 4;
    }
    if file_size < (1 << 20) && ct > 2 {
        ct = 2;
    }
    ct.max(1)
}

/// Build the whole-file preprocessed variants and the mode table.
///
/// Returns `(buffers, modes)` where `buffers[0]` is always the original
/// data and `modes` maps each pass slot to `(buffer index, preproc type)`.
fn build_modes(
    data: Vec<u8>,
    chunks: &[Chunk],
    arch: Option<Arch>,
    is_elf: bool,
    opt_level: u8,
) -> (Vec<Vec<u8>>, Vec<(usize, u8)>) {
    let mut buffers: Vec<Vec<u8>> = vec![data];
    let mut modes: Vec<(usize, u8)> = vec![(0, 0)];

    let need_adv = is_elf && arch == Some(Arch::Arm64) && opt_level >= 2;
    let need_total_delta = opt_level >= 3 || (opt_level >= 2 && !is_elf);
    let need_norm_total_delta =
        opt_level >= 3 || (opt_level >= 2 && is_elf && arch == Some(Arch::X86));

    // tmp_total_delta: whole-file delta of the original.
    let mut total_delta: Option<Vec<u8>> = None;
    if need_total_delta {
        let mut tmp = buffers[0].clone();
        delta::encode(&mut tmp);
        total_delta = Some(tmp);
    }

    // tmp_norm: branch-normalized code sections.
    let mut norm: Option<Vec<u8>> = None;
    if is_elf && opt_level >= 1 {
        let mut tmp = buffers[0].clone();
        for c in chunks {
            if c.is_code {
                let slice = &mut tmp[c.off..c.off + c.size];
                match arch {
                    Some(Arch::Arm64) => normalize::arm64_normalize(slice),
                    Some(Arch::X86) => normalize::x86_normalize(slice),
                    None => {}
                }
            }
        }
        norm = Some(tmp);
    }

    // tmp_adv: normalize + in-place planes + delta (ARM64 code only).
    // tmp_planes: normalize + in-place planes, no delta (type 8). Delta on
    // opcode slices destroys match periodicity for LZMA2, so the pure
    // plane-split variant joins the optimizer next to type 4.
    let mut adv: Option<Vec<u8>> = None;
    let mut planes_blob: Option<Vec<u8>> = None;
    if need_adv {
        let mut tmp = buffers[0].clone();
        let mut tmp_no_delta = buffers[0].clone();
        for c in chunks {
            if c.is_code {
                let slice = &mut tmp[c.off..c.off + c.size];
                normalize::arm64_normalize(slice);
                let planed = planes::encode(slice);
                slice.copy_from_slice(&planed);
                let n_instr = c.size / 4;
                if n_instr > 1 {
                    for p in 0..4 {
                        delta::encode(&mut slice[p * n_instr..(p + 1) * n_instr]);
                    }
                }
                let pslice = &mut tmp_no_delta[c.off..c.off + c.size];
                normalize::arm64_normalize(pslice);
                let p = planes::encode(pslice);
                pslice.copy_from_slice(&p);
            }
        }
        adv = Some(tmp);
        planes_blob = Some(tmp_no_delta);
    }

    // tmp_norm_total_delta: delta of the normalized image.
    let mut norm_total_delta: Option<Vec<u8>> = None;
    if need_norm_total_delta {
        if let Some(ref n) = norm {
            let mut tmp = n.clone();
            delta::encode(&mut tmp);
            norm_total_delta = Some(tmp);
        }
    }

    if let Some(buf) = norm {
        buffers.push(buf);
        modes.push((buffers.len() - 1, 3));
    }
    if opt_level >= 3 {
        for (buf, typ) in [
            (adv, 4u8),
            (planes_blob, 8u8),
            (total_delta, 5u8),
            (norm_total_delta, 6u8),
        ] {
            if let Some(buf) = buf {
                buffers.push(buf);
                modes.push((buffers.len() - 1, typ));
            }
        }
    } else if opt_level >= 2 {
        if let Some(buf) = adv {
            buffers.push(buf);
            modes.push((buffers.len() - 1, 4));
        }
        if let Some(buf) = planes_blob {
            buffers.push(buf);
            modes.push((buffers.len() - 1, 8));
        }
        if !is_elf {
            if let Some(buf) = total_delta {
                buffers.push(buf);
                modes.push((buffers.len() - 1, 5));
            }
        }
        if is_elf && arch == Some(Arch::X86) {
            if let Some(buf) = norm_total_delta {
                buffers.push(buf);
                modes.push((buffers.len() - 1, 6));
            }
        }
    }

    (buffers, modes)
}

/// (lc, lp, pb) combination list for the given level.
fn build_combos(opt_level: u8) -> Vec<(u32, u32, u32)> {
    if opt_level >= 3 {
        let mut combos = Vec::with_capacity(45);
        for &lc in &LCS {
            for &lp in &LPS {
                for &pb in &PBS {
                    combos.push((lc, lp, pb));
                }
            }
        }
        combos
    } else if opt_level >= 2 {
        SMART_COMBOS
            .iter()
            .map(|&[lc, lp, pb]| (lc, lp, pb))
            .collect()
    } else {
        vec![(3, 0, 2)]
    }
}

/// Compress raw bytes into a complete UCOMP01 archive image.
///
/// `chunks`/`arch` describe the data (ELF section layout for single files,
/// one plain chunk for opaque/packed blobs).
pub fn compress_data(
    data: &[u8],
    chunks: Vec<Chunk>,
    arch: Option<Arch>,
    opts: &CompressOpts,
) -> Result<Vec<u8>, Error> {
    let file_size = data.len();
    if file_size > u32::MAX as usize {
        return Err(Error::TooLarge("input exceeds 4 GiB".to_string()));
    }
    let opt_level = opts.level;
    let quiet = opts.quiet;
    let threads = opts.threads.max(1);
    let is_elf = arch.is_some();

    // ---- Multi-block path (levels 1-3). ----
    let mut multi_results: Option<Vec<ChunkResult>> = None;
    let mut multi_total = usize::MAX;
    if opt_level > 0 {
        if !quiet {
            println!(
                "[*] Multi-block compression ({} chunks). Using all CPU cores...",
                chunks.len()
            );
        }
        let ct = chunk_thread_count(opt_level, file_size, threads);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(ct)
            .build()
            .map_err(|e| Error::Lzma(format!("thread pool: {e}")))?;
        let results: Result<Vec<ChunkResult>, Error> = pool.install(|| {
            chunks
                .par_iter()
                .map(|c| {
                    compress_chunk_best(&data[c.off..c.off + c.size], c.is_code, arch, opt_level)
                })
                .collect()
        });
        let results = results?;
        let payload: usize = results.iter().map(ChunkResult::comp_size).sum();
        multi_total = 8 + 8 + 4 + chunks.len() * (1 + 4 + 4) + payload;
        if !quiet {
            println!("[*] Multi-block result: {multi_total} bytes");
        }
        multi_results = Some(results);
    }

    // ---- Single-blob brute force. ----
    let (buffers, modes) = build_modes(data.to_vec(), &chunks, arch, is_elf, opt_level);
    let combos = build_combos(opt_level);
    let total_passes = combos.len() * modes.len();

    let mut bf_threads = threads;
    bf_threads = bf_threads.min(total_passes).max(1);
    if !quiet {
        println!(
            "[*] Running optimizer (level: {opt_level} | threads: {bf_threads} | combinations: {total_passes})"
        );
    }

    let done = AtomicUsize::new(0);
    let report_step = if total_passes >= 20 {
        total_passes / 20
    } else {
        1
    };
    // (payload size, pass index, payload, preproc type). Lower size wins,
    // ties keep the earlier pass — same rule as C's critical section.
    let best: Mutex<Option<(usize, usize, Vec<u8>, u8)>> = Mutex::new(None);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(bf_threads)
        .build()
        .map_err(|e| Error::Lzma(format!("thread pool: {e}")))?;
    pool.install(|| {
        (0..total_passes).into_par_iter().for_each(|p| {
            let combo_idx = p / modes.len();
            let mode_idx = p % modes.len();
            let (lc, lp, pb) = combos[combo_idx];
            let (buf_idx, preproc_type) = modes[mode_idx];
            let input = &buffers[buf_idx];
            if let Ok(comp) = lzma::compress_buf(input, lc, lp, pb, opt_level) {
                let mut guard = best.lock().unwrap();
                let replace = match guard.as_ref() {
                    None => true,
                    Some((size, idx, _, _)) => {
                        comp.len() < *size || (comp.len() == *size && p < *idx)
                    }
                };
                if replace {
                    *guard = Some((comp.len(), p, comp, preproc_type));
                }
            }
            let n = done.fetch_add(1, Ordering::Relaxed) + 1;
            if !quiet && total_passes > 2 && (n == total_passes || n % report_step == 0) {
                print!("\r    Trying variants: {n} / {total_passes} ...");
                let _ = std::io::stdout().flush();
            }
        });
    });
    if !quiet && total_passes > 2 {
        println!("\r    Trying variants: {total_passes} / {total_passes} ... Done!    ");
    }
    let (_size, _pass, best_comp, best_type) = best
        .into_inner()
        .unwrap()
        .ok_or_else(|| Error::Lzma("single-blob optimizer found nothing".to_string()))?;

    let single_total = 8 + 8 + 4 + 1 + 4 + 4 + best_comp.len();
    if !quiet {
        println!(
            "[*] Best single-blob result: {single_total} bytes (preprocessing: {best_type})"
        );
    }

    // ---- Emit the winner. ----
    let mut out = Vec::new();
    if single_total < multi_total {
        if !quiet {
            println!("[*] Selected single-blob layout (max compression)");
        }
        let metas = [ChunkMeta {
            preproc: best_type,
            orig_size: file_size as u32,
            comp_size: best_comp.len() as u32,
        }];
        out.extend_from_slice(&format::encode_header(file_size as u64, &metas));
        out.extend_from_slice(&best_comp);
    } else {
        if !quiet {
            println!("[*] Selected multi-block layout");
        }
        let results = multi_results.expect("multi path must exist when it wins");
        let metas: Vec<ChunkMeta> = results
            .iter()
            .map(|r| ChunkMeta {
                preproc: r.preproc_type,
                orig_size: r.orig_size as u32,
                comp_size: r.comp_size() as u32,
            })
            .collect();
        out.extend_from_slice(&format::encode_header(file_size as u64, &metas));
        for r in &results {
            out.extend_from_slice(&r.compressed);
        }
    }
    Ok(out)
}

/// Compress `in_path` into `out_path`.
pub fn compress_file(
    in_path: &str,
    out_path: &str,
    opt_level: u8,
    threads: usize,
) -> Result<(), Error> {
    let data = fs::read(in_path)?;
    let file_size = data.len();
    println!("[*] Input file: {in_path} ({file_size} bytes)");

    let (chunks, arch) = build_chunks(&data);
    if arch.is_some() {
        println!(
            "[*] ELF detected. Architecture: {}",
            if arch == Some(Arch::Arm64) {
                "ARM64"
            } else {
                "x86 / x86_64"
            }
        );
    }

    let opts = CompressOpts {
        level: opt_level,
        threads: threads.max(1),
        quiet: false,
    };
    let out = compress_data(&data, chunks, arch, &opts)?;
    fs::write(out_path, &out)?;

    let out_size = out.len();
    println!(
        "\n[+] RESULT: {file_size} -> {out_size} bytes ({:.2}%)",
        100.0 * out_size as f64 / file_size.max(1) as f64
    );
    Ok(())
}
