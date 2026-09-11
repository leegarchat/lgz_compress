//! Whole-file compression pipeline.
//!
//! Direct port of `compress_file` from lgzv3.c:
//! ELF-aware chunking, parallel multi-block compression, parallel
//! single-blob brute force over (preprocessing x lc/lp/pb), then the
//! smaller of the two layouts wins. `rayon` thread pools replace OpenMP.
//!
//! The `if (0 && ...)` shortlist block from C never executes and is not
//! ported. Files larger than 4 GiB are rejected (C silently truncated them
//! to 32 bits in chunk headers).

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
struct Chunk {
    off: usize,
    size: usize,
    is_code: bool,
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

fn hw_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// Split the file into chunks along ELF PROGBITS sections.
///
/// Gaps between sections become plain chunks; without ELF (or without
/// sections) the whole file is a single plain chunk.
fn build_chunks(data: &[u8]) -> (Vec<Chunk>, Option<Arch>) {
    let Some(info) = elf::parse(data) else {
        return (vec![Chunk { off: 0, size: data.len(), is_code: false }], None);
    };
    if info.sections.is_empty() {
        return (vec![Chunk { off: 0, size: data.len(), is_code: false }], Some(info.arch));
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
            size: data.len() as usize - pos as usize,
            is_code: false,
        });
    }
    (chunks, Some(info.arch))
}

fn chunk_thread_count(opt_level: u8, file_size: usize, hw: usize) -> usize {
    let mut ct = 1;
    if opt_level >= 3 {
        ct = hw;
    } else if opt_level == 2 {
        ct = hw.min(8);
    } else if opt_level == 1 {
        ct = hw.min(3);
    }
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
    let mut adv: Option<Vec<u8>> = None;
    if need_adv {
        let mut tmp = buffers[0].clone();
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
            }
        }
        adv = Some(tmp);
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
        SMART_COMBOS.iter().map(|&[lc, lp, pb]| (lc, lp, pb)).collect()
    } else {
        vec![(3, 0, 2)]
    }
}

/// Compress `in_path` into `out_path` at the given optimization level (0-3).
pub fn compress_file(in_path: &str, out_path: &str, opt_level: u8) -> Result<(), Error> {
    let data = fs::read(in_path)?;
    let file_size = data.len();
    if file_size > u32::MAX as usize {
        return Err(Error::TooLarge("input exceeds 4 GiB".to_string()));
    }
    println!("[*] Входной файл: {in_path} ({file_size} байт)");

    let (chunks, arch) = build_chunks(&data);
    let is_elf = arch.is_some();
    if is_elf {
        println!(
            "[*] Обнаружен ELF. Архитектура: {}",
            if arch == Some(Arch::Arm64) {
                "ARM64"
            } else {
                "x86 / x86_64"
            }
        );
    }

    let hw = hw_threads();

    // ---- Multi-block path (levels 1-3). ----
    let mut multi_results: Option<Vec<ChunkResult>> = None;
    let mut multi_total = usize::MAX;
    if opt_level > 0 {
        println!(
            "[*] Сжатие мульти-блоком ({} чанков). Используются все ядра CPU...",
            chunks.len()
        );
        let ct = chunk_thread_count(opt_level, file_size, hw);
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
        println!("[*] Мульти-блочный метод: {multi_total} байт");
        multi_results = Some(results);
    }

    // ---- Single-blob brute force. ----
    let (buffers, modes) = build_modes(data, &chunks, arch, is_elf, opt_level);
    let combos = build_combos(opt_level);
    let total_passes = combos.len() * modes.len();

    let mut bf_threads = hw;
    if opt_level == 2 {
        bf_threads = hw.min(8);
    } else if opt_level <= 1 && bf_threads > 6 {
        bf_threads = 6;
    }
    bf_threads = bf_threads.min(total_passes).max(1);
    println!(
        "[*] Запуск ОПТИМИЗАТОРА (Уровень: {opt_level} | Потоков: {bf_threads} | Комбинаций: {total_passes})"
    );

    let done = AtomicUsize::new(0);
    let report_step = if total_passes >= 20 { total_passes / 20 } else { 1 };
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
            if total_passes > 2 && (n == total_passes || n % report_step == 0) {
                print!("\r    Анализ вариантов: {n} / {total_passes} ...");
                let _ = std::io::stdout().flush();
            }
        });
    });
    if total_passes > 2 {
        println!("\r    Анализ вариантов: {total_passes} / {total_passes} ... Готово!    ");
    }
    let (_size, _pass, best_comp, best_type) = best
        .into_inner()
        .unwrap()
        .ok_or_else(|| Error::Lzma("single-blob optimizer found nothing".to_string()))?;

    let single_total = 8 + 8 + 4 + 1 + 4 + 4 + best_comp.len();
    println!("[*] Лучший результат единым блоком: {single_total} байт (препроцессинг: {best_type})");

    // ---- Emit the winner. ----
    let mut out = Vec::new();
    if single_total < multi_total {
        println!("[*] Выбран метод единого блока (максимальное сжатие)");
        let metas = [ChunkMeta {
            preproc: best_type,
            orig_size: file_size as u32,
            comp_size: best_comp.len() as u32,
        }];
        out.extend_from_slice(&format::encode_header(file_size as u64, &metas));
        out.extend_from_slice(&best_comp);
    } else {
        println!("[*] Выбран мульти-блочный метод");
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
    fs::write(out_path, &out)?;

    let out_size = out.len();
    println!(
        "\n[+] РЕЗУЛЬТАТ: {file_size} -> {out_size} байт ({:.2}%)",
        100.0 * out_size as f64 / file_size.max(1) as f64
    );
    Ok(())
}
