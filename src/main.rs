//! lgz_compress — low-level standalone binary compression utility.
//!
//! Rust port of lgzv3.c: ELF-aware preprocessing (ARM64/x86 branch
//! normalization, byte planes, delta coding) + LZMA2, with a brute-force
//! optimizer over preprocessing modes and lc/lp/pb combinations.
//! Pure-Rust dependencies only (`lzma-rust2`, `rayon`), static musl builds
//! for x86_64 / i686 / aarch64 / armv7. Primary focus: arm64.
//!
//! CLI and archive format are compatible with the C version:
//! files compress/decompress cross-wise. Intentional deviations from C:
//! - bound checks on archive parsing (C trusted the header);
//! - nonzero exit code on errors (C always returned 0);
//! - inputs over 4 GiB are rejected (C truncated them to 32 bits).

mod chunk;
mod compress;
mod decompress;
mod delta;
mod elf;
mod error;
mod format;
mod lzma;
mod manifest;
mod normalize;
mod planes;

use std::process::ExitCode;

fn print_usage(program: &str) {
    eprintln!("Использование:");
    eprintln!("  {program} compress <вход> <выход> [уровень 0-3]");
    eprintln!("    Уровни: 0=Быстрый, 1=Баланс, 2=Глубокий(90, по умолч.), 3=Экстремальный(225+)");
    eprintln!("  {program} decompress <вход> <выход>");
    eprintln!("  {program} decompress_all <манифест>");
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let program = argv.first().map(String::as_str).unwrap_or("lgz_compress");
    let args: &[String] = &argv[1..];

    let result = match args.first().map(String::as_str) {
        None => {
            print_usage(program);
            return ExitCode::from(1);
        }
        Some("compress") => {
            if args.len() < 3 || args.len() > 4 {
                eprintln!(
                    "Использование: {program} compress <входной_файл> <выходной_файл> [уровень_оптимизации 0-3]"
                );
                return ExitCode::from(1);
            }
            let mut opt_level: i32 = 2;
            if args.len() == 4 {
                opt_level = args[3].parse().unwrap_or(2);
                opt_level = opt_level.clamp(0, 3);
            }
            compress::compress_file(&args[1], &args[2], opt_level as u8)
        }
        Some("decompress") => {
            if args.len() != 3 {
                eprintln!(
                    "Использование: {program} decompress <входной_файл> <выходной_файл>"
                );
                return ExitCode::from(1);
            }
            decompress::decompress_file(&args[1], &args[2])
        }
        Some("decompress_all") => {
            if args.len() != 2 {
                eprintln!(
                    "Использование: {program} decompress_all <путь_к_манифесту>"
                );
                return ExitCode::from(1);
            }
            manifest::decompress_all(&args[1])
        }
        Some(cmd) => {
            eprintln!("Неизвестная команда: {cmd}");
            return ExitCode::from(1);
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[!] Ошибка: {e}");
            ExitCode::from(1)
        }
    }
}
