//! lgz_compress — low-level standalone binary compression utility.
//!
//! Rust port of lgzv3.c: ELF-aware preprocessing (ARM64/x86 branch
//! normalization, byte planes, delta coding) + LZMA2, with a brute-force
//! optimizer over preprocessing modes and lc/lp/pb combinations.
//! Pure-Rust dependencies only (`lzma-rust2`, `rayon`, `libc` for
//! chown/xattr bindings), static musl builds for x86_64 / i686 /
//! aarch64 / armv7. Primary focus: arm64.
//!
//! Two archive formats:
//! - UCOMP01: single byte stream (C-compatible payload framing);
//! - UCOMP02: multi-file container (entry tree + metadata + one solid
//!   UCOMP01 blob shared by all files).

mod chunk;
mod compress;
mod decompress;
mod delta;
mod elf;
mod error;
mod format;
mod inspect;
mod lzma;
mod manifest;
mod meta;
mod normalize;
mod pack;
mod planes;

use std::process::ExitCode;

use error::Error;
use meta::MetaFilter;
use pack::PackOptions;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_global_help(program: &str) {
    println!(
        "lgz_compress {VERSION} — low-level binary compression utility (ARM64-oriented)
Single-file archives (UCOMP01) are payload-compatible with the C version.

Usage:
  {program} <command> [arguments] [options]

Commands:
  compress <input> <output> [level]   Compress one file.
                                      Without metadata flags -> UCOMP01.
                                      With metadata flags    -> UCOMP02 (1 entry).
  pack <manifest> <output>            Pack many files into one UCOMP02 archive
                                      (solid cluster: one shared LZMA2 stream).
  decompress <archive> [dest]         Unpack. UCOMP01 needs <dest> file path.
                                      UCOMP02 unpacks the tree into [dest] dir
                                      (default: current directory).
  list <archive>  (alias: ls)         Show archive contents without unpacking.
  extract <archive> <file> [dest]     Pull one entry out of a UCOMP02 archive
                      (alias: x)      (structure kept, or --flatten).
  help [command]                      Show this help or command help.
  --version, -V                       Print version.

Options (compress, pack):
  -l, --level <0-3>        Optimization level (default 2):
                             0 = fast, 1 = balanced,
                             2 = deep (default), 3 = extreme.
  -j, --threads <N>        Worker threads (default: all CPU cores).
                           Level 0 runs a single serial pass by design
                           (one LZMA2 stream), so -j only helps level 1+.
                           Deep levels with many threads need RAM
                           (roughly one dictionary per thread).
  --preserve-perms         Store permission bits read from the filesystem.
  --preserve-owner         Store uid/gid read from the filesystem.
  --preserve-context       Store SELinux context read from the filesystem.
  --preserve-all           All of the above.
  --chmod <mode>           Force one mode for all entries.
                           Formats: 755, 0755, 4755, rwxr-xr-x.
  --owner <owner>          Force one owner for all entries.
                           Formats: root, 0, root:shell, 0:2000, 0:shell.
  --context <ctx>          Force one SELinux context for all entries.
                           Format: u:object_r:system_file:s0.

Precedence for metadata: --chmod/--owner/--context override everything,
manifest line values are used as written, --preserve-* fills the rest.
By default nothing is stored.

Options (decompress, extract — which stored metadata to restore):
  (default: restore everything stored)
  --no-meta, --skip-meta           Restore nothing at all.
  --no-perms, --skip-perms         Skip chmod.
  --no-owner, --skip-owner         Skip chown (no superuser warnings).
  --no-context, --skip-context     Skip SELinux xattrs.
  --preserve-perms                 Restore only permission bits.
  --preserve-owner                 Restore only uid/gid.
  --preserve-context               Restore only SELinux contexts.
  --preserve-all                   Restore everything stored (default).
  (extract only: --flatten, --strip-path, -f — drop archived paths.)

Examples:
  {program} compress app_process64 app.lgz 2
  {program} compress --level 0 --preserve-all linker64 linker64.lgz
  {program} pack tree.txt system.lgz --level 1 --preserve-all
  {program} decompress system.lgz /tmp/restore
  {program} help manifest

Exit codes: 0 = ok, 1 = error. Metadata apply failures (chown/xattr
without privileges) are warnings, not errors."
    );
}

fn print_command_help(program: &str, cmd: &str) {
    match cmd {
        "compress" => println!(
            "Usage: {program} compress <input> <output> [level] [options]

Compress one file. Plain mode writes UCOMP01 (same framing as the C tool,
decompressible by it and vice versa). When any metadata flag is given
(--preserve-*, --chmod, --owner, --context), a single-entry UCOMP02 file
is written instead so permissions/owner/context travel with the data.

  level              0..3, clamped. Default 2. -l/--level overrides it.
  -l, --level <0-3>  Same as above; conflicts with a different positional
                     level are an error.

Examples:
  {program} compress app_process64 app.lgz 2
  {program} compress -l 0 --preserve-perms --preserve-context f f.lgz"
        ),
        "pack" => println!(
            "Usage: {program} pack <manifest> <output> [options]

Pack every entry listed in <manifest> (plain text, see `help manifest`)
into one UCOMP02 archive. Regular files are normalized per-file, then
concatenated into a single solid blob compressed once — the LZMA2
dictionary spans file boundaries and the optimizer runs once for all
files instead of once per file.

  -l, --level <0-3>  Optimization level, default 2.

Examples:
  {program} pack tree.txt system.lgz -l 1 --preserve-all
  {program} pack bins.txt bins.lgz --chmod 755 --owner 0:2000"
        ),
        "decompress" => println!(
            "Usage: {program} decompress <archive> [dest]

Unpack an archive, auto-detected by magic:
  UCOMP01 single file -> [dest] is required, it is the output file path.
  UCOMP02 container   -> [dest] is the target directory (created when
                         missing, default: current directory). The stored
                         tree (dirs, files, symlinks) is recreated inside,
                         stored metadata is applied (failures are warnings).
                         Writes never traverse symlinks (Zip-Slip guard).

Examples:
  {program} decompress app.lgz app.out
  {program} decompress system.lgz /tmp/restore
  {program} decompress system.lgz
  {program} decompress system.lgz /tmp/restore --no-owner --no-context

Which stored metadata to restore (default: everything stored):
  --no-meta / --skip-meta, --no-perms / --skip-perms,
  --no-owner / --skip-owner, --no-context / --skip-context,
  --preserve-perms, --preserve-owner, --preserve-context, --preserve-all"
        ),
        "list" | "ls" => println!(
            "Usage: {program} list <archive.lgz>   (alias: ls)

Show archive contents without unpacking (the solid payload is never
decompressed). UCOMP02 prints one row per entry (type, perms, owner,
SELinux context, size, path) plus a footer with counts and the total
compression ratio. UCOMP01 prints the single file size, chunk count
and preprocessing types."
        ),
        "extract" | "x" => println!(
            "Usage: {program} extract <archive.lgz> <target_file> [destination] [options]
  (alias: x)

Pull one entry out of a UCOMP02 archive. The whole solid blob is
decoded (inherent to the solid format), then only the requested range
is written. Zip-Slip guards apply: no writes through symlinks.

  <target_file>  Exact archived path, e.g. bin/toybox.
  [destination]  Existing directory (or a path ending with /): place
                 inside, keeping archived structure, or only the file
                 name with --flatten. Otherwise it names the output
                 file itself (missing parents are created).
  -f, --flatten, --strip-path
                 Drop archived directories, write just the file name.

Same --no-* / --preserve-* metadata flags as decompress.

Examples:
  {program} extract system.lgz bin/toybox /tmp/out
  {program} extract system.lgz bin/toybox /tmp/out --flatten
  {program} x system.lgz bin/lib.so ./lib.so --no-owner --no-context"
        ),
        "manifest" => println!(
            "Manifest format (plain text, one entry per line):

  file <path> [chmod] [owner] [context]
  dir  <path> [chmod] [owner] [context]
  link <path> -> <target> [chmod] [owner] [context]

  <path>   Relative to the current directory at pack time.
  chmod    755, 0755, 4755 or rwxr-xr-x (use - to skip).
  owner    root, 0, root:shell, 0:2000 (use - to skip).
           Names are resolved to ids while packing.
  context  u:object_r:system_file:s0 (use - to skip).
  # starts a comment, blank lines are ignored.

Example:
  # system/bin tree
  dir  system/bin 755 root:2000 u:object_r:system_file:s0
  file system/bin/toybox 755 root:2000 u:object_r:system_file:s0
  link system/bin/sh -> toybox - - -
  file system/bin/apexd-lsof.sh - - -"
        ),
        _ => {
            eprintln!("Unknown help topic: {cmd}");
            print_global_help(program);
        }
    }
}

/// Shared `-l/--level/-j/--threads/--preserve-*/--chmod/--owner/--context`
/// parsing.
///
/// Returns `(positionals, level, threads, pack_options)` where `threads`
/// is `None` when the flag was not given (all cores are used).
fn parse_common(
    args: &[String],
) -> Result<(Vec<String>, Option<u8>, Option<usize>, PackOptions), Error> {
    let mut positionals = Vec::new();
    let mut level: Option<u8> = None;
    let mut threads: Option<usize> = None;
    let mut opts = PackOptions::default();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-l" | "--level" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| {
                    Error::Usage(format!("{} needs a value 0-3", args[i - 1]))
                })?;
                let n: i32 = v
                    .parse()
                    .map_err(|_| Error::Usage(format!("bad level: {v}")))?;
                if !(0..=3).contains(&n) {
                    return Err(Error::Usage(format!("bad level (want 0-3): {v}")));
                }
                level = Some(n as u8);
            }
            "-j" | "--threads" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| {
                    Error::Usage(format!("{} needs a thread count (>= 1)", args[i - 1]))
                })?;
                let n: usize = v
                    .parse()
                    .map_err(|_| Error::Usage(format!("bad thread count: {v}")))?;
                if n < 1 {
                    return Err(Error::Usage(format!("bad thread count (want >= 1): {v}")));
                }
                threads = Some(n);
            }
            "--preserve-perms" => opts.preserve.perms = true,
            "--preserve-owner" => opts.preserve.owner = true,
            "--preserve-context" => opts.preserve.context = true,
            "--preserve-all" => {
                opts.preserve.perms = true;
                opts.preserve.owner = true;
                opts.preserve.context = true;
            }
            "--chmod" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| {
                    Error::Usage("--chmod needs a value (e.g. 755 or rwxr-xr-x)".to_string())
                })?;
                opts.forced.mode = Some(meta::parse_mode(v).map_err(|e| Error::Usage(e.to_string()))?);
            }
            "--owner" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| {
                    Error::Usage("--owner needs a value (e.g. root:shell or 0:2000)".to_string())
                })?;
                let (uid, gid) = meta::parse_owner(v).map_err(|e| Error::Usage(e.to_string()))?;
                opts.forced.uid = uid;
                opts.forced.gid = gid;
            }
            "--context" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| {
                    Error::Usage("--context needs a value".to_string())
                })?;
                opts.forced.context =
                    Some(meta::parse_context(v).map_err(|e| Error::Usage(e.to_string()))?);
            }
            other if other.starts_with('-') => {
                return Err(Error::Usage(format!("unknown option: {other}")));
            }
            _ => positionals.push(args[i].clone()),
        }
        i += 1;
    }
    Ok((positionals, level, threads, opts))
}

fn cmd_compress(program: &str, args: &[String]) -> Result<(), Error> {
    let (pos, flag_level, flag_threads, opts) = parse_common(args)?;
    if pos.len() < 2 || pos.len() > 3 {
        return Err(Error::Usage(format!(
            "Usage: {program} compress <input> <output> [level] [options]"
        )));
    }
    let mut level: u8 = 2;
    if pos.len() == 3 {
        let n: i32 = pos[2]
            .parse()
            .map_err(|_| Error::Usage(format!("bad level: {}", pos[2])))?;
        level = n.clamp(0, 3) as u8;
    }
    if let Some(fl) = flag_level {
        if pos.len() == 3 && fl != level {
            return Err(Error::Usage(format!(
                "conflicting levels: positional {} vs --level {fl}",
                pos[2]
            )));
        }
        level = fl;
    }

    if !opts.forced.is_empty() || opts.preserve.any() {
        pack::pack_single(&pos[0], &pos[1], &PackOptions {
            opt_level: level,
            threads: flag_threads,
            forced: opts.forced,
            preserve: opts.preserve,
        })
    } else {
        compress::compress_file(
            &pos[0],
            &pos[1],
            level,
            flag_threads.unwrap_or_else(compress::hw_threads),
        )
    }
}

fn cmd_pack(program: &str, args: &[String]) -> Result<(), Error> {
    let (pos, flag_level, flag_threads, opts) = parse_common(args)?;
    if pos.len() != 2 {
        return Err(Error::Usage(format!(
            "Usage: {program} pack <manifest> <output> [options]"
        )));
    }
    pack::pack(&pos[0], &pos[1], &PackOptions {
        opt_level: flag_level.unwrap_or(2),
        threads: flag_threads,
        forced: opts.forced,
        preserve: opts.preserve,
    })
}

/// Parse restore-direction flags shared by `decompress` and `extract`.
///
/// Returns `(positionals, metadata filter, flatten)`. Pack-direction flags
/// (`-l`, `--chmod`, ...) are rejected here; `--flatten` is rejected by
/// `decompress` (it only makes sense for `extract`).
fn parse_restore_flags(args: &[String]) -> Result<(Vec<String>, MetaFilter, bool), Error> {
    let mut positionals = Vec::new();
    let mut flatten = false;
    let (mut wp, mut wo, mut wc, mut wa) = (false, false, false, false);
    let (mut np, mut no, mut nc, mut na) = (false, false, false, false);

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--preserve-perms" => wp = true,
            "--preserve-owner" => wo = true,
            "--preserve-context" => wc = true,
            "--preserve-all" => wa = true,
            "--no-meta" | "--skip-meta" => na = true,
            "--no-perms" | "--skip-perms" => np = true,
            "--no-owner" | "--skip-owner" => no = true,
            "--no-context" | "--skip-context" => nc = true,
            "--flatten" | "--strip-path" | "-f" => flatten = true,
            other if other.starts_with('-') => {
                return Err(Error::Usage(format!("unknown option: {other}")));
            }
            _ => positionals.push(args[i].clone()),
        }
        i += 1;
    }
    let filter = MetaFilter::resolve(wp, wo, wc, wa, np, no, nc, na);
    Ok((positionals, filter, flatten))
}

fn cmd_decompress(program: &str, args: &[String]) -> Result<(), Error> {
    let (pos, filter, flatten) = parse_restore_flags(args)?;
    if flatten {
        return Err(Error::Usage(format!(
            "--flatten belongs to extract, not decompress (see `{program} help extract`)"
        )));
    }
    if pos.is_empty() || pos.len() > 2 {
        return Err(Error::Usage(format!(
            "Usage: {program} decompress <archive> [dest] [options]"
        )));
    }
    let data = std::fs::read(&pos[0])?;
    if data.len() < 8 {
        return Err(Error::BadArchive("file too small".to_string()));
    }
    if &data[0..8] == format::MAGIC {
        let out = pos.get(1).ok_or_else(|| {
            Error::Usage(format!(
                "single-file archive needs an output file: {program} decompress <archive> <output>"
            ))
        })?;
        decompress::decompress_file(&pos[0], out)
    } else if &data[0..8] == pack::MAGIC2 {
        let dest = pos.get(1).map(String::as_str).unwrap_or(".");
        pack::unpack(&pos[0], dest, &filter)
    } else {
        Err(Error::BadArchive(
            "unknown magic (want UCOMP01 or UCOMP02)".to_string(),
        ))
    }
}

fn cmd_list(program: &str, args: &[String]) -> Result<(), Error> {
    if args.len() != 1 {
        return Err(Error::Usage(format!(
            "Usage: {program} list <archive.lgz>"
        )));
    }
    inspect::list(&args[0])
}

fn cmd_extract(program: &str, args: &[String]) -> Result<(), Error> {
    let (pos, filter, flatten) = parse_restore_flags(args)?;
    if pos.len() < 2 || pos.len() > 3 {
        return Err(Error::Usage(format!(
            "Usage: {program} extract <archive.lgz> <target_file> [destination] [options]"
        )));
    }
    let dest = pos.get(2).map(String::as_str);
    inspect::extract(
        &pos[0],
        &pos[1],
        dest,
        &inspect::ExtractOptions { flatten, filter },
    )
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let program = argv.first().map(String::as_str).unwrap_or("lgz_compress");
    let args: &[String] = &argv[1..];

    let result = match args.first().map(String::as_str) {
        None | Some("-h") | Some("--help") => {
            print_global_help(program);
            return ExitCode::SUCCESS;
        }
        Some("-V") | Some("--version") | Some("version") => {
            println!("lgz_compress {VERSION}");
            return ExitCode::SUCCESS;
        }
        Some("help") => {
            match args.get(1) {
                Some(topic) => print_command_help(program, topic),
                None => print_global_help(program),
            }
            return ExitCode::SUCCESS;
        }
        Some("compress") => cmd_compress(program, &args[1..]),
        Some("pack") => cmd_pack(program, &args[1..]),
        Some("decompress") => cmd_decompress(program, &args[1..]),
        Some("list") | Some("ls") => cmd_list(program, &args[1..]),
        Some("extract") | Some("x") => cmd_extract(program, &args[1..]),
        // Legacy alias: keep the old entry point working as single unpack.
        Some("decompress_all") => Err(Error::Usage(
            "decompress_all was removed. Unpack a UCOMP02 archive instead:\n\
             compress/pack store the tree + metadata, decompress restores it.\n\
             See `help decompress`."
                .to_string(),
        )),
        Some(cmd) => Err(Error::Usage(format!(
            "Unknown command: {cmd}\nRun `{program} help` for usage."
        ))),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(Error::Usage(msg)) => {
            eprintln!("{msg}");
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("[!] Error: {e}");
            ExitCode::from(1)
        }
    }
}
