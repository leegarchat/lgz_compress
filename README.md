# lgz_compress

> Standalone Rust port of the `lgz` binary compressor: ELF-aware preprocessing (ARM64/x86 branch normalization, byte-plane splitting, delta coding) + LZMA2 with a brute-force optimizer, single-file archives and solid multi-file containers with metadata and transparent ZIP ingestion.

The utility is completely standalone: pure safe Rust with no C dependencies, shipped as fully static musl binaries (x86_64, x86, aarch64, armv7). The host build packs (`compress`, `pack`); the decompress-only build flavor (`--no-default-features`, used for `target/push/` device binaries) unpacks and inspects only. Single-file payloads (UCOMP01) stay wire-compatible with the original C tool in both directions.

---

## Key Features

* **100% Standalone Static**: No `libc` C code, no liblzma, no runtime dependencies. `lzma-rust2` + `rayon` (host only) + `zip` + `libc` bindings — all pure Rust, musl-static on 4 architectures.
* **ELF-Aware Preprocessing**: ARM64 `B`/`BL`/`ADRP` and x86 `E8`/`E9` branch normalization (relative → absolute), ARM64 byte-plane splitting (stride 4), delta coding — applied per ELF `PROGBITS` code section.
* **Brute-Force Optimizer**: Levels 0–3 search (preprocessing × `lc`/`lp`/`pb` combos: 1 / 2 / 57 / 225 passes) with multi-block vs single-blob layout competition; winner is the smaller image, ties broken deterministically (thread count affects speed only, never bytes).
* **Solid Multi-File Containers (UCOMP02)**: Many files packed into one shared LZMA2 stream — per-file normalization, 4-byte alignment, filename clustering (ARM64 executables → shared objects → scripts → data), one optimizer run for the whole set.
* **Metadata Preservation**: Permission bits (octal `755` or symbolic `rwxr-xr-x`), owner (`root:shell` or `0:2000`), SELinux contexts — per manifest line, `--preserve-*` from the filesystem, or forced `--chmod/--owner/--context` for all entries; granular restore flags (`--no-owner`, `--preserve-perms`, …).
* **Transparent ZIP Ingestion**: `.zip` entries are opened at pack time — inner files (decompressed, legacy UCOMP payloads decoded to clean bytes) join the solid blob with full preprocessing; the virtual table of contents (methods, modes, timestamps, CRC) rebuilds a valid `.zip` on unpack (`unzip -t` clean).
* **Archive Inspector**: `list` prints an aligned contents table + footer (counts, sizes, ratio) without touching the solid payload; `extract` pulls a single entry (structure-preserving, `--flatten`, or explicit file path).
* **Decompress-Only Flavor**: `compress` Cargo feature (default on); `--no-default-features` drops the encoder, matchers and `rayon` — the ramdisk binary only runs `decompress`/`extract`/`list`.
* **Zip-Slip Safe**: `safe_join` rejects absolute paths and `..`; directories are created component-wise refusing symlink traversal; file writes use `O_NOFOLLOW`; symlinks are created last. All header/offset parsing is bounds-checked (`checked_*`, explicit range validation).
* **Deterministic Output**: Same inputs → byte-identical archives on any host arch and any thread count (verified host vs `qemu-aarch64`).

---

## Repository Architecture

```text
Cargo.toml                  Package root (features: default = ["compress"]; [profile.release]: LTO fat, abort, strip)
build.sh                    Static musl multi-arch builder (x86_64/x86/aarch64/armv7) via cargo or cross
dist/                       Prebuilt static binaries, full flavor (lgz_compress-linux-*)
target/push/                Push-ready copies {name}_{arch}, decompress-only flavor (adb push to device)
src/main.rs                 Command dispatch (compress/pack/decompress/list/ls/extract/x/help) + manuals
src/compress.rs             Whole-file pipeline: ELF chunking, multi-block vs single-blob brute force (rayon)
src/chunk.rs                Per-chunk best-of preprocessing (types 0/1/2)
src/decompress.rs           UCOMP01 decode + per-type post-processing inversion
src/pack.rs                 UCOMP02 container: manifest resolve, solid layout, unpack phases, zip rebuild
src/inspect.rs              list (framing-only) + single-entry extract
src/manifest.rs             Build manifest parser (file/dir/link/zip lines)
src/meta.rs                 chmod/owner/context parsing, FS preserve (stat/xattr), filtered apply (chmod/chown/setxattr)
src/elf.rs                  Bounds-checked ELF64 section/arch parser
src/normalize.rs            ARM64/x86 branch normalize/denormalize (exact involution)
src/planes.rs               ARM64 byte-plane split/merge (stride 4)
src/delta.rs                Delta encode/decode (wrapping arithmetic)
src/lzma.rs                 LZMA2 backend ([props][stream] framing, dict/props codec, depth mapping)
src/format.rs               UCOMP01 framing (magic, LE headers, chunk table + validation)
```

---

## Archive Formats

**UCOMP01** (single byte stream, C-compatible framing):

```text
[8] magic "UCOMP01\0" | [8] original size (LE) | [4] chunk count
per chunk: [1] preproc type | [4] orig size | [4] comp size (incl. LZMA2 props byte) | [N] payload
```

Preprocessing types: `0` raw · `1` arm64 planes+delta · `2` delta · `3` branch normalize ·
`4` normalize+planes+delta · `5` file delta · `6` normalize+file delta.

**UCOMP02** (multi-file solid container): entry table (path, type file/dir/link/zip, optional
mode/uid/gid/context, solid ranges, ELF code ranges for denormalization, zip virtual TOC with
methods/modes/timestamps/CRC) + one solid UCOMP01 blob + per-file 4-byte alignment.

**Manifest** (plain text, paths relative to CWD):

```text
file <path> [chmod] [owner] [context]
dir  <path> [chmod] [owner] [context]
link <path> -> <target> [chmod] [owner] [context]
zip  <path> [chmod] [owner] [context]
```

(`-` skips a field; a `file` line pointing at zip data auto-ingests.)

---

## Integrity & Safety Caps

* Container/chunk headers fully bounds-checked; unknown magic, bad counts, truncated payloads, size-sum mismatches → hard errors, never silent corruption.
* Decoder output cap: 256 MiB per UCOMP01 payload (same as C); solid ranges validated before slicing.
* Inputs over 4 GiB rejected (C silently truncated them to 32 bits).
* Metadata apply is best-effort with warnings (`chown`/`setxattr` without privileges never fail the run); `--no-*` flags disable categories entirely (FAT32/exFAT safe).
* Exit codes: `0` ok, `1` error. Errors propagate with context; `main` is the only exit point.

---

## Building & Compilation

**Prerequisites**:
* Rust toolchain (stable, edition 2024).
* Cargo package manager.
* For static builds: musl toolchains or `cross` (see `build.sh --help` for per-distro install hints).

```bash
# Fast local build (host target)
cargo build --release
# -> target/release/lgz_compress

# Decompress-only flavor (what goes to the device)
cargo build --release --no-default-features

# Static multi-arch builds via build.sh (musl, stripped):
#   --cargo | --cross | --auto   build method (auto = cross if containers exist, else cargo)
#   --arch all|x64|x86|arm64|arm32
./build.sh --cargo --arch x64      # x86_64-unknown-linux-musl
./build.sh --cross --arch arm64    # aarch64 via containers
./build.sh --arch all              # x86_64, x86, aarch64, armv7

# Checks
cargo test                  # full flavor: 5 passed
cargo test --no-default-features   # lean flavor: 4 passed
```

Build outputs:

* `dist/` — static binaries `lgz_compress-linux-*`, **full** flavor (compress + pack + unpack).
* `target/push/` — 8 push-ready copies, both flavors per arch, e.g.:
  `adb push target/push/lgz_compress_lean_arm64 /data/local/` (both `dist/` and `target/` are gitignored).

| Arch | `*_full_*` (compress + unpack) | `*_lean_*` (decompress-only) | Saved |
|---|---|---|---|
| x64 | 1 061 616 | 729 560 | −31% |
| x86 | 993 888 | 698 752 | −30% |
| arm64 | 913 552 | 642 968 | −30% |
| arm32 | 916 184 | 621 060 | −32% |

The lean flavor (`--no-default-features`) drops the LZMA2 encoder, matchers
and `rayon`; only `decompress`/`extract`/`list` remain. What stays (~600 KB)
is the irreducible decode core: LZMA2 decoder, `zip`+inflate, denormalization
tables and std. Deliberately rejected for size: `opt-level=z` (−75 KB but
+11% decode time) and dropping the decoder ASM (−192 B, zero gain).

---

## CLI Reference

```bash
lgz_compress compress <input> <output> [level] [-l N] [-j N] [meta flags]
lgz_compress pack <manifest> <output> [-l N] [-j N] [meta flags]
lgz_compress decompress <archive> [dest] [--no-owner --no-context ...]
lgz_compress list <archive>                      # alias: ls
lgz_compress extract <archive> <file> [dest] [--flatten]   # alias: x
lgz_compress help [command|manifest]
```

Levels: `0` fast (single pass) · `1` balanced · `2` deep, default (57 passes) · `3` extreme (225 passes, 64 MiB dict on big inputs). `-j/--threads` defaults to all cores (level 0 is serial by design).

Restore-side metadata control (`decompress`, `extract`): default restores everything
stored; `--no-meta` restores nothing; `--no-perms/--no-owner/--no-context` (or
`--skip-*`) drop categories; `--preserve-perms/--preserve-owner/--preserve-context`
whitelist single categories (`--preserve-all` = default). `extract` adds
`--flatten` (drop archived paths). Full manifest + flag docs: `help manifest`.

```bash
lgz_compress compress app_process64 app.lgz 2
lgz_compress pack tree.txt system.lgz -l 1 --preserve-all
lgz_compress decompress system.lgz /tmp/restore --no-owner --no-context
lgz_compress list system.lgz
lgz_compress extract system.lgz bin/toybox /tmp/out --flatten
```

---

## Benchmarks & Validation

Measured on a 16-core x86_64 host (plus `qemu-aarch64` decode check). Times are
wall-clock; `t_enc`/`t_dec` in seconds.

### Single files (one binary → one UCOMP01)

| File (RAW) | L0 size / enc / dec | L1 size / enc / dec | L2 size / enc / dec | L3 size / enc / dec |
|---|---|---|---|---|
| `toybox` (594 888) | 239 063 / 0.13 / 0.01 | 227 874 / 0.44 / 0.01 | 225 444 / 1.17 / 0.01 | 225 416 / 2.89 / 0.01 |
| `app_process64` (51 856) | 5 203 / 0.01 / 0.00 | 5 149 / 0.04 / 0.00 | 5 126 / 0.11 / 0.00 | 5 115 / 0.25 / 0.00 |
| `libLLVM_android.so` (14 175 016) | 4 463 181 / 5.30 / 0.21 | 4 061 309 / 17.95 / 0.20 | 4 021 034 / 46.13 / 0.20 | 4 022 287 / 108.23 / 0.20 |

Decompression stays flat (~0.2 s for 14 MB) on every level — only the
encoder works harder. L2→L3 on single files is noise (±0.03%); the
brute force saturates, remaining redundancy is cross-file.

### Small mixed set (12 entries: 3 ELF, 2 scripts, 1 rc, 1 prop + link, 2 fonts, 2 zips; 4 417 220 bytes RAW)

| Level | Per-file singles (sum / enc) | Solid UCOMP02 (size / enc) | Multi vs singles |
|---|---|---|---|
| L0 | 1 574 283 / 1.1 s | 1 498 130 / 1.3 s | 95.2% |
| L1 | 1 523 722 / 3.7 s | 1 475 667 / 5.0 s | 96.9% |
| L2 | 1 500 026 / 9.4 s | 1 485 905 / 9.3 s | 99.1% |
| L3 | 1 499 294 / 23.0 s | 1 475 653 / 13.6 s | 98.4% |

Multi round-trips verified (`diff` + inner zip content compare); multi
decode ≈ 0.08 s. On heterogeneous sets the shared dictionary wins on
every level while the single optimizer pass runs once instead of N times.

### Full ramdisk set (270 entries: 250 files + 20 zips with 156 inners; 94 604 983 bytes in, 130 898 200 bytes full RAW tree)

| Method | Size | Ratio | enc | dec |
|---|---|---|---|---|
| `gzip -9` tarball | 40 192 918 | 42.5% | 6.04 s | 0.25 s |
| Legacy C `lgz` per-file + stored zips | 32 629 379 | 34.5% | n/a (prebuilt) | ~2.1 s |
| Multi L0 | 26 172 615 | 27.7% | 40.3 s | 1.25 s |
| Multi L1 | 25 980 800 | 27.5% | 156.3 s | 1.27 s |
| Multi L2 | 25 980 723 | 27.5% | 290.8 s | 1.28 s |
| Multi L3 (64 MiB dict, ZIP ingestion) | **25 016 070** | **26.4%** | 496 s | 1.23 s |

End-to-end: **130 898 200 → 25 016 070 = 5.23x**. L1≈L2 (77 bytes apart —
the plateau is real, L2 buys nothing here); L0 already beats the legacy
C coverage by 20%. `qemu-aarch64` lean-binary unpack of the L3 archive:
~3.4 s, byte-identical.

### Validation checklist

* Full-tree `cmp` clean after every multi unpack (270/270 entries).
* Rebuilt zips pass `unzip -t`; inner contents match decoded ground truth;
  stored/deflated methods preserved.
* Host vs `qemu-aarch64` outputs byte-identical; C↔Rust cross-decode
  verified both ways on binaries, scripts and fonts.
* `cargo clippy`-clean policy (zero warnings in all four build/test ×
  default/no-default combos), `cargo test` green (5/5 full, 4/4 lean).

---

## Licensing

Dual-licensed under the terms of the [MIT License](LICENSE-MIT) and the [Apache License 2.0](LICENSE-APACHE), at your option — same scheme as the sibling `image-worker` / `super-image-worker` projects.
