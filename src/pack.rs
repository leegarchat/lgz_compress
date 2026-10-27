//! Multi-file cluster packing (UCOMP02 container).
//!
//! Many files (a whole tree) are packed into ONE archive:
//! 1. every regular file is branch-normalized individually (ELF code
//!    sections; the ranges are stored so unpacking can invert it),
//! 2. normalized contents are concatenated into one solid blob, each file
//!    starting at a 4-byte boundary (keeps LZMA pos_state aligned with
//!    ARM64 opcodes across files),
//! 3. the solid blob is compressed once with the full single-file pipeline
//!    ([`compress_data`]), so the LZMA2 dictionary spans file boundaries
//!    and the optimizer runs once instead of once per file,
//! 4. paths, types, metadata and blob ranges are stored in the entry table.
//!
//! Container layout (all integers little-endian):
//! ```text
//! [8]  magic "UCOMP02\0"
//! [4]  format flags (0, reserved)
//! [4]  entry count (u32)
//! per entry:
//!   [2]  path length (u16) + path bytes (relative, '/' separated)
//!   [1]  type: 0 = file, 1 = dir, 2 = symlink
//!   [1]  metadata flags: bit0 = mode, bit1 = owner, bit2 = context
//!   [4]  mode (if bit0)
//!   [4]  uid + [4] gid (if bit1)
//!   [2]  context length (u16) + context bytes (if bit2)
//!   file: [2] range count + per range [8]off + [8]size + [1]arch(1=arm64,2=x86)
//!         + [8] solid offset + [8] solid size
//!   symlink: [2] target length + target bytes
//!   dir: nothing more
//!   zip: [2] inner count + per inner file/dir/symlink:
//!     [1] inner kind (0 = file, 1 = dir, 2 = symlink)
//!     [2] inner path length + path bytes ('/' separated, no leading /)
//!     file: [1] method (0 = stored, 8 = deflated) + [4] unix mode
//!           + [2] year + [1]mo [1]day [1]hour [1]min [1]sec (mtime)
//!           + [4] crc32 + [2] range count + ranges (as above)
//!           + [8] solid offset + [8] solid size
//!     dir: [4] unix mode + mtime (7 bytes, as above)
//!     symlink: [2] target length + target bytes + [4] unix mode + mtime
//! [8]  solid UCOMP01 length (u64)
//! [N]  solid UCOMP01 bytes
//! ```
//!
//! Zip ingestion: a `zip` entry stores a virtual table of contents; inner
//! file bytes (fully decompressed) join the shared solid blob and get the
//! same normalization + clustering as top-level files. On unpack the `.zip`
//! is rebuilt with original methods, modes and timestamps.
//!
//! Single files compressed WITH metadata use the same container with one
//! entry whose payload is a regular single-file UCOMP01 image (no code
//! ranges). Unpacking is uniform for both cases.

use std::fs;
use std::io::{self, Write};
use std::ops::Range;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

#[cfg(feature = "compress")]
use crate::compress::{self, Chunk};
use crate::decompress;
#[cfg(feature = "compress")]
use crate::elf::{self, Arch};
use crate::error::Error;
use crate::manifest::EntryKind;
#[cfg(feature = "compress")]
use crate::manifest::{ManifestEntry, parse_manifest};
use crate::meta::{self, FileMeta};
#[cfg(feature = "compress")]
use crate::meta::Preserve;
use crate::normalize;

/// Container magic.
pub const MAGIC2: &[u8; 8] = b"UCOMP02\0";

const TYPE_FILE: u8 = 0;
const TYPE_DIR: u8 = 1;
const TYPE_LINK: u8 = 2;
const TYPE_ZIP: u8 = 3;

pub(crate) const ZIP_FILE: u8 = 0;
pub(crate) const ZIP_DIR: u8 = 1;
pub(crate) const ZIP_LINK: u8 = 2;

pub(crate) const ZIP_STORED: u8 = 0;
pub(crate) const ZIP_DEFLATED: u8 = 8;

const META_MODE: u8 = 0x01;
const META_OWNER: u8 = 0x02;
const META_CTX: u8 = 0x04;

const ARCH_ARM64: u8 = 1;
const ARCH_X86: u8 = 2;

/// One normalized code range inside a packed file.
#[derive(Debug, Clone)]
pub struct CodeRange {
    pub off: u64,
    pub size: u64,
    pub arch: u8,
}

/// One container entry.
#[derive(Debug, Clone)]
pub struct PackEntry {
    pub path: String,
    pub kind: EntryKind,
    pub meta: FileMeta,
    /// Symlink target (links only).
    pub link_target: Option<String>,
    /// Normalization ranges (files only).
    pub code_ranges: Vec<CodeRange>,
    /// Byte range inside the decompressed solid blob (files only).
    pub solid_off: u64,
    pub solid_size: u64,
    /// Virtual table of contents (zip entries only).
    pub zip_inners: Vec<ZipInner>,
}

/// Modification timestamp of a zip inner entry, component-wise (DOS time
/// has no single canonical integer form across readers).
#[derive(Debug, Clone, Copy, Default)]
pub struct ZipTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

/// One file/dir/symlink inside an ingested zip archive.
#[derive(Debug, Clone)]
pub struct ZipInner {
    /// 0 = file, 1 = dir, 2 = symlink.
    pub kind: u8,
    /// Inner relative path ('/' separated).
    pub path: String,
    /// Files: 0 = stored, 8 = deflated.
    pub method: u8,
    /// Full unix mode from the zip (perm bits used on rebuild).
    pub unix_mode: u32,
    pub mtime: ZipTime,
    /// Files: crc32 of the raw bytes. Integrity reference recorded at
    /// ingest (the reader already verifies it); the rebuild writer
    /// recomputes CRCs itself, so this is not read back on unpack.
    #[allow(dead_code)]
    pub crc: u32,
    /// Symlinks: target path.
    pub link_target: Option<String>,
    /// Files: normalization ranges for the solid slice.
    pub code_ranges: Vec<CodeRange>,
    /// Files: byte range inside the decompressed solid blob.
    pub solid_off: u64,
    pub solid_size: u64,
}

/// Pack options: optimizer level, worker threads, forced metadata,
/// filesystem preserve flags. Encode-only (`compress` feature).
#[cfg(feature = "compress")]
#[derive(Debug, Clone, Default)]
pub struct PackOptions {
    pub opt_level: u8,
    /// Worker threads; `None` = all online cores.
    pub threads: Option<usize>,
    /// `--chmod/--owner/--context` values: override everything.
    pub forced: FileMeta,
    /// `--preserve-*` flags: fill fields still empty from the filesystem.
    pub preserve: Preserve,
}

#[cfg(feature = "compress")]
impl PackOptions {
    /// Resolve the worker thread count (>= 1).
    pub fn resolve_threads(&self) -> usize {
        self.threads.unwrap_or_else(compress::hw_threads).max(1)
    }
}

// ---------------------------------------------------------------------------
// Container encode/decode.
// ---------------------------------------------------------------------------

#[cfg(feature = "compress")]
fn check_len(len: usize, what: &str) -> Result<u16, Error> {
    u16::try_from(len)
        .map_err(|_| Error::TooLarge(format!("{what} exceeds 64 KiB")))
}

#[cfg(feature = "compress")]
fn push_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

#[cfg(feature = "compress")]
fn push_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

#[cfg(feature = "compress")]
fn push_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

#[cfg(feature = "compress")]
fn push_str(out: &mut Vec<u8>, s: &str, what: &str) -> Result<(), Error> {
    push_u16(out, check_len(s.len(), what)?);
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

#[cfg(feature = "compress")]
fn push_ztime(out: &mut Vec<u8>, t: &ZipTime) {
    push_u16(out, t.year);
    out.push(t.month);
    out.push(t.day);
    out.push(t.hour);
    out.push(t.minute);
    out.push(t.second);
}

/// Serialize one ingested zip inner entry.
#[cfg(feature = "compress")]
fn encode_zip_inner(out: &mut Vec<u8>, z: &ZipInner) -> Result<(), Error> {
    out.push(z.kind);
    push_str(&mut *out, &z.path, "zip inner path")?;
    match z.kind {
        ZIP_FILE => {
            if z.method != ZIP_STORED && z.method != ZIP_DEFLATED {
                return Err(Error::TooLarge(format!(
                    "bad zip method {} for '{}'",
                    z.method, z.path
                )));
            }
            out.push(z.method);
            push_u32(&mut *out, z.unix_mode);
            push_ztime(&mut *out, &z.mtime);
            push_u32(&mut *out, z.crc);
            push_u16(&mut *out, check_len(z.code_ranges.len(), "range count")?);
            for r in &z.code_ranges {
                push_u64(&mut *out, r.off);
                push_u64(&mut *out, r.size);
                out.push(r.arch);
            }
            push_u64(&mut *out, z.solid_off);
            push_u64(&mut *out, z.solid_size);
        }
        ZIP_LINK => {
            push_str(
                out,
                z.link_target.as_deref().unwrap_or(""),
                "zip link target",
            )?;
            push_u32(&mut *out, z.unix_mode);
            push_ztime(&mut *out, &z.mtime);
        }
        _ => {
            // ZIP_DIR and forward-compatible kinds carry mode + mtime.
            push_u32(&mut *out, z.unix_mode);
            push_ztime(&mut *out, &z.mtime);
        }
    }
    Ok(())
}

/// Serialize entries + solid payload into a UCOMP02 image.
#[cfg(feature = "compress")]
pub fn encode_container(entries: &[PackEntry], solid: &[u8]) -> Result<Vec<u8>, Error> {
    if entries.len() > u32::MAX as usize {
        return Err(Error::TooLarge("too many entries".to_string()));
    }
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC2);
    push_u32(&mut out, 0);
    push_u32(&mut out, entries.len() as u32);

    for e in entries {
        push_str(&mut out, &e.path, "path")?;
        out.push(match e.kind {
            EntryKind::File => TYPE_FILE,
            EntryKind::Dir => TYPE_DIR,
            EntryKind::Link => TYPE_LINK,
            EntryKind::Zip => TYPE_ZIP,
        });
        let mut flags = 0u8;
        if e.meta.mode.is_some() {
            flags |= META_MODE;
        }
        if e.meta.uid.is_some() || e.meta.gid.is_some() {
            flags |= META_OWNER;
        }
        if e.meta.context.is_some() {
            flags |= META_CTX;
        }
        out.push(flags);
        if let Some(mode) = e.meta.mode {
            push_u32(&mut out, mode);
        }
        if flags & META_OWNER != 0 {
            push_u32(&mut out, e.meta.uid.unwrap_or(u32::MAX));
            push_u32(&mut out, e.meta.gid.unwrap_or(u32::MAX));
        }
        if let Some(ctx) = &e.meta.context {
            push_str(&mut out, ctx, "context")?;
        }
        match e.kind {
            EntryKind::File => {
                push_u16(&mut out, check_len(e.code_ranges.len(), "range count")?);
                for r in &e.code_ranges {
                    push_u64(&mut out, r.off);
                    push_u64(&mut out, r.size);
                    out.push(r.arch);
                }
                push_u64(&mut out, e.solid_off);
                push_u64(&mut out, e.solid_size);
            }
            EntryKind::Link => {
                let target = e.link_target.as_deref().unwrap_or("");
                push_str(&mut out, target, "link target")?;
            }
            EntryKind::Dir => {}
            EntryKind::Zip => {
                push_u16(
                    &mut out,
                    check_len(e.zip_inners.len(), "zip inner count")?,
                );
                for z in &e.zip_inners {
                    encode_zip_inner(&mut out, z)?;
                }
            }
        }
    }

    push_u64(&mut out, solid.len() as u64);
    out.extend_from_slice(solid);
    Ok(out)
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize, what: &str) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or_else(|| {
            Error::BadArchive(format!("truncated container ({what})"))
        })?;
        if end > self.data.len() {
            return Err(Error::BadArchive(format!("truncated container ({what})")));
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self, what: &str) -> Result<u8, Error> {
        Ok(self.take(1, what)?[0])
    }

    fn u16(&mut self, what: &str) -> Result<u16, Error> {
        let b = self.take(2, what)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self, what: &str) -> Result<u32, Error> {
        let b = self.take(4, what)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self, what: &str) -> Result<u64, Error> {
        let b = self.take(8, what)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn str(&mut self, what: &str) -> Result<String, Error> {
        let len = self.u16(what)? as usize;
        let bytes = self.take(len, what)?;
        String::from_utf8(bytes.to_vec())
            .map_err(|_| Error::BadArchive(format!("non-UTF8 {what}")))
    }

    fn ztime(&mut self, what: &str) -> Result<ZipTime, Error> {
        Ok(ZipTime {
            year: self.u16(what)?,
            month: self.u8(what)?,
            day: self.u8(what)?,
            hour: self.u8(what)?,
            minute: self.u8(what)?,
            second: self.u8(what)?,
        })
    }

    fn ranges(&mut self, entry_idx: usize, what: &str) -> Result<Vec<CodeRange>, Error> {
        let n = self.u16(what)? as usize;
        if n > 1_000_000 {
            return Err(Error::BadArchive(format!(
                "entry {entry_idx}: bad range count {n}"
            )));
        }
        let mut ranges = Vec::with_capacity(n);
        for _ in 0..n {
            let off = self.u64("range off")?;
            let size = self.u64("range size")?;
            let arch = self.u8("range arch")?;
            if arch != ARCH_ARM64 && arch != ARCH_X86 {
                return Err(Error::BadArchive(format!(
                    "entry {entry_idx}: bad range arch {arch}"
                )));
            }
            ranges.push(CodeRange { off, size, arch });
        }
        Ok(ranges)
    }

    /// Parse one ingested zip inner entry.
    fn zip_inner(&mut self, entry_idx: usize) -> Result<ZipInner, Error> {
        let kind = self.u8("zip inner kind")?;
        if kind != ZIP_FILE && kind != ZIP_DIR && kind != ZIP_LINK {
            return Err(Error::BadArchive(format!(
                "entry {entry_idx}: bad zip inner kind {kind}"
            )));
        }
        let path = self.str("zip inner path")?;
        if path.is_empty() {
            return Err(Error::BadArchive(format!(
                "entry {entry_idx}: empty zip inner path"
            )));
        }
        let (method, unix_mode, mtime, crc, link_target, code_ranges, solid_off, solid_size) =
            match kind {
                ZIP_FILE => {
                    let method = self.u8("zip method")?;
                    if method != ZIP_STORED && method != ZIP_DEFLATED {
                        return Err(Error::BadArchive(format!(
                            "entry {entry_idx}: bad zip method {method}"
                        )));
                    }
                    let unix_mode = self.u32("zip mode")?;
                    let mtime = self.ztime("zip mtime")?;
                    let crc = self.u32("zip crc")?;
                    let ranges = self.ranges(entry_idx, "range count")?;
                    let off = self.u64("solid off")?;
                    let size = self.u64("solid size")?;
                    (method, unix_mode, mtime, crc, None, ranges, off, size)
                }
                ZIP_LINK => {
                    let target = self.str("zip link target")?;
                    let unix_mode = self.u32("zip mode")?;
                    let mtime = self.ztime("zip mtime")?;
                    (
                        ZIP_STORED,
                        unix_mode,
                        mtime,
                        0,
                        Some(target),
                        Vec::new(),
                        0,
                        0,
                    )
                }
                _ => {
                    let unix_mode = self.u32("zip mode")?;
                    let mtime = self.ztime("zip mtime")?;
                    (
                        ZIP_STORED,
                        unix_mode,
                        mtime,
                        0,
                        None,
                        Vec::new(),
                        0,
                        0,
                    )
                }
            };
        Ok(ZipInner {
            kind,
            path,
            method,
            unix_mode,
            mtime,
            crc,
            link_target,
            code_ranges,
            solid_off,
            solid_size,
        })
    }
}

/// Parse a UCOMP02 image. Returns entries + byte range of the solid payload.
pub fn parse_container(data: &[u8]) -> Result<(Vec<PackEntry>, Range<usize>), Error> {
    let mut cur = Cursor { data, pos: 0 };
    if cur.take(8, "magic")? != MAGIC2 {
        return Err(Error::BadArchive(
            "not a multi-file archive (magic mismatch)".to_string(),
        ));
    }
    let _flags = cur.u32("flags")?;
    let count = cur.u32("entry count")?;
    if count == 0 || count > 10_000_000 {
        return Err(Error::BadArchive(format!("bad entry count: {count}")));
    }

    let mut entries = Vec::with_capacity(count.min(1_000_000) as usize);
    for i in 0..count {
        let path = cur.str("path")?;
        if path.is_empty() {
            return Err(Error::BadArchive(format!("entry {i}: empty path")));
        }
        let kind = match cur.u8("type")? {
            TYPE_FILE => EntryKind::File,
            TYPE_DIR => EntryKind::Dir,
            TYPE_LINK => EntryKind::Link,
            TYPE_ZIP => EntryKind::Zip,
            t => return Err(Error::BadArchive(format!("entry {i}: bad type {t}"))),
        };
        let flags = cur.u8("meta flags")?;
        if flags & !(META_MODE | META_OWNER | META_CTX) != 0 {
            return Err(Error::BadArchive(format!(
                "entry {i}: bad meta flags {flags}"
            )));
        }
        let mut meta = FileMeta::empty();
        if flags & META_MODE != 0 {
            meta.mode = Some(cur.u32("mode")? & 0o7777);
        }
        if flags & META_OWNER != 0 {
            let uid = cur.u32("uid")?;
            let gid = cur.u32("gid")?;
            meta.uid = if uid == u32::MAX { None } else { Some(uid) };
            meta.gid = if gid == u32::MAX { None } else { Some(gid) };
        }
        if flags & META_CTX != 0 {
            meta.context = Some(cur.str("context")?);
        }

        let (link_target, code_ranges, solid_off, solid_size, zip_inners) = match kind {
            EntryKind::File => {
                let ranges = cur.ranges(i as usize, "range count")?;
                let off = cur.u64("solid off")?;
                let size = cur.u64("solid size")?;
                (None, ranges, off, size, Vec::new())
            }
            EntryKind::Link => (
                Some(cur.str("link target")?),
                Vec::new(),
                0,
                0,
                Vec::new(),
            ),
            EntryKind::Dir => (None, Vec::new(), 0, 0, Vec::new()),
            EntryKind::Zip => {
                let n_inners = cur.u16("zip inner count")? as usize;
                if n_inners > 1_000_000 {
                    return Err(Error::BadArchive(format!(
                        "entry {i}: bad zip inner count {n_inners}"
                    )));
                }
                let mut inners = Vec::with_capacity(n_inners);
                for _ in 0..n_inners {
                    inners.push(cur.zip_inner(i as usize)?);
                }
                (None, Vec::new(), 0, 0, inners)
            }
        };
        entries.push(PackEntry {
            path,
            kind,
            meta,
            link_target,
            code_ranges,
            solid_off,
            solid_size,
            zip_inners,
        });
    }

    let solid_len = cur.u64("solid length")? as usize;
    let solid_end = cur.pos.checked_add(solid_len).ok_or_else(|| {
        Error::BadArchive("solid payload range overflow".to_string())
    })?;
    if solid_end != data.len() {
        return Err(Error::BadArchive(format!(
            "trailing data: payload ends at {solid_end}, file is {}",
            data.len()
        )));
    }
    Ok((entries, cur.pos..solid_end))
}

// ---------------------------------------------------------------------------
// Packing.
// ---------------------------------------------------------------------------

/// Branch-normalize one file for the solid blob.
///
/// Returns the (possibly normalized) bytes, the code ranges the unpacker
/// needs to invert the transform, and the ELF identity (arch + e_type)
/// used for pre-packing clustering. Non-ELF files pass through untouched
/// with no ranges.
#[cfg(feature = "compress")]
fn normalize_for_solid(data: &[u8]) -> (Vec<u8>, Vec<CodeRange>, Option<(Arch, u16)>) {
    let Some(info) = elf::parse(data) else {
        return (data.to_vec(), Vec::new(), None);
    };
    let arch_byte = match info.arch {
        Arch::Arm64 => ARCH_ARM64,
        Arch::X86 => ARCH_X86,
    };
    let mut out = data.to_vec();
    let mut ranges = Vec::new();
    for s in &info.sections {
        if !s.is_code {
            continue;
        }
        let (off, size) = (s.offset as usize, s.size as usize);
        if off + size > out.len() {
            continue;
        }
        match info.arch {
            Arch::Arm64 => normalize::arm64_normalize(&mut out[off..off + size]),
            Arch::X86 => normalize::x86_normalize(&mut out[off..off + size]),
        }
        ranges.push(CodeRange {
            off: s.offset,
            size: s.size,
            arch: arch_byte,
        });
    }
    (out, ranges, Some((info.arch, info.e_type)))
}

/// One manifest line resolved against the filesystem.
///
/// `blob` holds normalized file contents (top-level files only);
/// `zip_works` holds normalized inner blobs (zip entries only).
/// Solid offsets are assigned later, after clustering.
/// `sort` is the cluster key for top-level files.
#[cfg(feature = "compress")]
struct ResolvedEntry {
    entry: PackEntry,
    blob: Option<Vec<u8>>,
    sort: (u8, String),
    zip_works: Vec<ZipWork>,
}

/// One ingested zip inner file awaiting a solid slot.
#[cfg(feature = "compress")]
struct ZipWork {
    /// Index into the owning entry's `zip_inners`.
    inner_idx: usize,
    blob: Vec<u8>,
    sort: (u8, String),
}

/// Cluster key: arm64 executables first, then arm64 shared objects, then
/// other ELF, then scripts, then remaining data. Names order
/// lexicographically inside a class so related libraries (same CRT
/// glue, similar symbols) land next to each other.
#[cfg(feature = "compress")]
fn classify(path: &str, data: &[u8], elf_id: Option<(Arch, u16)>) -> (u8, String) {
    let class = match elf_id {
        Some((Arch::Arm64, 2)) => 0,
        Some((Arch::Arm64, _)) => 1,
        Some(_) => 2,
        None if path.ends_with(".sh") || data.starts_with(b"#!") => 3,
        None => 4,
    };
    (class, path.to_lowercase())
}

/// Heuristic zip detection for `file` manifest lines: known extensions
/// or a zip signature (local header, central directory, end record).
#[cfg(feature = "compress")]
fn looks_like_zip(path: &str, head: &[u8]) -> bool {
    let lower = path.to_lowercase();
    lower.ends_with(".zip") || lower.ends_with(".jar") || lower.ends_with(".apk")
        || head.starts_with(b"PK\x03\x04")
        || head.starts_with(b"PK\x01\x02")
        || head.starts_with(b"PK\x05\x06")
}

#[cfg(feature = "compress")]
fn zip_time_from(dt: Option<zip::DateTime>) -> ZipTime {
    match dt {
        Some(t) => ZipTime {
            year: t.year(),
            month: t.month(),
            day: t.day(),
            hour: t.hour(),
            minute: t.minute(),
            second: t.second().min(58),
        },
        None => ZipTime {
            year: 1980,
            month: 1,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
        },
    }
}

/// Ingest one zip archive: read every entry, normalize file contents for
/// the shared solid blob, record the virtual table of contents.
///
/// Only stored/deflated entries are supported; anything else (bzip2, zstd,
/// encrypted, unsafe names, duplicates) is a hard error — silently
/// degrading a ramdisk archive is worse than refusing it.
#[cfg(feature = "compress")]
fn ingest_zip(
    spec: &ManifestEntry,
    raw: &[u8],
    input_total: &mut u64,
) -> Result<(Vec<ZipInner>, Vec<ZipWork>), Error> {
    *input_total += raw.len() as u64;
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(raw)).map_err(|e| {
        Error::Manifest(format!("line {}: not a zip archive '{}': {e}", spec.line_no, spec.path))
    })?;
    let mut inners = Vec::new();
    let mut works = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for idx in 0..archive.len() {
        let mut file = archive.by_index(idx).map_err(|e| {
            Error::Manifest(format!("line {}: bad zip entry #{idx} in '{}': {e}", spec.line_no, spec.path))
        })?;
        let enclosed = file.enclosed_name().ok_or_else(|| {
            Error::Manifest(format!(
                "line {}: unsafe name in '{}': '{}'",
                spec.line_no,
                spec.path,
                file.name()
            ))
        })?;
        let name = enclosed
            .to_str()
            .ok_or_else(|| {
                Error::Manifest(format!(
                    "line {}: non-UTF8 name in '{}'",
                    spec.line_no, spec.path
                ))
            })?
            .replace('\\', "/");
        if name.is_empty() || !seen.insert(name.clone()) {
            return Err(Error::Manifest(format!(
                "line {}: bad/duplicate name in '{}': '{name}'",
                spec.line_no, spec.path
            )));
        }

        if file.is_dir() {
            inners.push(ZipInner {
                kind: ZIP_DIR,
                path: name,
                method: ZIP_STORED,
                unix_mode: file.unix_mode().unwrap_or(0o755),
                mtime: zip_time_from(file.last_modified()),
                crc: 0,
                link_target: None,
                code_ranges: Vec::new(),
                solid_off: 0,
                solid_size: 0,
            });
        } else if file.is_symlink() {
            let mut target = Vec::new();
            std::io::Read::read_to_end(&mut file, &mut target).map_err(|e| {
                Error::Manifest(format!("line {}: cannot read link '{name}': {e}", spec.line_no))
            })?;
            let target = String::from_utf8(target).map_err(|_| {
                Error::Manifest(format!(
                    "line {}: non-UTF8 link target '{name}'",
                    spec.line_no
                ))
            })?;
            inners.push(ZipInner {
                kind: ZIP_LINK,
                path: name,
                method: ZIP_STORED,
                unix_mode: file.unix_mode().unwrap_or(0o777),
                mtime: zip_time_from(file.last_modified()),
                crc: 0,
                link_target: Some(target),
                code_ranges: Vec::new(),
                solid_off: 0,
                solid_size: 0,
            });
        } else {
            let method = match file.compression() {
                zip::CompressionMethod::Stored => ZIP_STORED,
                zip::CompressionMethod::Deflated => ZIP_DEFLATED,
                m => {
                    return Err(Error::Manifest(format!(
                        "line {}: unsupported method {m:?} for '{name}' (only stored/deflated)",
                        spec.line_no
                    )));
                }
            };
            let unix_mode = file.unix_mode().unwrap_or(0o644);
            let mtime = zip_time_from(file.last_modified());
            let mut bytes = Vec::with_capacity(file.size() as usize);
            std::io::Read::read_to_end(&mut file, &mut bytes).map_err(|e| {
                Error::Manifest(format!("line {}: cannot read '{name}': {e}", spec.line_no))
            })?;
            let crc = file.crc32();
            // Transparent UCOMP01 ingestion: inner payloads compressed with
            // the legacy single-file tool are decoded to clean bytes first,
            // so the solid stream never sees opaque high-entropy blobs.
            // (The rebuilt zip therefore holds raw files by design.)
            let bytes = if bytes.len() >= 8 && bytes[0..8] == *crate::format::MAGIC {
                crate::decompress::decompress_bytes(&bytes).map_err(|e| {
                    Error::Manifest(format!(
                        "line {}: inner UCOMP payload '{name}' is corrupt: {e}",
                        spec.line_no
                    ))
                })?
            } else {
                bytes
            };
            let (blob, ranges, elf_id) = normalize_for_solid(&bytes);
            let sort = classify(&name, &bytes, elf_id);
            let inner_idx = inners.len();
            inners.push(ZipInner {
                kind: ZIP_FILE,
                path: name,
                method,
                unix_mode,
                mtime,
                crc,
                link_target: None,
                code_ranges: ranges,
                solid_off: 0,
                solid_size: 0,
            });
            works.push(ZipWork {
                inner_idx,
                blob,
                sort,
            });
        }
    }
    Ok((inners, works))
}

/// Resolve one manifest line against the filesystem.
///
/// Returns the entry (`None` for skipped special files). File contents are
/// returned separately; the caller clusters files and lays out the solid
/// blob afterwards.
#[cfg(feature = "compress")]
fn resolve_entry(
    spec: &ManifestEntry,
    opts: &PackOptions,
    input_total: &mut u64,
) -> Result<Option<ResolvedEntry>, Error> {
    if Path::new(&spec.path).is_absolute() {
        return Err(Error::Manifest(format!(
            "line {}: path must be relative: '{}'",
            spec.line_no, spec.path
        )));
    }
    let fs_path = Path::new(&spec.path);
    let st = fs::symlink_metadata(fs_path).map_err(|e| {
        Error::Manifest(format!(
            "line {}: cannot stat '{}': {e}",
            spec.line_no, spec.path
        ))
    })?;
    let ft = st.file_type();
    let expected = match spec.kind {
        EntryKind::File => "file",
        EntryKind::Dir => "dir",
        EntryKind::Link => "link",
        EntryKind::Zip => "zip",
    };
    let kind_ok = match spec.kind {
        EntryKind::File | EntryKind::Zip => ft.is_file(),
        EntryKind::Dir => ft.is_dir(),
        EntryKind::Link => ft.is_symlink(),
    };
    if !kind_ok {
        let actual = if ft.is_file() {
            "file"
        } else if ft.is_dir() {
            "dir"
        } else if ft.is_symlink() {
            "link"
        } else {
            "special"
        };
        if !(ft.is_file() || ft.is_dir() || ft.is_symlink()) {
            eprintln!(
                "[!] Warning: line {}: skipping special file '{}'",
                spec.line_no, spec.path
            );
            return Ok(None);
        }
        return Err(Error::Manifest(format!(
            "line {}: '{}' is {actual}, manifest wants {expected}",
            spec.line_no, spec.path
        )));
    }

    let mut meta = spec.meta.clone();
    meta.apply_forced(&opts.forced);
    meta::fill_preserve(&mut meta, fs_path, opts.preserve)?;

    // A `zip` line — or a `file` line pointing at zip data — is ingested:
    // inner files join the shared solid blob, the table of contents stays
    // in the entry for rebuild-on-unpack. The file is read once here and
    // reused below.
    let raw_file: Option<Vec<u8>> = match spec.kind {
        EntryKind::File | EntryKind::Zip => Some(fs::read(fs_path)?),
        _ => None,
    };
    if spec.kind == EntryKind::Zip
        || (spec.kind == EntryKind::File
            && looks_like_zip(&spec.path, raw_file.as_deref().unwrap_or_default()))
    {
        let raw = raw_file.unwrap_or_default();
        let (inners, works) = ingest_zip(spec, &raw, input_total)?;
        return Ok(Some(ResolvedEntry {
            entry: PackEntry {
                path: spec.path.clone(),
                kind: EntryKind::Zip,
                meta,
                link_target: None,
                code_ranges: Vec::new(),
                solid_off: 0,
                solid_size: 0,
                zip_inners: inners,
            },
            blob: None,
            sort: (0, String::new()),
            zip_works: works,
        }));
    }

    let (link_target, code_ranges, blob, sort) = match spec.kind {
        EntryKind::File => {
            let raw = raw_file.unwrap_or_default();
            *input_total += raw.len() as u64;
            let (blob, ranges, elf_id) = normalize_for_solid(&raw);
            let sort = classify(&spec.path, &raw, elf_id);
            (None, ranges, Some(blob), sort)
        }
        EntryKind::Link => {
            let target = fs::read_link(fs_path)?;
            let target = target.into_os_string().into_string().map_err(|_| {
                Error::Manifest(format!(
                    "line {}: non-UTF8 link target for '{}'",
                    spec.line_no, spec.path
                ))
            })?;
            // The manifest target is authoritative: the archive must match
            // the described tree exactly, not whatever the disk has today.
            if let Some(want) = &spec.target {
                if want != &target {
                    return Err(Error::Manifest(format!(
                        "line {}: link '{}' points to '{target}', manifest says '{want}'",
                        spec.line_no, spec.path
                    )));
                }
            }
            (Some(target), Vec::new(), None, (0, String::new()))
        }
        EntryKind::Dir => (None, Vec::new(), None, (0, String::new())),
        EntryKind::Zip => unreachable!("zip entries return from resolve_entry early"),
    };

    Ok(Some(ResolvedEntry {
        entry: PackEntry {
            path: spec.path.clone(),
            kind: spec.kind,
            meta,
            link_target,
            code_ranges,
            solid_off: 0,
            solid_size: 0,
            zip_inners: Vec::new(),
        },
        blob,
        sort,
        zip_works: Vec::new(),
    }))
}

/// Pack the files listed in `manifest_path` into one UCOMP02 archive.
#[cfg(feature = "compress")]
pub fn pack(manifest_path: &str, out_path: &str, opts: &PackOptions) -> Result<(), Error> {
    let text = fs::read_to_string(manifest_path)?;
    let specs = parse_manifest(&text)?;
    println!("[*] Manifest: {} entries", specs.len());

    let mut input_total: u64 = 0;
    let mut skipped = 0;
    let mut clustered: Vec<ResolvedEntry> = Vec::with_capacity(specs.len());
    let mut zips: Vec<ResolvedEntry> = Vec::new();
    let mut others: Vec<PackEntry> = Vec::new();
    for spec in &specs {
        match resolve_entry(spec, opts, &mut input_total)? {
            Some(r) => {
                if r.blob.is_some() {
                    clustered.push(r);
                } else if !r.zip_works.is_empty() {
                    zips.push(r);
                } else {
                    others.push(r.entry);
                }
            }
            None => skipped += 1,
        }
    }

    // Cluster: related files share the LZMA2 dictionary window at minimal
    // distance. Zip inners join the same pool as top-level files; dirs,
    // links and zip containers keep manifest order after the files.
    enum Back {
        Top(usize),
        Zip(usize, usize),
    }
    let mut pool: Vec<((u8, String), Vec<u8>, Back)> = Vec::new();
    for (i, r) in clustered.iter_mut().enumerate() {
        let blob = r.blob.take().expect("clustered entry has a blob");
        pool.push((r.sort.clone(), blob, Back::Top(i)));
    }
    for (zi, z) in zips.iter_mut().enumerate() {
        let works = std::mem::take(&mut z.zip_works);
        for w in works {
            pool.push((w.sort, w.blob, Back::Zip(zi, w.inner_idx)));
        }
    }
    pool.sort_by(|a, b| a.0.cmp(&b.0));

    // Lay out the solid blob in clustered order (4-byte aligned: keeps
    // LZMA pos_state (pb=2) in sync with ARM64 opcodes across boundaries).
    let mut solid = Vec::new();
    for (_, blob, back) in pool {
        let pad = (4 - (solid.len() % 4)) % 4;
        solid.resize(solid.len() + pad, 0);
        let (off, size) = (solid.len() as u64, blob.len() as u64);
        solid.extend_from_slice(&blob);
        match back {
            Back::Top(i) => {
                clustered[i].entry.solid_off = off;
                clustered[i].entry.solid_size = size;
            }
            Back::Zip(zi, ii) => {
                zips[zi].entry.zip_inners[ii].solid_off = off;
                zips[zi].entry.zip_inners[ii].solid_size = size;
            }
        }
    }
    let mut entries: Vec<PackEntry> = Vec::with_capacity(specs.len());
    for r in clustered {
        entries.push(r.entry);
    }
    for z in zips {
        entries.push(z.entry);
    }
    entries.extend(others);
    if entries.is_empty() {
        return Err(Error::Manifest("nothing to pack".to_string()));
    }

    let (n_files, n_dirs, n_links, n_zips, n_inner) =
        entries.iter().fold((0, 0, 0, 0, 0), |(f, d, l, z, n), e| match e.kind {
            EntryKind::File => (f + 1, d, l, z, n),
            EntryKind::Dir => (f, d + 1, l, z, n),
            EntryKind::Link => (f, d, l + 1, z, n),
            EntryKind::Zip => (
                f,
                d,
                l,
                z + 1,
                n + e.zip_inners.iter().filter(|i| i.kind == ZIP_FILE).count(),
            ),
        });
    println!(
        "[*] Packing {n_files} files, {n_dirs} dirs, {n_links} symlinks, \
         {n_zips} zips ({n_inner} inner files) (solid blob: {} bytes)",
        solid.len()
    );

    let solid_ucomp = compress::compress_data(
        &solid,
        vec![Chunk {
            off: 0,
            size: solid.len(),
            is_code: false,
        }],
        None,
        &compress::CompressOpts {
            level: opts.opt_level,
            threads: opts.resolve_threads(),
            quiet: true,
        },
    )?;
    let image = encode_container(&entries, &solid_ucomp)?;
    fs::write(out_path, &image)?;

    println!(
        "[+] PACKED: {n_files} files + {n_dirs} dirs + {n_links} links + \
         {n_zips} zips ({n_inner} inner files), \
         {input_total} -> {} bytes ({:.2}%){}",
        image.len(),
        100.0 * image.len() as f64 / input_total.max(1) as f64,
        if skipped > 0 {
            format!(" ({skipped} special files skipped)")
        } else {
            String::new()
        }
    );
    Ok(())
}

/// Compress one file WITH metadata into a single-entry UCOMP02 archive.
///
/// The payload is a regular single-file UCOMP01 image (full pipeline with
/// ELF chunking); unpacking is uniform with multi-file archives.
#[cfg(feature = "compress")]
pub fn pack_single(
    in_path: &str,
    out_path: &str,
    opts: &PackOptions,
) -> Result<(), Error> {
    let data = fs::read(in_path)?;
    let file_name = Path::new(in_path)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| Error::Manifest(format!("bad input name: {in_path}")))?
        .to_string();
    println!("[*] Input file: {in_path} ({} bytes)", data.len());

    let mut meta = FileMeta::empty();
    meta.apply_forced(&opts.forced);
    meta::fill_preserve(&mut meta, Path::new(in_path), opts.preserve)?;

    let (chunks, arch) = compress::build_chunks(&data);
    let solid_ucomp = compress::compress_data(&data, chunks, arch, &compress::CompressOpts {
        level: opts.opt_level,
        threads: opts.resolve_threads(),
        quiet: false,
    })?;
    let entry = PackEntry {
        path: file_name,
        kind: EntryKind::File,
        meta,
        link_target: None,
        code_ranges: Vec::new(),
        solid_off: 0,
        solid_size: data.len() as u64,
        zip_inners: Vec::new(),
    };
    let image = encode_container(std::slice::from_ref(&entry), &solid_ucomp)?;
    fs::write(out_path, &image)?;
    println!(
        "[+] PACKED single: {} -> {} bytes ({:.2}%)",
        data.len(),
        image.len(),
        100.0 * image.len() as f64 / data.len().max(1) as f64
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Unpacking.
// ---------------------------------------------------------------------------

/// Join an archive path onto the destination, rejecting absolute paths
/// and `..` escapes (archive path traversal protection).
pub(crate) fn safe_join(dest: &Path, rel: &str) -> Result<PathBuf, Error> {
    if rel.is_empty() {
        return Err(Error::BadArchive("empty path in archive".to_string()));
    }
    let p = Path::new(rel);
    if p.is_absolute() {
        return Err(Error::BadArchive(format!(
            "absolute path in archive: {rel}"
        )));
    }
    let mut out = PathBuf::from(dest);
    for comp in p.components() {
        match comp {
            Component::Normal(s) => out.push(s),
            Component::CurDir => {}
            _ => {
                return Err(Error::BadArchive(format!(
                    "unsafe path in archive: {rel}"
                )));
            }
        }
    }
    Ok(out)
}

/// Invert the solid-time normalization of one file.
pub(crate) fn denormalize_file(buf: &mut [u8], ranges: &[CodeRange]) -> Result<(), Error> {
    for r in ranges {
        let (off, size) = (r.off as usize, r.size as usize);
        let end = off.checked_add(size).ok_or_else(|| {
            Error::BadArchive("code range overflow".to_string())
        })?;
        if end > buf.len() {
            return Err(Error::BadArchive("code range outside file".to_string()));
        }
        let slice = &mut buf[off..end];
        match r.arch {
            ARCH_ARM64 => normalize::arm64_denormalize(slice),
            ARCH_X86 => normalize::x86_denormalize(slice),
            a => return Err(Error::BadArchive(format!("bad range arch {a}"))),
        }
    }
    Ok(())
}

/// Create directories component by component, refusing to traverse
/// symlinks (Zip-Slip guard: a malicious/absent-minded archive must not
/// redirect `dest/a/b` through a planted `dest/a -> /somewhere` link).
pub(crate) fn safe_mkdir_all(dest: &Path, rel: &Path) -> Result<(), Error> {
    let mut cur = PathBuf::from(dest);
    for comp in rel.components() {
        let name = match comp {
            Component::Normal(s) => s,
            Component::CurDir => continue,
            _ => {
                return Err(Error::BadArchive(format!(
                    "unsafe path component in '{}'",
                    rel.display()
                )));
            }
        };
        cur.push(name);
        match fs::symlink_metadata(&cur) {
            Ok(st) => {
                if st.file_type().is_symlink() {
                    return Err(Error::BadArchive(format!(
                        "refusing to traverse symlink: '{}'",
                        cur.display()
                    )));
                }
                if !st.file_type().is_dir() {
                    return Err(Error::BadArchive(format!(
                        "not a directory: '{}'",
                        cur.display()
                    )));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => fs::create_dir(&cur)?,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Write file bytes, refusing to follow a trailing symlink (O_NOFOLLOW).
pub(crate) fn safe_write_file(full: &Path, bytes: &[u8]) -> Result<(), Error> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(full)
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) {
                Error::BadArchive(format!(
                    "refusing to write through symlink: '{}'",
                    full.display()
                ))
            } else {
                Error::Io(e)
            }
        })?;
    f.write_all(bytes)?;
    Ok(())
}

fn zip_datetime(t: &ZipTime) -> zip::DateTime {
    zip::DateTime::from_date_and_time(
        t.year,
        t.month.max(1),
        t.day.max(1),
        t.hour,
        t.minute,
        t.second,
    )
    .unwrap_or_default()
}

/// Slice one file's bytes out of the solid blob with bounds checks.
fn solid_slice<'a>(
    solid: &'a [u8],
    off: u64,
    size: u64,
    what: &str,
) -> Result<&'a [u8], Error> {
    let end = off.checked_add(size).ok_or_else(|| {
        Error::BadArchive(format!("bad solid range for '{what}'"))
    })?;
    if end > solid.len() as u64 {
        return Err(Error::BadArchive(format!(
            "solid range outside blob for '{what}'"
        )));
    }
    Ok(&solid[off as usize..end as usize])
}

/// Rebuild one `.zip` file from its table of contents.
///
/// Inner files are sliced out of the solid blob, denormalized per their
/// code ranges, and stored back with original methods (stored/deflated),
/// unix modes and timestamps. CRCs are recomputed by the writer; the
/// stored CRC was already verified at pack time.
pub(crate) fn rebuild_zip(
    full: &Path,
    entry: &PackEntry,
    solid: &[u8],
) -> Result<(), Error> {
    // Never write through a pre-existing symlink (same guard as files).
    if fs::symlink_metadata(full).is_ok() {
        let st = fs::symlink_metadata(full)?;
        if st.file_type().is_symlink() {
            return Err(Error::BadArchive(format!(
                "refusing to write through symlink: '{}'",
                full.display()
            )));
        }
        if st.file_type().is_dir() {
            return Err(Error::Meta(format!(
                "cannot replace directory with zip: '{}'",
                entry.path
            )));
        }
        fs::remove_file(full)?;
    }
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(full)
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) {
                Error::BadArchive(format!(
                    "refusing to write through symlink: '{}'",
                    full.display()
                ))
            } else {
                Error::Io(e)
            }
        })?;
    let mut writer = zip::ZipWriter::new(file);
    for z in &entry.zip_inners {
        let dt = zip_datetime(&z.mtime);
        match z.kind {
            ZIP_FILE => {
                let method = match z.method {
                    ZIP_STORED => zip::CompressionMethod::Stored,
                    ZIP_DEFLATED => zip::CompressionMethod::Deflated,
                    m => {
                        return Err(Error::BadArchive(format!(
                            "bad zip method {m} for '{}'",
                            z.path
                        )));
                    }
                };
                let options = zip::write::SimpleFileOptions::default()
                    .compression_method(method)
                    .unix_permissions(z.unix_mode)
                    .last_modified_time(dt);
                let raw = solid_slice(solid, z.solid_off, z.solid_size, &z.path)?;
                let mut bytes = raw.to_vec();
                denormalize_file(&mut bytes, &z.code_ranges)?;
                writer.start_file(&z.path, options).map_err(|e| {
                    Error::BadArchive(format!("cannot add '{}' to zip: {e}", z.path))
                })?;
                std::io::Write::write_all(&mut writer, &bytes).map_err(|e| {
                    Error::BadArchive(format!("cannot write '{}' to zip: {e}", z.path))
                })?;
            }
            ZIP_LINK => {
                let options = zip::write::SimpleFileOptions::default()
                    .unix_permissions(z.unix_mode)
                    .last_modified_time(dt);
                writer
                    .add_symlink(
                        &z.path,
                        z.link_target.as_deref().unwrap_or(""),
                        options,
                    )
                    .map_err(|e| {
                        Error::BadArchive(format!("cannot add link '{}' to zip: {e}", z.path))
                    })?;
            }
            _ => {
                let options = zip::write::SimpleFileOptions::default()
                    .unix_permissions(z.unix_mode)
                    .last_modified_time(dt);
                writer.add_directory(&z.path, options).map_err(|e| {
                    Error::BadArchive(format!("cannot add dir '{}' to zip: {e}", z.path))
                })?;
            }
        }
    }
    writer.finish().map_err(|e| {
        Error::BadArchive(format!("cannot finish zip '{}': {e}", entry.path))
    })?;
    Ok(())
}

/// Unpack a UCOMP02 archive into `dest_dir` (created when missing).
///
/// Order matters for safety: directories first, then files, then symlinks,
/// then zip containers, metadata last. Nothing is ever written through a
/// symlink planted by an earlier entry (absolute link targets like
/// `/apex/...` are still honored as links, they just cannot redirect
/// file writes).
///
/// Only the metadata categories enabled in `filter` are applied.
pub fn unpack(arc_path: &str, dest_dir: &str, filter: &meta::MetaFilter) -> Result<(), Error> {
    let data = fs::read(arc_path)?;
    let (entries, solid_range) = parse_container(&data)?;
    let mut solid = decompress::decompress_bytes(&data[solid_range])?;
    println!(
        "[*] Unpacking {} entries to {dest_dir} (solid: {} bytes)",
        entries.len(),
        solid.len()
    );

    let dest = Path::new(dest_dir);
    fs::create_dir_all(dest)?;

    let mut full_paths: Vec<PathBuf> = Vec::with_capacity(entries.len());
    for e in &entries {
        full_paths.push(safe_join(dest, &e.path)?);
    }

    // Phase 1: directories (explicit + parents of files/links/zips).
    for (e, full) in entries.iter().zip(full_paths.iter()) {
        let rel = Path::new(&e.path);
        match e.kind {
            EntryKind::Dir => safe_mkdir_all(dest, rel)?,
            EntryKind::File | EntryKind::Link | EntryKind::Zip => {
                if let Some(parent) = rel.parent() {
                    if !parent.as_os_str().is_empty() {
                        safe_mkdir_all(dest, parent)?;
                    }
                }
                let _ = full;
            }
        }
    }

    // Phase 2: files. Denormalization runs in place on the solid slice,
    // so no per-file copy is allocated (the solid is already in RAM).
    for (e, full) in entries.iter().zip(full_paths.iter()) {
        if e.kind != EntryKind::File {
            continue;
        }
        let end = e.solid_off.checked_add(e.solid_size).ok_or_else(|| {
            Error::BadArchive(format!("bad solid range for '{}'", e.path))
        })?;
        if end > solid.len() as u64 {
            return Err(Error::BadArchive(format!(
                "solid range outside blob for '{}'",
                e.path
            )));
        }
        let range = e.solid_off as usize..end as usize;
        denormalize_file(&mut solid[range.clone()], &e.code_ranges)?;
        safe_write_file(full, &solid[range])?;
    }

    // Phase 3: symlinks (created last, so nothing can be written through
    // them during this unpack).
    for (e, full) in entries.iter().zip(full_paths.iter()) {
        if e.kind != EntryKind::Link {
            continue;
        }
        let target = e.link_target.as_deref().unwrap_or("");
        if fs::symlink_metadata(full).is_ok() {
            let st = fs::symlink_metadata(full)?;
            if st.file_type().is_dir() && !st.file_type().is_symlink() {
                return Err(Error::Meta(format!(
                    "cannot replace directory with symlink: '{}'",
                    e.path
                )));
            }
            fs::remove_file(full)?;
        }
        std::os::unix::fs::symlink(target, full)?;
    }

    // Phase 3b: zip containers — rebuilt from the table of contents with
    // original methods, modes and timestamps. Symlinks already exist, so
    // nothing inside a rebuilt zip can redirect these writes (and zip
    // writes never traverse: entries are created inside the new file).
    for (e, full) in entries.iter().zip(full_paths.iter()) {
        if e.kind != EntryKind::Zip {
            continue;
        }
        rebuild_zip(full, e, &solid)?;
    }

    // Phase 4: metadata — files/links first, directories last so interim
    // restrictive modes cannot block the restore itself.
    let mut warnings = 0;
    let mut apply_all = |dirs_last: bool| {
        for (e, full) in entries.iter().zip(full_paths.iter()) {
            let is_dir = e.kind == EntryKind::Dir;
            if is_dir != dirs_last {
                continue;
            }
            for w in meta::apply_filtered(full, &e.meta, e.kind == EntryKind::Link, filter) {
                eprintln!("[!] Warning: {w}");
                warnings += 1;
            }
        }
    };
    apply_all(false);
    apply_all(true);

    println!(
        "[+] UNPACKED: {} entries to {dest_dir}{}",
        entries.len(),
        if warnings > 0 {
            format!(" ({warnings} metadata warnings)")
        } else {
            String::new()
        }
    );
    Ok(())
}
