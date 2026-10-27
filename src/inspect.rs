//! Archive inspection (`list`) and single-entry extraction (`extract`).
//!
//! `list` parses only the container framing — the heavy solid payload is
//! never decompressed. `extract` decodes the whole solid blob (inherent to
//! the solid format), then materializes exactly one entry. All Zip-Slip
//! guards from `unpack` apply: `safe_join` for archive paths,
//! `safe_mkdir_all` for created directories, `safe_write_file`
//! (`O_NOFOLLOW`) for file data.

use std::fs;
use std::path::{Path, PathBuf};

use crate::decompress;
use crate::error::Error;
use crate::format;
use crate::manifest::EntryKind;
use crate::meta::{self, MetaFilter};
use crate::pack::{self, PackEntry};

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

fn entry_type_char(kind: EntryKind) -> char {
    match kind {
        EntryKind::File => 'F',
        EntryKind::Dir => 'D',
        EntryKind::Link => 'L',
        EntryKind::Zip => 'Z',
    }
}

/// Print a human-readable table of a UCOMP02 container (no solid decode).
fn list_container(arc_path: &str, data: &[u8]) -> Result<(), Error> {
    let (entries, solid_range) = pack::parse_container(data)?;

    let mut owner_w = 5usize;
    let mut ctx_w = 7usize;
    let mut size_w = 4usize;
    let mut rows: Vec<(char, String, String, String, String, String)> = Vec::new();
    let mut n_files = 0u64;
    let mut n_dirs = 0u64;
    let mut n_links = 0u64;
    let mut n_zips = 0u64;
    let mut n_inner = 0u64;
    let mut uncompressed: u64 = 0;

    for e in &entries {
        let perms = e
            .meta
            .mode
            .map(meta::format_mode_symbolic)
            .unwrap_or_else(|| "-".to_string());
        let owner = match (e.meta.uid, e.meta.gid) {
            (Some(u), Some(g)) => meta::format_owner(u, g),
            (Some(u), None) => u.to_string(),
            (None, Some(g)) => format!(":{g}"),
            (None, None) => "-".to_string(),
        };
        let ctx = e.meta.context.clone().unwrap_or_else(|| "-".to_string());
        let (size, shown_path) = match e.kind {
            EntryKind::File => {
                n_files += 1;
                uncompressed += e.solid_size;
                (
                    e.solid_size.to_string(),
                    e.path.clone(),
                )
            }
            EntryKind::Dir => {
                n_dirs += 1;
                ("-".to_string(), e.path.clone())
            }
            EntryKind::Link => {
                n_links += 1;
                (
                    "-".to_string(),
                    format!("{} -> {}", e.path, e.link_target.as_deref().unwrap_or("")),
                )
            }
            EntryKind::Zip => {
                n_zips += 1;
                let inner_files: Vec<&crate::pack::ZipInner> = e
                    .zip_inners
                    .iter()
                    .filter(|z| z.kind == crate::pack::ZIP_FILE)
                    .collect();
                n_inner += inner_files.len() as u64;
                let total: u64 = inner_files.iter().map(|z| z.solid_size).sum();
                uncompressed += total;
                let n = e.zip_inners.len();
                (
                    total.to_string(),
                    format!(
                        "{} (zip, {} {})",
                        e.path,
                        n,
                        if n == 1 { "entry" } else { "entries" }
                    ),
                )
            }
        };
        owner_w = owner_w.max(owner.len());
        ctx_w = ctx_w.max(ctx.len());
        size_w = size_w.max(size.len());
        rows.push((
            entry_type_char(e.kind),
            perms,
            owner,
            ctx,
            size,
            shown_path,
        ));
    }

    println!("Archive: {arc_path} (UCOMP02, {} entries)", entries.len());
    println!(
        "T PERMS     {:owner_w$} {:ctx_w$} {:>size_w$} PATH",
        "OWNER", "CONTEXT", "SIZE"
    );
    for (t, perms, owner, ctx, size, path) in rows {
        println!("{t} {perms:9} {owner:owner_w$} {ctx:ctx_w$} {size:>size_w$} {path}");
    }

    let solid_comp = solid_range.len() as u64;
    let total = data.len() as u64;
    println!(
        "Files: {n_files}, Dirs: {n_dirs}, Links: {n_links}, Zips: {n_zips} ({n_inner} inner files), \
         Uncompressed: {uncompressed} bytes"
    );
    println!(
        "Solid: {solid_comp} bytes, Archive: {total} bytes ({:.2}%)",
        100.0 * total as f64 / uncompressed.max(1) as f64
    );
    Ok(())
}

/// Print info about a UCOMP01 single-file archive.
fn list_single(arc_path: &str, data: &[u8]) -> Result<(), Error> {
    let header = format::parse_header(data)?;
    let mut comp_total: u64 = 0;
    println!(
        "Archive: {arc_path} (UCOMP01 single file, {} chunk(s))",
        header.chunks.len()
    );
    println!("  #  PREPROC                  ORIG      COMP");
    for (i, (meta, _)) in header.chunks.iter().enumerate() {
        comp_total += meta.comp_size as u64;
        println!(
            "  {i:<2} {:<22} {:>8} {:>8}",
            format::preproc_name(meta.preproc),
            meta.orig_size,
            meta.comp_size
        );
    }
    println!(
        "Original: {} bytes, Compressed payload: {comp_total} bytes ({:.2}%)",
        header.orig_size,
        100.0 * (comp_total + 20) as f64 / header.orig_size.max(1) as f64
    );
    Ok(())
}

/// List archive contents (auto-detected by magic).
pub fn list(arc_path: &str) -> Result<(), Error> {
    let data = fs::read(arc_path)?;
    if data.len() < 8 {
        return Err(Error::BadArchive("file too small".to_string()));
    }
    if &data[0..8] == format::MAGIC {
        list_single(arc_path, &data)
    } else if &data[0..8] == pack::MAGIC2 {
        list_container(arc_path, &data)
    } else {
        Err(Error::BadArchive(
            "unknown magic (want UCOMP01 or UCOMP02)".to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// extract
// ---------------------------------------------------------------------------

/// Options for single-entry extraction.
#[derive(Debug, Clone)]
pub struct ExtractOptions {
    /// Ignore archived paths, place the entry basename into the destination.
    pub flatten: bool,
    /// Which stored metadata categories to apply.
    pub filter: MetaFilter,
}

/// Recreate one symlink entry at `full` (parent must already exist).
fn place_link(full: &Path, target: &str, entry_path: &str) -> Result<(), Error> {
    if fs::symlink_metadata(full).is_ok() {
        let st = fs::symlink_metadata(full)?;
        if st.file_type().is_dir() && !st.file_type().is_symlink() {
            return Err(Error::Meta(format!(
                "cannot replace directory with symlink: '{entry_path}'"
            )));
        }
        fs::remove_file(full)?;
    }
    std::os::unix::fs::symlink(target, full)?;
    Ok(())
}

/// Extract one entry of a UCOMP02 archive.
///
/// `dest` resolution:
/// - missing destination = current directory, structure preserved;
/// - destination is an existing directory (or ends with `/`) = place inside
///   it (full archived path, or basename with `--flatten`);
/// - otherwise `dest` names the output file (or directory, for dir entries)
///   itself; missing parents are created.
pub fn extract(
    arc_path: &str,
    target: &str,
    dest_opt: Option<&str>,
    opts: &ExtractOptions,
) -> Result<(), Error> {
    let data = fs::read(arc_path)?;
    if data.len() < 8 || &data[0..8] != pack::MAGIC2 {
        return Err(Error::BadArchive(
            "extract works on multi-file (UCOMP02) archives".to_string(),
        ));
    }
    let (entries, solid_range) = pack::parse_container(&data)?;
    let entry: &PackEntry = entries
        .iter()
        .find(|e| e.path == target)
        .ok_or_else(|| Error::BadArchive(format!("no such entry: '{target}'")))?;

    let dest_str = dest_opt.unwrap_or(".");
    let dest_is_dir = dest_str.ends_with('/')
        || dest_str == "."
        || fs::metadata(dest_str).is_ok_and(|m| m.is_dir());

    // Full output path. Archive-derived paths go through safe_join;
    // an explicit user path is trusted (same rule as `unpack` dest).
    let dest_base = Path::new(dest_str);
    let entry_rel = Path::new(&entry.path);
    let flat_name: Option<PathBuf> = if opts.flatten {
        Some(PathBuf::from(entry_rel.file_name().and_then(|n| n.to_str()).ok_or_else(
            || Error::BadArchive(format!("bad entry name: '{}'", entry.path)),
        )?))
    } else {
        None
    };
    let full: PathBuf = if dest_is_dir {
        fs::create_dir_all(dest_base)?;
        match &flat_name {
            Some(name) => pack::safe_join(dest_base, name.to_str().unwrap_or(""))?,
            None => pack::safe_join(dest_base, &entry.path)?,
        }
    } else {
        PathBuf::from(dest_str)
    };

    // Ensure the parent directory: archive-derived parents are created
    // component-wise (no symlink traversal), explicit ones directly.
    let ensure_parent = || -> Result<(), Error> {
        if dest_is_dir {
            if flat_name.is_none() {
                if let Some(rel) = entry_rel.parent().filter(|p| !p.as_os_str().is_empty()) {
                    pack::safe_mkdir_all(dest_base, rel)?;
                }
            }
        } else if let Some(parent) = full.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        Ok(())
    };

    // Solid decode is all-or-nothing: the whole blob is decoded once,
    // then exactly the requested range is materialized (files and zips).
    let solid_for_zip: Option<Vec<u8>> =
        if matches!(entry.kind, EntryKind::File | EntryKind::Zip) {
            Some(decompress::decompress_bytes(&data[solid_range])?)
        } else {
            None
        };

    match entry.kind {
        EntryKind::Dir => {
            if dest_is_dir {
                let rel = flat_name.as_deref().unwrap_or(entry_rel);
                pack::safe_mkdir_all(dest_base, rel)?;
            } else {
                fs::create_dir_all(&full)?;
            }
        }
        EntryKind::File => {
            let solid = solid_for_zip.as_deref().expect("decoded above");
            let end = entry
                .solid_off
                .checked_add(entry.solid_size)
                .ok_or_else(|| Error::BadArchive(format!("bad solid range for '{}'", entry.path)))?;
            if end > solid.len() as u64 {
                return Err(Error::BadArchive(format!(
                    "solid range outside blob for '{}'",
                    entry.path
                )));
            }
            let mut bytes =
                solid[entry.solid_off as usize..end as usize].to_vec();
            pack::denormalize_file(&mut bytes, &entry.code_ranges)?;
            ensure_parent()?;
            pack::safe_write_file(&full, &bytes)?;
            println!("[+] Extracted: {} ({} bytes)", full.display(), bytes.len());
        }
        EntryKind::Link => {
            let link_target = entry.link_target.as_deref().unwrap_or("");
            ensure_parent()?;
            place_link(&full, link_target, &entry.path)?;
            println!("[+] Extracted link: {} -> {link_target}", full.display());
        }
        EntryKind::Zip => {
            ensure_parent()?;
            let solid = solid_for_zip.as_deref().expect("decoded above");
            pack::rebuild_zip(&full, entry, solid)?;
            println!(
                "[+] Extracted zip: {} ({} inner entries)",
                full.display(),
                entry.zip_inners.len()
            );
        }
    }

    let is_link = entry.kind == EntryKind::Link;
    let mut shown_warnings = 0;
    for w in meta::apply_filtered(&full, &entry.meta, is_link, &opts.filter) {
        // Directories created implicitly for structure mode carry no
        // metadata of their own; only the entry itself is restored.
        eprintln!("[!] Warning: {w}");
        shown_warnings += 1;
    }
    if entry.kind == EntryKind::Dir {
        println!("[+] Extracted dir: {}", full.display());
    }
    if shown_warnings > 0 {
        println!("({shown_warnings} metadata warnings)");
    }
    Ok(())
}
