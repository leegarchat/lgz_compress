//! Build manifest parsing.
//!
//! The manifest is a plain text file listing the tree to pack. Line format:
//! ```text
//! file <path> [chmod] [owner] [context]
//! dir  <path> [chmod] [owner] [context]
//! link <path> -> <target> [chmod] [owner] [context]
//! zip  <path> [chmod] [owner] [context]
//! ```
//! - `#` comments and blank lines are ignored;
//! - `<path>` is relative to the current directory at pack time;
//! - metadata fields are positional (`-` skips one);
//! - `chmod` accepts octal (`755`, `0755`) or symbolic (`rwxr-xr-x`);
//! - `owner` accepts `user`, `uid`, `user:group`, `uid:gid` and mixes;
//! - `context` is a SELinux string (`u:object_r:system_file:s0`);
//! - `zip` ingests the archive transparently: inner files join the solid
//!   blob and the archive is rebuilt on unpack (a plain `file` line whose
//!   target looks like a zip is ingested the same way).

# [cfg(feature = "compress")]
use std::collections::HashSet;

# [cfg(feature = "compress")]
use crate::error::Error;
# [cfg(feature = "compress")]
use crate::meta::{self, FileMeta};

/// Entry type requested by the manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Dir,
    Link,
    /// Transparent zip ingestion (also auto-detected for `file` lines
    /// pointing at zip data).
    Zip,
}

/// One parsed manifest line.
#[derive(Debug, Clone)]
# [cfg(feature = "compress")]
pub struct ManifestEntry {
    pub kind: EntryKind,
    pub path: String,
    /// Symlink target (only for `Link`).
    pub target: Option<String>,
    /// Metadata parsed from the line (partial is fine).
    pub meta: FileMeta,
    /// 1-based line number, for error messages.
    pub line_no: usize,
}

# [cfg(feature = "compress")]
fn parse_meta_slots(
    slots: &[&str],
    line_no: usize,
    raw: &str,
) -> Result<FileMeta, Error> {
    if slots.len() > 3 {
        return Err(Error::Manifest(format!(
            "line {line_no}: too many fields: {raw}"
        )));
    }
    let mut meta = FileMeta::empty();
    let get = |i: usize| slots.get(i).copied().unwrap_or("-");
    let chmod_s = get(0);
    let owner_s = get(1);
    let context_s = get(2);

    if chmod_s != "-" {
        meta.mode = Some(meta::parse_mode(chmod_s).map_err(|e| {
            Error::Manifest(format!("line {line_no}: {e}"))
        })?);
    }
    if owner_s != "-" {
        let (uid, gid) = meta::parse_owner(owner_s)
            .map_err(|e| Error::Manifest(format!("line {line_no}: {e}")))?;
        meta.uid = uid;
        meta.gid = gid;
    }
    if context_s != "-" {
        meta.context = Some(
            meta::parse_context(context_s)
                .map_err(|e| Error::Manifest(format!("line {line_no}: {e}")))?,
        );
    }
    Ok(meta)
}

/// Parse manifest text into entry specs.
# [cfg(feature = "compress")]
pub fn parse_manifest(text: &str) -> Result<Vec<ManifestEntry>, Error> {
    let mut entries = Vec::new();
    let mut seen = HashSet::new();

    for (idx, line) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = line.strip_suffix('\r').unwrap_or(line);
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 2 {
            return Err(Error::Manifest(format!("line {line_no}: bad entry: {line}")));
        }
        let kind = match tokens[0] {
            "file" => EntryKind::File,
            "dir" => EntryKind::Dir,
            "link" => EntryKind::Link,
            "zip" => EntryKind::Zip,
            other => {
                return Err(Error::Manifest(format!(
                    "line {line_no}: bad type '{other}' (want file/dir/link/zip)"
                )));
            }
        };
        let path = tokens[1].to_string();
        if path.is_empty() {
            return Err(Error::Manifest(format!("line {line_no}: empty path")));
        }

        let (target, slots) = if kind == EntryKind::Link {
            if tokens.get(2) != Some(&"->") || tokens.len() < 4 {
                return Err(Error::Manifest(format!(
                    "line {line_no}: link needs 'link <path> -> <target>'"
                )));
            }
            (Some(tokens[3].to_string()), &tokens[4..])
        } else {
            if tokens.get(2) == Some(&"->") {
                return Err(Error::Manifest(format!(
                    "line {line_no}: '->' is only valid for link entries"
                )));
            }
            (None, &tokens[2..])
        };

        if !seen.insert(path.clone()) {
            return Err(Error::Manifest(format!(
                "line {line_no}: duplicate path '{path}'"
            )));
        }

        let meta = parse_meta_slots(slots, line_no, line)?;
        entries.push(ManifestEntry {
            kind,
            path,
            target,
            meta,
            line_no,
        });
    }

    if entries.is_empty() {
        return Err(Error::Manifest("manifest lists no entries".to_string()));
    }
    Ok(entries)
}
