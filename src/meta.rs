//! File metadata: permission bits, owner (uid/gid), SELinux context.
//!
//! Each field is optional: an entry stores only what was explicitly given
//! (manifest line, `--chmod/--owner/--context` flags) or preserved from the
//! filesystem (`--preserve-*`). Supported input formats:
//! - mode: octal digits (`755`, `0755`, `4755`) or symbolic (`rwxr-xr-x`,
//!   with an optional leading file-type character as in `ls -l`);
//! - owner: `user`, `user:group`, `uid`, `uid:gid`, `user:gid`, `uid:group`;
//!   names are resolved to ids at pack time via `getpwnam`/`getgrnam`;
//! - context: an arbitrary SELinux string (`u:object_r:system_file:s0`).
//!
//! Applying metadata is best-effort: `chown`/`setxattr` failures (e.g. when
//! not running as root, or on filesystems without SELinux) produce warnings,
//! not errors.

use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use crate::error::Error;

/// Optional per-entry metadata. `None` means "not stored".
#[derive(Debug, Clone, Default)]
pub struct FileMeta {
    /// Permission bits (`st_mode & 0o7777`).
    pub mode: Option<u32>,
    /// Owner user id.
    pub uid: Option<u32>,
    /// Owner group id.
    pub gid: Option<u32>,
    /// SELinux context string.
    pub context: Option<String>,
}

impl FileMeta {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.mode.is_none()
            && self.uid.is_none()
            && self.gid.is_none()
            && self.context.is_none()
    }

    /// Override every `Some` field of `forced` over `self`.
    pub fn apply_forced(&mut self, forced: &FileMeta) {
        if forced.mode.is_some() {
            self.mode = forced.mode;
        }
        if forced.uid.is_some() {
            self.uid = forced.uid;
        }
        if forced.gid.is_some() {
            self.gid = forced.gid;
        }
        if forced.context.is_some() {
            self.context.clone_from(&forced.context);
        }
    }
}

/// Which fields to read from the filesystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct Preserve {
    pub perms: bool,
    pub owner: bool,
    pub context: bool,
}

impl Preserve {
    pub fn any(self) -> bool {
        self.perms || self.owner || self.context
    }
}

/// Parse permission bits: `755`, `0755`, `4755` or `rwxr-xr-x`.
pub fn parse_mode(s: &str) -> Result<u32, Error> {
    if !s.is_empty() && s.chars().all(|c| ('0'..='7').contains(&c)) && (3..=4).contains(&s.len())
    {
        let mode = u32::from_str_radix(s, 8)
            .map_err(|_| Error::Meta(format!("bad octal mode: {s}")))?;
        if mode > 0o7777 {
            return Err(Error::Meta(format!("mode out of range: {s}")));
        }
        return Ok(mode);
    }
    let chars: Vec<char> = s.chars().collect();
    let bits = match chars.len() {
        9 => &chars[..],
        10 => &chars[1..],
        _ => return Err(Error::Meta(format!("bad symbolic mode: {s}"))),
    };
    let mut mode: u32 = 0;
    for (i, &c) in bits.iter().enumerate() {
        let bit = 1 << (8 - i);
        match (i % 3, c) {
            (0, 'r') => mode |= bit,
            (1, 'w') => mode |= bit,
            (2, 'x') => mode |= bit,
            (_, '-') => {}
            _ => return Err(Error::Meta(format!("bad symbolic mode: {s}"))),
        }
    }
    Ok(mode)
}

/// Format permission bits as octal digits (`755`, `4755`).
#[allow(dead_code)]
pub fn format_mode(mode: u32) -> String {
    format!("{:o}", mode & 0o7777)
}

/// Format permission bits symbolically (`rwxr-xr-x`, 9 chars).
pub fn format_mode_symbolic(mode: u32) -> String {
    let mode = mode & 0o777;
    let mut s = String::with_capacity(9);
    for shift in [6, 3, 0] {
        let bits = (mode >> shift) & 0o7;
        s.push(if bits & 0o4 != 0 { 'r' } else { '-' });
        s.push(if bits & 0o2 != 0 { 'w' } else { '-' });
        s.push(if bits & 0o1 != 0 { 'x' } else { '-' });
    }
    s
}

fn resolve_user(name: &str) -> Result<u32, Error> {
    let cname =
        CString::new(name).map_err(|_| Error::Meta(format!("bad user name: {name}")))?;
    // SAFETY: getpwnam takes a valid NUL-terminated string; result is only
    // read (pw_uid) when non-NULL.
    unsafe {
        let pw = libc::getpwnam(cname.as_ptr());
        if pw.is_null() {
            return Err(Error::Meta(format!(
                "unknown user '{name}' (use a numeric uid)"
            )));
        }
        Ok((*pw).pw_uid)
    }
}

fn resolve_group(name: &str) -> Result<u32, Error> {
    let cname =
        CString::new(name).map_err(|_| Error::Meta(format!("bad group name: {name}")))?;
    // SAFETY: same contract as getpwnam above.
    unsafe {
        let gr = libc::getgrnam(cname.as_ptr());
        if gr.is_null() {
            return Err(Error::Meta(format!(
                "unknown group '{name}' (use a numeric gid)"
            )));
        }
        Ok((*gr).gr_gid)
    }
}

fn parse_id_or_name(s: &str, resolve: fn(&str) -> Result<u32, Error>) -> Result<u32, Error> {
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
        s.parse::<u32>()
            .map_err(|_| Error::Meta(format!("bad numeric id: {s}")))
    } else {
        resolve(s)
    }
}

/// Parse owner: `user`, `uid`, `user:group`, `uid:gid` (mixed forms allowed).
///
/// Returns `(uid, gid)` where each side is `None` when omitted.
pub fn parse_owner(s: &str) -> Result<(Option<u32>, Option<u32>), Error> {
    if s.is_empty() || s == "-" {
        return Err(Error::Meta("empty owner spec".to_string()));
    }
    let (user_part, group_part) = match s.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (s, None),
    };
    let uid = if user_part.is_empty() {
        None
    } else {
        Some(parse_id_or_name(user_part, resolve_user)?)
    };
    let gid = match group_part {
        None | Some("") => None,
        Some(g) => Some(parse_id_or_name(g, resolve_group)?),
    };
    if uid.is_none() && gid.is_none() {
        return Err(Error::Meta(format!("empty owner spec: {s}")));
    }
    Ok((uid, gid))
}

/// Format owner as numeric `uid:gid`.
#[allow(dead_code)]
pub fn format_owner(uid: u32, gid: u32) -> String {
    format!("{uid}:{gid}")
}

/// Parse SELinux context: any non-empty string without NUL bytes.
pub fn parse_context(s: &str) -> Result<String, Error> {
    if s.is_empty() || s.bytes().any(|b| b == 0) {
        return Err(Error::Meta(format!("bad SELinux context: {s}")));
    }
    Ok(s.to_string())
}

fn c_path(path: &Path) -> Result<CString, Error> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| Error::Meta(format!("path contains NUL: {}", path.display())))
}

/// Read the `security.selinux` xattr without following symlinks.
///
/// Returns `Ok(None)` when the filesystem entry has no context stored.
fn read_context(path: &Path) -> Result<Option<String>, Error> {
    let cpath = c_path(path)?;
    let attr = CString::new("security.selinux").unwrap();
    // SAFETY: valid pointers; NULL buffer with size 0 queries the length.
    let size = unsafe { libc::lgetxattr(cpath.as_ptr(), attr.as_ptr(), std::ptr::null_mut(), 0) };
    if size < 0 {
        let errno = unsafe { *libc::__errno_location() };
        if errno == libc::ENODATA || errno == libc::ENOTSUP {
            return Ok(None);
        }
        return Err(Error::Meta(format!(
            "lgetxattr failed for {}: errno {errno}",
            path.display()
        )));
    }
    // Include space for the trailing NUL the kernel reports in the size.
    let mut buf = vec![0u8; (size as usize) + 1];
    // SAFETY: buffer is large enough for `size` bytes.
    let got = unsafe {
        libc::lgetxattr(
            cpath.as_ptr(),
            attr.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            size as usize,
        )
    };
    if got < 0 {
        return Err(Error::Meta(format!(
            "lgetxattr read failed for {}",
            path.display()
        )));
    }
    let mut raw = buf[..got as usize].to_vec();
    if raw.last() == Some(&0) {
        raw.pop();
    }
    String::from_utf8(raw)
        .map(Some)
        .map_err(|_| Error::Meta(format!("non-UTF8 context on {}", path.display())))
}

/// Fill the missing fields of `meta` from the filesystem (no symlink
/// following: a symlink contributes its own `lstat` data).
pub fn fill_preserve(meta: &mut FileMeta, path: &Path, preserve: Preserve) -> Result<(), Error> {
    if !preserve.any() {
        return Ok(());
    }
    let st = fs::symlink_metadata(path)?;
    if preserve.perms && meta.mode.is_none() {
        meta.mode = Some(st.mode() & 0o7777);
    }
    if preserve.owner {
        if meta.uid.is_none() {
            meta.uid = Some(st.uid());
        }
        if meta.gid.is_none() {
            meta.gid = Some(st.gid());
        }
    }
    if preserve.context && meta.context.is_none() {
        meta.context = read_context(path)?;
    }
    Ok(())
}

/// Which stored metadata categories to apply on unpack/extract.
///
/// Default (no flags) is everything stored. `--no-*` subtracts, while any
/// `--preserve-*` switches to whitelist mode (only the listed categories).
#[derive(Debug, Clone, Copy)]
pub struct MetaFilter {
    /// Apply permission bits (chmod).
    pub perms: bool,
    /// Apply uid/gid (chown/lchown).
    pub owner: bool,
    /// Apply SELinux context (lsetxattr).
    pub context: bool,
}

impl MetaFilter {
    /// Restore everything stored (default behavior).
    pub fn all() -> Self {
        MetaFilter {
            perms: true,
            owner: true,
            context: true,
        }
    }

    /// Restore nothing (files get umask defaults and the current user).
    pub fn none() -> Self {
        MetaFilter {
            perms: false,
            owner: false,
            context: false,
        }
    }

    /// Resolve CLI selection: optional whitelist (`--preserve-*`, where
    /// `--preserve-all` enables all three) minus blacklist (`--no-*`).
    /// `white_all` = `--preserve-all` was given.
    pub fn resolve(
        white_perms: bool,
        white_owner: bool,
        white_context: bool,
        white_all: bool,
        no_perms: bool,
        no_owner: bool,
        no_context: bool,
        no_all: bool,
    ) -> Self {
        if no_all {
            return MetaFilter::none();
        }
        let mut f = if white_perms || white_owner || white_context || white_all {
            MetaFilter {
                perms: white_perms || white_all,
                owner: white_owner || white_all,
                context: white_context || white_all,
            }
        } else {
            MetaFilter::all()
        };
        if no_perms {
            f.perms = false;
        }
        if no_owner {
            f.owner = false;
        }
        if no_context {
            f.context = false;
        }
        f
    }
}

/// Apply stored metadata, restricted to the categories in `filter`.
///
/// `chmod` is skipped for symlinks (Linux symlinks are always 0777).
/// Failures are collected as warnings; the caller prints them.
pub fn apply_filtered(
    path: &Path,
    meta: &FileMeta,
    is_symlink: bool,
    filter: &MetaFilter,
) -> Vec<String> {
    let mut warnings = Vec::new();
    let what = path.display().to_string();

    if filter.perms {
        if let Some(mode) = meta.mode {
            if !is_symlink {
                if let Err(e) = fs::set_permissions(path, fs::Permissions::from_mode(mode)) {
                    warnings.push(format!("chmod {what}: {e}"));
                }
            }
        }
    }

    if filter.owner && (meta.uid.is_some() || meta.gid.is_some()) {
        let cpath = match c_path(path) {
            Ok(p) => p,
            Err(e) => {
                warnings.push(format!("chown {what}: {e}"));
                return warnings;
            }
        };
        // Unspecified side keeps its current value.
        let (cur_uid, cur_gid) = fs::symlink_metadata(path)
            .map(|st| (st.uid(), st.gid()))
            .unwrap_or((u32::MAX, u32::MAX));
        let uid = meta.uid.unwrap_or(cur_uid);
        let gid = meta.gid.unwrap_or(cur_gid);
        // SAFETY: valid path pointer, plain integer ids.
        let rc = unsafe {
            if is_symlink {
                libc::lchown(cpath.as_ptr(), uid, gid)
            } else {
                libc::chown(cpath.as_ptr(), uid, gid)
            }
        };
        if rc != 0 {
            let errno = unsafe { *libc::__errno_location() };
            warnings.push(format!("chown {what} to {uid}:{gid}: errno {errno}"));
        }
    }

    if filter.context {
        if let Some(ctx) = &meta.context {
            match (c_path(path), CString::new(ctx.as_str())) {
                (Ok(cpath), Ok(cctx)) => {
                    let attr = CString::new("security.selinux").unwrap();
                    // SAFETY: pointers and length describe the context bytes.
                    let rc = unsafe {
                        libc::lsetxattr(
                            cpath.as_ptr(),
                            attr.as_ptr(),
                            cctx.as_ptr() as *const libc::c_void,
                            ctx.len(),
                            0,
                        )
                    };
                    if rc != 0 {
                        let errno = unsafe { *libc::__errno_location() };
                        warnings.push(format!("setxattr {what}: errno {errno}"));
                    }
                }
                _ => warnings.push(format!("setxattr {what}: bad path or context")),
            }
        }
    }

    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_formats_roundtrip() {
        assert_eq!(parse_mode("755").unwrap(), 0o755);
        assert_eq!(parse_mode("0755").unwrap(), 0o755);
        assert_eq!(parse_mode("4755").unwrap(), 0o4755);
        assert_eq!(parse_mode("rwxr-xr-x").unwrap(), 0o755);
        assert_eq!(parse_mode("-rwxr-xr-x").unwrap(), 0o755);
        assert_eq!(parse_mode("rw-r--r--").unwrap(), 0o644);
        assert_eq!(format_mode(0o755), "755");
        assert_eq!(format_mode(0o4755), "4755");
        assert!(parse_mode("888").is_err());
        assert!(parse_mode("rwxr-x").is_err());
        assert!(parse_mode("rwxrwxrwx ".trim_end()).is_ok());
    }

    #[test]
    fn owner_forms() {
        assert_eq!(parse_owner("0:2000").unwrap(), (Some(0), Some(2000)));
        assert_eq!(parse_owner("root").unwrap(), (Some(0), None));
        assert_eq!(parse_owner("0").unwrap(), (Some(0), None));
        assert_eq!(parse_owner("root:root").unwrap(), (Some(0), Some(0)));
        assert!(parse_owner("nosuchuser12345").is_err());
    }
}
