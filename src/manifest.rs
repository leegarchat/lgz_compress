//! Batch decompression from a manifest file.
//!
//! Direct port of `decompress_all` from lgzv3.c. The manifest is a text
//! file with lines `<octal perms> <path>`; `#` comments and blank lines
//! are skipped. Each archive is decompressed to `<path>.lgz_tmp`, then
//! renamed over the original and `chmod`-ed to the listed permissions.

use std::fs;
use std::os::unix::fs::PermissionsExt;

use crate::decompress::decompress_file;
use crate::error::Error;

/// Decompress every archive listed in the manifest file.
pub fn decompress_all(manifest_path: &str) -> Result<(), Error> {
    let text = fs::read_to_string(manifest_path)?;
    let mut ok_count = 0;
    let mut fail_count = 0;

    for line in text.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((perms_str, path)) = line.split_once(' ') else {
            eprintln!("[LGZ] Неверный формат строки: {line}");
            continue;
        };
        let perms = u32::from_str_radix(perms_str, 8).unwrap_or(0o644);
        if fs::metadata(path).is_err() {
            eprintln!("[LGZ] Файл не найден: {path}");
            fail_count += 1;
            continue;
        }

        let tmp_path = format!("{path}.lgz_tmp");
        println!("[LGZ] Распаковка: {path}");
        if decompress_file(path, &tmp_path).is_err() {
            eprintln!("[LGZ] Ошибка при распаковке: {path}");
            let _ = fs::remove_file(&tmp_path);
            fail_count += 1;
            continue;
        }
        if fs::rename(&tmp_path, path).is_err() {
            eprintln!("[LGZ] Ошибка при замене оригинального файла: {path}");
            let _ = fs::remove_file(&tmp_path);
            fail_count += 1;
            continue;
        }
        if fs::set_permissions(path, fs::Permissions::from_mode(perms)).is_err() {
            eprintln!("[LGZ] Ошибка chmod: {path}");
            fail_count += 1;
            continue;
        }
        ok_count += 1;
    }

    println!("[LGZ] Завершено: {ok_count} успешно, {fail_count} с ошибками");
    Ok(())
}
