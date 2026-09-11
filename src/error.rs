//! Shared error type for the utility.
//!
//! Port of the C version, where errors were printed via `perror`/`fprintf`
//! and the function returned `void`. In the Rust version errors propagate
//! to the caller, and `main` exits with code 1 (intentional deviation
//! from C, where the exit code was always 0).

use std::fmt;
use std::io;

/// Compressor/decompressor error.
#[derive(Debug)]
pub enum Error {
    /// I/O error (opening/reading/writing files).
    Io(io::Error),
    /// LZMA2 codec error.
    Lzma(String),
    /// Invalid archive format.
    BadArchive(String),
    /// Limit exceeded (file size, dictionary, chunk).
    TooLarge(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Lzma(e) => write!(f, "ошибка LZMA2: {e}"),
            Error::BadArchive(e) => write!(f, "неверный архив: {e}"),
            Error::TooLarge(e) => write!(f, "превышен лимит: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}
