//! Shared error type for the utility.
//!
//! I/O and codec errors propagate to the caller; `main` exits with code 1.

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
    /// Metadata error (mode/owner/context parsing or application).
    Meta(String),
    /// Manifest error (syntax, missing files, unsafe paths).
    /// Pack-side only; decompress-only builds never parse manifests.
    #[cfg(feature = "compress")]
    Manifest(String),
    /// Command-line usage error.
    Usage(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Lzma(e) => write!(f, "LZMA2 error: {e}"),
            Error::BadArchive(e) => write!(f, "bad archive: {e}"),
            Error::TooLarge(e) => write!(f, "limit exceeded: {e}"),
            Error::Meta(e) => write!(f, "metadata error: {e}"),
            #[cfg(feature = "compress")]
            Error::Manifest(e) => write!(f, "manifest error: {e}"),
            Error::Usage(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}
