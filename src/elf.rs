//! ELF64 parsing for locating code sections.
//!
//! Direct port of `parse_elf_sections` from lgzv3.c:
//! magic and `e_machine` are checked (AARCH64 -> ARM64, X86_64/386 -> x86),
//! 64-bit class required; only `PROGBITS` sections (sh_type == 1) are
//! collected and sorted by offset. Deviation from C: all reads are
//! bounds-checked (C trusted the header and could read past the buffer).

/// ELF file architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    /// AARCH64 (`EM_AARCH64 = 183`).
    Arm64,
    /// x86 / x86_64 (`EM_386 = 3`, `EM_X86_64 = 62`).
    X86,
}

/// ELF section: file offset, size, executable flag.
#[derive(Debug, Clone, Copy)]
pub struct Section {
    pub offset: u64,
    pub size: u64,
    pub is_code: bool,
}

/// Parse result: sections + architecture + object type.
#[derive(Debug)]
pub struct ElfInfo {
    pub sections: Vec<Section>,
    pub arch: Arch,
    /// Raw `e_type`: 2 = executable, 3 = shared object, 1 = relocatable.
    /// Pack-side only (solid clustering); absent in decompress-only builds.
    #[cfg(feature = "compress")]
    pub e_type: u16,
}

const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;
const SHF_EXECINSTR: u64 = 0x4;
const SHT_PROGBITS: u32 = 1;
const EHDR_SIZE: usize = 64;
const SHDR_SIZE: usize = 64;

fn u16le(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

fn u32le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn u64le(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
        b[off + 4],
        b[off + 5],
        b[off + 6],
        b[off + 7],
    ])
}

/// Parse the ELF header and section table.
///
/// Returns `None` if the data is not a supported ELF64 (not ELF, unknown
/// architecture, 32-bit, no section table). An empty section list
/// (no `PROGBITS`) is a valid result with 0 sections.
pub fn parse(data: &[u8]) -> Option<ElfInfo> {
    if data.len() < EHDR_SIZE {
        return None;
    }
    if data[0..4] != [0x7f, b'E', b'L', b'F'] {
        return None;
    }
    // NOTE: 32-bit x86 (EM_386) is intentionally unsupported: those files
    // are ELFCLASS32 and are rejected by the class check below, exactly
    // like the C version did.
    let arch = match u16le(data, 18) {
        EM_AARCH64 => Arch::Arm64,
        EM_X86_64 => Arch::X86,
        _ => return None,
    };
    // e_ident[EI_CLASS] == 2 (ELFCLASS64), as in C: `ehdr->e_ident[4] != 2`.
    if data[4] != 2 {
        return None;
    }

    let shoff = u64le(data, 40);
    let shentsize = u16le(data, 58) as u64;
    let shnum = u16le(data, 60) as u64;

    let mut sections = Vec::new();
    let table_end = shoff.checked_add(shnum.checked_mul(shentsize)?)?;
    if shoff == 0 || shnum == 0 {
        return None;
    }
    if table_end > data.len() as u64 {
        return None;
    }

    for i in 0..shnum {
        let base = shoff + i * shentsize;
        // Guard against out-of-bounds reads when shentsize < 64 (C had none).
        if base + SHDR_SIZE as u64 > data.len() as u64 {
            continue;
        }
        let b = &data[base as usize..base as usize + SHDR_SIZE];
        let sh_type = u32le(b, 4);
        if sh_type != SHT_PROGBITS {
            continue;
        }
        let sh_size = u64le(b, 32);
        if sh_size == 0 {
            continue;
        }
        let sh_offset = u64le(b, 24);
        if sh_offset.checked_add(sh_size)? > data.len() as u64 {
            continue;
        }
        let sh_flags = u64le(b, 8);
        sections.push(Section {
            offset: sh_offset,
            size: sh_size,
            is_code: sh_flags & SHF_EXECINSTR != 0,
        });
    }

    // NOTE: no PT_LOAD fallback here for section-less (stripped) binaries.
    // Section-dependent normalization baked into an archive can only be
    // inverted by re-parsing the same sections on unpack; an older
    // decoder faced with such an archive finds no sections, skips
    // denormalization and silently outputs garbage. With the packer and
    // the ramdisk lean decoder routinely version-skewed, that failure
    // mode is unacceptable — stripped files stay opaque (still delta).
    // An empty section list remains a valid result (known layout, no
    // code sections), exactly as before. (UCOMP02 has its own
    // `parse_for_pack` below: its unpacker uses stored code_ranges, so
    // the fallback is safe there and ONLY there.)
    sections.sort_by_key(|s| s.offset);
    Some(ElfInfo {
        sections,
        arch,
        #[cfg(feature = "compress")]
        e_type: u16le(data, 16),
    })
}

/// Parse ELF for UCOMP02 solid packing: falls back to PT_LOAD executable
/// segments when the section table is stripped (shoff/shnum == 0).
///
/// Safe for old (lean) decoders BECAUSE UCOMP02 stores the discovered
/// `[off, size, arch]` triples explicitly as `code_ranges` in the
/// container header and never re-parses ELF on unpack — unlike UCOMP01
/// blobs (preproc 3/4/6), where the unpacker re-discovers sections and
/// a stripped input would silently skip denormalization. Never use this
/// for the single-file `compress`/`pack_single` path.
#[cfg(feature = "compress")]
pub fn parse_for_pack(data: &[u8]) -> Option<ElfInfo> {
    // An empty section list from a usable table used to short-circuit
    // here; now only a non-empty result does. A table stripped of all
    // SHT_PROGBITS (only SHT_NULL/.dynsym left) must still fall through
    // to PT_LOAD below.
    if let Some(info) = parse(data).filter(|i| !i.sections.is_empty()) {
        return Some(info);
    }
    if data.len() < EHDR_SIZE
        || data[0..4] != [0x7f, b'E', b'L', b'F']
        || data[4] != 2
    {
        return None;
    }
    let arch = match u16le(data, 18) {
        EM_AARCH64 => Arch::Arm64,
        EM_X86_64 => Arch::X86,
        _ => return None,
    };
    const PHDR_SIZE: u64 = 56;
    const PT_LOAD: u32 = 1;
    const PF_X: u32 = 0x1;
    let phoff = u64le(data, 32);
    let phentsize = u16le(data, 54) as u64;
    let phnum = u16le(data, 56) as u64;
    let ph_end = phoff.checked_add(phnum.checked_mul(phentsize)?)?;
    if phoff == 0 || phnum == 0 || phentsize < PHDR_SIZE || ph_end > data.len() as u64 {
        return None;
    }
    let mut sections = Vec::new();
    for i in 0..phnum {
        let base = (phoff + i * phentsize) as usize;
        let b = &data[base..base + PHDR_SIZE as usize];
        if u32le(b, 0) != PT_LOAD {
            continue;
        }
        let p_flags = u32le(b, 4);
        let p_offset = u64le(b, 8);
        let p_filesz = u64le(b, 32);
        if p_filesz == 0 || p_offset.checked_add(p_filesz)? > data.len() as u64 {
            continue;
        }
        sections.push(Section {
            offset: p_offset,
            size: p_filesz,
            is_code: p_flags & PF_X != 0,
        });
    }
    if sections.is_empty() {
        return None;
    }
    sections.sort_by_key(|s| s.offset);
    Some(ElfInfo {
        sections,
        arch,
        e_type: u16le(data, 16),
    })
}
