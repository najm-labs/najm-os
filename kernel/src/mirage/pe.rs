//! PE32+ parsing.
//!
//! Enough of the format to load an executable: the headers, the section
//! table, the import directory, and the base relocation table. Not a
//! general PE reader - no exports, no resources, no debug directory, no
//! delay imports, no TLS callbacks.
//!
//! ## Everything here is hostile input
//!
//! A PE image is a file, and the whole point of Mirage is to run files
//! that came from somewhere else. Every field read below is attacker
//! controlled, and the format is unusually generous with opportunities:
//! it is a graph of file offsets and relative virtual addresses that
//! point at each other, with lengths that are separate from the things
//! they describe.
//!
//! Two rules are applied consistently, and they are what most of the code
//! here is:
//!
//! 1. **Every offset is bounds-checked against the real slice**, never
//!    against the image's own claims about its size. An image that says
//!    it is 4 GiB does not become 4 GiB.
//! 2. **Every count is bounded before it is iterated.** An import
//!    directory that claims 4 billion entries must be rejected, not
//!    looped over until something else fails.
//!
//! The failure mode these guard against is not subtle. A PE loader that
//! trusts an RVA reads or writes at an attacker-chosen offset from the
//! image base, in the kernel, before the program has run a single
//! instruction.

use super::MirageError;
use alloc::string::String;
use alloc::vec::Vec;

const DOS_MAGIC: u16 = 0x5A4D; // "MZ"
const PE_MAGIC: u32 = 0x0000_4550; // "PE\0\0"
const MACHINE_AMD64: u16 = 0x8664;
const PE32_PLUS_MAGIC: u16 = 0x20B;

/// Section characteristic bits.
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// Data directory indices.
const DIRECTORY_IMPORT: usize = 1;
const DIRECTORY_BASERELOC: usize = 5;

/// Base relocation types. Only `DIR64` is meaningful for a 64-bit image;
/// `ABSOLUTE` is a padding entry that must be skipped rather than
/// applied.
const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
const IMAGE_REL_BASED_DIR64: u16 = 10;

/// A caps on how much the loader will iterate, so that a malformed count
/// is refused rather than turned into a very long loop.
const MAX_SECTIONS: usize = 96;
const MAX_IMPORTS: usize = 512;
const MAX_RELOCATIONS: usize = 65_536;

pub struct Section {
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_offset: usize,
    pub raw_size: usize,
    pub executable: bool,
    pub writable: bool,
    #[allow(dead_code)]
    pub readable: bool,
}

pub struct Import {
    /// The imported function's name, as it appears in the image.
    pub name: String,
    /// Where in the image the Import Address Table slot for it lives.
    /// This is the address the loader overwrites with a thunk.
    pub iat_rva: u32,
}

pub struct Image {
    pub entry_rva: u32,
    pub preferred_base: u64,
    pub image_size: usize,
    pub headers_size: usize,
    pub sections: Vec<Section>,
    pub imports: Vec<Import>,
    /// RVAs of 64-bit absolute addresses needing adjustment.
    pub relocations: Vec<u32>,
}

fn u16_at(bytes: &[u8], at: usize) -> Result<u16, MirageError> {
    bytes
        .get(at..at + 2)
        .map(|slice| u16::from_le_bytes(slice.try_into().unwrap()))
        .ok_or(MirageError::Malformed("read past the end of the image"))
}

fn u32_at(bytes: &[u8], at: usize) -> Result<u32, MirageError> {
    bytes
        .get(at..at + 4)
        .map(|slice| u32::from_le_bytes(slice.try_into().unwrap()))
        .ok_or(MirageError::Malformed("read past the end of the image"))
}

fn u64_at(bytes: &[u8], at: usize) -> Result<u64, MirageError> {
    bytes
        .get(at..at + 8)
        .map(|slice| u64::from_le_bytes(slice.try_into().unwrap()))
        .ok_or(MirageError::Malformed("read past the end of the image"))
}

/// Parses and validates a PE32+ image.
pub fn parse(bytes: &[u8]) -> Result<Image, MirageError> {
    if bytes.len() < 64 {
        return Err(MirageError::NotPe("smaller than a DOS header"));
    }
    if u16_at(bytes, 0)? != DOS_MAGIC {
        return Err(MirageError::NotPe("no MZ signature"));
    }

    // `e_lfanew` at offset 0x3C points at the PE header. It is a raw file
    // offset chosen by the file, so it is bounds-checked before use - the
    // classic first mistake in a PE parser is trusting it.
    let pe_offset = u32_at(bytes, 0x3C)? as usize;
    if pe_offset + 24 > bytes.len() {
        return Err(MirageError::NotPe("PE header offset is outside the file"));
    }
    if u32_at(bytes, pe_offset)? != PE_MAGIC {
        return Err(MirageError::NotPe("no PE signature at e_lfanew"));
    }

    let machine = u16_at(bytes, pe_offset + 4)?;
    if machine != MACHINE_AMD64 {
        return Err(MirageError::NotPe(
            "not an x86_64 image - Mirage runs Windows binaries natively rather than emulating \
             them, so the instruction set has to match the CPU",
        ));
    }

    let section_count = u16_at(bytes, pe_offset + 6)? as usize;
    let optional_header_size = u16_at(bytes, pe_offset + 20)? as usize;
    let optional_header = pe_offset + 24;

    if section_count > MAX_SECTIONS {
        return Err(MirageError::Malformed("implausible section count"));
    }
    if optional_header + optional_header_size > bytes.len() {
        return Err(MirageError::NotPe("optional header extends past the file"));
    }
    if u16_at(bytes, optional_header)? != PE32_PLUS_MAGIC {
        return Err(MirageError::NotPe(
            "not PE32+ - a 32-bit PE would need a different address space layout and a 32-bit \
             thunk ABI, neither of which exists here",
        ));
    }

    let entry_rva = u32_at(bytes, optional_header + 16)?;
    let preferred_base = u64_at(bytes, optional_header + 24)?;
    let image_size = u32_at(bytes, optional_header + 56)? as usize;
    let headers_size = u32_at(bytes, optional_header + 60)? as usize;
    let directory_count = u32_at(bytes, optional_header + 108)? as usize;

    // The image size decides how much address space is mapped, so an
    // absurd value is an out-of-memory request dressed as a header field.
    if image_size == 0 || image_size > 512 * 1024 * 1024 {
        return Err(MirageError::Malformed(
            "SizeOfImage is zero or implausibly large",
        ));
    }
    if headers_size > bytes.len() {
        return Err(MirageError::Malformed(
            "SizeOfHeaders extends past the end of the file",
        ));
    }

    let directories = optional_header + 112;
    let read_directory = |index: usize| -> Result<(u32, u32), MirageError> {
        if index >= directory_count {
            return Ok((0, 0));
        }
        let at = directories + index * 8;
        Ok((u32_at(bytes, at)?, u32_at(bytes, at + 4)?))
    };

    let section_table = optional_header + optional_header_size;
    let mut sections = Vec::new();
    for index in 0..section_count {
        let at = section_table + index * 40;
        if at + 40 > bytes.len() {
            return Err(MirageError::Malformed(
                "the section table extends past the end of the file",
            ));
        }

        let virtual_size = u32_at(bytes, at + 8)?;
        let virtual_address = u32_at(bytes, at + 12)?;
        let raw_size = u32_at(bytes, at + 16)? as usize;
        let raw_offset = u32_at(bytes, at + 20)? as usize;
        let characteristics = u32_at(bytes, at + 36)?;

        // The section's file range must be inside the file, and its
        // memory range inside the image. Both, separately - they are
        // independent fields and a malformed image routinely has one
        // valid and the other not.
        if raw_size > 0 {
            let end = raw_offset
                .checked_add(raw_size)
                .ok_or(MirageError::Malformed("section file range overflows"))?;
            if end > bytes.len() {
                return Err(MirageError::Malformed(
                    "a section's data extends past the end of the file",
                ));
            }
        }
        let memory_end = (virtual_address as usize)
            .checked_add(virtual_size.max(1) as usize)
            .ok_or(MirageError::Malformed("section memory range overflows"))?;
        if memory_end > image_size {
            return Err(MirageError::Malformed(
                "a section extends past SizeOfImage",
            ));
        }

        sections.push(Section {
            virtual_address,
            virtual_size,
            raw_offset,
            raw_size,
            executable: characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
            writable: characteristics & IMAGE_SCN_MEM_WRITE != 0,
            readable: characteristics & IMAGE_SCN_MEM_READ != 0,
        });
    }

    // Translating an RVA to a file offset needs the section table, so
    // this is defined after it. An RVA that falls in no section is an
    // error rather than a guess - guessing means reading whichever bytes
    // happen to be at that file offset.
    let rva_to_offset = |rva: u32| -> Option<usize> {
        // Inside the headers, RVA and file offset coincide.
        if (rva as usize) < headers_size {
            return Some(rva as usize);
        }
        for section in &sections {
            let start = section.virtual_address;
            let end = start + section.virtual_size.max(section.raw_size as u32);
            if rva >= start && rva < end {
                let delta = (rva - start) as usize;
                if delta >= section.raw_size {
                    return None;
                }
                return Some(section.raw_offset + delta);
            }
        }
        None
    };

    let imports = parse_imports(bytes, read_directory(DIRECTORY_IMPORT)?, &rva_to_offset)?;
    let relocations = parse_relocations(bytes, read_directory(DIRECTORY_BASERELOC)?, &rva_to_offset)?;

    Ok(Image {
        entry_rva,
        preferred_base,
        image_size,
        headers_size,
        sections,
        imports,
        relocations,
    })
}

/// Walks the import directory, collecting every imported function and the
/// IAT slot that will hold its address.
fn parse_imports(
    bytes: &[u8],
    directory: (u32, u32),
    rva_to_offset: &impl Fn(u32) -> Option<usize>,
) -> Result<Vec<Import>, MirageError> {
    let (directory_rva, _) = directory;
    if directory_rva == 0 {
        return Ok(Vec::new());
    }

    let mut imports = Vec::new();
    let mut descriptor = rva_to_offset(directory_rva)
        .ok_or(MirageError::Malformed("the import directory RVA is unmapped"))?;

    // Each descriptor is 20 bytes and the list is terminated by an
    // all-zero one. A bound on iterations as well, because a file with no
    // terminator would otherwise walk to the end of memory.
    for _ in 0..MAX_IMPORTS {
        if descriptor + 20 > bytes.len() {
            return Err(MirageError::Malformed(
                "the import descriptor list runs past the end of the file",
            ));
        }

        let lookup_rva = u32_at(bytes, descriptor)?;
        let name_rva = u32_at(bytes, descriptor + 12)?;
        let iat_rva = u32_at(bytes, descriptor + 16)?;

        if lookup_rva == 0 && name_rva == 0 && iat_rva == 0 {
            break;
        }

        // The lookup table and the IAT are parallel arrays: the first
        // names what is wanted, the second receives the address. An image
        // may omit the lookup table, in which case the IAT serves as
        // both - which is why this falls back rather than failing.
        let names_rva = if lookup_rva != 0 { lookup_rva } else { iat_rva };
        let mut names = rva_to_offset(names_rva)
            .ok_or(MirageError::Malformed("an import lookup table is unmapped"))?;
        let mut slot_rva = iat_rva;

        for _ in 0..MAX_IMPORTS {
            if imports.len() >= MAX_IMPORTS {
                return Err(MirageError::Malformed("implausible number of imports"));
            }
            let entry = u64_at(bytes, names)?;
            if entry == 0 {
                break;
            }

            // The high bit means "import by ordinal" rather than by name.
            // Mirage resolves by name only: an ordinal is an index into a
            // DLL's export table, and there is no DLL here to index.
            if entry & (1 << 63) != 0 {
                return Err(MirageError::Malformed(
                    "the image imports by ordinal; Mirage resolves imports by name, since there \
                     is no DLL export table to index into",
                ));
            }

            // The low 31 bits are an RVA to a hint/name structure: a
            // 2-byte hint followed by a NUL-terminated name.
            let hint_name = rva_to_offset((entry & 0x7FFF_FFFF) as u32)
                .ok_or(MirageError::Malformed("an import name RVA is unmapped"))?;
            let name_start = hint_name + 2;
            let name_end = bytes[name_start..]
                .iter()
                .position(|&byte| byte == 0)
                .map(|length| name_start + length)
                .ok_or(MirageError::Malformed(
                    "an import name is not NUL-terminated before the end of the file",
                ))?;

            imports.push(Import {
                name: String::from_utf8_lossy(&bytes[name_start..name_end]).into_owned(),
                iat_rva: slot_rva,
            });

            names += 8;
            slot_rva += 8;
        }

        descriptor += 20;
    }

    Ok(imports)
}

/// Collects the RVAs of every 64-bit absolute address that needs fixing
/// up when the image is moved from its preferred base.
fn parse_relocations(
    bytes: &[u8],
    directory: (u32, u32),
    rva_to_offset: &impl Fn(u32) -> Option<usize>,
) -> Result<Vec<u32>, MirageError> {
    let (directory_rva, directory_size) = directory;
    if directory_rva == 0 || directory_size == 0 {
        return Ok(Vec::new());
    }

    let start = rva_to_offset(directory_rva)
        .ok_or(MirageError::Malformed("the relocation directory is unmapped"))?;
    let end = start
        .checked_add(directory_size as usize)
        .filter(|&end| end <= bytes.len())
        .ok_or(MirageError::Malformed(
            "the relocation directory extends past the end of the file",
        ))?;

    let mut relocations = Vec::new();
    let mut at = start;

    // The table is a sequence of blocks: a page RVA, a byte count for the
    // block, then 2-byte entries each holding a 4-bit type and a 12-bit
    // offset within that page.
    while at + 8 <= end {
        let page_rva = u32_at(bytes, at)?;
        let block_size = u32_at(bytes, at + 4)? as usize;

        // A block claiming to be smaller than its own header, or larger
        // than the directory, would make this loop either spin forever or
        // read past the end.
        if block_size < 8 || at + block_size > end {
            return Err(MirageError::Malformed("a relocation block has a bad size"));
        }

        let entries = (block_size - 8) / 2;
        for index in 0..entries {
            if relocations.len() >= MAX_RELOCATIONS {
                return Err(MirageError::Malformed("implausible number of relocations"));
            }
            let entry = u16_at(bytes, at + 8 + index * 2)?;
            let kind = entry >> 12;
            let offset = entry & 0x0FFF;

            match kind {
                // Padding, present only to keep blocks 4-byte aligned.
                // Applying it would corrupt whatever is at the page base.
                IMAGE_REL_BASED_ABSOLUTE => {}
                IMAGE_REL_BASED_DIR64 => relocations.push(page_rva + offset as u32),
                _ => {
                    return Err(MirageError::Malformed(
                        "an unsupported relocation type is present; only 64-bit absolute \
                         relocations are handled",
                    ))
                }
            }
        }

        at += block_size;
    }

    Ok(relocations)
}
