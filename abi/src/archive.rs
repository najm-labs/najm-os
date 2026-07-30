//! The Najm Archive (NAR) format: how a filesystem gets into the boot
//! image.
//!
//! The kernel needs files before it has a disk driver, a partition table,
//! or an on-disk filesystem - the ELF loader has to read a program from
//! *somewhere*, and until now that somewhere was "the ramdisk is one
//! file, and it is the program." That works for exactly one program and
//! nothing else: no second binary, no configuration, no assets, no way to
//! ask what exists.
//!
//! NAR is the smallest format that fixes that. It is a flat, read-only,
//! offset-addressed archive: a header, a table of entries, and a blob.
//! The kernel parses the table once at boot and serves every file
//! directly out of the ramdisk pages the bootloader already mapped, with
//! no copying and no allocation per file.
//!
//! ## Why not tar, cpio, or a real filesystem
//!
//! - **tar** is 512-byte-block-aligned with octal ASCII numeric fields
//!   and a checksum whose definition varies by implementation. Parsing it
//!   correctly is more code than this whole format, and parsing it
//!   *incorrectly* is a well-known source of path-traversal bugs.
//! - **cpio** is better but still has multiple incompatible variants and
//!   the same ASCII-numeric awkwardness.
//! - **A real filesystem** (FAT, ext2) means block allocation, directory
//!   trees on disk, and a driver - all of which this project will
//!   eventually want for a *writable* disk, and none of which helps with
//!   the actual problem here, which is "get a known set of files into
//!   memory at boot."
//!
//! The honest framing: NAR is a boot-time bundle, not a filesystem. When
//! Najm OS gets a disk driver it gets a real filesystem too, and NAR
//! stays as what it is now - the thing that carries the initial userland
//! before any disk is readable.
//!
//! ## Layout
//!
//! ```text
//!   offset  size  field
//!   0       8     magic, [`MAGIC`]
//!   8       4     format version, [`VERSION`]
//!   12      4     entry count
//!   16      8     total archive length (for validation)
//!   24      ...   entry table: `count` x [`ENTRY_SIZE`] bytes
//!   ...     ...   file data, referenced by absolute offset
//! ```
//!
//! Each entry:
//!
//! ```text
//!   0   8   data offset, absolute from the start of the archive
//!   8   8   data length in bytes
//!   16  4   flags ([`FLAG_DIRECTORY`])
//!   20  4   path length in bytes
//!   24  ..  path, NOT NUL-terminated, [`MAX_PATH`] bytes at most
//! ```
//!
//! Entry size is fixed at [`ENTRY_SIZE`] so the table can be indexed
//! rather than walked. A variable-length table would have to be scanned
//! from the start to find entry *n*, which turns every lookup into a
//! parse and every malformed length into a chance to walk off the end.
//!
//! ## Everything here is untrusted
//!
//! The archive arrives as bytes in a ramdisk. Nothing about it is
//! guaranteed by construction, and a kernel that assumes otherwise has an
//! attack surface reachable before the first user program even runs. So:
//!
//! - Every offset and length is bounds-checked against the *actual* byte
//!   slice, not against the archive's own claimed total length.
//! - Paths are validated ([`path_is_valid`]) rather than sanitized. A
//!   path containing `..`, a NUL, or a missing leading `/` is rejected
//!   outright. Sanitizing - stripping the bad parts and continuing - is
//!   how path traversal bugs happen, because the sanitizer and the
//!   consumer inevitably disagree about what the string means.
//! - Nothing is length-prefixed in a way that could make the parser
//!   allocate: the kernel borrows slices of the ramdisk and never copies
//!   a file to read it.

/// `"NAJMAR"` plus two version-independent padding bytes, so a file can
/// be identified without parsing anything.
pub const MAGIC: [u8; 8] = *b"NAJMAR\0\0";

/// Bumped whenever the layout changes incompatibly. The kernel refuses an
/// archive whose version it does not recognize rather than trying to
/// interpret unknown bytes.
pub const VERSION: u32 = 1;

/// Bytes before the entry table.
pub const HEADER_SIZE: usize = 24;

/// Fixed size of one entry, including its inline path.
pub const ENTRY_SIZE: usize = 24 + MAX_PATH;

/// The longest path an entry may carry.
///
/// A fixed inline maximum rather than a variable-length string, so the
/// table stays indexable. 120 bytes brings [`ENTRY_SIZE`] to a round 144
/// and is long enough for anything this system's flat namespace produces;
/// a deeply nested tree would want a different design entirely, not a
/// bigger number here.
pub const MAX_PATH: usize = 120;

/// Set on an entry that is a directory. Directories carry no data - their
/// offset and length are zero - and exist so `readdir` can report
/// structure that would otherwise only be implied by file paths.
pub const FLAG_DIRECTORY: u32 = 1 << 0;

/// Whether `path` is a path this system will accept.
///
/// Rejects rather than repairs, deliberately. The classic archive
/// vulnerability is an entry named `../../etc/passwd` extracted by code
/// that strips the `..` *somewhere* but not everywhere, or that strips it
/// after having already resolved the path. There is no such thing as a
/// path that is nearly valid: either it names something inside the
/// namespace or it does not.
///
/// The rules:
///
/// - Must be absolute (`/`-prefixed). A relative path has no meaning
///   without a working directory, which this system does not have.
/// - No `..` component anywhere, in any position.
/// - No `.` component, which is harmless but only ever arrives from a
///   generator being sloppy, and accepting it means two spellings of the
///   same path.
/// - No empty components, so `//a` and `/a/` are both refused - again,
///   two spellings of one path.
/// - No interior NUL, which would let a path mean one thing to a
///   length-based comparison and another to anything C-shaped.
/// - Non-empty, and no longer than [`MAX_PATH`].
pub fn path_is_valid(path: &[u8]) -> bool {
    if path.is_empty() || path.len() > MAX_PATH {
        return false;
    }
    if path[0] != b'/' {
        return false;
    }
    if path.contains(&0) {
        return false;
    }

    // The root directory is the one path allowed to be a bare slash.
    if path == b"/" {
        return true;
    }

    // `split` on the leading slash yields an empty first component, which
    // is expected and skipped; every *other* empty component is a
    // doubled or trailing slash.
    let mut components = path.split(|&b| b == b'/');
    let first = components.next();
    debug_assert!(first == Some(&[][..]));

    for component in components {
        if component.is_empty() || component == b"." || component == b".." {
            return false;
        }
    }

    true
}

/// The parent directory of `path`, or `None` for the root.
///
/// Byte-slice arithmetic rather than string manipulation because this is
/// called on paths from an untrusted archive, and `str` would mean a
/// UTF-8 validation step whose failure mode ("this path is not valid
/// UTF-8") is not the question being asked.
pub fn parent_of(path: &[u8]) -> Option<&[u8]> {
    if path == b"/" || path.is_empty() {
        return None;
    }
    let slash = path.iter().rposition(|&b| b == b'/')?;
    if slash == 0 {
        Some(b"/")
    } else {
        Some(&path[..slash])
    }
}

/// The final component of `path` - its file name.
pub fn basename(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|&b| b == b'/') {
        Some(slash) => &path[slash + 1..],
        None => path,
    }
}
