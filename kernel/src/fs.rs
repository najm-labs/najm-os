//! The filesystem: a read-only namespace served out of the boot archive.
//!
//! Until this module, "the filesystem" was one byte slice that the ELF
//! loader was pointed at. That is enough to run a program and nothing
//! else - there is no way to have a second binary, a configuration file,
//! an asset, or to ask what exists.
//!
//! What this provides is a **namespace**: paths that resolve to content,
//! directories that can be listed, and file descriptors that a Ring 3
//! program can open, read and close. What it deliberately does not
//! provide is writing, creation, deletion, or persistence - see the
//! honesty section below.
//!
//! ## Zero-copy, and why that is the interesting part
//!
//! The bootloader has already mapped the entire archive into kernel
//! memory. A file's contents are therefore *already in RAM at a known
//! address*, and this module serves reads directly out of those pages: a
//! `File` is an offset and a length into the ramdisk, not a buffer. The
//! whole filesystem costs one `BTreeMap` of paths at boot and nothing per
//! open file.
//!
//! That has a consequence worth stating rather than discovering: file
//! contents live in kernel memory for the life of the machine, and a
//! `read` syscall copies from there into the caller's buffer. The copy is
//! not avoidable (the destination is a different address space) but it is
//! the *only* copy, and it goes through
//! `mm::memory::copy_to_user`, which validates the destination against
//! the calling process's own page tables.
//!
//! ## What this is not
//!
//! - **Not writable.** `open` with a write flag is refused rather than
//!   silently opening read-only. A program that thinks it wrote a file
//!   and did not is worse off than one that was told no.
//! - **Not persistent.** The archive is rebuilt into the boot image on
//!   every build; nothing survives a reboot because nothing is on a disk.
//! - **Not a VFS.** There is one filesystem, mounted at `/`, with no
//!   mount table and no indirection through a node-operations vtable.
//!   Adding a disk-backed filesystem later means introducing that
//!   indirection; doing it now would be designing an abstraction against
//!   a single implementation, which is how abstractions end up shaped
//!   like whatever happened to exist first.

use crate::serial_println;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use najm_abi::archive;
use spin::Mutex;

/// One entry in the namespace.
#[derive(Debug, Clone, Copy)]
pub struct Node {
    /// Byte offset of this file's contents within the archive, or 0 for a
    /// directory.
    offset: usize,
    /// Length in bytes, or 0 for a directory.
    len: usize,
    pub is_directory: bool,
}

impl Node {
    pub fn size(&self) -> usize {
        self.len
    }
}

/// The parsed namespace, plus where the archive itself lives.
struct FileSystem {
    /// Path to node. A flat map rather than a tree: the archive's
    /// namespace is flat, lookups are exact-path, and `readdir` is rare
    /// enough that scanning for a prefix is cheaper than maintaining
    /// child lists that could disagree with the map.
    nodes: BTreeMap<String, Node>,
    /// Where the archive is mapped, and how long it is. Held as raw
    /// address and length rather than a `&'static [u8]` so that the
    /// bounds check on every read is explicit at the point of use, rather
    /// than something a slice's construction promised earlier.
    base: u64,
    len: usize,
}

static FILESYSTEM: Mutex<Option<FileSystem>> = Mutex::new(None);

/// Why an archive could not be mounted.
#[derive(Debug)]
pub enum MountError {
    TooSmall,
    BadMagic,
    UnsupportedVersion(u32),
    /// An entry's data range falls outside the archive.
    EntryOutOfBounds { index: usize },
    /// An entry's path failed [`archive::path_is_valid`].
    BadPath { index: usize },
    /// Two entries claim the same path.
    DuplicatePath { index: usize },
}

impl core::fmt::Display for MountError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MountError::TooSmall => write!(f, "archive is smaller than its own header"),
            MountError::BadMagic => write!(f, "archive does not start with the NAR magic"),
            MountError::UnsupportedVersion(v) => {
                write!(f, "archive format version {} is not supported", v)
            }
            MountError::EntryOutOfBounds { index } => write!(
                f,
                "entry {} names data outside the archive - refusing to mount rather than \
                 serving whatever memory follows it",
                index
            ),
            MountError::BadPath { index } => write!(
                f,
                "entry {} has a path that is not absolute, or contains '..', '.', an empty \
                 component, or a NUL",
                index
            ),
            MountError::DuplicatePath { index } => write!(
                f,
                "entry {} repeats a path an earlier entry already claimed",
                index
            ),
        }
    }
}

fn read_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

/// Parses `bytes` as a NAR archive and makes it the filesystem.
///
/// Validates everything before accepting anything. The archive comes from
/// a ramdisk, which is to say from a file on disk, which is to say it is
/// untrusted input being parsed at Ring 0 before the first user program
/// runs. Every bound is checked against the actual slice length rather
/// than against the archive's own claims about itself - an archive that
/// says it is 4 GiB long does not become 4 GiB long by saying so.
pub fn mount(bytes: &[u8]) -> Result<usize, MountError> {
    if bytes.len() < archive::HEADER_SIZE {
        return Err(MountError::TooSmall);
    }
    if bytes[0..8] != archive::MAGIC {
        return Err(MountError::BadMagic);
    }
    let version = read_u32(bytes, 8);
    if version != archive::VERSION {
        return Err(MountError::UnsupportedVersion(version));
    }

    let count = read_u32(bytes, 12) as usize;

    // The table has to fit before any entry is read. Checking per-entry
    // instead would mean the first out-of-range index is discovered by
    // indexing past the end - safe in Rust (it panics) but a panic is not
    // an error, and a kernel panic triggered by a malformed boot image is
    // a machine that does not start with no explanation of why.
    let table_bytes = count
        .checked_mul(archive::ENTRY_SIZE)
        .ok_or(MountError::TooSmall)?;
    let table_end = archive::HEADER_SIZE
        .checked_add(table_bytes)
        .ok_or(MountError::TooSmall)?;
    if table_end > bytes.len() {
        return Err(MountError::TooSmall);
    }

    let mut nodes: BTreeMap<String, Node> = BTreeMap::new();

    for index in 0..count {
        let at = archive::HEADER_SIZE + index * archive::ENTRY_SIZE;
        let offset = read_u64(bytes, at) as usize;
        let len = read_u64(bytes, at + 8) as usize;
        let flags = read_u32(bytes, at + 16);
        let path_len = read_u32(bytes, at + 20) as usize;

        if path_len > archive::MAX_PATH {
            return Err(MountError::BadPath { index });
        }
        let path = &bytes[at + 24..at + 24 + path_len];
        if !archive::path_is_valid(path) {
            return Err(MountError::BadPath { index });
        }

        let is_directory = flags & archive::FLAG_DIRECTORY != 0;

        if is_directory {
            if len != 0 {
                return Err(MountError::EntryOutOfBounds { index });
            }
        } else {
            let end = offset
                .checked_add(len)
                .ok_or(MountError::EntryOutOfBounds { index })?;
            if end > bytes.len() {
                return Err(MountError::EntryOutOfBounds { index });
            }
        }

        // Paths are validated above, so this is a lossless conversion of
        // bytes that are known to contain no NUL and to form a valid
        // path. `from_utf8_lossy` rather than `from_utf8` because a
        // non-UTF-8 path is not a reason to refuse to boot - it is a
        // reason for that path to be un-nameable by a program that types
        // it, which lossy conversion produces naturally.
        let path = String::from(alloc::string::String::from_utf8_lossy(path));

        if nodes
            .insert(
                path,
                Node {
                    offset,
                    len,
                    is_directory,
                },
            )
            .is_some()
        {
            // Duplicate paths would make lookup order-dependent, which is
            // to say non-deterministic from the point of view of anything
            // that did not build the archive.
            return Err(MountError::DuplicatePath { index });
        }
    }

    // The root always exists, whether or not the archive bothered to
    // declare it. Without this, `readdir("/")` on an archive that only
    // listed files would report "no such directory" for a directory that
    // demonstrably has things in it.
    nodes.entry(String::from("/")).or_insert(Node {
        offset: 0,
        len: 0,
        is_directory: true,
    });

    let mounted = nodes.len();

    x86_64::instructions::interrupts::without_interrupts(|| {
        *FILESYSTEM.lock() = Some(FileSystem {
            nodes,
            base: bytes.as_ptr() as u64,
            len: bytes.len(),
        });
    });

    Ok(mounted)
}

/// Looks up `path`.
pub fn lookup(path: &str) -> Option<Node> {
    x86_64::instructions::interrupts::without_interrupts(|| {
        FILESYSTEM.lock().as_ref()?.nodes.get(path).copied()
    })
}

/// Reads up to `buf.len()` bytes of `node`, starting at `offset` within
/// the file. Returns how many were read.
///
/// Bounds are re-derived here rather than trusted from the `Node`,
/// because a `Node` is a `Copy` value a caller could in principle have
/// held across a remount. Cheap insurance against a class of bug where
/// the check and the read are separated in time.
pub fn read(node: &Node, offset: usize, buf: &mut [u8]) -> usize {
    if node.is_directory || offset >= node.len {
        return 0;
    }

    x86_64::instructions::interrupts::without_interrupts(|| {
        let guard = FILESYSTEM.lock();
        let Some(fs) = guard.as_ref() else {
            return 0;
        };

        let available = node.len - offset;
        let want = core::cmp::min(available, buf.len());

        let start = node.offset + offset;
        // The check that matters: everything about `node` came from a
        // parsed archive, and this is the last point before a raw read.
        if start + want > fs.len {
            return 0;
        }

        // Safety: `fs.base` is the address the bootloader mapped the
        // ramdisk at, readable for `fs.len` bytes, and `start + want` was
        // just confirmed to be within that. The source is kernel memory,
        // so no SMAP bracket applies; `buf` is a kernel slice, and the
        // two cannot overlap (one is in the ramdisk mapping, the other on
        // the kernel heap or stack).
        unsafe {
            core::ptr::copy_nonoverlapping(
                (fs.base as *const u8).add(start),
                buf.as_mut_ptr(),
                want,
            );
        }
        want
    })
}

/// The immediate children of `path`, as full paths.
///
/// Computed by scanning rather than stored, for the reason given on
/// `FileSystem::nodes`: a maintained child list is a second source of
/// truth that can disagree with the first.
pub fn read_dir(path: &str) -> Option<Vec<String>> {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let guard = FILESYSTEM.lock();
        let fs = guard.as_ref()?;

        let node = fs.nodes.get(path)?;
        if !node.is_directory {
            return None;
        }

        let prefix = if path == "/" {
            String::from("/")
        } else {
            let mut p = String::from(path);
            p.push('/');
            p
        };

        let mut children = Vec::new();
        for candidate in fs.nodes.keys() {
            if candidate == path {
                continue;
            }
            let Some(rest) = candidate.strip_prefix(prefix.as_str()) else {
                continue;
            };
            // Immediate children only: anything with a further slash
            // belongs to a subdirectory, and listing it here would make
            // `readdir` return a recursive walk.
            if rest.is_empty() || rest.contains('/') {
                continue;
            }
            children.push(String::from(candidate.as_str()));
        }

        Some(children)
    })
}

/// Every path in the namespace, for the boot report.
pub fn all_paths() -> Vec<(String, usize, bool)> {
    x86_64::instructions::interrupts::without_interrupts(|| {
        FILESYSTEM
            .lock()
            .as_ref()
            .map(|fs| {
                fs.nodes
                    .iter()
                    .map(|(path, node)| (path.clone(), node.len, node.is_directory))
                    .collect()
            })
            .unwrap_or_default()
    })
}

/// Reads an entire file into a heap buffer.
///
/// Used by the ELF loader, which needs the whole image at once. Bounded
/// by the file's own recorded length, which was validated at mount time
/// against the real archive size - so this cannot be induced to allocate
/// more than the archive actually contains.
pub fn read_all(path: &str) -> Option<Vec<u8>> {
    let node = lookup(path)?;
    if node.is_directory {
        return None;
    }
    let mut buf = alloc::vec![0u8; node.len];
    let got = read(&node, 0, &mut buf);
    buf.truncate(got);
    Some(buf)
}

/// Prints the namespace. Called once at boot, because a filesystem whose
/// contents are never shown is one whose absence looks identical to its
/// presence.
pub fn report() {
    for (path, size, is_dir) in all_paths() {
        if is_dir {
            serial_println!("Najm Kernel:   {}/", path);
        } else {
            serial_println!("Najm Kernel:   {} ({} bytes)", path, size);
        }
    }
}
