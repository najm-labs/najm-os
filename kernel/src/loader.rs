//! A first, minimal ELF64 loader.
//!
//! Reads a program from the bootloader-provided ramdisk (see
//! `BOOTLOADER_CONFIG`'s `ramdisk_memory` mapping request in main.rs),
//! parses just enough of the ELF64 format to find its PT_LOAD segments,
//! maps each onto dedicated user-accessible pages, and jumps to the
//! program's declared entry point via `arch::x86_64::usermode`.
//!
//! Deliberately minimal: no dynamic linking, no relocations, no support
//! for anything but `ET_EXEC` (fixed-address, non-PIE) binaries, and only
//! the validation needed to avoid mapping obviously-malformed segment
//! data. This is a first proof that the mechanism - parse, map, jump -
//! works end to end with a real ELF file, not a hardened implementation
//! that should ever be pointed at untrusted input.
//!
//! Kept at the top level (not under `arch::x86_64`) on purpose: the ELF64
//! *format* itself is architecture-independent - only the `e_machine`
//! check below is x86_64-specific, and everything else here would look
//! identical on a future `arch::aarch64`.

use crate::mm::address_space::AddressSpace;
use crate::serial_println;
use alloc::collections::BTreeSet;
use x86_64::structures::paging::{Page, PageTableFlags, Size4KiB};
use x86_64::VirtAddr;

const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ET_EXEC: u16 = 2;
const EM_X86_64: u16 = 0x3E;
const PT_LOAD: u32 = 1;

/// Segment permission bits from the ELF program header's `p_flags`.
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

/// Translates an ELF segment's declared permissions into page table
/// flags, enforcing W^X on the way.
///
/// Every user page used to be mapped `PRESENT | WRITABLE |
/// USER_ACCESSIBLE` regardless of what the segment actually asked for,
/// which meant a program's code was writable and its data and stack were
/// executable. That is the condition every memory-corruption exploit
/// technique of the last thirty years was designed around: overwrite a
/// buffer, then execute what you wrote.
///
/// The rules applied here:
///
/// - **Writable implies non-executable.** A segment that asks for both -
///   which is legal ELF, and exactly what the old single-RWX-segment
///   linker script produced - is refused rather than quietly downgraded.
///   Refusing is the right call because silently dropping `X` from a
///   segment a program genuinely intended to execute produces a fault at
///   a confusing place later, while refusing at load time names the
///   actual problem.
/// - **Non-executable is set explicitly**, not left to default. `NO_EXECUTE`
///   is bit 63 of the page table entry and does nothing unless `EFER.NXE`
///   is on - see `arch::x86_64::cpu`. If NX is unavailable on this CPU
///   the bit must not be set at all (it would be a reserved-bit
///   violation), so this returns flags without it and the caller reports
///   the degraded state rather than mapping something that faults.
/// - **`PF_R` is required.** A segment that is neither readable nor
///   executable is meaningless, and one that is executable but not
///   readable cannot be expressed in x86_64 paging anyway.
fn segment_flags(p_flags: u32, nx_available: bool) -> Result<PageTableFlags, &'static str> {
    let readable = p_flags & PF_R != 0;
    let writable = p_flags & PF_W != 0;
    let executable = p_flags & PF_X != 0;

    if !readable {
        return Err("segment is not readable - x86_64 paging cannot express that");
    }
    if writable && executable {
        return Err(
            "segment requests both write and execute permission; Najm OS enforces W^X, so a \
             writable segment can never be executable. Split it into separate PT_LOAD segments \
             on page boundaries.",
        );
    }

    let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
    if writable {
        flags |= PageTableFlags::WRITABLE;
    }
    if !executable && nx_available {
        flags |= PageTableFlags::NO_EXECUTE;
    }
    Ok(flags)
}

/// A dedicated, fixed stack address for ELF-loaded programs - distinct
/// from `usermode::run_test`'s own hardcoded test range, so the two
/// mechanisms can't collide now that both run in the same boot (see the
/// call sites in main.rs).
const USER_STACK_ADDR: u64 = crate::mm::layout::USER_STACK_BOTTOM;

/// How many pages the user stack gets.
///
/// This was one page while the only programs were hand-encoded payloads a
/// dozen instructions long, which never touched their stack at all. A
/// compiled Rust program does: an unoptimized debug build spills freely
/// and nests real call frames, and running out of stack would show up as
/// a page fault at an address just below the stack rather than as
/// anything self-explanatory. Four pages (16 KiB) matches what the
/// kernel's own tasks get in `sched::task::STACK_SIZE`, chosen for the
/// same reason: comfortable headroom for code that isn't trying to be
/// frugal.
///
/// There is still no guard page below it - a program that overflows its
/// stack corrupts whatever is mapped underneath rather than faulting
/// cleanly. That's the same gap task stacks have, and it needs the same
/// fix (per-program page tables), so it's recorded here rather than
/// solved locally.
const USER_STACK_PAGES: u64 = crate::mm::layout::USER_STACK_PAGES;

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

// `load_and_run` and its `load` helper used to live here: they mapped an
// image into whatever address space was currently active and ran it
// inline. They are gone, replaced by `load_image` above plus
// `process::spawn`.
//
// The reason is not tidiness. Mapping into the *active* address space is
// correct only while exactly one program can exist, and it made three
// things impossible at once: two programs could not be loaded (both link
// to 0x400000, so the second `map_to` failed), a program could not be
// preempted (it was running on `kernel_main`'s stack, not a task's), and
// its memory could never be reclaimed (nothing recorded which of the
// shared address space's mappings had been its). Keeping the old path
// alongside the new one would have meant maintaining a second, weaker
// way to run a program, whose only distinguishing feature was the
// limitations.

/// Parses an ELF64 image and builds a complete, private address space for
/// it, ready to be handed to `process::spawn`.
///
/// The single entry point for turning a file into something runnable. It
/// does four things, in this order, and the order matters:
///
/// 1. Validate the header *completely* before reading any segment, so a
///    truncated or hostile file produces one clear error rather than an
///    out-of-bounds slice index deep inside a field read.
/// 2. Build a fresh `AddressSpace`, so the image's fixed load address
///    (`0x400000` - the loader supports only `ET_EXEC`) cannot collide
///    with any other process's.
/// 3. Map each segment writable, zero the whole mapped range, copy the
///    file contents in, then tighten the permissions to what the segment
///    declared. Zeroing before copying is not optional: fresh frames come
///    from the pool holding whatever the previous owner left in them.
/// 4. Map a stack, non-executable, with an unmapped guard page below.
pub fn load_image(bytes: &[u8], name: &str) -> Result<crate::process::LoadedImage, LoadError> {
    let header = parse_header(bytes)?;
    let mut space = AddressSpace::new().ok_or(LoadError::OutOfMemory)?;
    let nx_available = crate::arch::x86_64::cpu::detect().nx;

    serial_println!(
        "Najm Kernel: loading '{}' into a private address space - entry {:#x}, {} program \
         header(s)",
        name,
        header.entry,
        header.phnum
    );

    // Every page mapped so far by this load. Two segments sharing a page
    // is not merely awkward, it is a W^X hole: permissions are a property
    // of a page, so an r-x segment and an rw- segment overlapping in one
    // page means whichever mapping wins silently grants the other
    // permissions it never asked for. The fix belongs in the linker
    // script; this reports rather than papering over it.
    let mut mapped_pages: BTreeSet<u64> = BTreeSet::new();

    for i in 0..header.phnum {
        let ph_offset = header.phoff + i * header.phentsize;
        if read_u32(bytes, ph_offset) != PT_LOAD {
            continue;
        }

        let p_flags = read_u32(bytes, ph_offset + 4);
        let p_offset = read_u64(bytes, ph_offset + 8) as usize;
        let p_vaddr = read_u64(bytes, ph_offset + 16);
        let p_filesz = read_u64(bytes, ph_offset + 32) as usize;
        let p_memsz = read_u64(bytes, ph_offset + 40) as usize;

        let final_flags =
            segment_flags(p_flags, nx_available).map_err(|reason| LoadError::BadSegment {
                index: i,
                vaddr: p_vaddr,
                reason,
            })?;

        // A user program must never be able to name a kernel address in
        // its own program headers. Without this check, a hand-crafted ELF
        // with `p_vaddr` in the higher half would have the loader map
        // user-accessible pages over the kernel's own - which is not an
        // exploit needing a bug, just a file the loader was asked to
        // open. `AddressSpace::map_page` refuses it too; both checks
        // exist because this one produces a diagnosable error naming the
        // segment, and that one is the last line of defence.
        if !crate::mm::layout::is_user_address(p_vaddr) {
            return Err(LoadError::BadSegment {
                index: i,
                vaddr: p_vaddr,
                reason: "load address is outside user space",
            });
        }
        if p_filesz > p_memsz {
            return Err(LoadError::BadSegment {
                index: i,
                vaddr: p_vaddr,
                reason: "file size exceeds memory size",
            });
        }
        let file_end = p_offset.checked_add(p_filesz).ok_or(LoadError::BadSegment {
            index: i,
            vaddr: p_vaddr,
            reason: "file offset + size overflows",
        })?;
        if file_end > bytes.len() {
            return Err(LoadError::BadSegment {
                index: i,
                vaddr: p_vaddr,
                reason: "segment extends past the end of the image",
            });
        }
        // Overflowing here would wrap `end_page` to a *smaller* address
        // than `start_page`, under-mapping the segment while the copy
        // below still used the original size - an out-of-bounds write
        // onto whatever sat after the truncated mapping.
        let segment_end = p_vaddr
            .checked_add(p_memsz as u64)
            .ok_or(LoadError::BadSegment {
                index: i,
                vaddr: p_vaddr,
                reason: "vaddr + memsz overflows",
            })?;
        if p_memsz == 0 {
            continue;
        }

        let start_page: Page<Size4KiB> = Page::containing_address(VirtAddr::new(p_vaddr));
        let end_page: Page<Size4KiB> = Page::containing_address(VirtAddr::new(segment_end - 1));

        // Mapped writable first and tightened after the contents are in.
        // Forced by CR0.WP: with write protection on, Ring 0 cannot write
        // to a read-only page either, so a code segment mapped
        // read-execute up front would be unwritable at exactly the moment
        // the loader needs to put code in it.
        let load_flags =
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;

        for page in Page::range_inclusive(start_page, end_page) {
            if !mapped_pages.insert(page.start_address().as_u64()) {
                return Err(LoadError::BadSegment {
                    index: i,
                    vaddr: page.start_address().as_u64(),
                    reason: "two segments share a page, so they cannot have different \
                             permissions - page-align them in the linker script",
                });
            }
            space.map_page(page, load_flags).map_err(LoadError::Mapping)?;
        }

        // Zero the whole mapped range *before* copying anything into it.
        //
        // Not just the `.bss` tail. Fresh frames come from the physical
        // frame pool still holding whatever the last owner left there -
        // kernel memory, or another process's. Zeroing only the declared
        // `.bss` would leave the page padding either side of a segment
        // carrying that data straight into Ring 3: an information leak
        // through a gap that belongs to no segment and that nobody would
        // think to look at.
        let mapped_start = start_page.start_address().as_u64();
        let mapped_len = (end_page.start_address().as_u64() + 4096 - mapped_start) as usize;
        space
            .zero_at(mapped_start, mapped_len)
            .map_err(LoadError::Mapping)?;

        space
            .write_at(p_vaddr, &bytes[p_offset..file_end])
            .map_err(LoadError::Mapping)?;

        for page in Page::range_inclusive(start_page, end_page) {
            space
                .protect_page(page, final_flags)
                .map_err(LoadError::Mapping)?;
        }

        serial_println!(
            "Najm Kernel:   segment {} - vaddr {:#x}, {} bytes ({} in memory), permissions {}{}{}",
            i,
            p_vaddr,
            p_filesz,
            p_memsz,
            if p_flags & PF_R != 0 { "r" } else { "-" },
            if p_flags & PF_W != 0 { "w" } else { "-" },
            if p_flags & PF_X != 0 { "x" } else { "-" }
        );
    }

    // The stack: writable, never executable. `layout::USER_STACK_GUARD`
    // sits immediately below and is simply never mapped by this loop -
    // its protection is its absence, so there is nothing here to create.
    let mut stack_flags =
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
    if nx_available {
        stack_flags |= PageTableFlags::NO_EXECUTE;
    }
    for i in 0..USER_STACK_PAGES {
        let page: Page<Size4KiB> =
            Page::containing_address(VirtAddr::new(USER_STACK_ADDR + i * 4096));
        space.map_page(page, stack_flags).map_err(LoadError::Mapping)?;
    }
    // Same reasoning as the segment zeroing: a stack handed to a process
    // must not start out holding whoever used those frames last.
    space
        .zero_at(USER_STACK_ADDR, (USER_STACK_PAGES * 4096) as usize)
        .map_err(LoadError::Mapping)?;

    Ok(crate::process::LoadedImage {
        name: alloc::string::String::from(name),
        entry: header.entry,
        stack_top: USER_STACK_ADDR + USER_STACK_PAGES * 4096,
        address_space: space,
    })
}

/// Why building an image's address space failed.
///
/// An error type rather than the assertions the previous loader used,
/// because this function is on the path a `spawn` syscall will take: a
/// malformed program file must be an error a caller can report, never a
/// kernel panic. A panic here would mean any user able to name a corrupt
/// file could halt the machine.
#[derive(Debug)]
pub enum LoadError {
    NotAnElf(&'static str),
    BadSegment {
        index: usize,
        vaddr: u64,
        reason: &'static str,
    },
    Mapping(crate::mm::address_space::MapError),
    OutOfMemory,
}

impl core::fmt::Display for LoadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LoadError::NotAnElf(why) => write!(f, "not a loadable ELF64 image: {}", why),
            LoadError::BadSegment {
                index,
                vaddr,
                reason,
            } => write!(
                f,
                "segment {} at {:#x} is not loadable: {}",
                index, vaddr, reason
            ),
            LoadError::Mapping(err) => write!(f, "could not map the image: {}", err),
            LoadError::OutOfMemory => write!(f, "out of memory building the address space"),
        }
    }
}

struct ElfHeader {
    entry: u64,
    phoff: usize,
    phentsize: usize,
    phnum: usize,
}

/// Validates the ELF header and returns the fields the loader needs.
///
/// Every bound is checked here rather than discovered field-by-field
/// inside the segment loop. A truncated or hostile header would otherwise
/// produce an out-of-bounds slice index deep inside `read_u64` - correct
/// in the sense that it does not read past the buffer, but a panic where
/// an error belongs.
fn parse_header(bytes: &[u8]) -> Result<ElfHeader, LoadError> {
    if bytes.len() < 64 {
        return Err(LoadError::NotAnElf("smaller than an ELF64 header"));
    }
    if bytes[0..4] != ELF_MAGIC {
        return Err(LoadError::NotAnElf("wrong magic number"));
    }
    if bytes[4] != ELFCLASS64 {
        return Err(LoadError::NotAnElf("not 64-bit"));
    }
    if bytes[5] != ELFDATA2LSB {
        return Err(LoadError::NotAnElf("not little-endian"));
    }
    if read_u16(bytes, 16) != ET_EXEC {
        return Err(LoadError::NotAnElf(
            "not ET_EXEC - PIE and dynamic linking are not supported",
        ));
    }
    if read_u16(bytes, 18) != EM_X86_64 {
        return Err(LoadError::NotAnElf("not x86_64"));
    }

    let phoff = read_u64(bytes, 32) as usize;
    let phentsize = read_u16(bytes, 54) as usize;
    let phnum = read_u16(bytes, 56) as usize;

    // A program header entry smaller than the fields this loader reads
    // would make every per-segment offset below read into the *next*
    // entry, or past the table entirely - checked here rather than
    // trusting `e_phentsize` to be the standard 56.
    if phentsize < 56 {
        return Err(LoadError::NotAnElf(
            "program header entries are too small to contain the fields the loader reads",
        ));
    }
    let table_size = phnum
        .checked_mul(phentsize)
        .ok_or(LoadError::NotAnElf("program header table size overflows"))?;
    let table_end = phoff
        .checked_add(table_size)
        .ok_or(LoadError::NotAnElf("program header table offset overflows"))?;
    if table_end > bytes.len() {
        return Err(LoadError::NotAnElf(
            "program header table extends past the end of the image",
        ));
    }

    Ok(ElfHeader {
        entry: read_u64(bytes, 24),
        phoff,
        phentsize,
        phnum,
    })
}
