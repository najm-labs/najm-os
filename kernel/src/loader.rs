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

use crate::arch::x86_64::usermode::ProgramExit;
use crate::serial_println;
use alloc::collections::BTreeSet;
use x86_64::structures::paging::{FrameAllocator, Mapper, Page, PageTableFlags, Size4KiB};
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

/// Parses the ELF64 binary in `bytes`, maps its `PT_LOAD` segments as
/// user-accessible pages, transitions to Ring 3 at its entry point, and
/// reports how the program ended.
///
/// Returns rather than diverging: `arch::x86_64::usermode::run_program`,
/// which this calls as its final step, gained a way back for both a
/// clean exit and a fault. Note that a returned
/// `ProgramExit::PageFault`/`GeneralProtectionFault` means the *program*
/// was terminated, not that loading failed - a malformed ELF still fails
/// loudly through the assertions above, before Ring 3 is ever reached.
pub fn load_and_run(bytes: &[u8]) -> ProgramExit {
    // Mapping and running are deliberately separated, and the page-table
    // lock is released between them. Holding it across `run_program`
    // would be a guaranteed deadlock: the program's very first syscall
    // reaches a handler that needs to touch memory, and the lock is
    // non-reentrant.
    let (entry, stack_top) = crate::mm::memory::with_memory(|mapper, frame_allocator| {
        load(bytes, mapper, frame_allocator)
    });

    serial_println!("Najm Kernel: ELF loaded, entering Ring 3 at {:#x}", entry);

    // Safety: `entry` falls within a PT_LOAD segment `load` just mapped
    // executable and user-accessible; `stack_top` sits at the top of the
    // equally-mapped stack it also created.
    unsafe { crate::arch::x86_64::usermode::run_program(entry, stack_top) }
}

/// Parses and maps the program, returning `(entry point, stack top)`.
///
/// Split out of `load_and_run` so that the mapping work can happen inside
/// a `with_memory` block while the Ring 3 transition happens outside one.
fn load(
    bytes: &[u8],
    mapper: &mut impl Mapper<Size4KiB>,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> (u64, u64) {
    assert!(
        bytes.len() >= 64,
        "ramdisk is too small to contain an ELF64 header"
    );
    assert_eq!(
        &bytes[0..4],
        &ELF_MAGIC,
        "ramdisk does not start with the ELF magic number"
    );
    assert_eq!(bytes[4], ELFCLASS64, "only 64-bit ELF binaries are supported");
    assert_eq!(
        bytes[5], ELFDATA2LSB,
        "only little-endian ELF binaries are supported"
    );

    let e_type = read_u16(bytes, 16);
    let e_machine = read_u16(bytes, 18);
    let e_entry = read_u64(bytes, 24);
    let e_phoff = read_u64(bytes, 32) as usize;
    let e_phentsize = read_u16(bytes, 54) as usize;
    let e_phnum = read_u16(bytes, 56) as usize;

    assert_eq!(
        e_type, ET_EXEC,
        "only ET_EXEC (fixed-address) binaries are supported - no PIE/dynamic linking yet"
    );
    assert_eq!(e_machine, EM_X86_64, "ELF machine type is not x86_64");

    // Validates the *entire* program header table is in-bounds up front,
    // rather than discovering a truncated or malicious `e_phoff`/
    // `e_phnum` one field-read at a time inside the loop below. Without
    // this, a malformed ELF (accidentally corrupt, not necessarily
    // hostile - this loader was never meant to be pointed at untrusted
    // input, see the module docs) would panic on a raw slice-index
    // out-of-bounds deep inside `read_u32`/`read_u64`, which is correct
    // in the sense that it doesn't read past the buffer, but unhelpful
    // as a diagnostic and needlessly fragile as a contract: callers of
    // `load_and_run` deserve one clear assertion message, not an
    // internal index-panic that happens to be safe by accident.
    let phdr_table_size = e_phnum
        .checked_mul(e_phentsize)
        .expect("ELF program header table size overflows usize");
    let phdr_table_end = e_phoff
        .checked_add(phdr_table_size)
        .expect("ELF program header table offset overflows usize");
    assert!(
        phdr_table_end <= bytes.len(),
        "ELF program header table extends past the end of the ramdisk"
    );

    serial_println!(
        "Najm Kernel: ELF parsed - entry point {:#x}, {} program header(s)",
        e_entry,
        e_phnum
    );

    let nx_available = crate::arch::x86_64::cpu::detect().nx;

    // Every page mapped so far by this load, so that two segments sharing
    // a page are detected as the conflict they are rather than failing
    // deep inside `map_to` with "already mapped".
    //
    // Sharing a page is not merely awkward, it is a W^X hole: if a
    // read-execute segment and a read-write segment overlap in one page,
    // that page has to be both, and whichever mapping wins silently
    // grants the other segment permissions it never asked for. The fix
    // belongs in the linker script (page-align the segments), so this
    // reports rather than papering over it.
    let mut mapped_pages: BTreeSet<u64> = BTreeSet::new();

    // Segments are mapped writable, filled in, and only then re-protected
    // to their real permissions. That two-step is forced by CR0.WP, which
    // this kernel now sets: with write protection on, Ring 0 cannot write
    // to a read-only page any more than Ring 3 can, so a code segment
    // mapped read-execute up front would be unwritable at the moment the
    // loader needs to put the code in it. Mapping writable and then
    // tightening is the standard resolution, and the window is entirely
    // inside this function - no user code runs during it.
    let mut segments_to_protect: alloc::vec::Vec<(Page<Size4KiB>, Page<Size4KiB>, PageTableFlags)> =
        alloc::vec::Vec::new();

    let load_flags =
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;

    for i in 0..e_phnum {
        // Safe from overflow: `phdr_table_end` above already validated
        // `e_phoff + e_phnum * e_phentsize` fits in `bytes.len()`, and
        // `i` only ranges over `0..e_phnum`, so this per-entry offset is
        // always strictly less than that already-checked total.
        let ph_offset = e_phoff + i * e_phentsize;
        let p_type = read_u32(bytes, ph_offset);
        if p_type != PT_LOAD {
            continue;
        }

        let p_flags = read_u32(bytes, ph_offset + 4);
        let p_offset = read_u64(bytes, ph_offset + 8) as usize;
        let p_vaddr = read_u64(bytes, ph_offset + 16);
        let p_filesz = read_u64(bytes, ph_offset + 32) as usize;
        let p_memsz = read_u64(bytes, ph_offset + 40) as usize;

        let final_flags = match segment_flags(p_flags, nx_available) {
            Ok(flags) => flags,
            Err(reason) => panic!(
                "refusing to load ELF segment {} at {:#x} with flags {:#x}: {}",
                i, p_vaddr, p_flags, reason
            ),
        };

        serial_println!(
            "Najm Kernel: mapping PT_LOAD segment - vaddr {:#x}, file size {}, mem size {}, \
             permissions {}{}{}",
            p_vaddr,
            p_filesz,
            p_memsz,
            if p_flags & PF_R != 0 { "r" } else { "-" },
            if p_flags & PF_W != 0 { "w" } else { "-" },
            if p_flags & PF_X != 0 { "x" } else { "-" }
        );

        // A user program must never be able to name a kernel address in
        // its own program headers. Without this, a hand-crafted ELF with
        // `p_vaddr` in the higher half would have the loader map
        // user-accessible pages *over the kernel's own mappings* - which
        // is not an exploit needing a bug, just a file the loader was
        // asked to open.
        assert!(
            crate::mm::layout::is_user_address(p_vaddr),
            "ELF segment {} declares a load address ({:#x}) outside user space",
            i,
            p_vaddr
        );

        assert!(
            p_filesz <= p_memsz,
            "malformed ELF: a segment's file size exceeds its memory size"
        );
        assert!(
            p_offset
                .checked_add(p_filesz)
                .expect("ELF segment file offset + size overflows usize")
                <= bytes.len(),
            "ELF segment file range extends past the end of the ramdisk"
        );
        // `p_vaddr + p_memsz` overflowing would otherwise silently wrap
        // `end_page` below to a *smaller* address than `start_page`,
        // under-mapping the segment while the zero-fill/copy further
        // down still uses the original, un-wrapped `p_memsz` - an
        // out-of-bounds write onto whatever memory happens to sit right
        // after the truncated mapping. Rejecting the overflow outright
        // is cheap insurance against a malformed segment size class of
        // bug that would otherwise be very hard to notice from the
        // symptom alone.
        let segment_end = p_vaddr
            .checked_add(p_memsz as u64)
            .expect("ELF segment vaddr + mem size overflows u64");

        let start_page: Page<Size4KiB> = Page::containing_address(VirtAddr::new(p_vaddr));
        let end_page: Page<Size4KiB> =
            Page::containing_address(VirtAddr::new(segment_end - 1));

        for page in Page::range_inclusive(start_page, end_page) {
            assert!(
                mapped_pages.insert(page.start_address().as_u64()),
                "ELF segments overlap on the page at {:#x}. Two segments sharing a page cannot \
                 have different permissions, so one would silently inherit the other's - page-align \
                 the segments in the linker script.",
                page.start_address().as_u64()
            );

            let frame = frame_allocator
                .allocate_frame()
                .expect("out of physical frames while mapping an ELF segment");

            // Safety: `frame` just came from `frame_allocator`, which
            // only hands out frames from bootloader-reported usable
            // regions and never repeats one. `page` is derived directly
            // from this segment's own declared virtual address range,
            // which was checked to be a user address above.
            unsafe {
                mapper
                    .map_to(page, frame, load_flags, frame_allocator)
                    .expect("failed to map an ELF segment page")
                    .flush();
            }
        }

        // Safety: every byte of the destination range was just mapped
        // PRESENT | WRITABLE in the loop immediately above. The source
        // range was validated against `bytes.len()` above too. The
        // destination is user-accessible memory, so the write goes inside
        // a `with_user_access` bracket - required once SMAP is on, and a
        // no-op otherwise.
        crate::arch::x86_64::cpu::with_user_access(|| unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr().add(p_offset),
                p_vaddr as *mut u8,
                p_filesz,
            );

            // Zero-fill the remainder - `p_memsz > p_filesz` is how ELF
            // represents `.bss`: uninitialized data that isn't stored in
            // the file at all, only reserved as address space. Note this
            // is not merely about giving the program zeroes: without it
            // the program would read whatever the frame allocator handed
            // over last, which is stale kernel data, i.e. an information
            // leak straight into Ring 3.
            if p_memsz > p_filesz {
                core::ptr::write_bytes((p_vaddr as *mut u8).add(p_filesz), 0, p_memsz - p_filesz);
            }
        });

        // Deferred rather than applied now: the segment has to stay
        // writable until every byte of it has been written, and a segment
        // may be filled in more than one step above.
        if final_flags != load_flags {
            segments_to_protect.push((start_page, end_page, final_flags));
        }
    }

    // Apply the real permissions. From this point the program's code is
    // read-execute and its data is read-write-no-execute, which is what
    // makes W^X a property of the running program rather than a claim in
    // a comment.
    for (start_page, end_page, flags) in segments_to_protect {
        for page in Page::range_inclusive(start_page, end_page) {
            // Safety: `page` was mapped by the loop above and is still
            // mapped; `update_flags` only changes permission bits on an
            // existing mapping and cannot make it point elsewhere.
            unsafe {
                mapper
                    .update_flags(page, flags)
                    .expect("failed to re-protect an ELF segment page")
                    .flush();
            }
        }
    }

    // A dedicated user stack, entirely separate from any PT_LOAD segment
    // - the same approach `usermode::run_test` already proved works.
    //
    // Mapped NO_EXECUTE. A stack is the single most valuable page in the
    // address space to an attacker who can only write data: it is where
    // return addresses live, it is where overflowing buffers usually are,
    // and if it is executable then "overwrite a local array" and "run
    // arbitrary code" are the same operation. The `NO_EXECUTE` bit is
    // what separates them.
    //
    // Below it, `layout::USER_STACK_GUARD` is deliberately left unmapped.
    // A program that overflows its stack faults on that page instead of
    // silently corrupting whatever happens to be mapped underneath -
    // which, before this, was nothing in particular, making a stack
    // overflow present as a page fault at an unrelated address with no
    // hint of the real cause.
    let mut stack_flags =
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
    if nx_available {
        stack_flags |= PageTableFlags::NO_EXECUTE;
    }

    for i in 0..USER_STACK_PAGES {
        let stack_page: Page<Size4KiB> = Page::containing_address(VirtAddr::new(
            USER_STACK_ADDR + i * Page::<Size4KiB>::SIZE,
        ));
        let frame = frame_allocator
            .allocate_frame()
            .expect("out of physical frames while mapping the ELF program's stack");
        // Safety: same reasoning as the segment-mapping loop above.
        unsafe {
            mapper
                .map_to(stack_page, frame, stack_flags, frame_allocator)
                .expect("failed to map the ELF program's stack")
                .flush();
        }
    }

    // Checked rather than assumed. The guard page is "protective" only if
    // nothing ever maps it, and the way that guarantee dies is quietly -
    // some future allocator picks the address, everything keeps working,
    // and the protection is gone with no symptom. One page-table walk at
    // load time is cheap enough to make that impossible to miss.
    assert!(
        !crate::mm::memory::user_range_is_accessible(crate::mm::layout::USER_STACK_GUARD, 4096),
        "the page below the user stack ({:#x}) is mapped - it must stay unmapped to catch \
         stack overflow",
        crate::mm::layout::USER_STACK_GUARD
    );

    // The stack grows *down* from its top, so the entry value is the
    // address just past the highest mapped stack page. 16-byte aligned by
    // construction (a page-aligned base plus a whole number of pages),
    // which is what the SysV ABI requires at a program's entry point.
    let stack_top = USER_STACK_ADDR + USER_STACK_PAGES * Page::<Size4KiB>::SIZE;

    (e_entry, stack_top)
}