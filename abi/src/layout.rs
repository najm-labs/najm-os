//! The virtual address map, in one place.
//!
//! Until now every fixed virtual address in this kernel was a `const`
//! declared next to the code that used it, and the only thing keeping two
//! of them from overlapping was a table in CLAUDE.md and whoever
//! remembered to check it. That was survivable while there were four such
//! addresses. It stops being survivable the moment address spaces become
//! per-process, because then "does this collide?" is no longer a single
//! global question - it depends on which half of the address space the
//! range lives in, and getting that wrong produces a kernel that boots
//! fine and corrupts memory later.
//!
//! ## The split, and why it had to happen
//!
//! x86_64 divides the 48-bit canonical address space into two halves with
//! a non-canonical hole between them:
//!
//! ```text
//!   0x0000_0000_0000_0000 .. 0x0000_7fff_ffff_ffff   lower half  (PML4 0..=255)
//!   <non-canonical hole - any address here faults>
//!   0xffff_8000_0000_0000 .. 0xffff_ffff_ffff_ffff   higher half (PML4 256..=511)
//! ```
//!
//! Najm OS puts **the entire kernel in the higher half and nothing else
//! there**, and **every user process in the lower half**. That is not
//! decoration; it is what makes per-process address spaces cheap and
//! correct. Creating a new address space becomes "allocate a PML4 and
//! copy entries 256..512 from the kernel's" - 256 pointer copies, after
//! which the kernel is mapped identically in every address space (so a
//! syscall, an interrupt, or a page fault can run no matter which process
//! is current) while entries 0..256 are that process's alone (so its
//! mappings are invisible to every other process, and tearing it down is
//! just freeing what those entries reach).
//!
//! Before this split, the kernel heap sat at `0x4444_4444_0000` - lower
//! half, PML4 index 136 - directly in the middle of what user address
//! spaces need to own. Any per-process page table would have had to
//! either share that entry (leaking the kernel heap into every process's
//! private half, and making one process's mapping changes visible to all)
//! or lose the kernel heap on CR3 switch (instantly fatal). Moving it was
//! the prerequisite, not a tidy-up.
//!
//! Where the bootloader's own mappings land is controlled the same way:
//! `BOOTLOADER_CONFIG` in the kernel's main.rs sets `dynamic_range_start`
//! to [`HIGHER_HALF_START`], so the kernel image, its stack, the boot
//! info, the framebuffer, the physical-memory mapping and the ramdisk are
//! all placed in the higher half too, rather than wherever the bootloader
//! would otherwise have chosen. The kernel's
//! `mm::memory::pml4_entries_in_use` counts the entries in each half at
//! boot and the self-test fails if any kernel mapping ended up in the
//! lower half - checking that the request was honoured, rather than
//! trusting that it was.
//!
//! ## Rules for adding an address here
//!
//! 1. Kernel-only ranges go in the higher half, user ranges in the lower
//!    half. A kernel range in the lower half is the bug described above.
//! 2. Every range gets a `_START` and a size, and non-overlap with its
//!    neighbours is the reviewer's job - the constants are laid out below
//!    in ascending order specifically so that is checkable by reading.
//! 3. Anything a user program can name goes below [`USER_SPACE_END`], and
//!    `mm::memory::user_range_is_accessible` rejects everything above it
//!    before it even walks the page tables.

/// First canonical higher-half address. Everything at or above this is
/// kernel-only, in every address space, forever.
pub const HIGHER_HALF_START: u64 = 0xffff_8000_0000_0000;

/// One past the last address a user program may name.
///
/// The lower half technically runs to `0x0000_7fff_ffff_ffff`; this stops
/// one page short of the top of it so that a range ending exactly at the
/// boundary can be expressed without the end pointer becoming
/// non-canonical.
pub const USER_SPACE_END: u64 = 0x0000_7fff_ffff_f000;

/// The PML4 index at which the higher half begins. Copying entries from
/// here to 512 is what shares the kernel between address spaces - see
/// `mm::address_space`.
pub const KERNEL_PML4_FIRST_INDEX: usize = 256;

// ---------------------------------------------------------------------
// Lower half - per-process, private to one address space each
// ---------------------------------------------------------------------

/// Where `ET_EXEC` userland programs are linked to load
/// (`userland/*/linker.ld`). The conventional x86_64 fixed load address;
/// kept because the ELF loader supports neither PIE nor relocations.
pub const USER_IMAGE_BASE: u64 = 0x0000_0000_0040_0000;

/// Load address of the hand-encoded fallback ELF built by
/// `runner/build.rs`. Deliberately distinct from [`USER_IMAGE_BASE`] so
/// that a boot image built without the userland crate is identifiable
/// from the log rather than silently substituting one program for
/// another.
pub const USER_FALLBACK_IMAGE_BASE: u64 = 0x0000_0000_0050_0000;

/// Base of the per-process heap region that `mmap`-style allocation hands
/// out from. Grows upward; nothing else is placed between here and the
/// Mirage region below.
pub const USER_HEAP_BASE: u64 = 0x0000_1000_0000_0000;

/// Where the Mirage compatibility layer maps a PE image and its thunk
/// table (see `mirage/`). Windows binaries declare their own preferred
/// base (usually `0x0000_0001_4000_0000` for 64-bit), but Mirage relocates
/// them into this range instead so a PE image can never be placed on top
/// of a native segment.
pub const MIRAGE_IMAGE_BASE: u64 = 0x0000_2000_0000_0000;

/// The single page the hand-written Ring 3 test payload
/// (`arch::x86_64::usermode::run_test`) executes from.
pub const USERMODE_TEST_CODE: u64 = 0x0000_5555_5555_0000;

/// The hand-written test payload's one-page stack (top is one page above).
pub const USERMODE_TEST_STACK: u64 = 0x0000_6666_6666_0000;

/// Top of a user process's main stack - the value placed in RSP at entry.
/// The stack grows *down* from here.
pub const USER_STACK_TOP: u64 = 0x0000_7fff_f000_0000;

/// How many pages a user stack gets. 16 pages (64 KiB) rather than the 4
/// it had before: an unoptimized debug build of a real Rust program
/// spills freely and nests genuine call frames, and a stack overflow used
/// to present as an unexplained page fault at an address just below the
/// stack. With [`USER_STACK_GUARD`] below it now presents as a page fault
/// on a deliberately unmapped page, which is diagnosable.
pub const USER_STACK_PAGES: u64 = 16;

/// Lowest mapped address of a user stack.
pub const USER_STACK_BOTTOM: u64 = USER_STACK_TOP - USER_STACK_PAGES * 4096;

/// A deliberately **unmapped** page immediately below every user stack.
///
/// Overflowing the stack writes here, which faults, instead of silently
/// corrupting whatever the allocator happened to place underneath. This
/// is the same trick the bootloader already uses for the kernel's own
/// stack, applied to user stacks now that per-process page tables make it
/// cheap - the address is simply never mapped, so it costs one page of
/// address space and no physical memory at all.
pub const USER_STACK_GUARD: u64 = USER_STACK_BOTTOM - 4096;

// ---------------------------------------------------------------------
// Higher half - kernel-only, shared by every address space
// ---------------------------------------------------------------------

/// Start of the kernel heap.
///
/// PML4 index 384, chosen to sit far clear of the bootloader's own
/// dynamic allocations, which start at [`HIGHER_HALF_START`] (PML4 index
/// 256) and run upward - the physical-memory mapping alone covers at
/// least 4 GiB, i.e. through PML4 index 256 and a little beyond, so there
/// is an enormous gap between the two.
pub const KERNEL_HEAP_START: u64 = 0xffff_c000_0000_0000;

/// 16 MiB.
///
/// Was 1 MiB, sized when the only heap users were `Vec`/`Box` bookkeeping
/// and a handful of 16 KiB task stacks. The compositor's off-screen
/// framebuffer alone is larger than that at any real resolution (a
/// 1024x768 32-bit buffer is 3 MiB), and the VFS holds every ramdisk file
/// in memory. This is still a fixed number rather than a growable heap -
/// the honest description is "sized against the workloads that now exist"
/// rather than "solved."
pub const KERNEL_HEAP_SIZE: usize = 16 * 1024 * 1024;

/// A kernel address that userland self-tests deliberately hand to the
/// kernel in order to watch it be refused.
///
/// It has to be an address that is genuinely *mapped and present* - the
/// base of the kernel heap is - because an unmapped address would be
/// rejected for the wrong reason and would prove nothing about the check
/// that matters. What must reject it is the user/supervisor rule, not the
/// absence of a mapping. Exported here rather than hardcoded in the test
/// program so that moving the heap cannot silently turn a real test into
/// a vacuous one.
pub const KERNEL_PROBE_ADDRESS: u64 = KERNEL_HEAP_START;

/// Whether `addr` is an address a user program is allowed to name at all.
///
/// Checked before any page table walk, and separately from it: the walk
/// answers "is this mapped and user-accessible", which is the right
/// question but an expensive one, and it would answer "no" for a
/// higher-half address only because the kernel's own pages happen not to
/// carry `USER_ACCESSIBLE`. Making the address-space rule explicit means
/// the boundary is a stated policy rather than an emergent property of
/// how the kernel's own mappings were flagged - if some kernel page were
/// ever mapped user-accessible by mistake, this check still refuses it.
pub const fn is_user_address(addr: u64) -> bool {
    addr < USER_SPACE_END
}
