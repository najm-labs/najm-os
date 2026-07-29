//! Physical memory management: page table access and a physical frame
//! allocator.
//!
//! This deliberately does the least amount of work that's actually
//! correct. Frames are handed out from the bootloader's memory map and
//! never reclaimed - there is no `deallocate_frame` yet, because nothing
//! in the kernel frees memory yet either. Building a free-capable
//! allocator now would mean designing against a workload that doesn't
//! exist - that's exactly backwards for a from-scratch kernel.

use bootloader_api::info::{MemoryRegionKind, MemoryRegions};
use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::{
    structures::paging::{
        page_table::PageTableFlags, FrameAllocator, OffsetPageTable, PageTable, PhysFrame, Size4KiB,
    },
    PhysAddr, VirtAddr,
};

/// Sentinel for "`init` has not run yet" in `PHYSICAL_MEMORY_OFFSET`.
/// A real offset is a canonical virtual address, so `u64::MAX` can never
/// collide with one.
const OFFSET_UNINITIALIZED: u64 = u64::MAX;

/// The bootloader's physical-memory mapping offset, stashed at `init`
/// time so code reached by an interrupt - which has no way to be handed
/// the `OffsetPageTable` that `kernel_main` owns - can still walk the
/// page tables. Read by `user_range_is_accessible` below.
static PHYSICAL_MEMORY_OFFSET: AtomicU64 = AtomicU64::new(OFFSET_UNINITIALIZED);

/// Returns a mutable reference to the currently active level 4 page
/// table.
///
/// # Safety
/// The caller must guarantee that `physical_memory_offset` is exactly
/// what the bootloader reported (see `BOOTLOADER_CONFIG` in main.rs,
/// which requests this mapping in the first place), and must ensure this
/// function - and `memory::init`, which calls it - is only ever called
/// once. Calling it twice would produce two live `&'static mut`
/// references to the same page table, which is immediate undefined
/// behavior regardless of what's done with them afterward.
unsafe fn active_level_4_table(physical_memory_offset: VirtAddr) -> &'static mut PageTable {
    use x86_64::registers::control::Cr3;

    let (level_4_table_frame, _) = Cr3::read();
    let phys = level_4_table_frame.start_address();
    let virt = physical_memory_offset + phys.as_u64();
    let page_table_ptr: *mut PageTable = virt.as_mut_ptr();

    &mut *page_table_ptr
}

/// Builds an `OffsetPageTable` capable of translating virtual addresses
/// and creating new mappings, using the bootloader's physical-memory
/// mapping to reach arbitrary physical frames - including page tables
/// that aren't mapped anywhere else yet, which is exactly what's needed
/// to map new heap pages in `allocator::init_heap`.
///
/// # Safety
/// Same requirement as `active_level_4_table`: `physical_memory_offset`
/// must be exactly correct, and this must only be called once.
pub unsafe fn init(physical_memory_offset: VirtAddr) -> OffsetPageTable<'static> {
    PHYSICAL_MEMORY_OFFSET.store(physical_memory_offset.as_u64(), Ordering::SeqCst);

    let level_4_table = active_level_4_table(physical_memory_offset);
    OffsetPageTable::new(level_4_table, physical_memory_offset)
}

/// Whether every byte of `start..start + len` is mapped *and* marked
/// user-accessible in the active page tables.
///
/// This exists because of a specific, concrete hole: a syscall like
/// `write` receives a pointer chosen entirely by a Ring 3 program, and
/// dereferencing it in Ring 0 without checking would hand any user
/// program an arbitrary kernel-memory read primitive - it could pass a
/// pointer to the kernel heap, a page table, or another program's pages
/// and have the kernel dutifully print the contents back. That would make
/// the capability isolation the rest of this kernel is built around
/// meaningless, since the check the CPU normally performs (the
/// USER_ACCESSIBLE bit) is only applied to accesses made *at* Ring 3, not
/// to a Ring 0 kernel touching the same address on the program's behalf.
/// Checking the bit in software is what restores that guarantee for the
/// syscall path.
///
/// Deliberately a read-only walk of the page tables rather than reusing
/// the `OffsetPageTable` from `init`: that value is owned by
/// `kernel_main`, and an interrupt handler has no way to reach it without
/// creating a second aliasing `&mut` to the same page table. Reading the
/// entries directly needs no such reference and can't invalidate the one
/// that already exists.
///
/// Known limits, stated rather than implied: this validates *mapping and
/// privilege*, not ownership. With one kernel-wide address space and no
/// per-program page tables (see `usermode.rs`'s module docs), any page
/// belonging to any user program passes for any other - there is
/// currently only ever one program running, so that gap isn't reachable
/// yet, but it closes properly only when address spaces become per-Realm.
pub fn user_range_is_accessible(start: u64, len: u64) -> bool {
    range_is_user(start, len, false)
}

/// The shared implementation behind `user_range_is_accessible` and
/// `user_range_is_writable`. See both for what each is for.
fn range_is_user(start: u64, len: u64, require_writable: bool) -> bool {
    if len == 0 {
        // An empty range is trivially in-bounds. Checked explicitly
        // because `start + len - 1` would underflow below.
        return true;
    }

    let Some(last) = start.checked_add(len - 1) else {
        // Wrapping past the top of the address space - a length a valid
        // buffer could never have.
        return false;
    };

    // The address-space rule, checked before and separately from the page
    // table walk below. The walk alone would reject a kernel address only
    // as a side effect of the kernel's pages not carrying
    // USER_ACCESSIBLE - true today, but an emergent property of how those
    // mappings happen to be flagged rather than a stated policy. Stating
    // it means a single mis-flagged kernel page cannot turn into a read
    // primitive. See `mm::layout::is_user_address`.
    if !crate::mm::layout::is_user_address(start) || !crate::mm::layout::is_user_address(last) {
        return false;
    }

    let offset = PHYSICAL_MEMORY_OFFSET.load(Ordering::SeqCst);
    if offset == OFFSET_UNINITIALIZED {
        return false;
    }
    let offset = VirtAddr::new(offset);

    let mut page = start & !0xFFF;
    let last_page = last & !0xFFF;
    loop {
        // `try_new`, not `new`: a user program can pass a non-canonical
        // address, and `VirtAddr::new` *panics* on one. A user pointer
        // must never be able to panic the kernel - that would trade an
        // information leak for a denial of service rather than fixing
        // anything.
        let Ok(addr) = VirtAddr::try_new(page) else {
            return false;
        };

        // Safety: `offset` is the bootloader's physical-memory mapping
        // offset, recorded by `init` above, so `offset + <physical frame
        // address>` is a valid, readable virtual address for any frame -
        // that mapping is exactly what `BOOTLOADER_CONFIG` requests. Only
        // shared reads happen through it; nothing here mutates a page
        // table or forms a `&mut` that could alias `kernel_main`'s.
        if !unsafe { page_is_user_accessible(addr, offset, require_writable) } {
            return false;
        }

        if page == last_page {
            return true;
        }
        page += 4096;
    }
}

/// Walks the four page table levels for one page, requiring `PRESENT` and
/// `USER_ACCESSIBLE` at *every* level.
///
/// Checking every level rather than just the final entry is the point: a
/// leaf entry marked user-accessible under a parent entry that isn't is
/// not reachable from Ring 3, and treating it as if it were would
/// reintroduce exactly the hole this is here to close.
///
/// # Safety
/// `physical_memory_offset` must be the bootloader's physical-memory
/// mapping offset, so that physical frame addresses can be read through
/// it.
unsafe fn page_is_user_accessible(
    addr: VirtAddr,
    physical_memory_offset: VirtAddr,
    require_writable: bool,
) -> bool {
    use x86_64::registers::control::Cr3;

    let (level_4_frame, _) = Cr3::read();
    let mut frame = level_4_frame;
    let indices = [addr.p4_index(), addr.p3_index(), addr.p2_index(), addr.p1_index()];

    for (level, index) in indices.into_iter().enumerate() {
        let table_virt = physical_memory_offset + frame.start_address().as_u64();
        // Safety: forwarded from this function's contract - `table_virt`
        // is a mapped, readable address for this frame, and a `PageTable`
        // is exactly what lives at the start of a page table frame.
        let table: &PageTable = unsafe { &*table_virt.as_ptr() };
        let flags = table[index].flags();

        if !flags.contains(PageTableFlags::PRESENT)
            || !flags.contains(PageTableFlags::USER_ACCESSIBLE)
        {
            return false;
        }

        // WRITABLE is checked at every level for the same reason
        // USER_ACCESSIBLE is: on x86_64 the effective permission for a
        // page is the *conjunction* of the flags along its entire path,
        // so a leaf marked writable beneath a read-only parent is not
        // actually writable. Requiring it at each level matches how the
        // hardware resolves it rather than approximating.
        if require_writable && !flags.contains(PageTableFlags::WRITABLE) {
            return false;
        }

        // A huge page ends the walk early - the translation is already
        // resolved, and its flags (just checked) are the ones that
        // govern it. Only meaningful at the L3/L2 levels: at L1 the same
        // bit position means PAT, so testing it there would misread an
        // ordinary 4 KiB entry.
        if level < 3 && flags.contains(PageTableFlags::HUGE_PAGE) {
            return true;
        }

        frame = PhysFrame::containing_address(table[index].addr());
    }

    true
}

/// The largest single buffer a syscall will copy in or out.
///
/// A limit is required, not merely prudent. `copy_from_user` allocates a
/// kernel buffer sized by a length the *caller* chose; without a cap, a
/// user program asks for a 100 GiB write and the kernel either exhausts
/// its heap trying to honour it or panics in the allocator. Both are a
/// denial of service handed out through a perfectly ordinary syscall.
/// 1 MiB is comfortably larger than any legitimate single call today and
/// small enough that even a program calling it in a tight loop cannot
/// outrun the heap.
pub const MAX_USER_TRANSFER: usize = 1024 * 1024;

/// Copies `len` bytes out of a user buffer into kernel memory.
///
/// This, not raw pointer arithmetic, is how a syscall should read a user
/// buffer. Two things it does that a bare `from_raw_parts` at the call
/// site would not:
///
/// 1. It validates the *whole* range against the page tables first (see
///    `user_range_is_accessible`), so there is exactly one place that
///    check can be forgotten rather than one per syscall.
/// 2. It **copies**, rather than lending the kernel a reference into
///    memory the user still controls. That distinction matters more than
///    it looks: a borrowed user buffer is a time-of-check/time-of-use
///    hazard the moment anything can run between the check and the use -
///    another thread in the same address space, or a page fault handler,
///    could change the bytes after they were validated but before they
///    were acted on. Copying collapses check and use into one moment.
///    Today this kernel is single-core with no user threads, so the race
///    is not yet reachable; building the interface to be safe *now* is
///    much cheaper than auditing every syscall for it later.
pub fn copy_from_user(ptr: u64, len: usize) -> Option<alloc::vec::Vec<u8>> {
    if len > MAX_USER_TRANSFER {
        return None;
    }
    if !user_range_is_accessible(ptr, len as u64) {
        return None;
    }

    let mut buffer = alloc::vec::Vec::with_capacity(len);

    // Safety: `user_range_is_accessible` has just confirmed every page of
    // `ptr..ptr + len` is present and user-accessible in the active page
    // tables, so the read is in-bounds and cannot fault. `buffer` has
    // capacity for exactly `len` bytes and the two regions cannot overlap
    // (one is user memory in the lower half, the other a kernel heap
    // allocation in the higher half).
    unsafe {
        core::ptr::copy_nonoverlapping(ptr as *const u8, buffer.as_mut_ptr(), len);
        buffer.set_len(len);
    }

    Some(buffer)
}

/// Copies `bytes` into a user buffer, returning how many were written.
///
/// Refuses rather than truncating silently if the destination is not a
/// writable user range: a partial write to a buffer the program cannot
/// actually see would be indistinguishable, from userland, from a
/// successful one.
pub fn copy_to_user(ptr: u64, bytes: &[u8]) -> Option<usize> {
    if bytes.len() > MAX_USER_TRANSFER {
        return None;
    }
    if !user_range_is_writable(ptr, bytes.len() as u64) {
        return None;
    }

    // Safety: `user_range_is_writable` has just confirmed every page of
    // the destination is present, user-accessible and writable. The
    // source is a kernel slice, and kernel and user memory are in
    // different halves of the address space, so they cannot overlap.
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr as *mut u8, bytes.len());
    }

    Some(bytes.len())
}

/// Like `user_range_is_accessible`, but also requires every page to be
/// writable.
///
/// A separate function rather than a flag argument, so that a call site
/// reading `user_range_is_writable(...)` states which of the two checks
/// it wanted. Writing through a range that was only validated as
/// *readable* would let a user program get the kernel to write into its
/// own read-only pages - which, on a page marked read-only precisely
/// because it holds a program's code, is a W^X bypass with the kernel as
/// the confused deputy.
pub fn user_range_is_writable(start: u64, len: u64) -> bool {
    range_is_user(start, len, true)
}

/// How many top-level (PML4) entries are present in each half of the
/// address space right now: `(lower_half, higher_half)`.
///
/// Exists to *verify* the split `mm::layout` describes rather than assume
/// it. `BOOTLOADER_CONFIG` asks the bootloader to place every dynamic
/// mapping above `layout::HIGHER_HALF_START`, but a request is not a
/// guarantee - a future bootloader version could ignore the field, or a
/// mapping this kernel makes itself could land in the wrong half by
/// accident. Either way the symptom would not be a crash: it would be
/// per-process address spaces silently sharing a page table entry with
/// the kernel, which is a security boundary quietly ceasing to exist.
/// Counting the entries is a two-line check that turns that into a
/// visible boot-time failure.
pub fn pml4_entries_in_use() -> (usize, usize) {
    use x86_64::registers::control::Cr3;

    let offset = PHYSICAL_MEMORY_OFFSET.load(Ordering::SeqCst);
    assert_ne!(
        offset, OFFSET_UNINITIALIZED,
        "pml4_entries_in_use called before memory::init"
    );

    let (frame, _) = Cr3::read();
    let table_virt = VirtAddr::new(offset) + frame.start_address().as_u64();

    // Safety: `offset` is the bootloader's physical-memory mapping offset
    // recorded by `init`, so this address reads the active PML4 through
    // that mapping. A shared reference only - nothing here mutates a page
    // table or aliases the `&mut` that `kernel_main`'s `OffsetPageTable`
    // holds.
    let table: &PageTable = unsafe { &*table_virt.as_ptr() };

    let mut lower = 0;
    let mut higher = 0;
    for (index, entry) in table.iter().enumerate() {
        if !entry.flags().contains(PageTableFlags::PRESENT) {
            continue;
        }
        if index < crate::mm::layout::KERNEL_PML4_FIRST_INDEX {
            lower += 1;
        } else {
            higher += 1;
        }
    }

    (lower, higher)
}

/// Removes every lower-half mapping the bootloader left behind, and
/// reports which top-level entries were cleared.
///
/// There is normally exactly one. A bootloader cannot simply load CR3
/// with the kernel's new page table and carry on - the very next
/// instruction fetch would come from an address that table does not map,
/// which is an instant triple fault. The standard solution, and the one
/// `bootloader` 0.11 uses, is to identity-map the small stub that
/// performs the switch, so that the same physical address is valid before
/// and after. That leaves one PML4 entry covering low memory pointing at
/// bootloader code the kernel has long since stopped needing.
///
/// Harmless in a kernel with a single address space. Not harmless here:
/// per-process address spaces are built by giving each process its own
/// lower half, and an inherited entry there would be a page of *someone
/// else's* memory mapped into every process, at a low address, executable
/// (nothing sets NX on it), for the entire life of the machine. That is a
/// gadget source and an information leak, handed to every program on the
/// system, for no benefit at all - the code it maps can never run again.
///
/// So it is unmapped rather than tolerated. The frames themselves are not
/// returned to the allocator: they sit in regions the bootloader marked
/// as its own rather than `Usable`, so the frame allocator was never
/// going to hand them out anyway, and pretending to free memory this
/// module does not own would be worse than leaving a few pages of low
/// memory unused forever.
///
/// # Safety
/// Nothing may still be executing from, or holding a pointer into, any
/// lower-half address. In practice that means this must run before the
/// first user process is created and after the kernel has switched to its
/// own stack - both true at the point `kernel_main` calls it.
pub unsafe fn clear_lower_half_mappings() -> alloc::vec::Vec<usize> {
    use x86_64::registers::control::Cr3;

    let offset = PHYSICAL_MEMORY_OFFSET.load(Ordering::SeqCst);
    assert_ne!(
        offset, OFFSET_UNINITIALIZED,
        "clear_lower_half_mappings called before memory::init"
    );

    let (frame, flags) = Cr3::read();
    let table_virt = VirtAddr::new(offset) + frame.start_address().as_u64();

    // Safety: forwarded from this function's contract. `table_virt`
    // reaches the active PML4 through the bootloader's physical-memory
    // mapping, and this is the only `&mut` to it in existence for the
    // duration of this function - `kernel_main`'s `OffsetPageTable` is
    // not borrowed across this call.
    let table: &mut PageTable = unsafe { &mut *table_virt.as_mut_ptr() };

    let mut cleared = alloc::vec::Vec::new();
    for index in 0..crate::mm::layout::KERNEL_PML4_FIRST_INDEX {
        if table[index].flags().contains(PageTableFlags::PRESENT) {
            table[index].set_unused();
            cleared.push(index);
        }
    }

    if !cleared.is_empty() {
        // Reloading CR3 flushes the entire TLB, which is what makes the
        // removal take effect. A targeted `invlpg` is not usable here:
        // clearing a top-level entry invalidates an enormous range
        // (512 GiB per entry), and there is no instruction that
        // invalidates a range rather than a page.
        //
        // Safety: writing back the value just read, with the same flags -
        // this changes nothing about which table is active, and exists
        // purely for its TLB-flushing side effect.
        unsafe {
            Cr3::write(frame, flags);
        }
    }

    cleared
}

/// Hands out unused physical frames from the memory map the bootloader
/// already computed during boot.
///
/// A bump allocator, not a general-purpose one: frames are never
/// returned to the pool, and there is no way to free one. That's a real,
/// deliberate limitation rather than an oversight - see the module-level
/// note above.
pub struct BootInfoFrameAllocator {
    memory_regions: &'static MemoryRegions,
    /// Which entry of `memory_regions` the next frame will come from.
    region_index: usize,
    /// The next frame-aligned physical address to hand out within that
    /// region - not a count of how many frames have been given out
    /// overall, which is what an earlier version of this allocator
    /// tracked instead (see the fix note below).
    next_addr: u64,
}

impl BootInfoFrameAllocator {
    /// # Safety
    /// The caller must guarantee that every region `memory_regions`
    /// marks `Usable` is, in fact, currently unused physical memory. This
    /// is trusted here because it comes directly from the
    /// bootloader-provided boot info - the same trust boundary the rest
    /// of early boot already depends on.
    pub unsafe fn init(memory_regions: &'static MemoryRegions) -> Self {
        let mut allocator = BootInfoFrameAllocator {
            memory_regions,
            region_index: 0,
            next_addr: 0,
        };
        allocator.skip_to_usable_region();
        allocator
    }

    /// Advances `region_index` forward until it lands on a `Usable`
    /// region (or runs off the end of the map entirely), and sets
    /// `next_addr` to that region's start. Called both from `init` and
    /// from `allocate_frame` whenever the current region is exhausted.
    fn skip_to_usable_region(&mut self) {
        while self.region_index < self.memory_regions.len() {
            let region = &self.memory_regions[self.region_index];
            if region.kind == MemoryRegionKind::Usable {
                self.next_addr = region.start;
                return;
            }
            self.region_index += 1;
        }
    }
}

// Safety: every frame this yields comes from a region the bootloader
// marked `Usable`, is 4 KiB-aligned (regions themselves are page-aligned,
// and `next_addr` only ever advances by exactly 4096), and every address
// handed out is strictly less than the last one before it - no frame is
// ever repeated.
unsafe impl FrameAllocator<Size4KiB> for BootInfoFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        // Fix note: the original version of this allocator called
        // `self.usable_frames().nth(self.next)` here, rebuilding and
        // re-walking the *entire* iterator chain over every usable
        // region from scratch on every single call, just to throw away
        // the first `next` results each time. That's O(n) work per
        // allocation and O(n^2) total - invisible at the scale of a few
        // hundred calls (a heap, a handful of task stacks, a couple of
        // ELF segments), but exactly the kind of thing that turns into a
        // real, measurable slowdown the moment this kernel does anything
        // at real-machine memory scale. Tracking a cursor directly
        // (`region_index` + `next_addr`) makes each call O(1) amortized:
        // it either returns immediately or advances past a region
        // exactly once, ever, for the lifetime of the allocator.
        loop {
            if self.region_index >= self.memory_regions.len() {
                return None;
            }

            let region = &self.memory_regions[self.region_index];
            if region.kind != MemoryRegionKind::Usable || self.next_addr + 4096 > region.end {
                self.region_index += 1;
                self.skip_to_usable_region();
                continue;
            }

            let frame_addr = self.next_addr;
            self.next_addr += 4096;
            return Some(PhysFrame::containing_address(PhysAddr::new(frame_addr)));
        }
    }
}