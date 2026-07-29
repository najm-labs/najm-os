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
        if !unsafe { page_is_user_accessible(addr, offset) } {
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
unsafe fn page_is_user_accessible(addr: VirtAddr, physical_memory_offset: VirtAddr) -> bool {
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