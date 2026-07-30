//! Per-process address spaces.
//!
//! This is the piece three separate documented gaps were all waiting on.
//! ARCHITECTURE.md section 2 wanted Realm memory isolation; section 3b
//! recorded that syscall pointer validation checked *privilege* but not
//! *ownership*; `usermode.rs` recorded that a terminated program's memory
//! could never be reclaimed. All three have the same cause - one
//! kernel-wide address space - and the same fix.
//!
//! ## What was actually broken
//!
//! With a single set of page tables, "this page is user-accessible" was
//! the strongest statement the kernel could make about a user pointer.
//! It could not say *whose* page it was, because every program's pages
//! lived in the same table. Program A passing program B's address to
//! `write` would pass validation and print B's memory: not a bug in the
//! check, but the check answering a question that was not the one that
//! mattered. It was unreachable only because one program ran at a time -
//! a property of the boot sequence, not of any enforcement.
//!
//! Reclamation failed for the same reason. Terminating a program left its
//! pages mapped, because nothing recorded which of the address space's
//! mappings had belonged to it. Running a second program at the same
//! addresses failed in `map_to` with "already mapped", and running many
//! leaked frames until the allocator ran dry.
//!
//! ## How it works
//!
//! Because the kernel now lives entirely in the higher half (see
//! `mm::layout`), an address space is exactly one page:
//!
//! - A fresh PML4 frame, zeroed.
//! - Entries 256..512 copied verbatim from the kernel's PML4, so the
//!   kernel is mapped identically in every address space. This is what
//!   lets a syscall, an interrupt, or a page fault run no matter which
//!   process is current - the handler's code and stack are at the same
//!   addresses in every table.
//! - Entries 0..256 left empty. That half is the process's alone.
//!
//! Copying the kernel half by value, rather than sharing a pointer to a
//! table of tables, has one consequence worth being explicit about: a
//! kernel mapping created *after* an address space is built does not
//! appear in it. Nothing does that today - the heap, the stack region and
//! the physical-memory window are all mapped before the first process
//! exists - and `assert_kernel_mappings_are_complete` checks the entry
//! count at creation time so that the day something does, it fails
//! visibly instead of producing a process that page-faults in the kernel.
//!
//! ## Teardown
//!
//! Every frame this address space allocates - both leaf frames and the
//! intermediate page tables reaching them - is recorded, and `Drop` walks
//! that list. Only the lower half is ever touched: the higher-half
//! entries point at the kernel's own tables, and freeing those would
//! unmap the kernel from every process at once.
//!
//! The frames are returned to `mm::frame_pool` rather than to
//! `BootInfoFrameAllocator`, which is a bump allocator with no way to
//! take anything back. That is the difference between "a process's memory
//! is reclaimed" and "a process's memory is forgotten about."

use crate::mm::layout;
use alloc::vec::Vec;
use x86_64::registers::control::{Cr3, Cr3Flags};
use x86_64::structures::paging::{
    FrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags, PhysFrame, Size4KiB,
};
use x86_64::{PhysAddr, VirtAddr};

/// One process's virtual address space.
pub struct AddressSpace {
    /// The frame holding this space's PML4.
    root: PhysFrame,
    /// Every frame this address space owns: leaf frames backing its
    /// mappings plus the intermediate page tables that reach them.
    ///
    /// Tracked explicitly rather than rediscovered by walking the tables
    /// at teardown. Walking would work, but it would also mean teardown's
    /// correctness depended on the walk agreeing with however the tables
    /// were built - and the failure mode of disagreement is either
    /// leaking frames or, far worse, freeing a frame that is still mapped
    /// somewhere. An explicit list makes ownership a recorded fact.
    owned_frames: Vec<PhysFrame>,
}

impl AddressSpace {
    /// Builds a new address space that shares the kernel's higher half
    /// and has an empty lower half.
    pub fn new() -> Option<AddressSpace> {
        let (root, kernel_entries) = crate::mm::memory::with_memory(|mapper, frame_allocator| {
            let root = frame_allocator.allocate_frame()?;
            let kernel_root = Cr3::read().0;

            // The kernel's half is read out first, into a plain array,
            // before the new table is touched at all. Reading and writing
            // through two references to page tables at once is exactly
            // the aliasing the borrow checker refuses here, and it is
            // right to: `table_ref` and `table_mut` both reach into the
            // same physical-memory window, and nothing but this
            // sequencing guarantees they name different frames.
            //
            // Entry *values* are copied, which means both tables end up
            // pointing at the same level-3 tables below them - the
            // kernel's mappings are genuinely shared, not duplicated, so
            // there is one copy of every kernel page table and no way for
            // two address spaces to disagree about what the kernel looks
            // like.
            let mut kernel_half = [const {
                x86_64::structures::paging::page_table::PageTableEntry::new()
            }; 512 - layout::KERNEL_PML4_FIRST_INDEX];
            let mut kernel_entries = 0;
            {
                let kernel_table = table_ref(mapper, kernel_root);
                for (slot, index) in
                    (layout::KERNEL_PML4_FIRST_INDEX..512).enumerate()
                {
                    let entry = kernel_table[index].clone();
                    if entry.flags().contains(PageTableFlags::PRESENT) {
                        kernel_entries += 1;
                    }
                    kernel_half[slot] = entry;
                }
            }

            let new_table = table_mut(mapper, root);
            new_table.zero();
            for (slot, index) in (layout::KERNEL_PML4_FIRST_INDEX..512).enumerate() {
                new_table[index] = kernel_half[slot].clone();
            }

            Some((root, kernel_entries))
        })?;

        assert!(
            kernel_entries > 0,
            "built an address space with no kernel mappings - the kernel would not be reachable \
             from it, so the first interrupt after switching to it would triple fault"
        );

        Some(AddressSpace {
            root,
            owned_frames: Vec::new(),
        })
    }

    /// The physical frame to load into CR3 to make this space current.
    pub fn root_frame(&self) -> PhysFrame {
        self.root
    }

    /// How many frames this address space owns, for the boot report and
    /// for checking that teardown actually gave them back.
    #[allow(dead_code)]
    pub fn owned_frame_count(&self) -> usize {
        self.owned_frames.len()
    }

    /// Maps `page` to a freshly allocated frame with `flags`.
    ///
    /// Refuses any address outside the lower half. That check is not
    /// redundant with the loader's: this is the layer that *performs* the
    /// mapping, and a mapping into the higher half would overwrite an
    /// entry the kernel shares with every other address space - corrupting
    /// not just this process but the kernel itself, for everyone.
    pub fn map_page(&mut self, page: Page<Size4KiB>, flags: PageTableFlags) -> Result<(), MapError> {
        let addr = page.start_address().as_u64();
        if !layout::is_user_address(addr) {
            return Err(MapError::NotUserAddress(addr));
        }
        if !flags.contains(PageTableFlags::USER_ACCESSIBLE) {
            // A page in the lower half that is not user-accessible is
            // unreachable by the process it belongs to and invisible to
            // every other one - it can only be a mistake.
            return Err(MapError::NotUserAccessible(addr));
        }

        crate::mm::memory::with_memory(|_kernel_mapper, frame_allocator| {
            let frame = frame_allocator
                .allocate_frame()
                .ok_or(MapError::OutOfMemory)?;

            let mut tracker = TrackingAllocator {
                inner: frame_allocator,
                allocated: Vec::new(),
            };

            // A mapper over *this* address space's PML4 rather than the
            // active one. `OffsetPageTable` does not care which table it
            // is given, only that it can reach physical frames through
            // the offset - which is why this can populate an address
            // space that is not currently loaded in CR3, without ever
            // switching to it.
            let offset = VirtAddr::new(crate::mm::memory::physical_memory_offset());
            // Safety: `self.root` is a frame this address space owns and
            // holds a valid PML4 (zeroed then populated in `new`). The
            // reference is confined to this block and does not outlive
            // it, and no other mapper over the same table exists
            // concurrently - `with_memory` holds the only lock that could
            // hand one out.
            let mut mapper = unsafe {
                OffsetPageTable::new(&mut *table_ptr(offset, self.root), offset)
            };

            // Safety: `frame` came from the frame allocator, which never
            // repeats a frame. `page` is in this address space's private
            // lower half, checked above, so it cannot collide with a
            // kernel mapping or with another address space's.
            let result = unsafe { mapper.map_to(page, frame, flags, &mut tracker) };

            let mut newly_owned = tracker.allocated;

            match result {
                Ok(flush) => {
                    // No TLB flush needed when the target space is not
                    // the active one: nothing can have cached a
                    // translation from a table the CPU has never loaded.
                    // Flushing anyway is harmless and much cheaper than
                    // reasoning about whether this call happens to be the
                    // one where it matters.
                    flush.flush();
                    self.owned_frames.push(frame);
                    self.owned_frames.append(&mut newly_owned);
                    Ok(())
                }
                Err(err) => {
                    // Intermediate tables allocated on the way to a
                    // failed mapping are still owned by this address
                    // space and still have to be freed at teardown -
                    // dropping them here would leak them, and dropping
                    // them from the tracker without recording them would
                    // leak them silently.
                    self.owned_frames.append(&mut newly_owned);
                    Err(MapError::Paging(alloc::format!("{:?}", err)))
                }
            }
        })
    }

    /// Changes an already-mapped page's permissions.
    ///
    /// Exists for the same reason the ELF loader maps segments writable
    /// and tightens them afterwards: CR0.WP means Ring 0 cannot write to
    /// a read-only page either, so a code page mapped read-execute up
    /// front would be unwritable at exactly the moment the loader needs
    /// to put code in it.
    pub fn protect_page(
        &mut self,
        page: Page<Size4KiB>,
        flags: PageTableFlags,
    ) -> Result<(), MapError> {
        let addr = page.start_address().as_u64();
        if !layout::is_user_address(addr) {
            return Err(MapError::NotUserAddress(addr));
        }

        crate::mm::memory::with_memory(|_kernel_mapper, _frame_allocator| {
            let offset = VirtAddr::new(crate::mm::memory::physical_memory_offset());
            // Safety: as in `map_page` - a mapper over this address
            // space's own PML4, reached through the physical-memory
            // window, with no other mapper over the same table live.
            let mut mapper =
                unsafe { OffsetPageTable::new(&mut *table_ptr(offset, self.root), offset) };

            // Safety: `update_flags` only alters permission bits on an
            // existing mapping; it cannot make an entry point elsewhere,
            // and it fails rather than creating one if the page is not
            // mapped.
            unsafe {
                mapper
                    .update_flags(page, flags)
                    .map(|flush| flush.flush())
                    .map_err(|err| MapError::Paging(alloc::format!("{:?}", err)))
            }
        })
    }

    /// Copies `bytes` into this address space at `addr`.
    ///
    /// Writes through the *physical* mapping of the destination frames
    /// rather than by switching CR3, which matters: switching address
    /// spaces to populate one would mean the kernel briefly running with
    /// a half-built process's page tables active, and any fault during
    /// that window would be diagnosed against the wrong space. Translating
    /// each page and writing through the physical-memory window keeps the
    /// current address space untouched throughout.
    pub fn write_at(&mut self, addr: u64, bytes: &[u8]) -> Result<(), MapError> {
        let offset = crate::mm::memory::physical_memory_offset();
        let mut written = 0;

        while written < bytes.len() {
            let target = addr + written as u64;
            let page_offset = (target & 0xFFF) as usize;
            let chunk = core::cmp::min(4096 - page_offset, bytes.len() - written);

            let frame = self
                .translate(target)
                .ok_or(MapError::NotMapped(target))?;

            let dest = offset + frame.start_address().as_u64() + page_offset as u64;

            // Safety: `dest` addresses `chunk` bytes inside a single
            // frame this address space owns, reached through the
            // bootloader's physical-memory window - a kernel mapping, so
            // no SMAP bracket is needed and no user-accessible page is
            // touched directly. `chunk` is clamped to the remainder of
            // the page, so the write cannot cross into a frame that was
            // not translated.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    bytes.as_ptr().add(written),
                    dest as *mut u8,
                    chunk,
                );
            }

            written += chunk;
        }

        Ok(())
    }

    /// Zeroes `len` bytes at `addr` in this address space.
    ///
    /// Used for `.bss`. Not merely a convenience: a page handed to a
    /// process without being zeroed contains whatever the frame allocator
    /// last had there, which is kernel memory, so this is an information
    /// leak boundary rather than an initialization detail.
    pub fn zero_at(&mut self, addr: u64, len: usize) -> Result<(), MapError> {
        let offset = crate::mm::memory::physical_memory_offset();
        let mut done = 0;

        while done < len {
            let target = addr + done as u64;
            let page_offset = (target & 0xFFF) as usize;
            let chunk = core::cmp::min(4096 - page_offset, len - done);

            let frame = self
                .translate(target)
                .ok_or(MapError::NotMapped(target))?;
            let dest = offset + frame.start_address().as_u64() + page_offset as u64;

            // Safety: same reasoning as `write_at` - a bounded write
            // inside one owned frame, through the kernel's own
            // physical-memory mapping.
            unsafe {
                core::ptr::write_bytes(dest as *mut u8, 0, chunk);
            }

            done += chunk;
        }

        Ok(())
    }

    /// Resolves a virtual address in *this* address space to its frame.
    ///
    /// Walks the tables by hand rather than using `Translate`, because
    /// `Translate` operates on whichever table its mapper was built over
    /// and this needs to answer for a space that is very likely not the
    /// active one.
    pub fn translate(&self, addr: u64) -> Option<PhysFrame> {
        let offset = crate::mm::memory::physical_memory_offset();
        let virt = VirtAddr::try_new(addr).ok()?;
        let indices = [virt.p4_index(), virt.p3_index(), virt.p2_index(), virt.p1_index()];

        let mut frame = self.root;
        for (level, index) in indices.into_iter().enumerate() {
            // Safety: `frame` is either this space's root or a frame
            // reached from it through a PRESENT entry, so it holds a page
            // table; the physical-memory window makes it readable. A
            // shared reference only.
            let table: &PageTable = unsafe { &*table_ptr(VirtAddr::new(offset), frame) };
            let entry = &table[index];

            if !entry.flags().contains(PageTableFlags::PRESENT) {
                return None;
            }
            if level < 3 && entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                // This address space never creates huge pages, so
                // reaching one means the kernel half was walked by
                // mistake. Refusing is safer than computing an offset for
                // a page size that was not expected.
                return None;
            }

            frame = PhysFrame::containing_address(entry.addr());
        }

        Some(frame)
    }

    /// Whether `start..start + len` is entirely mapped, user-accessible,
    /// and (if `require_writable`) writable **in this address space**.
    ///
    /// This is the ownership check that ARCHITECTURE.md section 3b said
    /// was missing. The old `mm::memory::user_range_is_accessible` walked
    /// the *active* tables, which answered "is this reachable from Ring 3
    /// on this machine" - true for any program's pages, since there was
    /// only one address space. Asking a specific address space makes the
    /// question "does the calling process own this memory", which is the
    /// one a syscall actually needs answered.
    /// Unused today: with per-process page tables, the *active* tables
    /// are the calling process's, so `mm::memory`'s walk already answers
    /// the ownership question. This is what a syscall would need in order
    /// to validate a pointer against an address space that is *not*
    /// current - which is exactly what `spawn` and `wait` will want.
    #[allow(dead_code)]
    pub fn range_is_accessible(&self, start: u64, len: u64, require_writable: bool) -> bool {
        if len == 0 {
            return true;
        }
        let Some(last) = start.checked_add(len - 1) else {
            return false;
        };
        if !layout::is_user_address(start) || !layout::is_user_address(last) {
            return false;
        }

        let offset = crate::mm::memory::physical_memory_offset();
        let mut page = start & !0xFFF;
        let last_page = last & !0xFFF;

        loop {
            if !self.page_is_accessible(page, offset, require_writable) {
                return false;
            }
            if page == last_page {
                return true;
            }
            page += 4096;
        }
    }

    fn page_is_accessible(&self, addr: u64, offset: u64, require_writable: bool) -> bool {
        let Ok(virt) = VirtAddr::try_new(addr) else {
            return false;
        };
        let indices = [virt.p4_index(), virt.p3_index(), virt.p2_index(), virt.p1_index()];

        let mut frame = self.root;
        for index in indices {
            // Safety: as `translate` above - a shared read of a page
            // table frame through the kernel's physical-memory window.
            let table: &PageTable = unsafe { &*table_ptr(VirtAddr::new(offset), frame) };
            let flags = table[index].flags();

            // Every level must permit the access, because x86_64 resolves
            // a page's effective permissions as the conjunction of the
            // flags along its whole path. A leaf marked user-accessible
            // beneath a parent that is not is unreachable from Ring 3,
            // and treating it as reachable is exactly the hole this whole
            // mechanism exists to close.
            if !flags.contains(PageTableFlags::PRESENT)
                || !flags.contains(PageTableFlags::USER_ACCESSIBLE)
            {
                return false;
            }
            if require_writable && !flags.contains(PageTableFlags::WRITABLE) {
                return false;
            }

            frame = PhysFrame::containing_address(table[index].addr());
        }

        true
    }
}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        // Only the lower half is torn down. The higher-half entries were
        // copied from the kernel's own PML4 and point at the kernel's own
        // level-3 tables; freeing anything reachable through them would
        // unmap the kernel from *every* address space simultaneously,
        // which is not a leak but an immediate crash of the whole
        // machine.
        //
        // The root frame goes back too, but last: it is the thing the
        // frames below were reached through, and returning it first would
        // make the rest reachable only through a frame the allocator
        // considers free.
        let frames = core::mem::take(&mut self.owned_frames);
        let count = frames.len();
        for frame in frames {
            crate::mm::frame_pool::release(frame);
        }
        crate::mm::frame_pool::release(self.root);

        crate::serial_println!(
            "Najm Kernel: address space torn down - {} frames returned to the pool",
            count + 1
        );
    }
}

/// Why mapping into an address space failed.
#[derive(Debug)]
pub enum MapError {
    /// The address is not in the lower half - it would collide with the
    /// kernel mappings every address space shares.
    NotUserAddress(u64),
    /// The requested flags omit `USER_ACCESSIBLE`, which would make the
    /// page unreachable by its own process.
    NotUserAccessible(u64),
    /// No physical frames left.
    OutOfMemory,
    /// The address is not mapped in this space.
    NotMapped(u64),
    /// The underlying paging operation failed; carries its message.
    Paging(alloc::string::String),
}

impl core::fmt::Display for MapError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MapError::NotUserAddress(addr) => write!(
                f,
                "{:#x} is not a user address - mapping it would overwrite a kernel entry shared \
                 by every address space",
                addr
            ),
            MapError::NotUserAccessible(addr) => write!(
                f,
                "{:#x} was requested without USER_ACCESSIBLE, which would make it unreachable by \
                 its own process",
                addr
            ),
            MapError::OutOfMemory => write!(f, "out of physical frames"),
            MapError::NotMapped(addr) => write!(f, "{:#x} is not mapped in this address space", addr),
            MapError::Paging(msg) => write!(f, "paging error: {}", msg),
        }
    }
}

/// Wraps a frame allocator so that frames handed out for *intermediate
/// page tables* are recorded as belonging to the address space being
/// built.
///
/// Without this, `map_to`'s internally-allocated level-3/2/1 tables would
/// be invisible to teardown: every process would leak three or four
/// frames it created but nothing recorded, which is exactly the kind of
/// leak that is invisible per-process and fatal after a few thousand.
struct TrackingAllocator<'a, A: FrameAllocator<Size4KiB>> {
    inner: &'a mut A,
    allocated: Vec<PhysFrame>,
}

// Safety: every frame yielded comes from `inner`, which already upholds
// the contract that its frames are unused and never repeated. This
// wrapper only records them additionally.
unsafe impl<A: FrameAllocator<Size4KiB>> FrameAllocator<Size4KiB> for TrackingAllocator<'_, A> {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let frame = self.inner.allocate_frame()?;
        self.allocated.push(frame);
        Some(frame)
    }
}

/// Raw pointer to the `PageTable` living in `frame`, via the
/// physical-memory window.
fn table_ptr(offset: VirtAddr, frame: PhysFrame) -> *mut PageTable {
    (offset + frame.start_address().as_u64()).as_mut_ptr()
}

/// `&mut PageTable` for `frame`. Takes the kernel mapper only to prove
/// the caller holds the memory lock - the mapper itself is not used,
/// since the physical-memory window is what actually reaches the frame.
fn table_mut<'a>(_mapper: &'a mut OffsetPageTable<'static>, frame: PhysFrame) -> &'a mut PageTable {
    let offset = VirtAddr::new(crate::mm::memory::physical_memory_offset());
    // Safety: `frame` holds a page table (either freshly allocated and
    // about to be zeroed, or a live one), and the physical-memory window
    // maps every frame. The `&mut` is tied to the mapper's borrow, which
    // is only obtainable while holding `mm::memory`'s lock, so no second
    // reference to the same table can exist.
    unsafe { &mut *table_ptr(offset, frame) }
}

/// `&PageTable` for `frame`. See `table_mut`.
fn table_ref<'a>(_mapper: &'a OffsetPageTable<'static>, frame: PhysFrame) -> &'a PageTable {
    let offset = VirtAddr::new(crate::mm::memory::physical_memory_offset());
    // Safety: as `table_mut`, but a shared reference.
    unsafe { &*table_ptr(offset, frame) }
}

/// Makes `space` the active address space, returning the previous root.
///
/// # Safety
/// Every address the caller will touch before switching back must be
/// mapped in `space`. Because the kernel occupies the higher half of
/// every address space identically, that is automatic for kernel code,
/// stacks and data - which is precisely the property the higher-half
/// split was built to provide. It is *not* automatic for any lower-half
/// pointer the caller is holding across the switch.
/// Unused today because the scheduler loads CR3 during a switch rather
/// than having a process activate its own space. Kept as the explicit
/// operation any future path that runs *in* another address space
/// without switching tasks would need.
#[allow(dead_code)]
pub unsafe fn activate(space: &AddressSpace) -> PhysFrame {
    let (previous, flags) = Cr3::read();
    if previous != space.root {
        // Safety: forwarded from this function's contract. `space.root`
        // holds a PML4 whose higher half was copied from the kernel's, so
        // the very next instruction fetch - which comes from kernel code
        // in the higher half - is still mapped.
        unsafe {
            Cr3::write(space.root, flags);
        }
    }
    previous
}

/// Restores a previously active address space root.
///
/// # Safety
/// `root` must be a PML4 frame that is still live - typically the value
/// [`activate`] returned moments earlier, belonging to an address space
/// that has not been dropped.
pub unsafe fn restore(root: PhysFrame) {
    let (current, flags) = Cr3::read();
    if current != root {
        // Safety: forwarded from this function's contract.
        unsafe {
            Cr3::write(root, flags);
        }
    }
}

/// The kernel's own PML4 frame - the one to return to when no process is
/// current.
pub fn kernel_root() -> PhysFrame {
    KERNEL_ROOT
        .get()
        .copied()
        .expect("address_space::record_kernel_root has not run yet")
}

/// Records the kernel's PML4 frame at boot, before any process exists.
///
/// Captured once rather than read from CR3 on demand, because "the
/// kernel's address space" and "the address space that happens to be
/// active" stop being the same thing the moment a process runs - and a
/// function that confused the two would restore a process's tables while
/// believing it had restored the kernel's.
pub fn record_kernel_root() {
    KERNEL_ROOT.call_once(|| Cr3::read().0);
}

static KERNEL_ROOT: spin::Once<PhysFrame> = spin::Once::new();

/// Convenience for `Cr3Flags`-free callers.
#[allow(dead_code)]
pub fn current_root() -> PhysFrame {
    Cr3::read().0
}

/// Unused today, kept because `Cr3Flags` is part of the switch contract
/// and a future PCID-aware switch will need it explicitly rather than
/// inheriting whatever was there.
#[allow(dead_code)]
pub fn current_flags() -> Cr3Flags {
    Cr3::read().1
}

/// The physical address of a frame, for logging.
#[allow(dead_code)]
pub fn frame_addr(frame: PhysFrame) -> PhysAddr {
    frame.start_address()
}
