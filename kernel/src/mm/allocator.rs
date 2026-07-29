//! Kernel heap setup.
//!
//! Nothing before this milestone could use `alloc` - no `Box`, `Vec`,
//! `String`, none of it, because there was nowhere for them to allocate
//! from. This module maps a fixed virtual address range to real physical
//! frames and registers a global allocator over it, so `alloc` actually
//! works kernel-wide from here on.

use linked_list_allocator::LockedHeap;
use x86_64::{
    structures::paging::{mapper::MapToError, FrameAllocator, Mapper, Page, PageTableFlags, Size4KiB},
    VirtAddr,
};

/// Start of the kernel heap in virtual address space. Arbitrary but
/// fixed, chosen - following established from-scratch-kernel convention -
/// to sit well clear of the kernel image, stacks, and the bootloader's
/// physical-memory mapping, so it can't collide with any of them.
pub const HEAP_START: usize = 0x_4444_4444_0000;

/// 1 MiB. Bumped up from an earlier, smaller value once task stacks
/// started competing for the same heap: at 16 KiB per task stack (see
/// `task::STACK_SIZE`) plus the small `Box<Task>` metadata allocation
/// per task, even a handful of tasks add up fast against a heap sized
/// only for `Vec`/`Box`/`String` bookkeeping. Still a fixed constant, not
/// dynamically extensible - the real fix, later, is a heap that can grow
/// on demand rather than a bigger guessed number, but that needs more
/// memory-management infrastructure than exists yet.
pub const HEAP_SIZE: usize = 1024 * 1024;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

/// Maps the heap's virtual address range to physical frames and hands
/// that range to the global allocator.
///
/// Must run after `memory::init()` (it needs a working `Mapper`) and
/// before anything anywhere in the kernel tries to use `Box`, `Vec`,
/// `String`, or anything else backed by `alloc` - the global allocator
/// isn't usable until this succeeds.
pub fn init_heap(
    mapper: &mut impl Mapper<Size4KiB>,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> Result<(), MapToError<Size4KiB>> {
    let page_range = {
        let heap_start = VirtAddr::new(HEAP_START as u64);
        let heap_end = heap_start + HEAP_SIZE as u64 - 1u64;
        let heap_start_page = Page::containing_address(heap_start);
        let heap_end_page = Page::containing_address(heap_end);
        Page::range_inclusive(heap_start_page, heap_end_page)
    };

    for page in page_range {
        let frame = frame_allocator
            .allocate_frame()
            .ok_or(MapToError::FrameAllocationFailed)?;
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;

        // Safety: `frame` was just handed out by `frame_allocator`, which
        // only yields frames from bootloader-reported usable regions and
        // never repeats one - it isn't aliased with anything else the
        // kernel is using. `page` falls within HEAP_START..HEAP_START+
        // HEAP_SIZE, the fixed range this module exclusively owns.
        unsafe {
            mapper.map_to(page, frame, flags, frame_allocator)?.flush();
        }
    }

    // Safety: the address range mapped in the loop directly above is
    // exactly HEAP_START..HEAP_START+HEAP_SIZE - identical to what's
    // handed to the allocator here, and this function is the only place
    // `ALLOCATOR.lock().init(...)` is ever called.
    unsafe {
        ALLOCATOR.lock().init(HEAP_START as *mut u8, HEAP_SIZE);
    }

    Ok(())
}
