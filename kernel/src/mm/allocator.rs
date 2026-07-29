//! Kernel heap setup.
//!
//! Nothing before this milestone could use `alloc` - no `Box`, `Vec`,
//! `String`, none of it, because there was nowhere for them to allocate
//! from. This module maps a fixed virtual address range to real physical
//! frames and registers a global allocator over it, so `alloc` actually
//! works kernel-wide from here on.

use core::alloc::{GlobalAlloc, Layout};
use linked_list_allocator::LockedHeap;
use x86_64::{
    structures::paging::{mapper::MapToError, FrameAllocator, Mapper, Page, PageTableFlags, Size4KiB},
    VirtAddr,
};

/// Start of the kernel heap in virtual address space.
///
/// Now defined in `mm::layout` rather than here, because *which half of
/// the address space this lands in* is a property of the whole system's
/// memory map, not of the allocator. It used to be `0x4444_4444_0000` -
/// lower half - which made per-process address spaces impossible; see the
/// module docs in `mm::layout` for the full reasoning.
pub const HEAP_START: usize = crate::mm::layout::KERNEL_HEAP_START as usize;

/// See `mm::layout::KERNEL_HEAP_SIZE`.
pub const HEAP_SIZE: usize = crate::mm::layout::KERNEL_HEAP_SIZE;

/// A `LockedHeap` that cannot be interrupted while it holds its own lock.
///
/// This is a fix for a real deadlock, not defensive decoration. The
/// underlying `LockedHeap` guards itself with a `spin::Mutex`, which is
/// correct against another *core* but not against an *interrupt on the
/// same core*, and this kernel gained exactly that hazard when preemption
/// landed:
///
/// 1. Task A calls `alloc` and takes the heap lock.
/// 2. A timer interrupt preempts A mid-allocation and switches to task B.
/// 3. B disables interrupts (every scheduler-lock acquisition outside an
///    interrupt handler does - see `sched::task::spawn`) and calls
///    `alloc`, e.g. to build a new task's stack.
/// 4. B spins on a lock held by A, with interrupts disabled, so A can
///    never be scheduled again to release it. The machine is dead, with
///    no fault, no message, and no way to tell it apart from a hang
///    anywhere else.
///
/// Single-core makes this *unlikely*, not impossible - it needs a timer
/// tick to land inside the handful of instructions the allocator holds
/// its lock for. That is precisely the kind of bug that survives every
/// test run and then reproduces once, unrepeatably, on someone else's
/// machine.
///
/// Disabling interrupts for the duration of the critical section closes
/// it: on a single core, an allocation can no longer be interrupted
/// part-way, so no other context can arrive to contend for the lock at
/// all. `without_interrupts` restores the previous flag rather than
/// unconditionally enabling, so this is safe to call from inside an
/// interrupt handler too (where interrupts are already off and must stay
/// off).
///
/// The cost is bounded by how long the linked-list allocator holds its
/// lock, which is a short list walk - acceptable interrupt latency today,
/// and a thing to revisit if the Gaming Realm's latency budget ever gets
/// tight enough to measure it. When SMP arrives this stops being
/// sufficient on its own (interrupts-off does nothing about another
/// core), and the answer then is per-core allocation caches rather than a
/// bigger hammer here.
struct InterruptSafeHeap(LockedHeap);

// Safety: every method forwards to `LockedHeap`'s own implementation
// under the same contract, with the sole addition of an
// interrupts-disabled window around it. That neither weakens any
// guarantee `GlobalAlloc` requires nor changes which pointer is returned.
unsafe impl GlobalAlloc for InterruptSafeHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Safety: forwarded verbatim from this method's own contract.
        x86_64::instructions::interrupts::without_interrupts(|| unsafe { self.0.alloc(layout) })
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // Safety: forwarded verbatim - `ptr`/`layout` are the caller's
        // responsibility exactly as they would be without this wrapper.
        x86_64::instructions::interrupts::without_interrupts(|| unsafe {
            self.0.dealloc(ptr, layout)
        })
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // Safety: forwarded verbatim. Wrapping `realloc` too, rather than
        // letting the default implementation decompose it into
        // alloc+copy+dealloc, keeps the whole operation inside one
        // interrupts-disabled window instead of three.
        x86_64::instructions::interrupts::without_interrupts(|| unsafe {
            self.0.realloc(ptr, layout, new_size)
        })
    }
}

#[global_allocator]
static ALLOCATOR: InterruptSafeHeap = InterruptSafeHeap(LockedHeap::empty());

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
        ALLOCATOR.0.lock().init(HEAP_START as *mut u8, HEAP_SIZE);
    }

    Ok(())
}

/// `(bytes in use, bytes free)` on the kernel heap.
///
/// Reported in the boot log rather than kept for a debugger, because heap
/// exhaustion is one of the few kernel failures that has a *gradual*
/// symptom: nothing breaks until an allocation returns null, and by then
/// the interesting question - which subsystem grew - is unanswerable from
/// the crash alone. Printing the number before and after each major
/// subsystem initializes turns "we ran out" into "we ran out and here is
/// where it went."
pub fn heap_stats() -> (usize, usize) {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let heap = ALLOCATOR.0.lock();
        (heap.used(), heap.free())
    })
}
