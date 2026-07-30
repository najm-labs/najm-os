//! A free list of physical frames, so memory can actually be given back.
//!
//! `BootInfoFrameAllocator` is a bump allocator: it walks the
//! bootloader's memory map handing out the next frame, forever, and has
//! no `deallocate_frame` at all. That was an honest choice while nothing
//! in the kernel ever freed memory - building a free-capable allocator
//! against a workload that did not exist would have been designing
//! backwards.
//!
//! Per-process address spaces are the workload. A process that exits owns
//! a PML4, three or four intermediate page tables, its code and data
//! pages and its stack - call it twenty to thirty frames. Without a way
//! to return them, "reclaiming a process's memory" is a phrase rather
//! than a behaviour: the frames are unmapped and then never seen again,
//! and a machine that launches programs in a loop runs out of physical
//! memory at a rate set by how often programs start rather than by how
//! much memory they use at once.
//!
//! ## Deliberately a free list and not an allocator
//!
//! This does not merge adjacent frames, track sizes, or serve anything
//! but 4 KiB frames. It does not need to: every consumer wants exactly
//! one 4 KiB frame, so there is nothing for a size class or a buddy
//! system to be better at. What it does need to be is *fast and
//! predictable*, because it is reached from the page fault path and from
//! process teardown, and it needs to never fragment, which a
//! uniform-size free list cannot.
//!
//! ## The correctness property that matters
//!
//! A frame must be released exactly once, and must not be mapped
//! anywhere when it is. Releasing a still-mapped frame hands one
//! process's live memory to the next process that asks - the single worst
//! bug this module could have, because it produces no fault and no
//! symptom until two unrelated programs start seeing each other's data.
//!
//! The discipline that prevents it is ownership rather than checking:
//! `AddressSpace` records every frame it allocates and is the only thing
//! that releases them, from `Drop`, at which point its page tables are
//! about to cease existing. `release` additionally refuses a frame it
//! already holds, which catches a double-free at the cost of a linear
//! scan - affordable at these list lengths, and worth far more than the
//! nanoseconds it costs.

use alloc::vec::Vec;
use spin::Mutex;
use x86_64::structures::paging::{PhysFrame, Size4KiB};

static FREE_FRAMES: Mutex<Vec<PhysFrame>> = Mutex::new(Vec::new());

/// Total frames ever released, for the boot report.
static RELEASED: Mutex<u64> = Mutex::new(0);

/// Hands a frame back for reuse.
///
/// Ignores a frame that is already in the list rather than corrupting it.
/// A double release is a bug in the caller, but the consequence of
/// *acting* on one - the same frame handed to two different address
/// spaces - is so much worse than the consequence of dropping it that
/// refusing is clearly right, and it is reported so the bug is still
/// visible.
pub fn release(frame: PhysFrame<Size4KiB>) {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut free = FREE_FRAMES.lock();
        if free.contains(&frame) {
            crate::serial_println!(
                "Najm Kernel: FRAME POOL FAILURE - frame {:#x} released twice; ignoring the \
                 second release rather than handing the same physical memory to two address \
                 spaces",
                frame.start_address().as_u64()
            );
            return;
        }
        free.push(frame);
        *RELEASED.lock() += 1;
    });
}

/// Takes a frame from the free list, if there is one.
///
/// Called by `BootInfoFrameAllocator::allocate_frame` before it falls
/// back to bumping, so reuse is automatic for every caller rather than
/// something each one has to remember to try first.
pub fn acquire() -> Option<PhysFrame<Size4KiB>> {
    // Not `without_interrupts` here: this is called from inside
    // `with_memory`, which has already disabled them. Disabling again
    // would be harmless but would obscure that this function has no
    // business being called from an interrupts-enabled context in the
    // first place - it is an allocator internal, not a public entry
    // point.
    FREE_FRAMES.lock().pop()
}

/// `(frames currently free for reuse, frames ever released)`.
pub fn stats() -> (usize, u64) {
    x86_64::instructions::interrupts::without_interrupts(|| {
        (FREE_FRAMES.lock().len(), *RELEASED.lock())
    })
}
