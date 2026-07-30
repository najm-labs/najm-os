//! Kernel task stacks, each with a guard page beneath it.
//!
//! ## What this replaces, and why
//!
//! Task stacks used to be plain heap allocations:
//! `alloc::alloc(Layout::from_size_align(16 KiB, 16))`. That worked, and
//! it was the right first version - it needed no new machinery and the
//! 16-byte alignment the ABI requires was easy to state explicitly. It
//! had one flaw that could not be fixed where it lived: **a heap
//! allocation cannot have a guard page.** The memory immediately below a
//! task's stack belongs to the allocator and is very likely another live
//! allocation. A task that recurses one frame too deep does not fault; it
//! writes over someone else's data and keeps running, and the damage
//! surfaces later somewhere with no connection to the actual cause. For a
//! kernel, where the "someone else" might be the scheduler's own ready
//! queue, that is close to the worst failure mode available.
//!
//! Stacks therefore get their own virtual region. Each slot is
//! `KERNEL_STACK_SIZE` bytes of mapped stack with one page below it that
//! is **deliberately never mapped**. Overflow touches that page, the CPU
//! raises a page fault, and the fault handler reports it - a diagnosable
//! error instead of silent corruption. The guard page costs one absent
//! page-table entry and no physical memory at all.
//!
//! A second benefit falls out of the same change: stacks no longer
//! compete with the rest of the kernel for heap space, so raising the
//! stack size and raising the heap size stop being the same decision.
//!
//! ## What it does not do yet
//!
//! Slots are handed out by a bump counter and returned to a free list on
//! release, but the physical frames behind a released stack are *not*
//! given back to the frame allocator - `BootInfoFrameAllocator` still has
//! no `deallocate_frame`. A released slot's frames are reused when the
//! slot is, which bounds the waste at "the high-water mark of
//! simultaneously live tasks" rather than "every task ever created", but
//! it is reuse rather than reclamation and worth naming as such.

use crate::mm::layout;
use alloc::vec::Vec;
use spin::Mutex;
use x86_64::structures::paging::{FrameAllocator, Mapper, Page, PageTableFlags, Size4KiB, Translate};
use x86_64::VirtAddr;

/// One allocated kernel stack.
///
/// Carries the slot index as well as the addresses so that releasing it
/// is a matter of handing back an identity rather than recomputing which
/// slot an address belonged to - arithmetic that would silently produce a
/// plausible wrong answer if the region constants ever changed.
#[derive(Debug, Clone, Copy)]
pub struct KernelStack {
    slot: u64,
    /// Lowest mapped address. The guard page sits immediately below this.
    pub bottom: u64,
    /// One past the highest mapped byte - the value to put in RSP.
    ///
    /// 16-byte aligned by construction, since both the slot base and the
    /// stack size are multiples of 4096. The System V ABI's alignment
    /// requirement at a `call` is therefore satisfied without any
    /// per-allocation rounding, which is what the old heap-based version
    /// needed an explicit `Layout` alignment for.
    pub top: u64,
}

impl KernelStack {
    /// The unmapped page below this stack.
    pub fn guard_page(&self) -> u64 {
        self.bottom - 4096
    }
}

struct Allocator {
    /// The next never-yet-used slot index.
    next_slot: u64,
    /// Slots whose tasks have exited, available for reuse. Reused in LIFO
    /// order, which keeps a recently-touched stack's page table entries
    /// warm in the TLB.
    free_slots: Vec<u64>,
}

static ALLOCATOR: Mutex<Allocator> = Mutex::new(Allocator {
    next_slot: 0,
    free_slots: Vec::new(),
});

/// Maps a new kernel stack and returns its bounds.
///
/// Returns `None` when the region is exhausted rather than panicking:
/// running out of task slots is a resource limit, and a kernel that
/// panics on one cannot implement a policy about it.
pub fn allocate(
    mapper: &mut impl Mapper<Size4KiB>,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> Option<KernelStack> {
    let (slot, is_reuse) = {
        // Interrupts off around the lock for the same reason every
        // scheduler-lock acquisition disables them: a timer tick landing
        // inside the critical section, followed by anything on the other
        // side of the switch taking the same lock, is a deadlock against
        // a holder that can never run again.
        x86_64::instructions::interrupts::without_interrupts(|| {
            let mut allocator = ALLOCATOR.lock();
            if let Some(slot) = allocator.free_slots.pop() {
                Some((slot, true))
            } else if allocator.next_slot < layout::KERNEL_STACK_SLOTS {
                let slot = allocator.next_slot;
                allocator.next_slot += 1;
                Some((slot, false))
            } else {
                None
            }
        })?
    };

    // Slot layout, lowest address first: one guard page, then the stack.
    // Putting the guard *below* the stack is what matters - stacks grow
    // downward on x86_64, so an overflow runs off the bottom.
    let slot_base = layout::KERNEL_STACK_AREA + slot * layout::KERNEL_STACK_SLOT;
    let bottom = slot_base + 4096;
    let top = bottom + layout::KERNEL_STACK_SIZE;

    // A reused slot is already mapped; re-mapping it would fail. The
    // frames from the previous occupant are reused as-is.
    if !is_reuse {
        // WRITABLE, and NO_EXECUTE where the CPU supports it: a kernel
        // stack has no business being executable, and marking it so
        // closes the most attractive target in the address space for
        // anyone who can write data but not code.
        let mut flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        if crate::arch::x86_64::cpu::detect().nx {
            flags |= PageTableFlags::NO_EXECUTE;
        }

        let pages = layout::KERNEL_STACK_SIZE / 4096;
        for i in 0..pages {
            let page: Page<Size4KiB> =
                Page::containing_address(VirtAddr::new(bottom + i * 4096));
            let frame = frame_allocator.allocate_frame()?;

            // Safety: `frame` came from the frame allocator, which hands
            // out only bootloader-reported usable frames and never
            // repeats one. `page` is inside this module's exclusive
            // region, at a slot index no other live stack holds.
            unsafe {
                mapper
                    .map_to(page, frame, flags, frame_allocator)
                    .ok()?
                    .flush();
            }
        }
    }

    // The guard page is never mapped, on either path. Nothing below is
    // needed to *create* it - its protection is precisely its absence.
    Some(KernelStack { slot, bottom, top })
}

/// Returns a stack's slot for reuse.
///
/// The mapping is deliberately left in place: unmapping it would let the
/// address range be reused for something else, and the whole value of a
/// fixed slot is that a dangling pointer into a dead task's stack lands
/// somewhere identifiable rather than in an unrelated live allocation.
pub fn release(stack: KernelStack) {
    x86_64::instructions::interrupts::without_interrupts(|| {
        ALLOCATOR.lock().free_slots.push(stack.slot);
    });
}

/// `(slots in use, slots ever allocated, capacity)`, for the boot report.
pub fn stats() -> (u64, u64, u64) {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let allocator = ALLOCATOR.lock();
        (
            allocator.next_slot - allocator.free_slots.len() as u64,
            allocator.next_slot,
            layout::KERNEL_STACK_SLOTS,
        )
    })
}

/// Whether the guard page below `stack` is genuinely unmapped.
///
/// Checked rather than assumed, and checked through an actual page table
/// walk rather than by reasoning about the code above. A guard page is
/// protective only because nothing maps it; that guarantee dies quietly
/// if some future allocator picks the address, since everything keeps
/// working and the protection is simply gone.
pub fn guard_page_is_unmapped(stack: &KernelStack, mapper: &impl Translate) -> bool {
    mapper
        .translate_addr(VirtAddr::new(stack.guard_page()))
        .is_none()
}
