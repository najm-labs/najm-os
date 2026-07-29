//! Global Descriptor Table (GDT) and Task State Segment (TSS) setup.
//!
//! The bootloader crate already sets up a minimal GDT to get the kernel
//! into 64-bit mode, but it doesn't include a TSS - and a TSS with a
//! dedicated Interrupt Stack Table (IST) entry is what lets the double
//! fault handler run on a known-good stack instead of whatever stack the
//! CPU happened to be using when things went wrong.
//!
//! Why this matters concretely: if a kernel stack overflows, the CPU
//! tries to push a double-fault exception frame - onto the same,
//! already-overflowed stack. That push fails too, which triggers a
//! *third* fault. A triple fault is an unconditional hardware reset with
//! no diagnostic output whatsoever. Giving the double-fault handler its
//! own separate stack via the IST is what turns "the machine silently
//! reboots" into "the machine tells you exactly what went wrong."

use lazy_static::lazy_static;
use x86_64::instructions::segmentation::{Segment, CS, SS};
use x86_64::instructions::tables::load_tss;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

/// Which entry in the Interrupt Stack Table the double fault handler uses.
/// An arbitrary but fixed convention - documented here as a public
/// constant specifically so `interrupts.rs` and this file can't silently
/// drift apart on which index means what.
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

/// A fixed-size stack buffer with a guaranteed 16-byte alignment.
///
/// A bare `[u8; N]` has an alignment of 1, so nothing stops the linker
/// from placing one at an address that isn't 16-byte aligned - and both
/// stacks below are used as *CPU stacks*, where the x86_64 System V ABI
/// requires 16-byte alignment at every `call`. Two things depend on that
/// here, neither of which fails loudly if it's wrong:
///
/// 1. `extern "x86-interrupt"` handlers may spill SSE registers with
///    aligned moves (`movaps`), which fault on a misaligned stack.
/// 2. `interrupts::syscall_entry`'s hand-written `call` into the syscall
///    dispatcher computes its alignment relative to RSP0 (see the
///    arithmetic in that function's comments), so a misaligned RSP0
///    silently misaligns the dispatcher.
///
/// As it happens, the linker was already placing both stacks at 16-byte
/// aligned addresses on this toolchain - this type is what turns that
/// from luck into a guarantee, before the naked syscall stub starts
/// depending on it. `N` must be a multiple of 16 for the stack *top*
/// (base + N) to inherit the alignment; both uses below are, and
/// `new` asserts it rather than trusting the caller to notice.
#[repr(C, align(16))]
struct AlignedStack<const N: usize>([u8; N]);

impl<const N: usize> AlignedStack<N> {
    const fn new() -> Self {
        assert!(
            N.is_multiple_of(16),
            "stack size must be a multiple of 16 for its top to stay 16-byte aligned"
        );
        AlignedStack([0; N])
    }
}

struct Selectors {
    code_selector: SegmentSelector,
    data_selector: SegmentSelector,
    tss_selector: SegmentSelector,
    /// Ring 3 counterparts of the two selectors above - see
    /// `usermode.rs`, the first (and so far only) consumer of these.
    user_code_selector: SegmentSelector,
    user_data_selector: SegmentSelector,
}

lazy_static! {
    static ref TSS: TaskStateSegment = {
        let mut tss = TaskStateSegment::new();
        tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
            const STACK_SIZE: usize = 4096 * 5;

            // A static buffer used purely as stack memory - never read or
            // written as data, only ever pointed to as the CPU's stack
            // top. This is the standard approach for a freestanding
            // kernel with no heap allocator yet: the stack has to come
            // from somewhere fixed at compile time. `AlignedStack` rather
            // than a bare array so the 16-byte ABI alignment is
            // guaranteed rather than left to the linker - see that type's
            // docs.
            static mut STACK: AlignedStack<STACK_SIZE> = AlignedStack::new();

            // `addr_of!` forms a raw pointer without creating a
            // reference, so it doesn't require `unsafe` here - only
            // *dereferencing* a pointer to a mutable static would.
            let stack_start = VirtAddr::from_ptr(core::ptr::addr_of!(STACK));
            stack_start + STACK_SIZE as u64
        };

        // `privilege_stack_table[0]` (RSP0): the stack the CPU switches
        // to on *any* transition from a lower privilege level into Ring
        // 0 - not just syscalls, but also any interrupt or exception that
        // fires while Ring 3 code is running. Without this, the very
        // first such event (in practice, the deliberate General
        // Protection Fault `usermode.rs`'s test payload triggers) has no
        // valid Ring 0 stack to switch to and turns into a triple fault
        // instead of a diagnosed error - the exact same class of problem
        // the double-fault IST stack above solves, for a different
        // trigger.
        //
        // Its 16-byte alignment is load-bearing beyond the usual ABI
        // reasons: `interrupts::syscall_entry` derives the alignment of
        // its `call` into the syscall dispatcher from this value, since
        // the CPU loads RSP0 here verbatim before pushing the interrupt
        // frame onto it. Hence `AlignedStack` rather than a bare array.
        tss.privilege_stack_table[0] = {
            const STACK_SIZE: usize = 4096 * 5;
            static mut STACK: AlignedStack<STACK_SIZE> = AlignedStack::new();
            let stack_start = VirtAddr::from_ptr(core::ptr::addr_of!(STACK));
            stack_start + STACK_SIZE as u64
        };

        tss
    };
}

lazy_static! {
    static ref GDT: (GlobalDescriptorTable, Selectors) = {
        let mut gdt = GlobalDescriptorTable::new();
        let code_selector = gdt.append(Descriptor::kernel_code_segment());
        let data_selector = gdt.append(Descriptor::kernel_data_segment());
        let tss_selector = gdt.append(Descriptor::tss_segment(&TSS));
        // Order relative to the kernel selectors above doesn't matter
        // for the IRETQ-based privilege transition `usermode.rs` uses -
        // unlike the `syscall`/`sysret` instruction pair, which requires
        // a specific fixed GDT layout encoded implicitly via the STAR
        // MSR. IRETQ instead takes explicit selector values, which is
        // exactly why it's the mechanism used here: it doesn't carry
        // that fragile, easy-to-get-wrong ordering constraint.
        let user_data_selector = gdt.append(Descriptor::user_data_segment());
        let user_code_selector = gdt.append(Descriptor::user_code_segment());
        (
            gdt,
            Selectors {
                code_selector,
                data_selector,
                tss_selector,
                user_code_selector,
                user_data_selector,
            },
        )
    };
}

/// The Ring 3 code segment selector, for anything that needs to build an
/// IRETQ frame transitioning into user mode. See `usermode.rs`.
pub fn user_code_selector() -> SegmentSelector {
    GDT.1.user_code_selector
}

/// The Ring 3 data segment selector - see `user_code_selector` above.
pub fn user_data_selector() -> SegmentSelector {
    GDT.1.user_data_selector
}

/// Installs this kernel's own GDT and TSS, replacing the minimal one the
/// bootloader used just to get into long mode. Must run before
/// `interrupts::init()` - the double fault handler's IST index only means
/// anything once this TSS is actually loaded into the CPU.
pub fn init() {
    GDT.0.load();
    unsafe {
        // Safety: `code_selector`, `data_selector`, and `tss_selector` are
        // selectors into the `GDT` static defined immediately above,
        // which was just loaded on the line before this.
        CS::set_reg(GDT.1.code_selector);

        // Explicitly reloading SS matters, not just CS: the stack segment
        // register was still holding whatever selector *the bootloader's*
        // GDT assigned it, and that raw index means something completely
        // different (or nothing valid at all) once it's interpreted
        // against *our* new GDT. This went unnoticed until the first
        // `IRETQ` (returning from the breakpoint self-test in
        // `kernel_main`) - the CPU validates/reloads SS as part of that,
        // and a stale selector caused an immediate general protection
        // fault right after the breakpoint handler itself worked
        // correctly. CS didn't show the same problem only because it was
        // set explicitly, right above, in the first place.
        SS::set_reg(GDT.1.data_selector);

        load_tss(GDT.1.tss_selector);
    }
}
