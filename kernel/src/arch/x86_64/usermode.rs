//! A first, minimal proof that Ring 3 (user-mode) execution and its
//! privilege enforcement actually work.
//!
//! This is deliberately not a real "run a user program" mechanism - there
//! is no ELF loader, no filesystem, nothing resembling a process yet.
//! What exists here is the smallest possible test that can't lie: three
//! hand-written machine code bytes, mapped onto a page explicitly marked
//! user-accessible, executed via a real Ring 0 -> Ring 3 privilege
//! transition - not just "we jumped somewhere and it didn't crash." The
//! test payload does two things a real user process will eventually need
//! validated for real: making a syscall (via `int 0x80`, see
//! `interrupts::syscall_handler`), and attempting a privileged
//! instruction that *must* fault if Ring 3 restriction is actually
//! enforced by the CPU rather than just assumed to be.
//!
//! ## The Ring 3 round trip
//!
//! Entering Ring 3 used to be a one-way door: the original
//! `enter_usermode_at` was `-> !`, so a Ring 3 program ending - cleanly
//! or by faulting - had nowhere to hand control back to, and the fault
//! handlers in `interrupts.rs` had no choice but to halt the entire
//! machine even for a fault that was purely the *program's* fault. That
//! was recorded as a known gap rather than papered over; `run_program`
//! below is what closes it.
//!
//! The mechanism is the same one `sched/task.rs`'s `context_switch`
//! already uses, applied to a different kind of context: save the
//! callee-saved registers and RSP of the Ring 0 side before transitioning
//! away, and restore exactly those to resume later. It is deliberately
//! *not* built on the cooperative task scheduler - a Ring 3 program is
//! not a kernel task that politely yields, it's a context that can be
//! terminated involuntarily from an exception handler, which is a
//! different lifecycle with a different failure mode.
//!
//! What this still does **not** do, stated plainly rather than left to be
//! discovered: terminating a program does not reclaim any of its
//! resources. Its `PT_LOAD` pages and stack page stay mapped and their
//! physical frames stay allocated after it dies. Running a second program
//! at the same virtual addresses would therefore fail in `map_to`, and
//! running many programs would leak frames until the allocator runs out.
//! Reclamation needs per-program page tables (so an address space can be
//! torn down as a unit) rather than the single kernel-wide one this
//! kernel has today - see ARCHITECTURE.md section 2 on per-Realm memory
//! isolation, which is the same missing piece.

use crate::serial_println;
use core::arch::naked_asm;
use x86_64::structures::paging::{FrameAllocator, Mapper, Page, PageTableFlags, Size4KiB};
use x86_64::VirtAddr;

/// Fixed virtual address for the one-page test payload. Defined in
/// `mm::layout` alongside every other fixed range, rather than here -
/// see that module for why a scattered set of `const`s stopped being
/// good enough once the address space acquired two halves with different
/// ownership rules.
const USER_CODE_ADDR: u64 = crate::mm::layout::USERMODE_TEST_CODE;

/// Same reasoning, for the one-page user stack.
const USER_STACK_ADDR: u64 = crate::mm::layout::USERMODE_TEST_STACK;

/// The page `run_nx_test` marks non-executable and then jumps into.
/// Placed one page above the main test payload so the two tests cannot
/// affect each other's mappings.
const NX_TEST_DATA: u64 = USER_CODE_ADDR + 0x1000;

/// The stack `run_nx_test` gives its (never-executed) payload.
const NX_TEST_STACK: u64 = USER_STACK_ADDR + 0x1000;

/// Hand-assembled machine code, not compiled from a Rust function -
/// deliberately. Extracting the exact byte range of an arbitrary
/// Rust-compiled function to copy onto a separate page is fragile (Rust
/// makes no guarantee about a function's size or where it ends in
/// memory), whereas these instructions' encodings are simple,
/// well-known, and unambiguous:
///
/// - `mov rax, 0xEE` = `48 C7 C0 EE 00 00 00` - loads a syscall number
///   this kernel deliberately does not implement, so the syscall below
///   exercises the dispatcher's unknown-number path and, more
///   importantly, *doesn't* accidentally request something. This used to
///   be absent, back when the syscall handler ignored its registers
///   entirely; once `enter_usermode_and_wait` started zeroing registers
///   before entering Ring 3, a bare `int 0x80` became `exit(0)` - which
///   would have ended this program cleanly and quietly skipped the
///   privileged-instruction test that is the entire point of it.
/// - `int 0x80` = `0xCD 0x80` - a software interrupt used as the syscall
///   entry, caught by `interrupts::syscall_entry`.
/// - `hlt` = `0xF4` - a privileged instruction. At Ring 3 this **must**
///   fault (a General Protection Fault, caught by the existing
///   `interrupts::general_protection_fault_handler`) - if it doesn't,
///   Ring 3 isn't actually restricting anything and this "isolation" is
///   fiction dressed up as a passing test.
static USERMODE_TEST_PAYLOAD: [u8; 10] =
    [0x48, 0xC7, 0xC0, 0xEE, 0x00, 0x00, 0x00, 0xCD, 0x80, 0xF4];

/// Maps the test payload and a small stack onto dedicated,
/// user-accessible pages, then transitions into Ring 3 to run it.
///
/// Returns how the payload ended rather than diverging, since
/// `run_program` gained a way back (see the module docs). The *expected*
/// return value here is `ProgramExit::GeneralProtectionFault` - the
/// payload's final `hlt` being refused at Ring 3 is the entire point of
/// this test, so a clean exit would mean the privilege check silently
/// stopped working.
pub fn run_test() -> ProgramExit {
    // Mapping happens inside the page-table lock; the Ring 3 transition
    // happens outside it, because the payload's first instruction is a
    // syscall and the handler will need that lock itself.
    crate::mm::memory::with_memory(map_test_pages);

    serial_println!(
        "Najm Kernel: entering Ring 3 - expect a syscall confirmation, then a General \
         Protection Fault (the payload's `hlt` being correctly refused *is* the proof this works)"
    );

    // Safety: `USER_CODE_ADDR` was mapped read-execute and
    // user-accessible by `map_test_pages` and now holds the payload
    // bytes; the stack top sits above the equally-mapped stack page.
    unsafe { run_program(USER_CODE_ADDR, USER_STACK_ADDR + Page::<Size4KiB>::SIZE) }
}

fn map_test_pages(
    mapper: &mut impl Mapper<Size4KiB>,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) {
    let code_page: Page<Size4KiB> = Page::containing_address(VirtAddr::new(USER_CODE_ADDR));
    let stack_page: Page<Size4KiB> = Page::containing_address(VirtAddr::new(USER_STACK_ADDR));

    let nx_available = super::cpu::detect().nx;

    // Both pages start writable so the payload can be written into one of
    // them, and the code page is tightened to read-execute immediately
    // afterwards. That two-step exists because CR0.WP is now set: with
    // write protection on, Ring 0 cannot write to a read-only page
    // either, so a code page mapped read-execute up front would be
    // unwritable at exactly the moment the payload needs to go into it.
    let writable_flags =
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;

    for page in [code_page, stack_page] {
        let frame = frame_allocator
            .allocate_frame()
            .expect("out of physical frames while mapping the usermode test");

        // Safety: `frame` just came from `frame_allocator`, which only
        // hands out frames from bootloader-reported usable regions and
        // never repeats one - unaliased with anything else in use. Both
        // `page` values are fixed addresses this module exclusively
        // owns, distinct from the kernel heap and every task stack.
        unsafe {
            mapper
                .map_to(page, frame, writable_flags, frame_allocator)
                .expect("failed to map a usermode test page")
                .flush();
        }
    }

    // Safety: the page containing `USER_CODE_ADDR` was just mapped
    // PRESENT | WRITABLE immediately above, so writing the payload's
    // bytes into it is an in-bounds write to memory nothing else
    // references yet. The `with_user_access` bracket is required once
    // SMAP is enabled and is a plain call otherwise.
    super::cpu::with_user_access(|| unsafe {
        core::ptr::copy_nonoverlapping(
            USERMODE_TEST_PAYLOAD.as_ptr(),
            USER_CODE_ADDR as *mut u8,
            USERMODE_TEST_PAYLOAD.len(),
        );
    });

    // Now that the payload is in place, drop write permission from the
    // code page and execute permission from the stack page. W^X applies
    // to this hand-written test exactly as it applies to a real program -
    // if it did not, this test would be proving Ring 3 works under
    // conditions no real program ever runs under.
    let code_flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
    let mut stack_flags = writable_flags;
    if nx_available {
        stack_flags |= PageTableFlags::NO_EXECUTE;
    }

    // Safety: both pages were mapped by the loop above and remain mapped;
    // `update_flags` changes only permission bits on an existing mapping.
    unsafe {
        mapper
            .update_flags(code_page, code_flags)
            .expect("failed to re-protect the usermode test code page")
            .flush();
        mapper
            .update_flags(stack_page, stack_flags)
            .expect("failed to re-protect the usermode test stack page")
            .flush();
    }
}

/// Proves the `NO_EXECUTE` bit is genuinely enforced by the CPU, by
/// jumping into a page marked non-executable and requiring a fault.
///
/// This test exists because W^X is otherwise entirely unfalsifiable from
/// inside the kernel. The loader can set `NO_EXECUTE` on every data page,
/// the boot log can report it, `update_flags` can succeed - and if
/// `EFER.NXE` were never enabled, all of that would still happen and the
/// bit would mean nothing. Every stack in the system would be executable
/// and no test would notice. The only evidence that carries any weight is
/// an execution attempt that *fails*.
///
/// The payload is a single `ret` (0xC3) - deliberately the most harmless
/// instruction available, because if NX is somehow not enforced this code
/// does execute, and it should then do nothing dangerous rather than fall
/// through into whatever the rest of the page contains. Its stack is set
/// up so that `ret` would return into a `hlt`, producing a general
/// protection fault instead of a runaway - so even the failure mode of
/// the failure mode is contained.
///
/// Returns `None` when the CPU has no NX support, which is the honest
/// answer: on such a machine the property being tested does not exist,
/// and reporting a pass would be a lie.
pub fn run_nx_test() -> Option<ProgramExit> {
    if !super::cpu::detect().nx {
        return None;
    }

    crate::mm::memory::with_memory(map_nx_test_pages);

    serial_println!(
        "Najm Kernel: entering Ring 3 at a NO_EXECUTE page - a page fault here is the pass \
         condition, because it means the CPU is enforcing the bit rather than ignoring it"
    );

    // Safety: `NX_TEST_DATA` is a mapped, user-accessible address and
    // `NX_TEST_STACK + 0x1000` is the top of a mapped, user-accessible
    // stack. The entry is deliberately *not* executable, which is the
    // property under test; the CPU is expected to refuse the instruction
    // fetch rather than execute anything.
    Some(unsafe { run_program(NX_TEST_DATA, NX_TEST_STACK + 0x1000) })
}

fn map_nx_test_pages(
    mapper: &mut impl Mapper<Size4KiB>,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) {
    let data_page: Page<Size4KiB> = Page::containing_address(VirtAddr::new(NX_TEST_DATA));
    let stack_page: Page<Size4KiB> = Page::containing_address(VirtAddr::new(NX_TEST_STACK));

    let writable_flags =
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;

    for page in [data_page, stack_page] {
        let frame = frame_allocator
            .allocate_frame()
            .expect("out of physical frames while mapping the NX test");
        // Safety: same reasoning as `run_test` above - a fresh frame from
        // the bump allocator, and a fixed address this module owns.
        unsafe {
            mapper
                .map_to(page, frame, writable_flags, frame_allocator)
                .expect("failed to map an NX test page")
                .flush();
        }
    }

    // A lone `ret`. See the function docs for why this instruction in
    // particular.
    // Safety: the page was just mapped writable; nothing else references
    // it.
    super::cpu::with_user_access(|| unsafe {
        (NX_TEST_DATA as *mut u8).write(0xC3);
        // Fill the stack page's top word with an address that faults
        // safely if `ret` ever does execute - see the docs above.
        ((NX_TEST_STACK + 0xFF8) as *mut u64).write(NX_TEST_DATA + 0x800);
    });

    // The whole point: mark the page non-executable, then jump to it.
    // Safety: the page is mapped and stays mapped; only permission bits
    // change.
    unsafe {
        mapper
            .update_flags(
                data_page,
                writable_flags | PageTableFlags::NO_EXECUTE,
            )
            .expect("failed to mark the NX test page non-executable")
            .flush();
    }
}

/// How a Ring 3 program's run ended.
///
/// Deliberately an enum rather than a bare exit code: "the program asked
/// to exit with status 3" and "the program was killed after a page fault"
/// are different outcomes that a caller may well want to treat
/// differently, and collapsing them into one integer is exactly the kind
/// of stringly-typed-adjacent shortcut this project's error handling
/// avoids elsewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramExit {
    /// The program ended voluntarily via the `exit` syscall, with this
    /// status code.
    Exited(u32),
    /// The program was terminated after triggering a page fault.
    PageFault,
    /// The program was terminated after triggering a general protection
    /// fault - what the milestone 9/10 test payloads deliberately do by
    /// executing a privileged instruction at Ring 3.
    GeneralProtectionFault,
}

// Encoding of `ProgramExit` into the single u64 that
// `return_to_supervisor` hands back through RAX. Assembly can only
// return one register's worth of anything, and a `#[repr(C)]` enum with a
// payload has no layout guarantee stable enough to reconstruct by hand
// from asm - so the crossing is done as one explicitly-defined integer,
// packed and unpacked in exactly one place each (`encode`/`decode`
// below), rather than leaving the representation implicit.
const KIND_EXITED: u64 = 0;
const KIND_PAGE_FAULT: u64 = 1;
const KIND_GENERAL_PROTECTION_FAULT: u64 = 2;

impl ProgramExit {
    /// Packs into the u64 `return_to_supervisor` carries: kind in the
    /// high 32 bits, payload (the exit status, where there is one) in the
    /// low 32.
    fn encode(self) -> u64 {
        match self {
            ProgramExit::Exited(status) => (KIND_EXITED << 32) | status as u64,
            ProgramExit::PageFault => KIND_PAGE_FAULT << 32,
            ProgramExit::GeneralProtectionFault => KIND_GENERAL_PROTECTION_FAULT << 32,
        }
    }

    /// Inverse of `encode`. Panics on an unrecognized kind rather than
    /// silently picking a default: the only values that can reach here
    /// are ones `encode` produced a few instructions earlier, so an
    /// unknown kind means the RAX handoff itself was corrupted, which is
    /// not something to paper over with a plausible-looking fallback.
    fn decode(raw: u64) -> Self {
        let status = raw as u32;
        match raw >> 32 {
            KIND_EXITED => ProgramExit::Exited(status),
            KIND_PAGE_FAULT => ProgramExit::PageFault,
            KIND_GENERAL_PROTECTION_FAULT => ProgramExit::GeneralProtectionFault,
            kind => panic!("corrupted ProgramExit handoff from Ring 3: unknown kind {}", kind),
        }
    }
}

// The Ring 0 resume point for a running Ring 3 program is **per task**,
// not global. It lives in `sched::task::Task::supervisor_rsp` and is
// reached through `sched::task::supervisor_slot()`, which returns the
// current task's slot - or the boot context's, for the self-tests that
// run Ring 3 code before any task exists.
//
// It was a single `AtomicU64` here until processes became tasks. One
// global slot is correct exactly as long as Ring 3 execution cannot nest
// or interleave, which was true while the only Ring 3 code ran from
// `kernel_main`. Once two tasks can each be inside a Ring 3 program, the
// second one to enter overwrites the first one's resume point, and the
// first program's fault then returns into a stack frame that no longer
// exists - a corrupted `ret` into freed memory, which is about as bad as
// a scheduler bug gets.
//
// The reason it has to be reachable without being passed as an argument
// is unchanged: the code that reads it is a CPU fault handler, reached by
// an exception rather than by a call chain that could have been handed a
// pointer.

/// Whether a Ring 3 program is currently running on the current context -
/// and therefore whether `end_program` has a supervisor context to return
/// to. The fault handlers check this before trying to terminate "the
/// running program," since a Ring 3 fault with no program running would
/// mean something far stranger has happened than a misbehaving user
/// binary.
pub fn program_is_running() -> bool {
    let slot = crate::sched::task::supervisor_slot();
    // Safety: `supervisor_slot` returns a pointer to either a field of
    // the live current `Task` (heap-stable) or to a `static` - both valid
    // for the duration of this read.
    unsafe { slot.read_volatile() != 0 }
}

/// Ends the running Ring 3 program and resumes whoever called
/// `run_program`, which returns `exit`.
///
/// Callable from an exception handler (that's the point - see
/// `interrupts::end_or_halt_after_fault`), which is why it takes no
/// self/context argument and reads the resume point from the static
/// above.
///
/// # Panics
/// If no Ring 3 program is running. Callers must check
/// `program_is_running()` first; reaching here without a saved context
/// would mean jumping to a stack pointer of 0.
pub fn end_program(exit: ProgramExit) -> ! {
    let slot = crate::sched::task::supervisor_slot();
    // Safety: as `program_is_running` - the pointer names a live field or
    // a static.
    let supervisor_rsp = unsafe { slot.read_volatile() };
    assert_ne!(
        supervisor_rsp, 0,
        "end_program called with no Ring 3 program running - check program_is_running() first"
    );

    // Safety: `supervisor_rsp` is non-zero, so it was written by
    // `enter_usermode_and_wait` below and has not been cleared by
    // `run_program`'s return path - meaning the six callee-saved
    // registers and the return address it expects to pop are still
    // sitting exactly where that function left them, on a kernel stack
    // that is still live (the frame belongs to `run_program`, which is
    // by definition still on the call stack while its program runs).
    unsafe { return_to_supervisor(supervisor_rsp, exit.encode()) }
}

/// Runs an already-mapped Ring 3 program to completion and reports how it
/// ended - the shared mechanism both `run_test` (above) and the ELF
/// loader (`crate::loader`) use, so the IRETQ-based transition exists in
/// exactly one place rather than being duplicated per caller.
///
/// # Safety
/// `entry` must point at valid, mapped, user-accessible, executable code.
/// `stack_top` must be the top of a valid, mapped, user-accessible stack.
pub unsafe fn run_program(entry: u64, stack_top: u64) -> ProgramExit {
    assert!(
        !program_is_running(),
        "Ring 3 execution cannot nest - a program is already running"
    );

    let code_selector = super::gdt::user_code_selector();
    let data_selector = super::gdt::user_data_selector();

    // Both return paths out of Ring 3 (the `exit` syscall and either
    // fault handler) arrive through an IDT *interrupt* gate, which clears
    // IF on entry, and then leave via `return_to_supervisor` - which
    // deliberately never executes `iretq`, so the RFLAGS the CPU saved on
    // interrupt entry are never restored. Interrupts would therefore stay
    // disabled forever after the first program ends, silently freezing
    // the timer tick. Snapshotting the flag here and restoring it below
    // is what keeps this mechanism transparent to its caller.
    let interrupts_were_enabled = x86_64::instructions::interrupts::are_enabled();

    // Safety: forwarded from this function's own safety contract, plus
    // `code_selector`/`data_selector` coming from `gdt::init()`, which
    // `kernel_main` guarantees has already run before anything can reach
    // here. `SUPERVISOR_RSP.as_ptr()` is a valid, permanently-live
    // pointer to a `static`, and the assert above guarantees nothing else
    // is currently using that slot.
    let slot = crate::sched::task::supervisor_slot();

    let raw = unsafe {
        enter_usermode_and_wait(
            entry,
            stack_top,
            code_selector.0 as u64,
            data_selector.0 as u64,
            slot,
            super::gdt::privilege_stack_ptr(),
        )
    };

    // Cleared *before* anything below can fault or panic, so a failure in
    // the reporting path can't leave a stale resume point pointing at
    // this function's now-dead frame.
    //
    // Safety: the slot pointer names the same live field or static it did
    // before the transition - the current task cannot have changed, since
    // control only reaches here by resuming *this* context.
    unsafe {
        slot.write_volatile(0);
    }

    if interrupts_were_enabled {
        x86_64::instructions::interrupts::enable();
    }

    ProgramExit::decode(raw)
}

/// Performs the Ring 0 -> Ring 3 privilege transition via `iretq`, after
/// saving enough of the Ring 0 context for `return_to_supervisor` to
/// resume it later. Returns the encoded `ProgramExit` that
/// `return_to_supervisor` was handed.
///
/// `iretq` is chosen over the `syscall`/`sysret` instruction pair
/// specifically because it takes explicit selector values as part of a
/// stack frame it builds itself, rather than relying on a fixed GDT
/// layout implicitly encoded in the STAR MSR - one fewer easy-to-get-wrong
/// constraint for a first Ring 3 implementation to satisfy. `iretq` is
/// normally how the CPU *returns* from an interrupt; using it to make a
/// deliberate, first-time transition rather than a genuine return is a
/// well-established technique, not a hack specific to this kernel.
///
/// Naked, for the same reason `context_switch` in task.rs is: this
/// function's entire body is the exact stack layout `iretq` expects, and
/// a normal compiler-generated prologue/epilogue would corrupt that
/// layout by pushing its own data onto the same stack first.
///
/// Note what is *not* saved: only the six callee-saved registers the SysV
/// ABI requires a function to preserve across a call, exactly like
/// `context_switch`. Caller-saved registers don't need preserving here
/// because this is a normal `extern "C"` function as far as its Rust
/// caller is concerned - the compiler already assumes they're clobbered.
///
/// # Safety
/// `user_entry` must point at valid, mapped, user-accessible, executable
/// code. `user_stack` must be the top of a valid, mapped,
/// user-accessible stack. `code_selector`/`data_selector` must be real
/// Ring 3 selectors from this kernel's own GDT (see
/// `gdt::user_code_selector`/`gdt::user_data_selector`) - not arbitrary
/// values, since `iretq` will load them directly into CS/SS with no
/// further validation beyond what the CPU's own descriptor checks catch.
/// `supervisor_rsp_out` must be a valid, exclusively-owned pointer to
/// write a `u64` through, which stays live for as long as the program
/// runs.
#[unsafe(naked)]
unsafe extern "C" fn enter_usermode_and_wait(
    user_entry: u64,
    user_stack: u64,
    code_selector: u64,
    data_selector: u64,
    supervisor_rsp_out: *mut u64,
    tss_rsp0_out: *mut u64,
) -> u64 {
    naked_asm!(
        // Save the Ring 0 context `return_to_supervisor` will restore.
        // Same six registers, same order, as `context_switch` in task.rs
        // - the two mechanisms are deliberately mirror images, and
        // keeping the sequences identical means a reader who has verified
        // one has effectively verified the other.
        "push rbp",
        "push rbx",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        // Publish the resulting RSP through `supervisor_rsp_out` (5th
        // arg, R8 per SysV64) so the fault handlers can find it.
        "mov [r8], rsp",
        // And publish it, minus 8, as TSS RSP0 (6th arg, R9).
        //
        // This line is the difference between Ring 3 preemption working
        // and silently corrupting the kernel stack, so it is worth
        // spelling out completely.
        //
        // RSP0 is the stack the CPU switches to on any Ring 3 -> Ring 0
        // transition. It used to be one fixed buffer shared by
        // everything, which made preemption unsafe (a parked program's
        // interrupt frame sat on memory the next Ring 3 entry reused).
        // The obvious fix - point RSP0 at the current *task's* kernel
        // stack - is wrong in a way that looks right: this task is
        // already using the top of that stack. `run_program`'s frame and
        // everything that called it live between RSP and the stack top,
        // and they have to survive the whole Ring 3 excursion, because
        // returning from Ring 3 means returning *into* them. Pointing
        // RSP0 at the top would have the very first syscall's interrupt
        // frame land directly on top of the frames it is supposed to
        // return to.
        //
        // The correct value is the stack pointer *right here*: everything
        // above it is live, everything below is free. RSP is 8 (mod 16)
        // at this point (the `call` pushed a return address, then six
        // more pushes), and the syscall entry stub's alignment argument
        // requires RSP0 to be 16-byte aligned - so the value stored is
        // RSP - 8, which is both aligned and still below every live byte.
        //
        // The five pushes that follow build the `iretq` frame and are
        // consumed by `iretq` itself, so they are gone before any Ring 3
        // code runs and cannot be clobbered.
        "lea rax, [rsp - 8]",
        "mov [r9], rax",
        // `iretq` pops, in order: RIP, CS, RFLAGS, RSP, SS - so this
        // pushes them in exactly the reverse order, SS first.
        "push rcx", // SS = data_selector (4th arg, RCX per SysV64)
        "push rsi", // RSP = user_stack (2nd arg, RSI)
        // RFLAGS: bit 1 is a reserved, always-1 bit; bit 9 is IF
        // (interrupt flag) - set so hardware interrupts (the timer,
        // notably) still fire while Ring 3 code runs, rather than
        // silently disabling them for the duration of this test.
        "mov rax, 0x202",
        "push rax", // RFLAGS
        "push rdx", // CS = code_selector (3rd arg, RDX)
        "push rdi", // RIP = user_entry (1st arg, RDI)
        // Zero every general-purpose register before handing control to
        // Ring 3. Without this, a user program starts life able to read
        // whatever the kernel happened to leave in its registers - which
        // was not hypothetical: the first boot log after the syscall ABI
        // landed showed the milestone 9 payload arriving at `int 0x80`
        // with RAX = 0x202 (the RFLAGS constant three lines above), RDI =
        // its own entry address and RSI = its stack address, all straight
        // out of this function's arguments. None of those particular
        // values are secret, but "the register file is whatever the
        // kernel last used it for" is a leak by construction, not by
        // accident, and the next value to pass through here might not be
        // so harmless. Zeroing is also what makes a program's starting
        // state *defined* rather than a detail of this function's
        // register allocation.
        //
        // Safe to do after the pushes: everything `iretq` needs is
        // already on the stack, and everything `return_to_supervisor`
        // restores was pushed further down still.
        "xor rax, rax",
        "xor rbx, rbx",
        "xor rcx, rcx",
        "xor rdx, rdx",
        "xor rsi, rsi",
        "xor rdi, rdi",
        "xor rbp, rbp",
        "xor r8, r8",
        "xor r9, r9",
        "xor r10, r10",
        "xor r11, r11",
        "xor r12, r12",
        "xor r13, r13",
        "xor r14, r14",
        "xor r15, r15",
        "iretq",
        // Nothing follows `iretq`: control does not come back here. The
        // way back into this function's *caller* is `return_to_supervisor`
        // below, which resumes from the stack saved above rather than
        // returning through this point.
    );
}

/// Restores the Ring 0 context `enter_usermode_and_wait` saved and
/// returns `result` from it, as though that function had returned
/// normally.
///
/// The exact mirror image of `enter_usermode_and_wait`'s prologue, and
/// the reason both are naked: this pops a frame it never pushed, on a
/// stack that belongs to a different call than the one currently
/// executing. A compiler-generated epilogue would try to unwind the
/// interrupt handler's frame that this is called from instead, which is
/// precisely the frame being abandoned.
///
/// Note that the interrupt frame the CPU pushed on entry to whichever
/// handler called this is simply discarded, never `iretq`-ed through.
/// That's sound - the frame lives on the TSS RSP0 stack, which is reset
/// to the same fixed top on every Ring 3 -> Ring 0 transition, so
/// abandoning it leaks nothing.
///
/// # Safety
/// `supervisor_rsp` must be a stack pointer previously written by
/// `enter_usermode_and_wait` for a call that is still live - i.e. whose
/// `run_program` frame has not returned yet.
#[unsafe(naked)]
unsafe extern "C" fn return_to_supervisor(supervisor_rsp: u64, result: u64) -> ! {
    naked_asm!(
        // Switch back to the Ring 0 stack saved before the transition.
        // Every instruction after this line executes on a completely
        // different stack than every instruction before it.
        "mov rsp, rdi",
        // The value `enter_usermode_and_wait` returns to its caller: RAX
        // is where SysV64 puts a u64 return value.
        "mov rax, rsi",
        // Exactly reverses the six pushes in `enter_usermode_and_wait`.
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbx",
        "pop rbp",
        // Pops the return address that the original `call` to
        // `enter_usermode_and_wait` pushed, landing back inside
        // `run_program`.
        "ret",
    );
}
