//! Interrupt Descriptor Table (IDT) setup, plus hardware interrupts.
//!
//! Two distinct things live in this file, registered in the same table
//! but conceptually different:
//!
//! - **CPU exceptions** (breakpoint, page fault, double fault, GP fault):
//!   the processor raises these itself in response to something that
//!   happened in currently-executing code. Until these are registered,
//!   any exception cascades into a triple fault - an unconditional
//!   hardware reset with zero diagnostic output.
//! - **Hardware interrupts** (timer, keyboard): external devices raise
//!   these asynchronously, routed through the legacy 8259 Programmable
//!   Interrupt Controller (PIC) rather than the modern APIC - see the
//!   `pic8259` dependency comment in Cargo.toml for why that's the right
//!   choice at this stage and not a shortcut being taken.
//!
//! The timer interrupt in particular is the actual point of this
//! milestone: it's the mechanism a preemptive scheduler will eventually
//! hook into to reclaim the CPU from whatever's running, on a schedule,
//! without that code's cooperation. Nothing here preempts anything yet -
//! today it just counts ticks - but the interrupt plumbing it needs is
//! exactly what's being built here.

use super::gdt;
use super::usermode::{self, ProgramExit};
use crate::serial_print;
use crate::serial_println;
use core::arch::naked_asm;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use lazy_static::lazy_static;
use pic8259::ChainedPics;
use spin::Mutex;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

/// The 8259 PIC has two chained controllers (primary + secondary), each
/// handling 8 IRQ lines. Their interrupt vectors default to 0-15, which
/// collides directly with the CPU exception vectors this same IDT already
/// uses (breakpoint, double fault, etc. all live in 0-31) - so the PICs
/// are remapped to start right after that range instead.
pub const PIC_1_OFFSET: u8 = 32;
pub const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 8;

/// Safety of the `unsafe` construction below is discharged by `init()`,
/// which calls `PICS.lock().initialize()` exactly once, before hardware
/// interrupts are ever enabled - see the safety note there.
pub static PICS: Mutex<ChainedPics> =
    Mutex::new(unsafe { ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET) });

/// IDT vector numbers for the two hardware interrupts currently handled.
/// Defined relative to `PIC_1_OFFSET` rather than as bare numbers so the
/// mapping between "IRQ line" and "IDT vector" can't silently drift out
/// of sync with the offset above.
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum InterruptIndex {
    Timer = PIC_1_OFFSET,
    Keyboard,
}

impl InterruptIndex {
    fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Ticks since the timer interrupt was enabled. Deliberately just a
/// counter for now, not driving anything - the eventual scheduler reads
/// this (or a mechanism like it) to decide when to preempt, but no
/// scheduler exists yet to do that.
static TIMER_TICKS: AtomicU64 = AtomicU64::new(0);

/// Current tick count. `Relaxed` ordering is sufficient: this is a
/// monotonically increasing counter with no other memory operations that
/// need to be ordered relative to it, not a synchronization primitive.
///
/// Unrestricted, and stays that way deliberately: this is the kernel
/// Core's own internal reading of its own counter (used by the boot-time
/// self-test in `kernel_main`, for instance), the same "Core doesn't need
/// to ask permission" reasoning as the unconditional `serial_print!`
/// macros in serial.rs. `ticks_with_capability` below is the separate,
/// gated entry point for anything that isn't Core.
pub fn timer_ticks() -> u64 {
    TIMER_TICKS.load(Ordering::Relaxed)
}

/// The capability-gated counterpart to `timer_ticks` - the same value,
/// but only returned if `cap` hasn't been revoked. A second, deliberately
/// unrelated demonstration of `capability::Capability` (see
/// `serial::write_with_capability` for the first) proving the primitive
/// generalizes to more than the one right it was originally built
/// against.
pub fn ticks_with_capability(
    cap: &crate::security::capability::Capability<crate::security::capability::TimerRead>,
) -> Result<u64, crate::security::capability::CapabilityError> {
    if cap.is_revoked() {
        return Err(crate::security::capability::CapabilityError::Revoked);
    }

    Ok(timer_ticks())
}

lazy_static! {
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();

        idt.breakpoint.set_handler_fn(breakpoint_handler);
        idt.page_fault.set_handler_fn(page_fault_handler);
        idt.general_protection_fault
            .set_handler_fn(general_protection_fault_handler);

        // Safety: `DOUBLE_FAULT_IST_INDEX` names a stack that
        // `gdt::init()` installs into the TSS - `init()` below runs
        // `gdt::init()` first, unconditionally, so by the time this
        // handler could ever actually fire, the stack it points at is
        // real and valid. Using a dedicated known-good stack here, rather
        // than whatever stack the CPU was already using, is specifically
        // what prevents a double fault from cascading into an
        // undiagnosable triple fault.
        unsafe {
            idt.double_fault
                .set_handler_fn(double_fault_handler)
                .set_stack_index(gdt::DOUBLE_FAULT_IST_INDEX);
        }

        idt[InterruptIndex::Timer.as_u8()].set_handler_fn(timer_interrupt_handler);
        idt[InterruptIndex::Keyboard.as_u8()].set_handler_fn(keyboard_interrupt_handler);

        // Vector 0x80: a software-interrupt syscall gate, in the classic
        // (pre-`syscall`/`sysret`) style - deliberately the simpler of
        // the two mechanisms real x86_64 kernels use, chosen for the
        // same reason IRETQ was chosen over `sysret` in usermode.rs: no
        // MSR programming, no fragile GDT-ordering requirement, and it
        // reuses IDT infrastructure this kernel already has working.
        //
        // The `set_privilege_level(Ring3)` call is not optional
        // decoration - IDT gates default to DPL 0, meaning Ring 3 code
        // executing `int 0x80` would fault immediately on the privilege
        // check before ever reaching the handler, without it.
        //
        // `set_handler_addr`, not `set_handler_fn`, because the handler
        // is a naked function rather than an `extern "x86-interrupt"`
        // one - see `syscall_entry` for why that distinction is forced
        // rather than stylistic. `set_handler_fn` would not typecheck
        // against it, and more importantly the x86-interrupt calling
        // convention is exactly what has to be avoided here.
        //
        // Safety: `syscall_entry` is a real interrupt handler for this
        // entry type - it takes no arguments, reads only the interrupt
        // frame the CPU itself pushed, and ends in `iretq` (or diverts
        // to the supervisor via `end_program`, which is the documented
        // way a syscall handler is allowed not to return).
        unsafe {
            idt[0x80]
                .set_handler_addr(x86_64::VirtAddr::new(syscall_entry as *const () as u64))
                .set_privilege_level(x86_64::PrivilegeLevel::Ring3);
        }

        idt
    };
}

/// Installs the IDT, remaps and initializes the PICs, and enables
/// maskable hardware interrupts (`sti`) - in that exact order.
///
/// Must run after `gdt::init()` (see the double fault safety note above).
/// The ordering *within* this function matters too: the IDT has to be
/// loaded, with handlers already registered for both PIC-driven vectors,
/// before interrupts are enabled - enabling interrupts first would open a
/// window where a timer or keyboard IRQ could fire with no handler
/// installed for it yet, which is exactly the kind of bug that's
/// invisible in testing and shows up as an unexplained fault later.
pub fn init() {
    IDT.load();

    // Safety: this is the only place `PICS.lock().initialize()` is ever
    // called, and it runs after the line above, so both PIC-driven IDT
    // entries (Timer, Keyboard) already have handlers registered before
    // the PICs - and therefore actual hardware interrupts - can reach the
    // CPU at all.
    unsafe {
        PICS.lock().initialize();
    }

    x86_64::instructions::interrupts::enable();
}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    // Breakpoint (int3) is the one exception here that's expected to
    // happen deliberately (debuggers use it, and kernel_main triggers one
    // on purpose right after this IDT loads, as a live self-test) and
    // that execution can safely resume from - the handler just reports
    // it and returns.
    serial_println!("EXCEPTION: BREAKPOINT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    // The x86_64 crate enforces `-> !` here: a double fault handler is
    // not allowed to return. It deliberately doesn't attempt recovery
    // either - by the time a double fault has fired, something has
    // already gone wrong badly enough that continuing risks corrupting
    // state further. Reporting it clearly over serial and halting is the
    // honest response, not a silent reset.
    panic!("EXCEPTION: DOUBLE FAULT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    // The faulting address (CR2 register) is deliberately not read here
    // yet - the exact API for it varies across x86_64 crate versions
    // (fallible vs. infallible read), and guessing wrong risks a build
    // that looks right but doesn't compile. Worth adding once verified
    // against the pinned crate version; the error code and stack frame
    // below are already a large improvement over a silent triple fault.
    serial_println!("EXCEPTION: PAGE FAULT");
    serial_println!("Error Code: {:?}", error_code);
    serial_println!("Faulted in: {:?}", stack_frame.code_segment.rpl());
    serial_println!("{:#?}", stack_frame);

    end_or_halt_after_fault(stack_frame, ProgramExit::PageFault);
}

extern "x86-interrupt" fn general_protection_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    serial_println!("EXCEPTION: GENERAL PROTECTION FAULT");
    serial_println!("Error Code: {:#x}", error_code);
    serial_println!("Faulted in: {:?}", stack_frame.code_segment.rpl());
    serial_println!("{:#?}", stack_frame);

    end_or_halt_after_fault(stack_frame, ProgramExit::GeneralProtectionFault);
}

/// Shared tail for `page_fault_handler` and `general_protection_fault_handler`:
/// decides whether a fault kills one program or the whole machine.
///
/// The distinction is the privilege level the fault came from, which is
/// the whole reason `code_segment.rpl()` is logged at both call sites:
///
/// - **Ring 0** - the kernel itself faulted. There is no smaller unit to
///   terminate and no reason to believe continuing is safe, so this still
///   halts, exactly as it always did.
/// - **Ring 3** - a user program faulted. That program is terminated and
///   control returns to whoever called `usermode::run_program`, which is
///   what a real OS does. The kernel keeps running.
///
/// The Ring 3 branch has one precondition worth stating: it needs a
/// supervisor context to return *to*. `program_is_running()` is that
/// check. A Ring 3 fault with no program running would mean the CPU was
/// executing user code that this kernel never launched, which is a far
/// stranger situation than a misbehaving binary - halting is the honest
/// response to it rather than jumping through a resume point that was
/// never set.
///
/// Still missing, and deliberately not pretended otherwise: terminating a
/// program here reclaims none of its memory. See the module docs in
/// `usermode.rs` for why that needs per-program page tables first.
fn end_or_halt_after_fault(stack_frame: InterruptStackFrame, exit: ProgramExit) -> ! {
    if stack_frame.code_segment.rpl() == x86_64::PrivilegeLevel::Ring3 {
        if usermode::program_is_running() {
            serial_println!(
                "Najm Kernel: the above fault occurred in Ring 3 (user mode) - terminating \
                 only the faulting program and returning control to the supervisor. The \
                 kernel keeps running."
            );
            usermode::end_program(exit);
        }

        serial_println!(
            "Najm Kernel: the above fault occurred in Ring 3, but no Ring 3 program is \
             registered as running - there is no supervisor context to return to, so the \
             machine halts. See end_or_halt_after_fault() in interrupts.rs."
        );
    }

    crate::halt_loop();
}

/// Syscall numbers, passed by the caller in RAX.
///
/// Loosely following Linux's own register convention (RAX = number,
/// RDI/RSI/RDX = arguments) for familiarity, explicitly *not* for
/// compatibility - nothing here aims to run Linux binaries, and the
/// numbers themselves are this kernel's own.
pub const SYS_EXIT: u64 = 0;
pub const SYS_WRITE: u64 = 1;

/// Returned in RAX for a syscall number this kernel doesn't implement.
/// `-1` as a `u64`, in the C tradition of a negative return meaning
/// failure, since userland has no `Result` to receive here.
const SYSCALL_UNKNOWN: u64 = u64::MAX;

/// Returned by `write` when the buffer it was handed isn't a range the
/// calling program is actually allowed to read. Distinct from
/// `SYSCALL_UNKNOWN` so a program (and anyone reading a boot log) can
/// tell "no such syscall" from "that pointer was rejected."
const SYSCALL_BAD_ADDRESS: u64 = u64::MAX - 1;

/// The Ring 3 entry point for `int 0x80` - a naked function, and it has
/// to be.
///
/// An `extern "x86-interrupt" fn` cannot work here: that calling
/// convention defines only the `InterruptStackFrame` argument, and makes
/// no guarantee whatsoever about the general-purpose registers still
/// holding what the caller put in them by the time the function body
/// runs. The compiler is free to emit a prologue that clobbers RAX before
/// a single line of Rust executes, so reading syscall arguments out of
/// registers via inline `asm!` at the top of such a function is reading
/// whatever happens to be left - which may work by accident today and
/// stop working after an unrelated change. Hand-written assembly that
/// saves the registers as its very first instructions is the only way to
/// see the values the user program actually passed.
///
/// Register handling, and why every part of it is needed:
///
/// - RAX, RDI, RSI, RDX carry the syscall number and its three arguments.
/// - RCX, R8, R9, R10, R11 carry nothing this kernel wants, but they are
///   *caller-saved* under SysV64, which means the Rust dispatcher called
///   below is entitled to destroy them. They belong to the interrupted
///   user program, which is not expecting a function call to have
///   happened at all - so they're saved and restored too. Omitting them
///   would silently corrupt user registers across any syscall.
/// - The callee-saved registers (RBX, RBP, R12-R15) need no handling
///   here: the dispatcher is an ordinary `extern "C"` function and is
///   already obliged to preserve them.
///
/// **Stack alignment**, the part with no compile-time safety net: SysV64
/// requires RSP to be 16-byte aligned immediately before a `call`. The
/// CPU loads RSP from TSS RSP0 (16-byte aligned by construction - see
/// `gdt::AlignedStack`) and pushes a 40-byte interrupt frame onto it
/// (SS, RSP, RFLAGS, CS, RIP - long mode always pushes SS:RSP, even
/// without a privilege change), leaving RSP ≡ 8 (mod 16). The nine
/// pushes below add 72 bytes, and 8 - 72 ≡ 0 (mod 16), so RSP is aligned
/// exactly where it needs to be. Change the number of pushes and this
/// stops being true - which is why the count is spelled out here rather
/// than left for a reader to recount.
#[unsafe(naked)]
unsafe extern "C" fn syscall_entry() {
    naked_asm!(
        // Nine caller-saved registers, saved in an order that puts RAX at
        // a known offset (RSP+64) for the return value write below.
        "push rax",
        "push rcx",
        "push rdx",
        "push rsi",
        "push rdi",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        // Translate the syscall ABI (RAX, RDI, RSI, RDX) into SysV64
        // argument order (RDI, RSI, RDX, RCX) for the dispatcher. The
        // sequence is deliberately ordered so each register is read
        // before anything overwrites it - moving RDI first, for example,
        // would destroy argument 1 before it was copied.
        "mov rcx, rdx", // arg3 <- user RDX
        "mov rdx, rsi", // arg2 <- user RSI
        "mov rsi, rdi", // arg1 <- user RDI
        "mov rdi, rax", // number <- user RAX
        // 5th argument (R8 per SysV64): RSP as it stands at the call
        // boundary, purely so the dispatcher can *prove* the alignment
        // reasoning above rather than leave it asserted in a comment.
        // Safe to clobber R8 - its user value is already saved above.
        // This must stay immediately before the `call`, since any further
        // push would invalidate the value it captures.
        "mov r8, rsp",
        "call {dispatch}",
        // The dispatcher's return value becomes the user program's RAX,
        // by overwriting the saved copy in place before it's popped.
        "mov [rsp + 64], rax",
        // Exactly reverses the nine pushes above.
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop rcx",
        "pop rax",
        "iretq",
        dispatch = sym syscall_dispatch,
    );
}

/// Reports, once per boot, whether `syscall_entry` really did hand the
/// dispatcher a 16-byte aligned stack.
///
/// This exists because stack misalignment is the one mistake in that
/// hand-written entry stub with no compile-time and almost no runtime
/// signal: nothing faults, nothing warns, and the damage only appears
/// later as corrupted data from an aligned SSE move somewhere entirely
/// unrelated. The arithmetic is spelled out in `syscall_entry`'s docs,
/// but arithmetic in a comment is a claim, and this project's standard is
/// to put the claim in the boot log where it can be checked. A wrong
/// answer here means the push count in `syscall_entry` changed without
/// its alignment reasoning being redone.
///
/// Once per boot rather than per syscall: it's a property of the stub's
/// instruction sequence, identical on every call, so printing it each
/// time would be noise rather than evidence.
fn check_syscall_stack_alignment(rsp_at_call: u64) {
    static REPORTED: AtomicBool = AtomicBool::new(false);

    if REPORTED.swap(true, Ordering::SeqCst) {
        return;
    }

    let misalignment = rsp_at_call % 16;
    if misalignment == 0 {
        serial_println!(
            "Najm Kernel: syscall entry stack alignment confirmed (RSP {:#x} is 16-byte \
             aligned at the dispatcher call)",
            rsp_at_call
        );
    } else {
        serial_println!(
            "Najm Kernel: SYSCALL STACK MISALIGNED - RSP {:#x} is {} bytes off a 16-byte \
             boundary at the dispatcher call. The push count in syscall_entry and its \
             alignment reasoning have drifted apart; SSE spills in any called code may \
             corrupt silently.",
            rsp_at_call,
            misalignment
        );
    }
}

/// Decides what a syscall actually does. An ordinary `extern "C"` Rust
/// function - all the fragile register and alignment work is confined to
/// `syscall_entry` above, so that everything from here on is normal, safe
/// Rust that can be read and changed without thinking about calling
/// conventions.
///
/// Returns the value the calling program receives in RAX. Note that
/// `SYS_EXIT` never returns at all: it diverts to the supervisor via
/// `usermode::end_program`, abandoning the interrupt frame rather than
/// `iretq`-ing back to a program that asked to stop existing.
extern "C" fn syscall_dispatch(
    number: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    rsp_at_call: u64,
) -> u64 {
    check_syscall_stack_alignment(rsp_at_call);

    match number {
        SYS_EXIT => {
            let status = arg1 as u32;
            serial_println!(
                "Najm Kernel: syscall exit(status = {}) - program requested termination",
                status
            );

            if usermode::program_is_running() {
                usermode::end_program(ProgramExit::Exited(status));
            }

            // `exit` from something this kernel never launched as a Ring
            // 3 program. There's no supervisor context to return to, and
            // silently continuing would be worse than saying so.
            serial_println!(
                "Najm Kernel: exit syscall with no Ring 3 program running - ignoring"
            );
            SYSCALL_UNKNOWN
        }

        SYS_WRITE => {
            let ptr = arg1;
            let len = arg2;

            // The security-critical line of this whole file: `ptr` was
            // chosen by a Ring 3 program, and the kernel is about to read
            // through it at Ring 0, where the CPU's own user/supervisor
            // check no longer applies. See
            // `mm::memory::user_range_is_accessible` for the full
            // reasoning on why this check is what keeps `write` from
            // being an arbitrary kernel-memory read primitive.
            if !crate::mm::memory::user_range_is_accessible(ptr, len) {
                serial_println!(
                    "Najm Kernel: syscall write REJECTED - buffer {:#x}..+{} is not a \
                     user-accessible mapped range",
                    ptr,
                    len
                );
                return SYSCALL_BAD_ADDRESS;
            }

            // Safety: `user_range_is_accessible` just confirmed every
            // page of `ptr..ptr + len` is present and user-accessible in
            // the active page tables, so this read is in-bounds and
            // cannot fault. Nothing can unmap it in between - this kernel
            // is single-core and the only other context that could change
            // a mapping is the one currently blocked inside this call.
            let bytes: &[u8] = unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) };

            // Written byte-by-byte through `serial_print!` rather than
            // via `from_utf8`: a user program's buffer is arbitrary
            // bytes, not guaranteed valid UTF-8, and rejecting a write
            // for bad encoding would be inventing a rule the syscall
            // never promised. Non-printable bytes are shown as an escape
            // rather than sent to the terminal raw, so a program can't
            // emit control sequences that scramble the kernel's own log.
            for &byte in bytes {
                match byte {
                    b'\n' | b'\t' | 0x20..=0x7e => serial_print!("{}", byte as char),
                    other => serial_print!("\\x{:02x}", other),
                }
            }

            // Same contract as POSIX `write`: the number of bytes taken.
            len
        }

        unknown => {
            serial_println!(
                "Najm Kernel: unknown syscall number {:#x} (args {:#x}, {:#x}, {:#x})",
                unknown,
                arg1,
                arg2,
                arg3
            );
            SYSCALL_UNKNOWN
        }
    }
}

extern "x86-interrupt" fn timer_interrupt_handler(stack_frame: InterruptStackFrame) {
    // Deliberately no serial output here: the PIT's default rate is fast
    // enough (tens of times per second) that printing on every tick would
    // flood the serial console forever, for as long as the machine stays
    // on - forever, since it never shuts down on its own. Silently
    // counting and letting `kernel_main`'s one-time self-test report the
    // result is the right amount of visibility for what this milestone
    // is actually proving.
    TIMER_TICKS.fetch_add(1, Ordering::Relaxed);

    // End Of Interrupt *before* any context switch, not after. Once
    // `preempt` switches away, this handler does not resume until the
    // interrupted task is scheduled again - which could be many ticks
    // from now, or never. The PIC will not deliver another timer IRQ
    // until it has been acknowledged, so sending EOI on the far side of
    // the switch would mean the very first preemption permanently
    // silenced the timer that drives preemption.
    //
    // Safety: this handler is only ever invoked by the CPU in response to
    // a real Timer IRQ delivered through `PICS`, which is exactly the
    // interrupt this End Of Interrupt signal acknowledges - so this can't
    // send an EOI for an interrupt that was never actually raised.
    unsafe {
        PICS.lock()
            .notify_end_of_interrupt(InterruptIndex::Timer.as_u8());
    }

    // Preemption, but only for an interrupt taken while already in Ring
    // 0. That restriction is the whole safety argument for switching
    // tasks from inside an `extern "x86-interrupt"` handler at all:
    //
    // - **Ring 0 -> Ring 0** (a kernel task was interrupted): the CPU
    //   does not switch stacks, so the interrupt frame and every register
    //   the handler's prologue saved live on *that task's own* kernel
    //   stack. Switching RSP to another task therefore parks all of it
    //   together, and switching back later finds it exactly as it was -
    //   the handler then returns and `iretq`s to the interrupted
    //   instruction as if nothing happened. Nothing about the interrupt
    //   frame needs rewriting, which is why this doesn't need the
    //   frame-rewriting technique a stackless design would.
    //
    // - **Ring 3 -> Ring 0** (a user program was interrupted): the CPU
    //   *does* switch stacks, to the single shared TSS RSP0 stack. That
    //   frame does not belong to any task's stack, so parking it by
    //   switching RSP would strand it on a stack the next Ring 3 entry
    //   will reuse and overwrite. Preempting a Ring 3 program needs its
    //   register state saved somewhere it owns, which is per-program
    //   context this kernel does not have yet - so it is explicitly not
    //   attempted rather than approximated.
    //
    // The practical effect today is nil: Ring 3 programs only run from
    // `kernel_main` before the scheduler starts. It is checked anyway
    // because "nothing currently reaches this case" is a property of
    // today's `kernel_main`, not of this handler, and the failure mode if
    // that changes is silent stack corruption.
    if stack_frame.code_segment.rpl() == x86_64::PrivilegeLevel::Ring0 {
        crate::sched::task::preempt();
    }
}

extern "x86-interrupt" fn keyboard_interrupt_handler(_stack_frame: InterruptStackFrame) {
    // pc-keyboard 0.9 splits PS/2 and USB handling into distinct types
    // (`PS2Keyboard` vs `UsbKeyboard`) where earlier versions had one
    // generic `Keyboard` type - we're reading raw scancodes off the
    // legacy PS/2 controller port below, so `PS2Keyboard` is the correct
    // one, not a naming preference.
    use pc_keyboard::{layouts, DecodedKey, HandleControl, PS2Keyboard, ScancodeSet1};
    use x86_64::instructions::port::Port;

    lazy_static! {
        static ref KEYBOARD: Mutex<PS2Keyboard<layouts::Us104Key, ScancodeSet1>> =
            Mutex::new(PS2Keyboard::new(
                ScancodeSet1::new(),
                layouts::Us104Key,
                HandleControl::Ignore
            ));
    }

    let mut keyboard = KEYBOARD.lock();

    // Safety: port 0x60 is the standard, fixed PS/2 controller data port
    // - reading it here, and only here, in response to a keyboard IRQ is
    // exactly how a PS/2 driver is meant to consume a pending scancode.
    let scancode: u8 = unsafe {
        let mut port = Port::new(0x60);
        port.read()
    };

    if let Ok(Some(key_event)) = keyboard.add_byte(scancode) {
        if let Some(key) = keyboard.process_keyevent(key_event) {
            match key {
                DecodedKey::Unicode(character) => serial_print!("{}", character),
                DecodedKey::RawKey(key) => serial_print!("{:?}", key),
            }
        }
    }

    // Safety: same reasoning as the timer handler above - this
    // acknowledges the Keyboard IRQ that's the only reason this function
    // is ever invoked in the first place.
    unsafe {
        PICS.lock()
            .notify_end_of_interrupt(InterruptIndex::Keyboard.as_u8());
    }
}
