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
use core::sync::atomic::{AtomicU64, Ordering};
use lazy_static::lazy_static;
use pic8259::ChainedPics;
use spin::Mutex;
use x86_64::instructions::port::Port;
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
    /// IRQ 12 - the PS/2 auxiliary device, i.e. the mouse. On the
    /// secondary PIC, which is why its handler has to acknowledge both
    /// controllers.
    Mouse = PIC_2_OFFSET + 4,
}

impl InterruptIndex {
    fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Ticks since the timer interrupt was enabled. Drives preemption (see
/// `sched::task::preempt`) and every time-based measurement the kernel
/// makes.
static TIMER_TICKS: AtomicU64 = AtomicU64::new(0);

/// How many times per second the PIT fires.
///
/// The PIT's *default* rate, if nothing programs it, is its input
/// frequency divided by 65536 - about 18.2065 Hz. That is a genuinely
/// bad number to build on for two separate reasons:
///
/// 1. **It is not a round number**, so "how long is a tick?" has no exact
///    answer in milliseconds, and every duration the kernel reports is
///    off by a fraction that compounds.
/// 2. **It is far too slow for a scheduler.** A 55 ms quantum means the
///    worst case for a task waiting behind one CPU-bound peer is 55 ms of
///    latency - an eternity against the Gaming Realm's stated
///    bounded-latency goal (ARCHITECTURE.md section 4), and visible as
///    stutter to a human.
///
/// 100 Hz gives a 10 ms quantum and an exact millisecond conversion. It
/// is deliberately not 1000 Hz: at that rate the interrupt overhead
/// starts to matter on emulated hardware, and this kernel does not yet
/// have the tickless/deadline machinery that makes a high tick rate
/// worthwhile. This is the number to revisit when the Gaming Realm's
/// scheduling class gets real deadline enforcement, not before.
pub const TIMER_HZ: u64 = 100;

/// The PIT's fixed input frequency, in Hz. A hardware constant
/// (1.193182 MHz, historically derived from the NTSC colour burst
/// frequency divided by 3) - not a tunable.
const PIT_INPUT_HZ: u64 = 1_193_182;

/// I/O ports for PIT channel 0.
const PIT_CHANNEL0_DATA: u16 = 0x40;
const PIT_COMMAND: u16 = 0x43;

/// Programs PIT channel 0 to fire at [`TIMER_HZ`].
///
/// Must run before interrupts are enabled: reprogramming the divisor
/// while ticks are already arriving would leave one interval at the old
/// rate, which is harmless but makes the very first timing measurement of
/// a boot wrong for no reason.
fn init_pit() {
    let divisor = PIT_INPUT_HZ / TIMER_HZ;
    assert!(
        divisor > 0 && divisor <= u16::MAX as u64,
        "TIMER_HZ is outside the range the PIT's 16-bit divisor can express"
    );

    // Safety: 0x43 and 0x40 are the standard, fixed PIT command and
    // channel-0 data ports on every x86 machine, and this function is the
    // only code in the kernel that writes them. The command byte 0x36
    // selects channel 0, access mode "lobyte then hibyte", operating mode
    // 3 (square wave, which is what a periodic interrupt source wants),
    // and binary rather than BCD counting - so the two data writes that
    // follow are exactly the low and high halves of the divisor, in that
    // order, which is what the access mode just requested.
    unsafe {
        let mut command: Port<u8> = Port::new(PIT_COMMAND);
        let mut data: Port<u8> = Port::new(PIT_CHANNEL0_DATA);
        command.write(0x36);
        data.write((divisor & 0xFF) as u8);
        data.write((divisor >> 8) as u8);
    }
}

/// Milliseconds since the timer started, derived from the tick counter.
///
/// Exact rather than approximate because [`TIMER_HZ`] divides 1000
/// evenly - which is one of the reasons that value was chosen. An
/// assertion is not needed here; a `TIMER_HZ` that did not divide 1000
/// would simply make this truncate, and the constant's own documentation
/// is where that constraint belongs.
pub fn uptime_ms() -> u64 {
    timer_ticks() * 1000 / TIMER_HZ
}

/// How many times the timer has taken the CPU away from a program running
/// at Ring 3. See the increment site in `timer_interrupt_handler`.
static RING3_PREEMPTIONS: AtomicU64 = AtomicU64::new(0);

/// How many Ring 3 programs have been preempted since boot.
pub fn ring3_preemptions() -> u64 {
    RING3_PREEMPTIONS.load(Ordering::Relaxed)
}

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
        idt[InterruptIndex::Mouse.as_u8()].set_handler_fn(mouse_interrupt_handler);

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

    // Before the PICs are initialized and before `sti`, so no tick can
    // arrive at the old default rate.
    init_pit();

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

// Syscall numbers, error codes, and what each call actually does have all
// moved out of this file. The numbers live in the `najm-abi` crate, which
// the kernel and every userland program compile against (see
// `abi/src/lib.rs`); the handlers live in `crate::syscall`. This file
// keeps only the mechanism - the naked entry stub below - because that is
// the part that is architecture-specific and the part that should change
// almost never.

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
        // Anything the dispatcher decided about *which* syscall this was,
        // and what it should return, lives in crate::syscall - this stub
        // deliberately knows nothing about it beyond the calling
        // convention.
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
        dispatch = sym crate::syscall::dispatch,
    );
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

    // Preemption. Both Ring 0 and Ring 3 now, which is the change this
    // milestone is really about - ARCHITECTURE.md section 4 recorded the
    // Ring 3 restriction as a real gap, and this is what closes it.
    //
    // The old reasoning, and what changed:
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
    //   *does* switch stacks, to the stack named by TSS RSP0. This used
    //   to be a single shared buffer, which is what made preemption
    //   unsafe: the frame did not belong to any task, so parking it by
    //   switching RSP would strand it on memory the next Ring 3 entry
    //   immediately reused and overwrote.
    //
    //   RSP0 now points at *the currently scheduled task's own kernel
    //   stack*, updated on every switch by `sched::task::perform_switch`.
    //   The interrupt frame therefore lands on memory that task owns, and
    //   parking it is exactly as safe as the Ring 0 case above - the
    //   frame goes to sleep with the rest of the task's stack and is
    //   found intact on resume.
    //
    // The one remaining precondition is that a task actually be current.
    // A Ring 3 program launched from the boot path (the usermode and NX
    // self-tests) runs before the scheduler owns the CPU, and RSP0 is
    // still the boot stack then - shared, exactly as before. Preempting
    // in that state would reintroduce the original bug, so it is checked
    // rather than assumed.
    let interrupted_ring3 = stack_frame.code_segment.rpl() == x86_64::PrivilegeLevel::Ring3;
    if !interrupted_ring3 || crate::sched::task::current_task_owns_kernel_stack() {
        if interrupted_ring3 {
            // Counted so the boot self-tests can *prove* Ring 3
            // preemption happened rather than infer it from output
            // ordering. Without this the claim rests on a human noticing
            // that `[userland]` and `[Task A]` lines interleave, which is
            // real evidence but not checkable evidence - and a kernel
            // that quietly stopped preempting Ring 3 would still produce
            // a plausible-looking log.
            RING3_PREEMPTIONS.fetch_add(1, Ordering::Relaxed);
        }
        crate::sched::task::preempt();
    }
}

extern "x86-interrupt" fn keyboard_interrupt_handler(_stack_frame: InterruptStackFrame) {
    // The handler does the minimum: take the byte off the port and queue
    // it. It used to decode the scancode and print the character to
    // serial, which was the right amount of machinery for proving the IRQ
    // arrives and no more - the keystroke was consumed by the act of
    // observing it, so no program could ever receive one.
    //
    // Doing less here also matters for latency. An interrupt handler runs
    // with interrupts disabled and holds up everything on the machine, so
    // any work it does is charged directly against the Gaming Realm's
    // scheduling budget. Decoding belongs at Ring 3, not here.
    crate::drivers::input::on_scancode(crate::drivers::input::read_data_port());

    // Safety: this acknowledges the Keyboard IRQ that is the only reason
    // this function is ever invoked.
    unsafe {
        PICS.lock()
            .notify_end_of_interrupt(InterruptIndex::Keyboard.as_u8());
    }
}

extern "x86-interrupt" fn mouse_interrupt_handler(_stack_frame: InterruptStackFrame) {
    crate::drivers::input::on_mouse_byte(crate::drivers::input::read_data_port());

    // The mouse is on IRQ 12, which is on the *secondary* PIC. Both PICs
    // have to be acknowledged - the secondary raised the interrupt, and
    // the primary relayed it through its cascade line. Acknowledging only
    // one leaves the other believing an interrupt is still in service,
    // and it stops delivering anything further. `notify_end_of_interrupt`
    // on the chained pair handles both, which is exactly why the driver
    // goes through it rather than writing the ports directly.
    //
    // Safety: acknowledges the Mouse IRQ that is the only reason this
    // function is ever invoked.
    unsafe {
        PICS.lock()
            .notify_end_of_interrupt(InterruptIndex::Mouse.as_u8());
    }
}
