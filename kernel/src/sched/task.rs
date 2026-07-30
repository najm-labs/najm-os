//! A minimal preemptive task scheduler.
//!
//! Two ways to switch, sharing one mechanism:
//!
//! - **Cooperatively**, when a task calls `yield_now()` itself. This came
//!   first, deliberately: it's how Windows 3.x and classic Mac OS worked,
//!   and it made it possible to verify hand-written context switching in
//!   isolation before anything asynchronous could interfere with it.
//! - **Preemptively**, when the timer interrupt calls `preempt()` on a
//!   task that never offered the CPU up at all.
//!
//! Preemption is an addition, not a replacement - a task can still yield
//! early, and `yield_now` remains the only way a task that *wants* to
//! give up the CPU can do so promptly rather than waiting for a tick.
//!
//! The switch itself is the same `context_switch` in both cases, which is
//! what keeps this simple. That works because a timer interrupt taken in
//! Ring 0 does not switch stacks: the interrupt frame and the handler's
//! saved registers land on the interrupted task's own kernel stack, so
//! switching RSP parks the whole thing together and switching back finds
//! it intact. No rewriting of the interrupt return frame is needed, which
//! is the technique a design without per-task kernel stacks would be
//! forced into instead. The corresponding restriction - that a Ring 3
//! program cannot be preempted this way, because its interrupt frame
//! lands on the shared TSS RSP0 stack rather than on anything it owns -
//! is enforced at the call site in `interrupts::timer_interrupt_handler`
//! and explained there.
//!
//! This is also, by a wide margin, the riskiest code in the kernel so
//! far. Every previous milestone's mistakes were compile errors; a bug
//! here is far more likely to be a silent stack corruption or a hang -
//! the CPU executing garbage because a register or return address ended
//! up in the wrong place. Every unsafe block below has a safety comment
//! explaining exactly what invariant makes it sound, and is worth reading
//! closely rather than trusting on faith.

use crate::mm::kstack::{self, KernelStack};
use x86_64::structures::paging::PhysFrame;
use x86_64::VirtAddr;
use crate::serial_println;
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use core::arch::naked_asm;
use spin::Mutex;

// Task stack size, alignment and lifetime now live in `mm::kstack`
// (`layout::KERNEL_STACK_SIZE`), not here.
//
// They used to be `alloc::alloc` allocations from the kernel heap with an
// explicit 16-byte `Layout`, which had two problems this module could not
// fix on its own. Stacks competed with every other kernel allocation for
// a fixed-size heap - the very first run of this scheduler failed because
// two 64 KiB stacks did not fit in a 100 KiB heap. And, more seriously, a
// heap allocation cannot have a **guard page**: the memory below it
// belongs to the allocator and is probably another live allocation, so a
// task that recursed one frame too deep silently corrupted something else
// instead of faulting.
//
// `mm::kstack` gives each stack its own virtual slot with an unmapped
// page beneath it, so overflow is a page fault at a known address. The
// 16-byte ABI alignment comes free from the slot base and size both being
// multiples of 4096.

/// The RFLAGS value a brand new task starts with.
///
/// Bit 1 is reserved and architecturally always 1; bit 9 is IF, the
/// interrupt flag. Setting IF is what makes a new task preemptible from
/// its very first instruction: `context_switch` restores RFLAGS from the
/// switched-to task's own saved context, and every path that reaches a
/// new task's first instruction does so with interrupts disabled - either
/// from inside the timer interrupt handler, or from `yield_now`, which
/// disables them around the switch. Without this, a task would begin life
/// with interrupts masked and could never be preempted, which is the
/// exact bug preemption is being added to fix.
const INITIAL_RFLAGS: u64 = 0x202;

/// One task's saved execution state: everything needed to pause it and
/// later resume it exactly where it left off.
pub struct Task {
    /// The stack pointer to restore when this task is next resumed. Only
    /// meaningful while the task is *not* currently running - while it's
    /// running, this field is stale (it holds wherever RSP was the last
    /// time this task was switched *away* from).
    stack_pointer: u64,
    /// The stack this task owns, with its guard page. Returned to
    /// `mm::kstack` in `Drop`.
    stack: KernelStack,
    /// The PML4 to load into CR3 when this task is scheduled, or `None`
    /// for a pure kernel task, which runs in whatever address space
    /// happens to be current.
    ///
    /// A kernel task genuinely does not care: every address space maps
    /// the kernel identically in its higher half, so kernel code, kernel
    /// stacks and the heap are reachable from all of them. Only a task
    /// with *user* mappings needs a specific one.
    address_space_root: Option<PhysFrame>,
    /// Where `usermode::run_program` saved the Ring 0 context to resume
    /// when this task's Ring 3 program ends, or 0 if it is not running
    /// one.
    ///
    /// Per-task rather than the single global it used to be. With one
    /// global slot, two tasks each running a Ring 3 program would
    /// overwrite each other's resume point, and the second program to
    /// fault would return into the first program's already-dead stack
    /// frame. That was unreachable while Ring 3 code only ran from the
    /// boot path; it becomes reachable the moment processes are tasks,
    /// which is what this milestone does.
    supervisor_rsp: u64,
}

// Safety: the `KernelStack` slot is exclusively owned by this `Task`
// (claimed in `Task::new`, released in `Drop`, never aliased elsewhere -
// `Task` has no `Clone`), and this kernel is single-core so there is no
// concurrent hardware access to guard against yet. This impl exists
// because `Mutex<Scheduler>` needs `Scheduler: Send` to be usable in a
// `static`, and the compiler cannot infer on its own that this ownership
// pattern is safe to hand across that boundary.
unsafe impl Send for Task {}

impl Task {
    /// The value TSS RSP0 must hold while this task is scheduled.
    ///
    /// Not simply the stack top, and the difference is the whole reason
    /// Ring 3 preemption is subtle. A task that is *inside a Ring 3
    /// program* is already using the top of its kernel stack: the frames
    /// belonging to `run_program` and everything that called it sit
    /// between `supervisor_rsp` and the top, and they must survive the
    /// excursion because returning from Ring 3 means returning into them.
    /// Pointing RSP0 at the top would put the next syscall's interrupt
    /// frame directly on top of them.
    ///
    /// `supervisor_rsp` is exactly the boundary: live above, free below.
    /// The `- 8` restores 16-byte alignment, which the syscall entry
    /// stub's own alignment argument depends on (`enter_usermode_and_wait`
    /// writes the same value into RSP0 at the moment of entry; this is
    /// what keeps it correct across a *preemption* and back).
    ///
    /// A task with no Ring 3 program running has an empty kernel stack
    /// from the CPU's point of view - it can only be in Ring 0 - so the
    /// top is right for it, and is also simply unused, since nothing will
    /// transition into Ring 0 from a task that never left it.
    fn kernel_rsp0(&self) -> u64 {
        if self.supervisor_rsp != 0 {
            self.supervisor_rsp - 8
        } else {
            self.stack.top
        }
    }

    /// Builds a new task ready to run `entry` the first time it's
    /// switched to. `entry` must never return (enforced by the `-> !` in
    /// its type) - there is no mechanism here for a task to "return
    /// normally"; the fabricated initial stack frame below only works
    /// because `context_switch`'s `ret` is the *only* thing that ever
    /// reads it.
    pub fn new(entry: extern "C" fn() -> !) -> Task {
        let stack = crate::mm::memory::with_memory(|mapper, frame_allocator| {
            kstack::allocate(mapper, frame_allocator)
        })
        .expect("out of kernel stack slots - raise layout::KERNEL_STACK_SLOTS");

        let mut rsp = stack.top;

        // Hand-builds the exact stack layout `context_switch` expects to
        // find for a task it's resuming for the first time: a starting
        // RFLAGS value, six placeholder callee-saved register values,
        // then the task's entry point sitting where `context_switch`'s
        // final `ret` expects a return address. This mirrors, byte for
        // byte, what the stack would look like if `entry` had been
        // reached via a real earlier call to `context_switch` from a task
        // that was already running - `context_switch` itself can't tell
        // the difference, which is exactly the point.
        //
        // Safety: each write targets an address strictly between
        // `stack_base` and `stack_top` (8 * 8 = 64 bytes below a
        // STACK_SIZE-byte, i.e. much larger, allocation), and nothing
        // else holds a reference into this freshly-allocated,
        // not-yet-shared memory yet.
        unsafe {
            rsp -= 8;
            (rsp as *mut u64).write(entry as usize as u64); // return address for the final `ret`
            rsp -= 8;
            (rsp as *mut u64).write(INITIAL_RFLAGS); // restored by `popfq`
            rsp -= 8;
            (rsp as *mut u64).write(0); // rbp
            rsp -= 8;
            (rsp as *mut u64).write(0); // rbx
            rsp -= 8;
            (rsp as *mut u64).write(0); // r12
            rsp -= 8;
            (rsp as *mut u64).write(0); // r13
            rsp -= 8;
            (rsp as *mut u64).write(0); // r14
            rsp -= 8;
            (rsp as *mut u64).write(0); // r15
        }

        Task {
            stack_pointer: rsp,
            stack,
            address_space_root: None,
            supervisor_rsp: 0,
        }
    }
}

impl Drop for Task {
    fn drop(&mut self) {
        // Returns the slot for reuse. Unlike the previous heap-based
        // version this frees no memory - the mapping stays in place
        // deliberately, so that a dangling pointer into a dead task's
        // stack lands on an identifiable address rather than inside an
        // unrelated live allocation. See `mm::kstack::release`.
        //
        // `Task` has no `Clone`, so a slot can never be released twice.
        kstack::release(self.stack);
    }
}

impl Task {
    /// Builds a task whose entry point receives a single opaque context
    /// pointer, rather than taking no arguments at all like `Task::new`.
    /// This is what makes it possible for a task to carry its own data -
    /// a Realm's capability set (see `realm.rs`), for instance - instead
    /// of only ever reaching for values sitting in some `static`.
    ///
    /// A second constructor, deliberately, rather than a change to
    /// `Task::new` itself: that zero-argument path is already proven
    /// correct (see the `task_a`/`task_b`/`task_c` self-test in
    /// main.rs), and keeping it completely untouched means a bug in this
    /// new path can't silently reintroduce a regression in the
    /// already-working one.
    pub fn new_with_context(entry: extern "C" fn(*mut u8) -> !, context: *mut u8) -> Task {
        let stack = crate::mm::memory::with_memory(|mapper, frame_allocator| {
            kstack::allocate(mapper, frame_allocator)
        })
        .expect("out of kernel stack slots - raise layout::KERNEL_STACK_SLOTS");

        let mut rsp = stack.top;

        // Same fabricated-frame technique as `Task::new`, with two
        // differences: the "return address" points at `task_trampoline`
        // instead of straight at the entry point, and two of the
        // placeholder register slots (r12, r13) carry real values
        // instead of zero. `task_trampoline` reads exactly those two
        // registers to set up the call into `entry` with `context` as
        // its argument - see that function's own documentation for the
        // full mechanism.
        //
        // Safety: every write targets an address strictly between
        // `stack_base` and `stack_top` (8 * 8 = 64 bytes below a
        // STACK_SIZE-byte allocation), on memory nothing else references
        // yet.
        unsafe {
            rsp -= 8;
            // Cast through `*const ()` first rather than straight to
            // `usize`: `task_trampoline` used bare like this is a
            // "function item" (a distinct, zero-sized-until-coerced
            // type unique to this one function), not yet a function
            // pointer - casting a function item directly to an integer
            // is exactly what `function_casts_as_integer` warns about,
            // because it skips the explicit coercion to a pointer first.
            // The runtime value is identical either way on this target;
            // this is purely about being explicit rather than relying on
            // an implicit coercion the lint would rather see spelled out.
            (rsp as *mut u64).write(task_trampoline as *const () as usize as u64); // return address
            rsp -= 8;
            (rsp as *mut u64).write(INITIAL_RFLAGS); // restored by `popfq`
            rsp -= 8;
            (rsp as *mut u64).write(0); // rbp
            rsp -= 8;
            (rsp as *mut u64).write(0); // rbx
            rsp -= 8;
            (rsp as *mut u64).write(context as u64); // r12 - read by task_trampoline
            rsp -= 8;
            (rsp as *mut u64).write(entry as usize as u64); // r13 - read by task_trampoline
            rsp -= 8;
            (rsp as *mut u64).write(0); // r14
            rsp -= 8;
            (rsp as *mut u64).write(0); // r15
        }

        Task {
            stack_pointer: rsp,
            stack,
            address_space_root: None,
            supervisor_rsp: 0,
        }
    }
}

/// A tiny hand-off between `context_switch`'s `ret` and a context-taking
/// task's actual entry point.
///
/// `context_switch` can only ever "return into" an address - it has no
/// way to also populate an argument register for whatever it lands on,
/// because the registers it restores (r12-r15, rbx, rbp) are fixed by
/// the calling convention as *callee-saved*, not argument, registers.
/// This function exists purely to bridge that gap: `new_with_context`
/// stashes the real entry point in r13 and the context pointer in r12
/// (arbitrary but fixed choices, matched here), and this moves the
/// context pointer into rdi (the first argument register per SysV64)
/// before jumping straight into the real entry point. `jmp`, not `call`:
/// nothing here ever needs to return, matching `entry`'s own `-> !`
/// contract, and `jmp` doesn't push a return address that would
/// otherwise just sit there unused forever.
#[unsafe(naked)]
unsafe extern "C" fn task_trampoline() -> ! {
    naked_asm!("mov rdi, r12", "jmp r13",);
}

/// Saves the currently running context's callee-saved registers and
/// stack pointer, then loads a different task's - the entire mechanism
/// that makes "switching tasks" mean anything at the hardware level.
///
/// Deliberately naked (no compiler-generated prologue/epilogue): a normal
/// function would push its own frame *before* this code runs and expect
/// to pop a matching frame *after* - both of which become nonsense the
/// instant `mov rsp, rsi` retargets the stack out from under it mid
/// function. Naked functions exist specifically so hand-written assembly
/// can own the entire function body with no such assumptions baked in by
/// the compiler.
///
/// # Safety
/// `current_stack_out` must be a valid, exclusively-owned pointer to
/// write a `u64` through (see call sites: it always points at a `Task`
/// whose heap allocation guarantees stability, per the `Box<Task>` note
/// in `Scheduler`). `next_stack` must be a stack pointer previously
/// produced either by `Task::new` (a never-yet-run task) or by this same
/// function's own write to a *different* task's `current_stack_out` on
/// some earlier call (a previously-paused task) - any other value is a
/// jump into undefined memory.
#[unsafe(naked)]
unsafe extern "C" fn context_switch(current_stack_out: *mut u64, next_stack: u64) {
    naked_asm!(
        // RFLAGS is part of a task's context, not just its registers.
        // This matters entirely because of preemption: a task switched
        // away from inside the timer interrupt handler was running with
        // IF cleared (the CPU clears it on entry through an interrupt
        // gate), while a task that called `yield_now` had it cleared
        // deliberately - so without saving and restoring it per task,
        // whichever task got resumed would inherit the *switcher's*
        // interrupt state instead of its own. A brand new task would
        // inherit IF=0 and could then never be preempted, which would
        // quietly reduce preemptive scheduling back to cooperative.
        // `Task::new` fabricates this slot as `INITIAL_RFLAGS`.
        "pushfq",
        // Save the currently running task's callee-saved registers.
        // (RDI and RSI, the incoming arguments, are caller-saved and
        // don't need preserving here - the values we need from them are
        // read immediately below, before anything could clobber them.)
        "push rbp",
        "push rbx",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        // Save the resulting RSP - pointing just below everything pushed
        // above - into *current_stack_out (first arg, RDI per SysV64).
        "mov [rdi], rsp",
        // Switch the stack itself to the next task's saved pointer
        // (second arg, RSI). Every instruction after this line executes
        // on a *completely different* stack than every instruction
        // before it.
        "mov rsp, rsi",
        // Restore the callee-saved registers exactly as the task now
        // resuming had them saved - either by an earlier call to this
        // same function, or fabricated by `Task::new` to look like one.
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbx",
        "pop rbp",
        // Restores the resuming task's own interrupt/flags state - see
        // the `pushfq` comment above for why this is per-task rather
        // than global.
        "popfq",
        // Pops the return address sitting just above those registers and
        // jumps to it - back into whatever called `context_switch` on
        // behalf of the task now resuming (for a task that's run before),
        // or straight into that task's entry point (for a brand new one,
        // per the stack `Task::new` fabricates).
        "ret",
    );
}

struct Scheduler {
    /// Tasks that are ready to run but not currently running.
    ///
    /// `Box<Task>`, not bare `Task`, specifically so a `Task`'s heap
    /// address stays stable no matter how this queue gets reordered or
    /// reallocated - `yield_now` takes a raw pointer into a `Task` while
    /// it's mid-transition between `current` and this queue, and that
    /// pointer has to remain valid across the `VecDeque` operations
    /// happening around it. Moving a `Box` moves a pointer; it never
    /// moves the heap allocation the pointer refers to.
    ready_queue: VecDeque<Box<Task>>,
    /// The task presently running - `None` only before the very first
    /// switch (see `run_until_idle`), and after the last task exits.
    current: Option<Box<Task>>,
    /// A task that has called `exit_task` and is waiting to be freed.
    ///
    /// It cannot be freed at the moment it exits, because at that moment
    /// the CPU is still *executing on its stack* - `dealloc` would hand
    /// the allocator back memory that the very next instruction still
    /// reads from. So the exiting task parks itself here, switches away,
    /// and whichever context runs next frees it from a stack it does not
    /// own. Exactly one slot is enough because only one task can be
    /// mid-exit at a time on a single core, and the next exit cannot
    /// begin until some other task has run - which is precisely when the
    /// previous zombie gets reaped.
    zombie: Option<Box<Task>>,
    /// Where to resume the boot context when the last task exits. Written
    /// by `run_until_idle` before it switches away, and used as the
    /// switch target when `exit_task` finds the ready queue empty.
    ///
    /// Zero means "no boot context to return to" - which is the case when
    /// the scheduler was entered via `start()` rather than
    /// `run_until_idle()`, and makes the last task's exit a halt instead
    /// of a return.
    boot_stack_pointer: u64,
}

impl Scheduler {
    const fn new() -> Self {
        Scheduler {
            ready_queue: VecDeque::new(),
            current: None,
            zombie: None,
            boot_stack_pointer: 0,
        }
    }
}

static SCHEDULER: Mutex<Scheduler> = Mutex::new(Scheduler::new());

/// Adds a new task to the ready queue. Safe to call at any point before
/// or after `start()` - it just appends to the queue either way.
///
/// `without_interrupts` around the lock is not optional now that the
/// timer interrupt can preempt: if a tick arrived while this held
/// `SCHEDULER`'s lock, `preempt` would try to take the same non-reentrant
/// spin lock and spin forever against a holder that can never run again.
/// That applies to every acquisition of this lock outside an interrupt
/// handler, which is why they all look like this.
pub fn spawn(entry: extern "C" fn() -> !) {
    // The `Task` is built *before* the scheduler lock is taken, not
    // inside it. Constructing one now maps a kernel stack, which takes
    // the page-table lock - and holding two kernel locks at once is how a
    // lock-order inversion gets introduced. Building first means only one
    // lock is ever held at a time on this path.
    let task = Box::new(Task::new(entry));
    x86_64::instructions::interrupts::without_interrupts(|| {
        SCHEDULER.lock().ready_queue.push_back(task);
    });
}

/// The `new_with_context` counterpart to `spawn` - adds a task built via
/// `Task::new_with_context` to the ready queue. See that function, and
/// `realm.rs`, for what "context" is for.
pub fn spawn_with_context(entry: extern "C" fn(*mut u8) -> !, context: *mut u8) {
    // Built before the lock is taken - see `spawn` for why.
    let task = Box::new(Task::new_with_context(entry, context));
    x86_64::instructions::interrupts::without_interrupts(|| {
        SCHEDULER.lock().ready_queue.push_back(task);
    });
}

/// Spawns a task bound to a specific address space - i.e. a process.
///
/// The address space root is recorded on the `Task` rather than being
/// loaded by the task's own entry point, because it has to be in place
/// *before* the task's first instruction runs and again after every
/// preemption. A task that loaded CR3 itself would be correct exactly
/// once: the first time it was scheduled. Every subsequent resume would
/// run its user code against whichever address space the previous task
/// left loaded.
pub fn spawn_process(
    entry: extern "C" fn(*mut u8) -> !,
    context: *mut u8,
    address_space_root: PhysFrame,
) {
    let mut task = Task::new_with_context(entry, context);
    task.address_space_root = Some(address_space_root);
    let task = Box::new(task);
    x86_64::instructions::interrupts::without_interrupts(|| {
        SCHEDULER.lock().ready_queue.push_back(task);
    });
}

/// Voluntarily gives up the CPU to the next ready task, if there is one.
/// Must only be called from within a task that was itself started via
/// `spawn` + `start` - calling this before any task is running has
/// nothing to save the caller's context *as*, and panics rather than
/// corrupting state silently.
///
/// If the ready queue is empty (this is the only runnable task), this
/// returns immediately without switching anywhere - "yielding" to no one
/// is a no-op, not an error.
pub fn yield_now() {
    yield_inner(SwitchKind::Voluntary)
}

/// The `yield` *syscall*'s entry point - identical to `yield_now` except
/// that "no task is running" is a quiet no-op rather than a panic.
///
/// The distinction is not pedantic; conflating the two was a real bug.
/// `yield_now` panics when nothing is current because a *kernel* task
/// calling it in that state means the scheduler's bookkeeping is broken,
/// and continuing would corrupt a stack. But the same condition reached
/// through a syscall means something entirely different and entirely
/// routine: a Ring 3 program launched directly from the boot context,
/// before the scheduler owns the CPU, asked to yield. There is nothing to
/// yield to and nothing wrong.
///
/// Routing a user program's request into the panicking path made
/// `yield()` a one-instruction kernel panic available to any program on
/// the system - a denial of service with no privileges required. The rule
/// this encodes: **a syscall handler may never reach a `panic!` that a
/// user program controls the trigger for.** Invalid input from Ring 3 is
/// an error to return, never a reason to stop the machine.
pub fn yield_from_syscall() {
    yield_inner(SwitchKind::VoluntaryFromUser)
}

fn yield_inner(kind: SwitchKind) {
    let interrupts_were_enabled = x86_64::instructions::interrupts::are_enabled();

    // Interrupts stay off from here until after the switch completes.
    // Two distinct races need this, not just the lock deadlock that
    // `spawn` guards against:
    //
    // 1. A tick arriving while this holds `SCHEDULER`'s lock would
    //    deadlock, exactly as described on `spawn`.
    // 2. Worse and subtler: a tick arriving in the window *between*
    //    releasing the lock and executing `context_switch` would find
    //    the scheduler already claiming `next` is the current task,
    //    while this code is still running on the old one. `preempt`
    //    would then save this stack pointer into `next`'s `Task`,
    //    corrupting a task that had not started running yet.
    //
    // Deliberately not `without_interrupts`, which would re-enable them
    // at the end of the block - i.e. squarely inside window 2.
    x86_64::instructions::interrupts::disable();

    let switch = plan_switch(kind);

    match switch {
        Some(switch) => {
            // Safety: interrupts are disabled (just above), the scheduler
            // lock was released inside `plan_switch`, and `switch` came
            // from that call - the three preconditions `perform_switch`
            // states.
            unsafe {
                perform_switch(switch);
            }

            // Execution returns here later - possibly much later, and
            // possibly "returning" for the first time ever if this call
            // is what a brand new task's fabricated stack frame resumes
            // into - whenever something switches back to this task.
            //
            // `context_switch`'s `popfq` restored the RFLAGS this task
            // saved on its way out, which had IF clear (disabled just
            // above), so the caller's interrupt state has to be put back
            // explicitly rather than assumed to have survived.
            if interrupts_were_enabled {
                x86_64::instructions::interrupts::enable();
            }
        }
        None => {
            // Nothing else to run - "yielding" to no one is a no-op, not
            // an error. Restore whatever interrupt state the caller had.
            if interrupts_were_enabled {
                x86_64::instructions::interrupts::enable();
            }
        }
    }
}

/// Switches away from the current task if there's another one ready -
/// the involuntary counterpart to `yield_now`, called from the timer
/// interrupt handler.
///
/// The difference from `yield_now` is entirely in what "no current task"
/// means. For `yield_now` it's a caller error worth panicking over: only
/// a running task can yield. Here it's routine - the timer fires
/// constantly during boot, long before `start()` is ever called - so it
/// returns quietly instead.
///
/// # Safety-relevant preconditions, enforced by the caller
/// Must only be called from an interrupt that did **not** switch stacks,
/// i.e. one taken while already in Ring 0. See the call site in
/// `interrupts::timer_interrupt_handler` for why that check lives there.
pub fn preempt() {
    // No interrupt-flag juggling here, unlike `yield_now`: this is only
    // ever reached from an interrupt gate, which already cleared IF, and
    // the eventual `iretq` restores the interrupted context's own flags.
    if let Some(switch) = plan_switch(SwitchKind::Preemptive) {
        // Safety: this is only ever reached from an interrupt gate, which
        // already cleared IF, and `plan_switch` released the scheduler
        // lock before returning.
        unsafe {
            perform_switch(switch);
        }
    }
}

/// Whether a switch was asked for by the running task or forced on it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SwitchKind {
    /// A kernel task called `yield_now()`. "Nothing is current" is a
    /// broken invariant here and panics.
    Voluntary,
    /// A Ring 3 program made the `yield` syscall. "Nothing is current" is
    /// routine - see `yield_from_syscall`.
    VoluntaryFromUser,
    /// The timer took the CPU away. "Nothing is current" is the normal
    /// case during boot.
    Preemptive,
}

/// The shared bookkeeping behind `yield_now` and `preempt`: picks the
/// next task, rotates the current one to the back of the ready queue, and
/// returns the two values `context_switch` needs - or `None` if no switch
/// should happen.
///
/// Critically, the lock is dropped *before* this returns, so it is never
/// held across `context_switch`. Holding it across the switch would mean
/// the task being switched *to* resumes with that lock still marked held,
/// by a stack frame that is paused rather than gone - the next task to
/// reach this function would deadlock against it. That ordering is the
/// difference between "a scheduler" and "a scheduler that hangs the
/// second task that ever yields."
///
/// Callers must have interrupts disabled: see the comments in `yield_now`
/// and `preempt` for the two different reasons each one already does.
fn plan_switch(kind: SwitchKind) -> Option<Switch> {
    let mut scheduler = SCHEDULER.lock();

    let next = scheduler.ready_queue.pop_front()?;

    let mut current = match scheduler.current.take() {
        Some(current) => current,
        None => {
            // Put back what was just taken - failing to would silently
            // drop a task (and free its stack out from under a `Task`
            // that may never have run).
            scheduler.ready_queue.push_front(next);

            return match kind {
                // The timer ticks throughout boot, before any task is
                // running. Nothing to preempt is the normal case.
                SwitchKind::Preemptive => None,
                // A user program yielding before the scheduler owns the
                // CPU. Also normal, and - critically - never a reason to
                // panic: the trigger is under a Ring 3 program's control.
                SwitchKind::VoluntaryFromUser => None,
                SwitchKind::Voluntary => panic!(
                    "yield_now() called with no current task running - \
                     only call this from within a task started via spawn()+start()"
                ),
            };
        }
    };

    // Safety-relevant: this pointer is taken from `current` *before*
    // `current` is moved into `ready_queue` on the next line - but since
    // `current` is a `Box<Task>`, moving the `Box` only moves the
    // (separate, stack-allocated-here) pointer *to* the heap data; the
    // `Task` this points at, and therefore this pointer itself, stays
    // valid.
    let current_stack_out: *mut u64 = &mut current.stack_pointer;
    let switch = Switch {
        current_stack_out,
        next_stack: next.stack_pointer,
        next_kernel_stack_top: next.kernel_rsp0(),
        next_address_space: next.address_space_root,
    };

    scheduler.ready_queue.push_back(current);
    scheduler.current = Some(next);

    Some(switch)
}

/// Everything `perform_switch` needs to move the CPU onto another task.
struct Switch {
    current_stack_out: *mut u64,
    next_stack: u64,
    /// The incoming task's kernel stack top, which becomes TSS RSP0.
    next_kernel_stack_top: u64,
    /// The incoming task's address space, if it has one of its own.
    next_address_space: Option<PhysFrame>,
}

/// Loads the incoming task's address space and kernel stack, then
/// switches to it.
///
/// The two lines before `context_switch` are what make Ring 3 preemption
/// safe, and both are easy to leave out without anything failing
/// immediately:
///
/// - **RSP0.** The CPU switches to this stack on any Ring 3 -> Ring 0
///   transition. Pointing it at the incoming task's own kernel stack is
///   what stops two user programs' interrupt frames from landing on the
///   same memory. Miss it, and preempting a Ring 3 program strands its
///   saved state on a stack the next Ring 3 entry overwrites.
/// - **CR3.** Without it a process would run against whichever address
///   space happened to be loaded, seeing another process's memory at its
///   own addresses. Note the order: CR3 is loaded *before*
///   `context_switch`, while still executing on the outgoing task's
///   kernel stack. That is safe precisely because every address space
///   maps the kernel identically in its higher half - the stack under the
///   CPU's feet does not move when CR3 changes. It is the single property
///   the whole higher-half split was built to provide.
///
/// # Safety
/// Must be called with interrupts disabled and the scheduler lock
/// released - see `yield_inner` and `preempt` for why each of those is
/// required. `switch` must have come from `plan_switch`.
unsafe fn perform_switch(switch: Switch) {
    // Safety: `next_kernel_stack_top` is the top of a `mm::kstack` slot
    // owned by a task that is now `current`, so it stays mapped until
    // that task is switched away from - exactly the lifetime this
    // requires.
    unsafe {
        crate::arch::x86_64::gdt::set_privilege_stack(VirtAddr::new(switch.next_kernel_stack_top));
    }

    if let Some(root) = switch.next_address_space {
        // Safety: `root` is the PML4 of an address space owned by a live
        // process (dropped only after its task exits, which cannot happen
        // while it is being switched *to*), and its higher half was
        // copied from the kernel's, so kernel code and this stack remain
        // mapped across the write.
        unsafe {
            crate::mm::address_space::restore(root);
        }
    } else {
        // A pure kernel task. Returning to the kernel's own address space
        // rather than inheriting the outgoing process's is deliberate: a
        // kernel task has no business having a user-mapped lower half
        // visible to it, and leaving one loaded would mean a stray
        // lower-half pointer dereference reads a process's memory instead
        // of faulting.
        //
        // Safety: the kernel root is recorded at boot and is live for the
        // machine's lifetime.
        unsafe {
            crate::mm::address_space::restore(crate::mm::address_space::kernel_root());
        }
    }

    // Safety: both pointers come from `plan_switch`, which only produces
    // them from heap-stable `Box<Task>` allocations it has just placed in
    // the scheduler.
    unsafe {
        context_switch(switch.current_stack_out, switch.next_stack);
    }
}

/// A pointer to the current task's Ring 3 resume slot, or to the boot
/// context's if no task is running.
///
/// `usermode` needs somewhere per-context to record where to return when
/// a Ring 3 program ends, and it is reached from a fault handler that has
/// no way to be handed a reference. It used to be a single global, which
/// was correct while Ring 3 code only ever ran from the boot path and
/// could not nest. Once a process is a task, two tasks can each be inside
/// a Ring 3 program at the same time, and one global slot would have the
/// second program's fault return into the first program's stack frame.
///
/// The boot-context fallback is not a special case bolted on: the boot
/// path genuinely is a context that runs Ring 3 programs (the usermode
/// and NX self-tests) and genuinely has no `Task`.
pub fn supervisor_slot() -> *mut u64 {
    static BOOT_SUPERVISOR_RSP: spin::Mutex<u64> = spin::Mutex::new(0);

    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut scheduler = SCHEDULER.lock();
        match scheduler.current.as_mut() {
            // Heap-stable per the `Box<Task>` reasoning in `Scheduler`:
            // the pointer stays valid across the queue operations that
            // happen while a Ring 3 program runs.
            Some(task) => &mut task.supervisor_rsp as *mut u64,
            None => {
                // `BOOT_SUPERVISOR_RSP`'s address, not the guard's - the
                // static outlives every borrow of it.
                let guard = BOOT_SUPERVISOR_RSP.lock();
                let ptr = &*guard as *const u64 as *mut u64;
                drop(guard);
                ptr
            }
        }
    })
}

/// Whether the current task has an address space of its own, and
/// therefore whether a Ring 3 program running on it can be preempted.
pub fn current_task_owns_kernel_stack() -> bool {
    x86_64::instructions::interrupts::without_interrupts(|| SCHEDULER.lock().current.is_some())
}

/// Ends the calling task permanently and switches to whatever runs next.
///
/// This is what a task's entry point should call instead of parking in
/// `halt_loop()` forever. The difference is not cosmetic: a parked task
/// stays in the ready queue, gets scheduled, and burns a time slice doing
/// nothing, for as long as the machine is on. Worse, it means the
/// scheduler can never observe "everything finished", which is exactly
/// the observation the boot self-tests need in order to report a verdict
/// and shut down.
///
/// The subtle part is that a task cannot free its own stack: the CPU is
/// still executing on it. So the exiting task hands itself to
/// `Scheduler::zombie` and lets the *next* context free it - see that
/// field's documentation.
///
/// # Panics
/// If called when no task is current, which would mean something outside
/// a task tried to exit one.
pub fn exit_task() -> ! {
    // Interrupts stay off through the whole sequence, for the same reason
    // `yield_now` disables them: a tick landing between "the scheduler
    // says the next task is current" and "the CPU is actually on the next
    // task's stack" would let `preempt` save this dying stack pointer
    // into a task that has not started running.
    x86_64::instructions::interrupts::disable();

    let (next_stack, next_kernel_stack_top, next_address_space, reaped) = {
        let mut scheduler = SCHEDULER.lock();

        let dying = scheduler
            .current
            .take()
            .expect("exit_task() called with no task running");

        // Reap the *previous* zombie before becoming one. Safe to do from
        // here because that allocation belongs to some other, already-
        // dead task - never to the stack currently executing.
        let reaped = scheduler.zombie.replace(dying);

        match scheduler.ready_queue.pop_front() {
            Some(next) => {
                let next_stack = next.stack_pointer;
                let top = next.kernel_rsp0();
                let space = next.address_space_root;
                scheduler.current = Some(next);
                (next_stack, top, space, reaped)
            }
            None => {
                // The last task just ended. Return to the boot context if
                // one is waiting (`run_until_idle`), otherwise there is
                // nowhere to go. The boot context has no task and
                // therefore no per-task kernel stack, so RSP0 goes back
                // to the fixed stack `gdt::init` installed - the same one
                // it had before the scheduler ever ran.
                (
                    scheduler.boot_stack_pointer,
                    crate::arch::x86_64::gdt::boot_privilege_stack().as_u64(),
                    None,
                    reaped,
                )
            }
        }
    };

    // Dropped after the scheduler lock is released, so a heap free cannot
    // be taken while holding it.
    drop(reaped);

    if next_stack == 0 {
        // Entered via `start()`, which promised never to return, and no
        // other task is ready. Nothing left to switch to.
        serial_println!(
            "Najm Kernel: last task exited and no boot context was saved - halting"
        );
        crate::halt_loop();
    }

    // A scratch slot for the outgoing stack pointer that is deliberately
    // never read. It lives on the dying task's own stack, which is still
    // allocated (this task is the zombie now, and nothing frees a zombie
    // until after the switch completes), so the write is in-bounds.
    let mut discarded: u64 = 0;

    // The same RSP0 and CR3 updates every other switch does. Leaving them
    // out here would be a subtle and nasty bug: the *last* switch a task
    // ever makes would hand the CPU to its successor while RSP0 still
    // pointed at the dying task's kernel stack (about to be reused for a
    // new task) and CR3 still held the dying process's page tables (about
    // to be freed). Everything would keep working until the successor
    // took its first interrupt from Ring 3.
    //
    // Safety: `next_kernel_stack_top` is either a live task's stack or
    // the boot stack, and `next_address_space` is a live process's PML4
    // or `None`; `next_stack` came from a `Task` just made current, or is
    // the boot context's saved pointer. `discarded` is a local on this
    // task's own stack, which is still mapped - the task is the zombie
    // now, and nothing frees a zombie until after the switch completes.
    unsafe {
        perform_switch(Switch {
            current_stack_out: &mut discarded,
            next_stack,
            next_kernel_stack_top,
            next_address_space,
        });
    }

    unreachable!("a task resumed after exit_task() switched away from it");
}

/// Frees any task that has exited since the last time this was called.
///
/// Called from the boot context after `run_until_idle` returns, where
/// interrupts are on and no scheduler lock is held - the safest possible
/// place to touch the heap.
fn reap_zombie() {
    let zombie = x86_64::instructions::interrupts::without_interrupts(|| SCHEDULER.lock().zombie.take());
    drop(zombie);
}

/// How many tasks are queued or running right now. Reported by the boot
/// self-tests so "the scheduler drained" is an observation rather than an
/// assumption.
pub fn task_count() -> usize {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let scheduler = SCHEDULER.lock();
        scheduler.ready_queue.len() + usize::from(scheduler.current.is_some())
    })
}

/// Runs every spawned task until they have all called `exit_task`, then
/// returns to the caller.
///
/// This is the counterpart `start()` never had. `start()` is a one-way
/// trip: it abandons the boot context, so there is no way for the kernel
/// to do anything *after* the tasks are done - no summary, no verdict, no
/// shutdown. That was tolerable while the tasks were three test loops
/// whose output a human read; it is not tolerable now that the boot log
/// is meant to be machine-checkable (`scripts/boot-test.sh`).
///
/// The mechanism is the same `context_switch` as everywhere else, applied
/// to the boot context: its stack pointer is saved into
/// `Scheduler::boot_stack_pointer` on the way out, and `exit_task` uses
/// that as its switch target when the ready queue is empty. The boot
/// context therefore behaves exactly like a task that is never in the
/// ready queue and is only ever resumed last.
pub fn run_until_idle() {
    let next_stack = x86_64::instructions::interrupts::without_interrupts(|| {
        let mut scheduler = SCHEDULER.lock();
        match scheduler.ready_queue.pop_front() {
            Some(next) => {
                let next_stack = next.stack_pointer;
                scheduler.current = Some(next);
                Some(next_stack)
            }
            // No tasks at all is not an error here (unlike `start()`,
            // where it left the machine with nothing to do) - there is
            // simply nothing to run, and returning immediately is the
            // correct answer.
            None => None,
        }
    });

    let Some(next_stack) = next_stack else {
        return;
    };

    // Interrupts off across the switch, for the reason spelled out in
    // `yield_now`: the window between the scheduler declaring `next`
    // current and the CPU actually being on `next`'s stack must not be
    // interruptible.
    let interrupts_were_enabled = x86_64::instructions::interrupts::are_enabled();
    x86_64::instructions::interrupts::disable();

    // Safety: `next_stack` came from a `Task` just placed into
    // `scheduler.current` (heap-stable per the `Box<Task>` reasoning in
    // `Scheduler`). The pointer written to is a field of a `static`
    // behind a lock, valid for the whole life of the kernel; taking the
    // lock again here would deadlock against the switch, so the address
    // is captured while holding it and written to by assembly afterwards
    // - the field is only ever read by `exit_task`, which cannot run
    // until after this write has happened.
    unsafe {
        let (boot_slot, switch) = {
            let mut scheduler = SCHEDULER.lock();
            let boot_slot = &mut scheduler.boot_stack_pointer as *mut u64;
            let current = scheduler
                .current
                .as_ref()
                .expect("run_until_idle set current above");
            (
                boot_slot,
                Switch {
                    current_stack_out: boot_slot,
                    next_stack,
                    next_kernel_stack_top: current.kernel_rsp0(),
                    next_address_space: current.address_space_root,
                },
            )
        };
        let _ = boot_slot;
        perform_switch(switch);
    }

    // Reached only when the last task called `exit_task`.
    if interrupts_were_enabled {
        x86_64::instructions::interrupts::enable();
    }
    reap_zombie();
}

/// Performs the one-time transition from the kernel's own boot context
/// into task-based execution, then never returns.
///
/// Kept alongside `run_until_idle` rather than replaced by it, because
/// the two describe genuinely different intents: this one is what a
/// finished OS does at the end of boot (hand the machine over and never
/// come back), while `run_until_idle` is what a *test* boot does (run the
/// work, then report). Deleting this would mean the eventual real boot
/// path had to be re-derived from the test path.
///
/// Unlike `yield_now`, there is no "current task" for the boot context to
/// be saved *as* - kernel_main's stack was set up by the bootloader, not
/// by `Task::new`, and isn't going to be resumed later. Its final stack
/// pointer is written somewhere harmless and then never read again; this
/// is a deliberate one-way trip, not an oversight.
#[allow(dead_code)]
pub fn start() -> ! {
    // Same lock discipline as `spawn`: a timer tick between taking this
    // lock and releasing it would deadlock against `preempt`.
    let next_stack = x86_64::instructions::interrupts::without_interrupts(|| {
        let mut scheduler = SCHEDULER.lock();
        let next = scheduler
            .ready_queue
            .pop_front()
            .expect("scheduler::start() called with no tasks spawned - spawn() at least one first");
        let next_stack = next.stack_pointer;
        scheduler.current = Some(next);
        next_stack
    });

    let mut discarded_boot_stack: u64 = 0;

    // Safety: `next_stack` came directly from a `Task` just placed into
    // `scheduler.current` above (heap-stable, per the reasoning
    // throughout this module). `discarded_boot_stack` is a valid local
    // to write through - its value is deliberately never read again,
    // since nothing will ever switch back into the boot context this
    // function is abandoning.
    unsafe {
        context_switch(&mut discarded_boot_stack, next_stack);
    }

    crate::halt_loop()
}
