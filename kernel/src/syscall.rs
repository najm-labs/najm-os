//! The syscall dispatcher: what each syscall number actually does.
//!
//! Split out of `arch::x86_64::interrupts` deliberately. That module owns
//! the *mechanism* - a naked entry stub that saves the caller's registers,
//! translates the syscall register convention into SysV64 argument order,
//! and calls exactly one function. This module owns the *policy*: which
//! numbers exist, what they mean, and what they are allowed to touch.
//!
//! Keeping them apart matters for two reasons beyond tidiness:
//!
//! - The entry stub is hand-written assembly whose correctness rests on a
//!   push count and a stack-alignment argument. It should change almost
//!   never. The syscall table changes constantly. Putting them in one
//!   file means every routine addition re-touches the file containing the
//!   most dangerous code in the kernel.
//! - Nothing in here is architecture-specific. A future `arch::aarch64`
//!   would need its own entry stub and could reuse this dispatcher
//!   unchanged, which is only true if it never mentions x86 registers.
//!
//! ## The rule that governs every handler here
//!
//! **Every pointer that arrives from Ring 3 is hostile until validated.**
//! Not "untrusted in principle" - hostile, because the check the CPU
//! normally performs (the `USER_ACCESSIBLE` bit) applies only to accesses
//! made *at* Ring 3, and every line of this file runs at Ring 0 where it
//! does not apply at all. A handler that dereferences an unvalidated user
//! pointer is not a bug that leaks a little information; it is an
//! arbitrary kernel-memory read primitive available to every program on
//! the system. See ARCHITECTURE.md section 3b.
//!
//! The enforcement is that handlers do not dereference user pointers *at
//! all*. They call `mm::memory::copy_from_user` / `copy_to_user`, which
//! validate and copy in one step. A handler containing a raw
//! `from_raw_parts` on a user address should be treated as a defect on
//! sight, whether or not a check appears nearby.

use crate::arch::x86_64::usermode::{self, ProgramExit};
use crate::serial_print;
use crate::serial_println;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use najm_abi::{encode_error, err, fd, sys};

/// Counts every syscall made since boot, for the boot log's
/// "the interface was actually exercised" line. Cheap enough
/// (one relaxed increment) to leave on permanently.
static SYSCALL_COUNT: AtomicU64 = AtomicU64::new(0);

/// How many syscalls have been dispatched since boot.
pub fn count() -> u64 {
    SYSCALL_COUNT.load(Ordering::Relaxed)
}

/// Reports, once per boot, whether the entry stub really did hand this
/// dispatcher a 16-byte aligned stack.
///
/// This exists because stack misalignment in that hand-written stub is
/// the one mistake with no compile-time and almost no runtime signal:
/// nothing faults, nothing warns, and the damage appears later as
/// corrupted data from an aligned SSE move somewhere entirely unrelated.
/// The arithmetic is spelled out in `syscall_entry`'s documentation, but
/// arithmetic in a comment is a claim, and this project's standard is to
/// put the claim in the boot log where it can be checked. A wrong answer
/// means the push count in `syscall_entry` changed without its alignment
/// reasoning being redone.
///
/// Once per boot rather than per syscall: it is a property of the stub's
/// instruction sequence, identical on every call, so printing it each
/// time would be noise rather than evidence.
fn check_stack_alignment(rsp_at_call: u64) {
    static REPORTED: AtomicBool = AtomicBool::new(false);

    if REPORTED.swap(true, Ordering::SeqCst) {
        return;
    }

    let misalignment = rsp_at_call % 16;
    crate::selftest::check(
        "syscall entry stack alignment",
        misalignment == 0,
        format_args!(
            "RSP {:#x} at the dispatcher call is {} bytes off a 16-byte boundary",
            rsp_at_call, misalignment
        ),
    );
}

/// Decides what a syscall actually does.
///
/// An ordinary `extern "C"` Rust function: all the fragile register and
/// alignment work is confined to `syscall_entry`, so everything from here
/// on is normal, safe Rust that can be read and changed without thinking
/// about calling conventions.
///
/// Returns the value the calling program receives in RAX. Note that
/// `EXIT` never returns at all: it diverts to the supervisor via
/// `usermode::end_program`, abandoning the interrupt frame rather than
/// `iretq`-ing back to a program that asked to stop existing.
pub extern "C" fn dispatch(number: u64, arg1: u64, arg2: u64, arg3: u64, rsp_at_call: u64) -> u64 {
    check_stack_alignment(rsp_at_call);
    SYSCALL_COUNT.fetch_add(1, Ordering::Relaxed);

    match number {
        sys::EXIT => sys_exit(arg1),
        sys::YIELD => sys_yield(),
        sys::WRITE => sys_write(arg1, arg2, arg3),
        sys::TICKS => crate::arch::x86_64::interrupts::timer_ticks(),
        sys::UPTIME_MS => crate::arch::x86_64::interrupts::uptime_ms(),

        unknown => {
            serial_println!(
                "Najm Kernel: unknown syscall number {:#x} (args {:#x}, {:#x}, {:#x})",
                unknown,
                arg1,
                arg2,
                arg3
            );
            encode_error(err::ENOSYS)
        }
    }
}

/// `exit(status)` - end the calling program.
fn sys_exit(status_arg: u64) -> u64 {
    let status = status_arg as u32;
    serial_println!(
        "Najm Kernel: syscall exit(status = {}) - program requested termination",
        status
    );

    if usermode::program_is_running() {
        usermode::end_program(ProgramExit::Exited(status));
    }

    // `exit` from something this kernel never launched as a Ring 3
    // program. There is no supervisor context to return to, and silently
    // continuing would be worse than saying so.
    serial_println!("Najm Kernel: exit syscall with no Ring 3 program running - ignoring");
    encode_error(err::EINVAL)
}

/// `yield_now()` - give up the rest of this time slice.
///
/// Returns 0 rather than diverging: from the program's point of view this
/// is an ordinary call that happens to take a while.
fn sys_yield() -> u64 {
    // `yield_from_syscall`, not `yield_now`: the latter panics when no
    // task is running, which is a routine state for a program launched
    // straight from the boot context - and a panic a Ring 3 program can
    // trigger is a denial of service, not a diagnostic. See that
    // function's documentation.
    crate::sched::task::yield_from_syscall();
    0
}

/// `write(fd, ptr, len)` - write bytes to a file descriptor.
///
/// Only the console descriptors are wired up at this point; anything else
/// is refused rather than silently accepted, so a program that assumes a
/// descriptor works finds out immediately.
fn sys_write(descriptor: u64, ptr: u64, len: u64) -> u64 {
    if descriptor != fd::STDOUT && descriptor != fd::STDERR {
        return encode_error(err::EBADF);
    }

    // The security-critical line of this whole file: `ptr` was chosen by
    // a Ring 3 program, and the kernel is about to read through it at
    // Ring 0, where the CPU's own user/supervisor check no longer
    // applies. `copy_from_user` validates the entire range against the
    // page tables and copies it in one step - see its documentation, and
    // `mm::memory::user_range_is_accessible` for the full reasoning on
    // why this check is what keeps `write` from being an arbitrary
    // kernel-memory read primitive.
    let Some(bytes) = crate::mm::memory::copy_from_user(ptr, len as usize) else {
        serial_println!(
            "Najm Kernel: syscall write REJECTED - buffer {:#x}..+{} is not a user-accessible \
             mapped range",
            ptr,
            len
        );
        return encode_error(err::EFAULT);
    };

    // Written byte-by-byte rather than via `from_utf8`: a user program's
    // buffer is arbitrary bytes, not guaranteed valid UTF-8, and
    // rejecting a write for bad encoding would be inventing a rule the
    // syscall never promised. Non-printable bytes are shown as an escape
    // rather than sent to the terminal raw, so a program cannot emit
    // control sequences that scramble the kernel's own log - a real
    // concern, not a theoretical one: a terminal that honours ANSI
    // escapes will happily let a user program repaint lines the kernel
    // already wrote, which turns the boot log from evidence into
    // something a program can edit.
    for &byte in &bytes {
        match byte {
            b'\n' | b'\t' | 0x20..=0x7e => serial_print!("{}", byte as char),
            other => serial_print!("\\x{:02x}", other),
        }
    }

    // Same contract as POSIX `write`: the number of bytes taken.
    bytes.len() as u64
}
