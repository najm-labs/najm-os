//! Thin wrappers around Najm OS's `int 0x80` syscall interface.
//!
//! The register convention is the kernel's, not a choice made here: RAX
//! carries the syscall number, RDI/RSI/RDX carry up to three arguments,
//! and RAX carries the return value back. See `syscall_entry` in
//! `kernel/src/arch/x86_64/interrupts.rs` (the mechanism) and
//! `kernel/src/syscall.rs` (the policy) for the other end of it.
//!
//! The syscall numbers themselves are **not** defined here any more.
//! They live in the `najm-abi` crate, which the kernel compiles against
//! too, so a renumbering is a change in one place rather than two
//! definitions silently drifting apart - the exact problem the previous
//! version of this file described and deferred.

use najm_abi::{decode, err, fd, sys};

/// Issues a syscall with three arguments.
///
/// One primitive rather than one per arity: the unused registers cost a
/// single instruction each, and the alternative is three near-identical
/// blocks of inline assembly - three places for the clobber list to go
/// wrong instead of one.
///
/// # Safety
/// The caller must ensure the arguments mean what the given syscall
/// number expects - for `WRITE`, a readable buffer pointer and its true
/// length.
unsafe fn syscall3(number: u64, arg1: u64, arg2: u64, arg3: u64) -> u64 {
    let result: u64;
    // Safety contract forwarded from this function's own. The kernel's
    // entry stub saves and restores every caller-saved register, so
    // nothing beyond RAX is actually clobbered - but RCX and R11 are
    // declared clobbered anyway, since that is what the hardware
    // `syscall` instruction would do, and depending on the current stub's
    // generosity would make this wrapper wrong the day it changes.
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("rax") number => result,
            in("rdi") arg1,
            in("rsi") arg2,
            in("rdx") arg3,
            lateout("rcx") _,
            lateout("r11") _,
            // `nostack`: the syscall pushes its frame onto the *kernel*
            // stack (the CPU switches to TSS RSP0 on the privilege
            // change), never this program's, so the compiler's red zone
            // stays intact across it.
            options(nostack),
        );
    }
    result
}

/// Writes `bytes` to standard output, returning how many were accepted.
pub fn write(bytes: &[u8]) -> Result<u64, u64> {
    // Safety: a slice's pointer and length are valid and consistent by
    // construction - exactly what WRITE requires.
    decode(unsafe {
        syscall3(
            sys::WRITE,
            fd::STDOUT,
            bytes.as_ptr() as u64,
            bytes.len() as u64,
        )
    })
}

/// Writes from a raw address, bypassing the guarantees a `&[u8]` carries.
///
/// This exists purely so the program can hand the kernel a pointer it
/// *should* refuse and observe that it does - a check that cannot be
/// written with `write` above, because a valid slice is the one thing
/// that can never test it.
pub fn write_raw(ptr: u64, len: u64) -> Result<u64, u64> {
    // Safety: none is being claimed - that is the point. The kernel
    // validates every user pointer against its own page tables before
    // dereferencing it (see `mm::memory::user_range_is_accessible`), so a
    // bad pointer here is refused rather than acted upon. This wrapper is
    // safe to *call* precisely because the kernel does not trust it.
    decode(unsafe { syscall3(sys::WRITE, fd::STDOUT, ptr, len) })
}

/// Writes to a file descriptor that is not open, so the program can check
/// that the kernel refuses it rather than writing somewhere arbitrary.
pub fn write_to_bad_descriptor() -> Result<u64, u64> {
    const NOT_OPEN: u64 = 4242;
    let message = b"this must never appear\n";
    // Safety: the buffer is a valid slice; only the descriptor is wrong,
    // which is exactly what is being tested.
    decode(unsafe {
        syscall3(
            sys::WRITE,
            NOT_OPEN,
            message.as_ptr() as u64,
            message.len() as u64,
        )
    })
}

/// Gives up the rest of this time slice.
pub fn yield_now() {
    // Safety: takes no pointers and no lengths; there is nothing for the
    // kernel to misuse.
    unsafe {
        syscall3(sys::YIELD, 0, 0, 0);
    }
}

/// Timer ticks since boot.
pub fn ticks() -> u64 {
    // Safety: as `yield_now` - no pointer arguments.
    unsafe { syscall3(sys::TICKS, 0, 0, 0) }
}

/// Milliseconds since boot.
pub fn uptime_ms() -> u64 {
    // Safety: as `yield_now` - no pointer arguments.
    unsafe { syscall3(sys::UPTIME_MS, 0, 0, 0) }
}

/// Calls a syscall number this kernel deliberately does not implement, so
/// the program can check that an unknown number is *refused* rather than
/// silently doing something.
pub fn call_unimplemented() -> Result<u64, u64> {
    // Safety: no pointer arguments, and by construction the kernel has no
    // handler that could act on them even if there were.
    decode(unsafe { syscall3(0xDEAD_BEEF, 0, 0, 0) })
}

/// Whether `e` is the "no such syscall" error.
pub fn is_enosys(e: u64) -> bool {
    e == err::ENOSYS
}

/// Whether `e` is the "bad address" error.
pub fn is_efault(e: u64) -> bool {
    e == err::EFAULT
}

/// Whether `e` is the "bad file descriptor" error.
pub fn is_ebadf(e: u64) -> bool {
    e == err::EBADF
}

/// Ends the program with `status`. Never returns.
pub fn exit(status: u32) -> ! {
    // Safety: EXIT reads only its status argument and never returns to
    // the caller, so there is no pointer for it to misuse.
    unsafe {
        syscall3(sys::EXIT, status as u64, 0, 0);
    }

    // Unreachable if the kernel honours `exit`. Spinning rather than
    // returning keeps the `-> !` promise honest even if it does not: a
    // hang is diagnosable, whereas falling off the end of a `-> !`
    // function is undefined behaviour.
    loop {
        core::hint::spin_loop();
    }
}
