//! Thin wrappers around Najm OS's `int 0x80` syscall interface.
//!
//! The register convention is the kernel's, not a choice made here: RAX
//! carries the syscall number, RDI/RSI/RDX carry up to three arguments,
//! and RAX carries the return value back. See `syscall_entry` and
//! `syscall_dispatch` in `kernel/src/arch/x86_64/interrupts.rs` for the
//! other end of it.
//!
//! The syscall numbers below are duplicated from the kernel rather than
//! shared, and that is a real (if currently small) problem: nothing makes
//! the two definitions move together, so a renumbering in the kernel
//! would be caught only by a program mysteriously misbehaving at runtime.
//! The fix is a crate both sides depend on, which is not worth creating
//! for two constants and one consumer - but it is worth doing the moment
//! there is a second userland program or a third syscall.

/// End the program. Never returns.
const SYS_EXIT: u64 = 0;
/// Write bytes to the kernel's console. Returns the number accepted.
const SYS_WRITE: u64 = 1;

/// Issues a syscall with two arguments.
///
/// # Safety
/// The caller must ensure `arg1`/`arg2` mean what the given syscall
/// number expects - for `SYS_WRITE`, a readable buffer pointer and its
/// true length.
unsafe fn syscall2(number: u64, arg1: u64, arg2: u64) -> u64 {
    let result: u64;
    // Safety contract forwarded from this function's own. The kernel's
    // entry stub saves and restores every caller-saved register, so
    // nothing beyond RAX is actually clobbered - but RCX and R11 are
    // declared clobbered anyway, since that is what the hardware `syscall`
    // instruction would do and depending on the current stub's generosity
    // would make this wrapper wrong the day it changes.
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("rax") number => result,
            in("rdi") arg1,
            in("rsi") arg2,
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

/// Writes `bytes` to the kernel console, returning how many it accepted.
pub fn write(bytes: &[u8]) -> u64 {
    // Safety: a slice's pointer and length are valid and consistent by
    // construction - exactly what SYS_WRITE requires.
    unsafe { syscall2(SYS_WRITE, bytes.as_ptr() as u64, bytes.len() as u64) }
}

/// Writes from a raw address, bypassing the guarantees a `&[u8]` carries.
///
/// This exists purely so the program can hand the kernel a pointer it
/// *should* refuse and observe that it does - a check that can't be
/// written with `write` above, because a valid slice is the one thing
/// that can never test it.
pub fn write_raw(ptr: u64, len: u64) -> u64 {
    // Safety: none is being claimed - that's the point. The kernel
    // validates every user pointer against its own page tables before
    // dereferencing it (see `mm::memory::user_range_is_accessible`), so
    // a bad pointer here is refused rather than acted upon. This wrapper
    // is safe to *call* precisely because the kernel does not trust it.
    unsafe { syscall2(SYS_WRITE, ptr, len) }
}

/// Ends the program with `status`. Never returns.
pub fn exit(status: u32) -> ! {
    // Safety: SYS_EXIT reads only its status argument and never returns
    // to the caller, so there is no pointer for it to misuse.
    unsafe {
        syscall2(SYS_EXIT, status as u64, 0);
    }

    // Unreachable if the kernel honours `exit`. Spinning rather than
    // returning keeps the `-> !` promise honest even if it doesn't: a
    // hang is diagnosable, whereas falling off the end of a `-> !`
    // function is undefined behaviour.
    loop {
        core::hint::spin_loop();
    }
}
