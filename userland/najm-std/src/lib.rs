#![no_std]

//! The Najm OS userland runtime: safe wrappers around `int 0x80`.
//!
//! The nearest thing this system has to a C library, and deliberately
//! almost nothing: syscall wrappers, and no allocator, no formatting
//! machinery, and no collections. A Ring 3 program here has a fixed
//! stack, no heap, and no unwinder, so anything that could allocate or
//! panic-with-formatting would be a liability rather than a convenience.
//!
//! It exists because there is now more than one userland program. The
//! wrappers used to live inside `hello` and were copied into the next
//! program that needed them, which is how one interface quietly becomes
//! two.
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

// --- Filesystem -----------------------------------------------------
//
// Every one of these returns `Result<_, u64>` where the error is a
// `najm_abi::err` number. Returning the *specific* error rather than a
// bare failure is what lets a program - and a test - distinguish "that
// file does not exist" from "I am not allowed to read files" from "that
// pointer was rejected", which are three completely different bugs.

/// Opens `path`, returning a file descriptor.
pub fn open(path: &[u8], flags: u64) -> Result<u64, u64> {
    // Safety: `path` is a real slice, so pointer and length are
    // consistent. The kernel validates the path itself - this wrapper
    // deliberately does not pre-validate, so that a program passing a
    // bad path observes the kernel's answer rather than a local one.
    decode(unsafe { syscall3(sys::OPEN, path.as_ptr() as u64, path.len() as u64, flags) })
}

/// Reads into `buf`, returning how many bytes were read. Zero means end
/// of file.
pub fn read(descriptor: u64, buf: &mut [u8]) -> Result<u64, u64> {
    // Safety: `buf` is a real mutable slice; the kernel writes at most
    // `buf.len()` bytes into it and validates the range against this
    // process's own page tables before doing so.
    decode(unsafe {
        syscall3(
            sys::READ,
            descriptor,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
        )
    })
}

/// Closes a descriptor.
pub fn close(descriptor: u64) -> Result<u64, u64> {
    // Safety: no pointer arguments.
    decode(unsafe { syscall3(sys::CLOSE, descriptor, 0, 0) })
}

/// Moves a descriptor's read position, returning the new position.
pub fn seek(descriptor: u64, offset: u64, whence: u64) -> Result<u64, u64> {
    // Safety: no pointer arguments.
    decode(unsafe { syscall3(sys::SEEK, descriptor, offset, whence) })
}

/// Fills `info` with metadata about `path`.
pub fn stat(path: &[u8], info: &mut najm_abi::FileInfo) -> Result<u64, u64> {
    // Safety: `path` is a real slice, and `info` is a real `&mut` to a
    // `#[repr(C)]` struct of the exact size the kernel writes. The kernel
    // validates the destination is writable in this process's page tables
    // regardless.
    decode(unsafe {
        syscall3(
            sys::STAT,
            path.as_ptr() as u64,
            path.len() as u64,
            info as *mut najm_abi::FileInfo as u64,
        )
    })
}

/// Fills `buf` with the NUL-separated names of a directory's entries,
/// returning how many bytes were written.
pub fn readdir(descriptor: u64, buf: &mut [u8]) -> Result<u64, u64> {
    // Safety: `buf` is a real mutable slice - same reasoning as `read`.
    decode(unsafe {
        syscall3(
            sys::READDIR,
            descriptor,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
        )
    })
}

/// This process's id.
pub fn getpid() -> u64 {
    // Safety: no pointer arguments.
    unsafe { syscall3(sys::GETPID, 0, 0, 0) }
}

/// Whether `e` is the "no such file or directory" error.
pub fn is_enoent(e: u64) -> bool {
    e == err::ENOENT
}

/// Whether `e` is the "not permitted" error - i.e. the calling Realm does
/// not hold the capability the operation requires.
pub fn is_eperm(e: u64) -> bool {
    e == err::EPERM
}

/// Whether `e` is the "invalid argument" error.
pub fn is_einval(e: u64) -> bool {
    e == err::EINVAL
}

/// Whether `e` is the "operation not supported on this object" error.
pub fn is_enotsup(e: u64) -> bool {
    e == err::ENOTSUP
}

/// Writes a `u64` in decimal to standard output.
///
/// Exists because `core::fmt` is genuinely dangerous in this environment:
/// it is deep, it allocates stack freely, and a program with a fixed
/// stack and no unwinder that overflows inside a formatting call produces
/// a page fault at a confusing address instead of the number it wanted to
/// print. Twenty digits and a manual loop cannot do that.
pub fn write_u64(value: u64) {
    let mut digits = [0u8; 20];
    let mut index = digits.len();
    let mut remaining = value;
    loop {
        index -= 1;
        digits[index] = b'0' + (remaining % 10) as u8;
        remaining /= 10;
        if remaining == 0 {
            break;
        }
    }
    let _ = write(&digits[index..]);
}

// --- Graphics and input ---------------------------------------------

/// Asks the compositor for a drawable surface.
///
/// Note the size is a *request*. The compositor decides the mode from the
/// calling Realm - a Gaming Realm gets the whole content area, everything
/// else gets a window - so a program must call `surface_info` afterwards
/// and draw at the size it was actually given. Assuming the requested
/// size is how a program ends up committing a buffer of the wrong length,
/// which the kernel refuses.
pub fn surface_create(width: u64, height: u64) -> Result<u64, u64> {
    // Safety: no pointer arguments.
    decode(unsafe { syscall3(sys::SURFACE_CREATE, width, height, 0) })
}

/// Reads a surface's actual geometry.
pub fn surface_info(id: u64, info: &mut najm_abi::SurfaceInfo) -> Result<u64, u64> {
    // Safety: `info` is a real `&mut` to a `#[repr(C)]` struct of exactly
    // the size the kernel writes, and the kernel validates the
    // destination against this process's page tables regardless.
    decode(unsafe {
        syscall3(
            sys::SURFACE_INFO,
            id,
            info as *mut najm_abi::SurfaceInfo as u64,
            0,
        )
    })
}

/// Hands a finished frame to the compositor.
///
/// `pixels` must be exactly `width * height` entries, in 0x00RRGGBB
/// form. The kernel refuses anything else rather than accepting a short
/// buffer - a partial commit would leave the rest of the frame holding
/// whatever was in that surface before, and surfaces are reused between
/// processes.
pub fn surface_commit(id: u64, pixels: &[u32]) -> Result<u64, u64> {
    // Safety: `pixels` is a real slice; pointer and length are consistent
    // by construction.
    decode(unsafe {
        syscall3(
            sys::SURFACE_COMMIT,
            id,
            pixels.as_ptr() as u64,
            (pixels.len() * 4) as u64,
        )
    })
}

/// Drains up to `events.len()` input events, returning how many arrived.
pub fn input_poll(events: &mut [najm_abi::InputEvent]) -> Result<u64, u64> {
    // Safety: `events` is a real mutable slice, and the kernel writes at
    // most `events.len()` entries into it.
    decode(unsafe {
        syscall3(
            sys::INPUT_POLL,
            events.as_mut_ptr() as u64,
            events.len() as u64,
            0,
        )
    })
}

/// Reads which Realm this process runs in and what it is allowed to
/// attempt.
pub fn realm_info(info: &mut najm_abi::RealmInfo) -> Result<u64, u64> {
    // Safety: as `surface_info` - a real `&mut` to a `#[repr(C)]` struct,
    // validated kernel-side regardless.
    decode(unsafe { syscall3(sys::REALM_INFO, info as *mut najm_abi::RealmInfo as u64, 0, 0) })
}

/// Whether `e` is the "out of memory" error.
pub fn is_enomem(e: u64) -> bool {
    e == err::ENOMEM
}

// --- IPC ------------------------------------------------------------

/// Creates a named port, returning a handle.
///
/// Requires `IPC_CREATE`, which is a strictly stronger right than
/// connecting: creating a port claims a name in a global namespace, which
/// is how a service gets impersonated.
pub fn port_create(name: &[u8]) -> Result<u64, u64> {
    // Safety: `name` is a real slice; pointer and length are consistent.
    decode(unsafe { syscall3(sys::PORT_CREATE, name.as_ptr() as u64, name.len() as u64, 0) })
}

/// Finds an existing port by name.
pub fn port_connect(name: &[u8]) -> Result<u64, u64> {
    // Safety: as `port_create`.
    decode(unsafe { syscall3(sys::PORT_CONNECT, name.as_ptr() as u64, name.len() as u64, 0) })
}

/// Queues a message, returning how many bytes were sent.
///
/// Fails with `EAGAIN` when the queue is full rather than blocking or
/// dropping - the sender is the only party that knows whether a
/// particular message is worth retrying.
pub fn port_send(handle: u64, bytes: &[u8]) -> Result<u64, u64> {
    // Safety: `bytes` is a real slice.
    decode(unsafe {
        syscall3(sys::PORT_SEND, handle, bytes.as_ptr() as u64, bytes.len() as u64)
    })
}

/// Takes the oldest message into `buf`, returning how many bytes arrived.
///
/// Non-blocking: an empty queue is `EAGAIN`, not a wait. Only the process
/// that created the port may receive from it.
pub fn port_recv(handle: u64, buf: &mut [u8]) -> Result<u64, u64> {
    // Safety: `buf` is a real mutable slice, and the kernel writes at
    // most `buf.len()` bytes into it.
    decode(unsafe {
        syscall3(sys::PORT_RECV, handle, buf.as_mut_ptr() as u64, buf.len() as u64)
    })
}

/// Destroys a port. Only its owner may.
pub fn port_close(handle: u64) -> Result<u64, u64> {
    // Safety: no pointer arguments.
    decode(unsafe { syscall3(sys::PORT_CLOSE, handle, 0, 0) })
}

/// Whether `e` is the "try again later" error - a full or empty queue.
pub fn is_eagain(e: u64) -> bool {
    e == err::EAGAIN
}

/// Whether `e` is the "already exists" error.
pub fn is_eexist(e: u64) -> bool {
    e == err::EEXIST
}
