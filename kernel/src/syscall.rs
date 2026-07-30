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
        sys::GETPID => crate::sched::task::current_pid(),

        sys::OPEN => sys_open(arg1, arg2, arg3),
        sys::READ => sys_read(arg1, arg2, arg3),
        sys::CLOSE => sys_close(arg1),
        sys::SEEK => sys_seek(arg1, arg2, arg3),
        sys::STAT => sys_stat(arg1, arg2, arg3),
        sys::READDIR => sys_readdir(arg1, arg2, arg3),

        sys::SURFACE_CREATE => sys_surface_create(arg1, arg2),
        sys::SURFACE_COMMIT => sys_surface_commit(arg1, arg2, arg3),
        sys::SURFACE_INFO => sys_surface_info(arg1, arg2),
        sys::INPUT_POLL => sys_input_poll(arg1, arg2),
        sys::REALM_INFO => sys_realm_info(arg1),

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

/// The longest path a syscall will accept from userland.
///
/// Matches the archive's own limit rather than being an independent
/// number: a path longer than any path that can exist cannot name
/// anything, so accepting it would only mean spending time to fail.
const MAX_PATH: usize = najm_abi::archive::MAX_PATH;

/// Reads a path argument from userland and validates it.
///
/// Every path-taking syscall goes through this, which is the point: path
/// handling is where archive and filesystem code has historically gone
/// wrong (traversal via `..`, ambiguity via `//`, truncation via an
/// embedded NUL), and one shared entry point means those checks cannot be
/// present in one syscall and missing in another.
///
/// Note it *rejects* rather than normalizes. A path with a `..` in it is
/// refused outright instead of being resolved, because normalization and
/// the eventual lookup are two pieces of code that can disagree about
/// what a string means - and every path-traversal vulnerability is
/// exactly that disagreement.
fn read_user_path(ptr: u64, len: u64) -> Result<alloc::string::String, u64> {
    if len == 0 || len as usize > MAX_PATH {
        return Err(encode_error(err::EINVAL));
    }
    let bytes = crate::mm::memory::copy_from_user(ptr, len as usize)
        .ok_or(encode_error(err::EFAULT))?;

    if !najm_abi::archive::path_is_valid(&bytes) {
        return Err(encode_error(err::EINVAL));
    }

    // Valid per `path_is_valid`, which already guarantees no NUL. UTF-8
    // is not guaranteed, and a non-UTF-8 path is simply one that names
    // nothing - lossy conversion produces exactly that outcome without a
    // separate error path.
    Ok(alloc::string::String::from(
        alloc::string::String::from_utf8_lossy(&bytes),
    ))
}

/// Whether the calling process holds `right`.
///
/// The default for "no current process" is **deny**. That direction
/// matters: the boot path runs Ring 3 self-tests before any process
/// exists, and defaulting to allow would make the state with no process
/// the most privileged state in the system - precisely inverted.
fn require(right: u64) -> Result<(), u64> {
    match crate::process::current_profile() {
        Some(profile) if profile.allows(right) => Ok(()),
        _ => Err(encode_error(err::EPERM)),
    }
}

/// `open(path_ptr, path_len, flags) -> fd`
fn sys_open(path_ptr: u64, path_len: u64, flags: u64) -> u64 {
    if let Err(e) = require(najm_abi::capability_bits::FILE_READ) {
        return e;
    }

    // Writing is refused rather than downgraded to read-only. A program
    // that believes it opened a file for writing, and then believes its
    // writes succeeded, is worse off than one that was told no at the
    // first step - the filesystem is read-only (see `crate::fs`), and
    // pretending otherwise would make that a runtime surprise instead of
    // an immediate, accurate error.
    if flags & najm_abi::open_flags::WRITE != 0 {
        return encode_error(err::ENOTSUP);
    }

    let path = match read_user_path(path_ptr, path_len) {
        Ok(path) => path,
        Err(e) => return e,
    };

    let Some(node) = crate::fs::lookup(&path) else {
        return encode_error(err::ENOENT);
    };

    if flags & najm_abi::open_flags::DIRECTORY != 0 && !node.is_directory {
        return encode_error(err::ENOTSUP);
    }

    let Some(open) = crate::process::OpenFile::new(node, &path) else {
        return encode_error(err::EINVAL);
    };
    match crate::process::open_file(open) {
        Some(descriptor) => descriptor,
        None => encode_error(err::ENOMEM),
    }
}

/// `read(fd, ptr, len) -> bytes read`
fn sys_read(descriptor: u64, ptr: u64, len: u64) -> u64 {
    // The console descriptors have no backing file. Reading from stdin
    // returns 0 - end of input - rather than an error, because "there is
    // no input" is a true and useful answer, while EBADF would suggest
    // the descriptor was invalid.
    if descriptor == fd::STDIN {
        return 0;
    }
    if descriptor == fd::STDOUT || descriptor == fd::STDERR {
        return encode_error(err::EBADF);
    }

    let Some(file) = crate::process::get_file(descriptor) else {
        return encode_error(err::EBADF);
    };
    if file.node.is_directory {
        // A directory is not a byte stream. `readdir` is the operation
        // that makes sense for one, and silently returning its raw
        // on-archive representation would be exposing a format detail as
        // if it were file content.
        return encode_error(err::ENOTSUP);
    }

    let want = core::cmp::min(len as usize, crate::mm::memory::MAX_USER_TRANSFER);
    let mut buffer = alloc::vec![0u8; want];
    let got = crate::fs::read(&file.node, file.position, &mut buffer);

    // Copy out *before* advancing the position. If the destination
    // pointer turns out to be invalid, the file's cursor must not have
    // moved - otherwise a program that passed a bad pointer would find
    // bytes silently skipped on its next successful read.
    let Some(written) = crate::mm::memory::copy_to_user(ptr, &buffer[..got]) else {
        return encode_error(err::EFAULT);
    };

    crate::process::set_file_position(descriptor, file.position + written);
    written as u64
}

/// `close(fd)`
fn sys_close(descriptor: u64) -> u64 {
    if crate::process::close_file(descriptor) {
        0
    } else {
        // Reported rather than ignored. In a system that reuses
        // descriptor numbers, a double close is the bug that eventually
        // closes a file some *other* part of the program is still using,
        // and it is invisible unless the first close-of-a-closed-file
        // says so.
        encode_error(err::EBADF)
    }
}

/// `seek(fd, offset, whence) -> new position`
fn sys_seek(descriptor: u64, offset: u64, whence: u64) -> u64 {
    let Some(file) = crate::process::get_file(descriptor) else {
        return encode_error(err::EBADF);
    };

    let size = file.node.size();
    let position = match whence {
        najm_abi::seek::SET => offset as usize,
        najm_abi::seek::CURRENT => file.position.saturating_add(offset as usize),
        najm_abi::seek::END => size.saturating_sub(offset as usize),
        _ => return encode_error(err::EINVAL),
    };

    // Clamped to the end of the file rather than allowed past it. A
    // position beyond EOF is legal in POSIX (it creates a hole on write),
    // but this filesystem cannot be written to, so the only thing an
    // out-of-range position could do here is make a subsequent `read`
    // return 0 for a reason the caller cannot distinguish from a real
    // end-of-file.
    let position = core::cmp::min(position, size);
    if !crate::process::set_file_position(descriptor, position) {
        return encode_error(err::EBADF);
    }
    position as u64
}

/// `stat(path_ptr, path_len, out_ptr)`
fn sys_stat(path_ptr: u64, path_len: u64, out_ptr: u64) -> u64 {
    if let Err(e) = require(najm_abi::capability_bits::FILE_READ) {
        return e;
    }

    let path = match read_user_path(path_ptr, path_len) {
        Ok(path) => path,
        Err(e) => return e,
    };
    let Some(node) = crate::fs::lookup(&path) else {
        return encode_error(err::ENOENT);
    };

    let info = najm_abi::FileInfo {
        size: node.size() as u64,
        is_directory: u64::from(node.is_directory),
    };

    // The struct is written through `copy_to_user`, which validates the
    // destination is writable in the *calling process's* page tables.
    // Writing it with a raw pointer would be the exact confused-deputy
    // bug ARCHITECTURE.md section 3b is about, in the other direction:
    // the kernel writing wherever a program pointed it.
    //
    // Safety: `FileInfo` is `#[repr(C)]` and contains only `u64`s, so it
    // has no padding and no invalid bit patterns - every byte of it is
    // initialized and meaningful, which is what makes viewing it as bytes
    // sound.
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &info as *const najm_abi::FileInfo as *const u8,
            core::mem::size_of::<najm_abi::FileInfo>(),
        )
    };

    match crate::mm::memory::copy_to_user(out_ptr, bytes) {
        Some(_) => 0,
        None => encode_error(err::EFAULT),
    }
}

/// `readdir(fd, buf_ptr, buf_len) -> bytes written`
///
/// Fills `buf` with the directory's entry names, each terminated by a
/// NUL. A flat NUL-separated block rather than an array of fixed-size
/// structs, because entry names vary in length and a fixed-size record
/// would have to pick a maximum - which is either wastefully large or
/// silently truncating, and truncation of a *name* is how a program ends
/// up opening the wrong file.
fn sys_readdir(descriptor: u64, buf_ptr: u64, buf_len: u64) -> u64 {
    let Some(file) = crate::process::get_file(descriptor) else {
        return encode_error(err::EBADF);
    };
    if !file.node.is_directory {
        return encode_error(err::ENOTSUP);
    }

    // The path comes from the descriptor, not from the node. Deriving it
    // from the node was the original design and was silently wrong: every
    // directory node is (offset 0, length 0, directory), so a reverse
    // lookup by node value returned whichever directory the map held
    // first, and `readdir("/etc")` listed the contents of `/`.
    let Some(children) = crate::fs::read_dir(file.path()) else {
        return encode_error(err::ENOENT);
    };

    let mut out = alloc::vec::Vec::new();
    for child in children {
        let name = najm_abi::archive::basename(child.as_bytes());
        // Stop before overflowing rather than truncating an entry
        // mid-name: a half-written name is indistinguishable from a real
        // one, and a caller acting on it would open something that does
        // not exist or, worse, something that does.
        if out.len() + name.len() + 1 > buf_len as usize {
            break;
        }
        out.extend_from_slice(name);
        out.push(0);
    }

    match crate::mm::memory::copy_to_user(buf_ptr, &out) {
        Some(written) => written as u64,
        None => encode_error(err::EFAULT),
    }
}

/// `surface_create(width, height) -> surface_id`
///
/// The Realm decides the mode, not the caller. A Gaming Realm gets
/// exclusive fullscreen because that is what its scheduling class and
/// capability set are for; everything else gets a window. Letting the
/// *program* choose would make "exclusive fullscreen" something any
/// application could request, which is the same failure as letting one
/// request its own Realm - see ARCHITECTURE.md 2e.
///
/// Note that fullscreen still excludes the trusted-path strip. That is
/// threat 4 in ARCHITECTURE.md 2d, and the answer there is not "find
/// somewhere else for the indicator" but "the strip was never available
/// to give away".
fn sys_surface_create(width: u64, height: u64) -> u64 {
    if let Err(e) = require(najm_abi::capability_bits::SURFACE_CREATE) {
        return e;
    }
    let Some(profile) = crate::process::current_profile() else {
        return encode_error(err::EPERM);
    };
    let pid = crate::sched::task::current_pid();

    let mode = if profile.allows(najm_abi::capability_bits::EXCLUSIVE_SCANOUT) {
        crate::graphics::compositor::SurfaceMode::Fullscreen
    } else {
        crate::graphics::compositor::SurfaceMode::Windowed
    };

    match crate::graphics::compositor::create_surface(
        pid,
        profile.kind,
        profile.name,
        width as usize,
        height as usize,
        mode,
    ) {
        Some(id) => id,
        None => encode_error(err::ENOMEM),
    }
}

/// `surface_commit(surface_id, pixels_ptr, len)`
///
/// `len` is in bytes and must exactly match the surface's size. See
/// `compositor::commit_surface` for why exactness rather than a
/// short-buffer allowance: a partial commit would leave the rest of the
/// frame holding whatever was in that buffer before, and surface buffers
/// are reused between processes.
fn sys_surface_commit(id: u64, pixels_ptr: u64, len: u64) -> u64 {
    let pid = crate::sched::task::current_pid();
    if pid == 0 {
        return encode_error(err::EPERM);
    }

    let Some((width, height)) = crate::graphics::compositor::surface_geometry(id, pid) else {
        // Covers both "no such surface" and "not yours" without
        // distinguishing them, which is deliberate: telling a caller that
        // a surface exists but belongs to someone else is an oracle for
        // enumerating other processes' surfaces.
        return encode_error(err::EBADF);
    };

    let expected = width * height * 4;
    if len as usize != expected {
        return encode_error(err::EINVAL);
    }

    // Copied straight into the surface buffer rather than through
    // `copy_from_user`, which caps at 1 MiB because it allocates a buffer
    // sized by a caller-chosen length. A frame is legitimately megabytes
    // and its size was bounded when the surface was created, so the cap
    // would be protecting against the wrong thing here - and raising it
    // globally would remove the protection where it is needed.
    if !crate::graphics::compositor::commit_surface_from_user(id, pid, pixels_ptr, expected) {
        return encode_error(err::EFAULT);
    }

    crate::graphics::compositor::present_throttled();
    0
}

/// `surface_info(surface_id, out_ptr)` - writes a `SurfaceInfo`.
fn sys_surface_info(id: u64, out_ptr: u64) -> u64 {
    let pid = crate::sched::task::current_pid();
    let Some((width, height)) = crate::graphics::compositor::surface_geometry(id, pid) else {
        return encode_error(err::EBADF);
    };

    let info = najm_abi::SurfaceInfo {
        width: width as u64,
        height: height as u64,
        stride: (width * 4) as u64,
        bytes_per_pixel: 4,
    };

    // Safety: `SurfaceInfo` is `#[repr(C)]` and holds only `u64`s, so it
    // has no padding and no invalid bit patterns - every byte is
    // initialized and meaningful, which is what makes viewing it as bytes
    // sound. The write itself goes through `copy_to_user`, which
    // validates the destination against the calling process's own page
    // tables.
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &info as *const najm_abi::SurfaceInfo as *const u8,
            core::mem::size_of::<najm_abi::SurfaceInfo>(),
        )
    };

    match crate::mm::memory::copy_to_user(out_ptr, bytes) {
        Some(_) => 0,
        None => encode_error(err::EFAULT),
    }
}

/// `input_poll(out_ptr, max_events) -> events written`
///
/// Consumes the events it returns. That is the right semantic for an
/// input queue - an event delivered twice is a keystroke typed twice -
/// but it means a program that polls and then fails to copy the result
/// has lost them. The copy therefore happens before the queue is
/// drained... which it cannot, because the events must be read to be
/// copied. So the events are taken first and the copy is checked: if the
/// destination is bad, the events are gone and the caller gets EFAULT.
/// That is a real, if minor, loss, and it is the honest trade for not
/// keeping a shadow copy of every poll.
fn sys_input_poll(out_ptr: u64, max_events: u64) -> u64 {
    if let Err(e) = require(najm_abi::capability_bits::INPUT_READ) {
        return e;
    }

    // Bounded so a caller cannot ask the kernel to allocate arbitrarily.
    let wanted = core::cmp::min(max_events as usize, 64);
    if wanted == 0 {
        return 0;
    }

    let mut events = alloc::vec![najm_abi::InputEvent::default(); wanted];
    let count = crate::drivers::input::poll(&mut events);
    if count == 0 {
        return 0;
    }

    // Safety: `InputEvent` is `#[repr(C)]` and holds only `u64`s - no
    // padding, no invalid bit patterns. Same reasoning as `sys_surface_info`.
    let bytes = unsafe {
        core::slice::from_raw_parts(
            events.as_ptr() as *const u8,
            count * core::mem::size_of::<najm_abi::InputEvent>(),
        )
    };

    match crate::mm::memory::copy_to_user(out_ptr, bytes) {
        Some(_) => count as u64,
        None => encode_error(err::EFAULT),
    }
}

/// `realm_info(out_ptr)` - writes a `RealmInfo`.
///
/// A process learning what it is allowed to attempt. Note it gains
/// nothing by lying to itself: the bitmask reported here is a *view* of
/// the kernel-side profile, and every syscall consults the profile
/// directly rather than anything the process holds.
fn sys_realm_info(out_ptr: u64) -> u64 {
    let pid = crate::sched::task::current_pid();
    let Some(profile) = crate::process::current_profile() else {
        return encode_error(err::EPERM);
    };

    let info = najm_abi::RealmInfo {
        kind: profile.kind,
        pid,
        capabilities: profile.capabilities,
    };

    // Safety: as `sys_surface_info` - `#[repr(C)]`, all `u64`, no padding.
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &info as *const najm_abi::RealmInfo as *const u8,
            core::mem::size_of::<najm_abi::RealmInfo>(),
        )
    };

    match crate::mm::memory::copy_to_user(out_ptr, bytes) {
        Some(_) => 0,
        None => encode_error(err::EFAULT),
    }
}
