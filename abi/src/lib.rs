//! The Najm OS kernel/userland contract.
//!
//! Everything both sides of the syscall boundary have to agree on lives
//! here, and *only* here: syscall numbers, error codes, flag bits, the
//! shape of structures passed across the boundary, and the virtual
//! address map (see [`layout`]).
//!
//! ## Why this crate exists
//!
//! It used to not. The syscall numbers were declared once in
//! `kernel/src/arch/x86_64/interrupts.rs` and again in
//! `userland/hello/src/syscall.rs`, with a comment in the latter
//! admitting the problem and deferring it: nothing made the two
//! definitions move together, so renumbering a syscall would produce a
//! program that misbehaved at runtime with no compile error anywhere.
//! That was a defensible trade at two constants and one consumer. It
//! stops being defensible the moment there are twenty-odd syscalls and
//! more than one program, which is where this project now is.
//!
//! ## What may and may not go in here
//!
//! This crate is linked into the kernel *and* into every userland
//! program, including ones this project did not write. So:
//!
//! - **No dependencies.** Anything pulled in here becomes part of the
//!   trusted surface of both sides.
//! - **No behaviour.** Constants, plain data, and `const fn`. The moment
//!   this crate contains logic, that logic is running at Ring 0 and Ring
//!   3 with different assumptions on each side.
//! - **No `unsafe`.** The unsafe part of a syscall is the instruction
//!   that makes it, which belongs to the caller's own wrapper, not to a
//!   shared definition of what the number means.
//!
//! ## Stability
//!
//! None yet, and that is stated deliberately rather than implied. Syscall
//! numbers here are free to change until Najm OS ships something a third
//! party builds against. When that changes, this is the file that gets a
//! freeze policy - not the kernel.

#![no_std]

pub mod archive;
pub mod layout;

/// Syscall numbers, passed by the caller in RAX.
///
/// The register convention (RAX = number, RDI/RSI/RDX = arguments, RAX =
/// return) loosely follows Linux's for familiarity, explicitly *not* for
/// compatibility - nothing here aims to run Linux binaries, and the
/// numbers are this system's own.
///
/// Numbers are grouped by subsystem with gaps left between the groups, so
/// a new call can be added next to its relatives instead of at the end
/// where the grouping stops meaning anything.
pub mod sys {
    // --- process lifecycle -------------------------------------------
    /// `exit(status) -> !`
    pub const EXIT: u64 = 0;
    /// `yield_now()` - give up the rest of this time slice voluntarily.
    pub const YIELD: u64 = 1;
    /// `getpid() -> pid`
    pub const GETPID: u64 = 2;
    /// `spawn(path_ptr, path_len) -> pid` - load and run a program from
    /// the filesystem in a new address space.
    pub const SPAWN: u64 = 3;
    /// `wait(pid) -> status` - block until `pid` exits.
    pub const WAIT: u64 = 4;
    /// `sleep_ticks(n)` - block for at least `n` timer ticks.
    pub const SLEEP_TICKS: u64 = 5;

    // --- I/O ---------------------------------------------------------
    /// `write(fd, ptr, len) -> written`
    pub const WRITE: u64 = 16;
    /// `read(fd, ptr, len) -> read`
    pub const READ: u64 = 17;
    /// `open(path_ptr, path_len, flags) -> fd`
    pub const OPEN: u64 = 18;
    /// `close(fd)`
    pub const CLOSE: u64 = 19;
    /// `seek(fd, offset, whence) -> new_offset`
    pub const SEEK: u64 = 20;
    /// `readdir(fd, buf_ptr, buf_len) -> bytes_written` - fills `buf`
    /// with NUL-separated entry names.
    pub const READDIR: u64 = 21;
    /// `stat(path_ptr, path_len, out_ptr) -> 0` - writes a [`FileInfo`].
    pub const STAT: u64 = 22;

    // --- memory ------------------------------------------------------
    /// `map(len, flags) -> addr` - anonymous memory, page-granular.
    pub const MAP: u64 = 32;
    /// `unmap(addr, len)`
    pub const UNMAP: u64 = 33;

    // --- IPC ---------------------------------------------------------
    /// `port_create(name_ptr, name_len) -> handle`
    pub const PORT_CREATE: u64 = 48;
    /// `port_connect(name_ptr, name_len) -> handle`
    pub const PORT_CONNECT: u64 = 49;
    /// `port_send(handle, ptr, len) -> sent`
    pub const PORT_SEND: u64 = 50;
    /// `port_recv(handle, ptr, len) -> received`
    pub const PORT_RECV: u64 = 51;
    /// `port_close(handle)`
    pub const PORT_CLOSE: u64 = 52;

    // --- Realm / system information ----------------------------------
    /// `realm_info(out_ptr) -> 0` - writes a [`RealmInfo`].
    pub const REALM_INFO: u64 = 64;
    /// `ticks() -> tick_count`
    pub const TICKS: u64 = 65;
    /// `uptime_ms() -> milliseconds`
    pub const UPTIME_MS: u64 = 66;

    // --- graphics ----------------------------------------------------
    /// `surface_create(width, height) -> surface_id`
    pub const SURFACE_CREATE: u64 = 80;
    /// `surface_commit(surface_id, pixels_ptr, len)` - hand a finished
    /// frame to the compositor.
    pub const SURFACE_COMMIT: u64 = 81;
    /// `surface_info(surface_id, out_ptr) -> 0` - writes a
    /// [`SurfaceInfo`].
    pub const SURFACE_INFO: u64 = 82;
    /// `input_poll(out_ptr) -> count` - fills a buffer of [`InputEvent`].
    pub const INPUT_POLL: u64 = 83;
}

/// Well-known file descriptors, open in every process from the moment it
/// starts.
pub mod fd {
    /// Standard input. Not connected to anything yet; reads return 0.
    pub const STDIN: u64 = 0;
    /// Standard output - the kernel console.
    pub const STDOUT: u64 = 1;
    /// Standard error, currently the same destination as [`STDOUT`], kept
    /// distinct so that diverting one later does not require every
    /// program to change.
    pub const STDERR: u64 = 2;
    /// The first descriptor `open` will hand out.
    pub const FIRST_DYNAMIC: u64 = 3;
}

/// Flags for [`sys::OPEN`].
pub mod open_flags {
    /// Open for reading. The default; present as a named constant so a
    /// call site says what it means rather than passing a bare 0.
    pub const READ: u64 = 0;
    /// Open for writing, creating the file if it does not exist.
    pub const WRITE: u64 = 1 << 0;
    /// Fail if the path is not a directory.
    pub const DIRECTORY: u64 = 1 << 1;
}

/// Flags for [`sys::MAP`].
pub mod map_flags {
    /// Readable. Implied by any mapping; named for symmetry.
    pub const READ: u64 = 0;
    /// Writable.
    pub const WRITE: u64 = 1 << 0;
    /// Executable.
    ///
    /// Requesting this *and* [`WRITE`] together is refused by the kernel:
    /// W^X is enforced at the syscall boundary, not merely encouraged.
    /// A JIT that genuinely needs both must map twice and flip, which is
    /// the point - it makes the moment a page becomes executable an
    /// explicit, auditable event rather than a property it quietly had
    /// all along.
    pub const EXEC: u64 = 1 << 1;
}

/// Whence values for [`sys::SEEK`].
pub mod seek {
    pub const SET: u64 = 0;
    pub const CURRENT: u64 = 1;
    pub const END: u64 = 2;
}

/// Error numbers.
///
/// Returned the way Linux returns them from a raw syscall: as the
/// two's-complement negation of the number, so `EBADF` (9) arrives in RAX
/// as `u64::MAX - 8`. That convention is worth copying specifically
/// because it makes success and failure distinguishable *without a
/// separate out-parameter*, using a range no plausible successful return
/// occupies - a valid pointer, length or descriptor is never within 4096
/// of `u64::MAX`.
///
/// Use [`is_error`] and [`decode`] rather than comparing by hand.
pub mod err {
    /// No such syscall number.
    pub const ENOSYS: u64 = 1;
    /// A pointer or length argument did not name memory the caller is
    /// allowed to touch.
    pub const EFAULT: u64 = 2;
    /// No such file or directory.
    pub const ENOENT: u64 = 3;
    /// An argument was structurally invalid (a bad flag combination, a
    /// zero length where one is required, a nonsensical offset).
    pub const EINVAL: u64 = 4;
    /// The caller does not hold the capability this operation requires.
    pub const EPERM: u64 = 5;
    /// Out of memory, or out of some other kernel resource.
    pub const ENOMEM: u64 = 6;
    /// The named object exists already.
    pub const EEXIST: u64 = 7;
    /// The operation would block and the caller asked not to.
    pub const EAGAIN: u64 = 8;
    /// Not a valid file descriptor or handle.
    pub const EBADF: u64 = 9;
    /// The operation is not supported on this kind of object (reading a
    /// directory as a file, for instance).
    pub const ENOTSUP: u64 = 10;
    /// The target of an IPC operation has gone away.
    pub const EPIPE: u64 = 11;

    /// The largest error number that may be encoded. Chosen to match the
    /// 4096-value window described on this module, so the boundary is a
    /// documented constant rather than a magic number in [`super::is_error`].
    pub const MAX: u64 = 4095;
}

/// Encodes an error number the way a syscall returns it.
pub const fn encode_error(errno: u64) -> u64 {
    // Wrapping negation: errno 1 becomes u64::MAX, 2 becomes u64::MAX-1,
    // and so on.
    (!errno).wrapping_add(1)
}

/// Whether a raw syscall return value is an error rather than a result.
///
/// The test is "within [`err::MAX`] of the top of the range", not
/// "greater than some threshold picked by eye" - the window has to be
/// large enough to hold every error number and small enough that no
/// legitimate return value falls inside it.
pub const fn is_error(raw: u64) -> bool {
    raw >= encode_error(err::MAX)
}

/// Splits a raw syscall return into a result or an error number.
pub const fn decode(raw: u64) -> Result<u64, u64> {
    if is_error(raw) {
        Err(encode_error(raw))
    } else {
        Ok(raw)
    }
}

/// What [`sys::STAT`] writes.
///
/// `#[repr(C)]` because the kernel writes it through a raw pointer into a
/// user buffer: field order and padding have to be something both sides
/// compute identically, which Rust's default representation explicitly
/// does not promise.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FileInfo {
    /// Size in bytes. Zero for a directory.
    pub size: u64,
    /// Non-zero if this is a directory.
    pub is_directory: u64,
}

/// Which Realm a process is running in. See ARCHITECTURE.md section 2.
///
/// `u64`-valued rather than a Rust enum with a niche, so that a value the
/// kernel does not recognize arriving from userland (or vice versa) is a
/// number to reject rather than instant undefined behaviour.
pub mod realm_kind {
    /// The default for anything without a verified publisher credential.
    /// See ARCHITECTURE.md section 2e: elevated placement is earned in
    /// advance, never requested at install time.
    pub const HOME: u64 = 0;
    /// Bounded-latency scheduling, reserved cores, exclusive scanout.
    pub const GAMING: u64 = 1;
    /// Stricter syscall auditing, no introspection, no ability to be read
    /// or injected into by other Realms.
    pub const VAULT: u64 = 2;
    /// The compositor and other Core-adjacent services. Not assignable to
    /// an installed application - listed so that a process can *observe*
    /// it, not request it.
    pub const SYSTEM: u64 = 3;
}

/// What [`sys::REALM_INFO`] writes.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RealmInfo {
    /// One of the [`realm_kind`] constants.
    pub kind: u64,
    /// This process's id.
    pub pid: u64,
    /// Bitmask of the capability rights this Realm holds - see
    /// [`capability_bits`].
    pub capabilities: u64,
}

/// Bit positions in [`RealmInfo::capabilities`].
///
/// This is a *reporting* view of a process's rights, not the mechanism
/// that enforces them. Enforcement is the kernel's typed `Capability<R>`
/// tokens, which cannot be represented as a bitmask precisely because
/// their unforgeability comes from being values that only the kernel can
/// construct. A program reading these bits learns what it is allowed to
/// attempt; it gains nothing by lying to itself about them.
pub mod capability_bits {
    pub const SERIAL_WRITE: u64 = 1 << 0;
    pub const TIMER_READ: u64 = 1 << 1;
    pub const FILE_READ: u64 = 1 << 2;
    pub const FILE_WRITE: u64 = 1 << 3;
    pub const PROCESS_SPAWN: u64 = 1 << 4;
    pub const IPC_CREATE: u64 = 1 << 5;
    pub const IPC_CONNECT: u64 = 1 << 6;
    pub const SURFACE_CREATE: u64 = 1 << 7;
    pub const INPUT_READ: u64 = 1 << 8;
    /// Exclusive scanout: the right to take over the whole framebuffer,
    /// which only a Gaming Realm gets. Note that even this does not let a
    /// process draw over the trusted-path region - see ARCHITECTURE.md
    /// section 2d, threat 4.
    pub const EXCLUSIVE_SCANOUT: u64 = 1 << 9;
}

/// What [`sys::SURFACE_INFO`] writes: the geometry a program should
/// render at.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SurfaceInfo {
    pub width: u64,
    pub height: u64,
    /// Bytes per row, which may exceed `width * 4` when the compositor's
    /// backing store is padded.
    pub stride: u64,
    /// Bytes per pixel. Always 4 today (32-bit BGRA); present so a
    /// program reads it rather than assuming.
    pub bytes_per_pixel: u64,
}

/// One input event, as delivered by [`sys::INPUT_POLL`].
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct InputEvent {
    /// One of the [`input_kind`] constants.
    pub kind: u64,
    /// Key code for a key event, button mask for a button event.
    pub code: u64,
    /// Absolute X for a motion event, otherwise 0.
    pub x: u64,
    /// Absolute Y for a motion event, otherwise 0.
    pub y: u64,
}

/// Values for [`InputEvent::kind`].
pub mod input_kind {
    pub const KEY_DOWN: u64 = 1;
    pub const KEY_UP: u64 = 2;
    pub const POINTER_MOTION: u64 = 3;
    pub const POINTER_BUTTON_DOWN: u64 = 4;
    pub const POINTER_BUTTON_UP: u64 = 5;
}
