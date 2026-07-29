//! Shutting the virtual machine down from inside the kernel.
//!
//! This exists for exactly one reason: to make the boot self-tests
//! *scriptable*. Until now the only way to read a test result was for a
//! human to watch the serial log and judge it, because the kernel never
//! ends - it hands the CPU to the scheduler and runs forever. A test
//! suite that can only be evaluated by a person is a test suite that
//! stops being run.
//!
//! QEMU's `isa-debug-exit` device turns a port write into a process exit
//! code, which is the one channel a guest has to report a verdict to
//! whatever launched it. `scripts/boot-test.sh` adds the device on the
//! command line and interprets the result.
//!
//! **This is emulator-only, and deliberately so.** On real hardware port
//! 0xf4 is not the debug-exit device and this write does nothing (an
//! unclaimed I/O port write is discarded, not faulted on), so `exit`
//! below simply returns and the caller falls through to its halt path.
//! That is the correct behaviour: a physical machine should not power
//! itself off because a self-test finished. `is_available` cannot
//! meaningfully be probed - there is no read-back register to
//! distinguish "device present" from "nothing here" - so the fallback is
//! structural rather than conditional: every caller must still have a
//! working non-QEMU path after calling this.

use x86_64::instructions::port::Port;

/// The I/O port `scripts/boot-test.sh` binds `isa-debug-exit` to. Both
/// sides have to agree, and this constant is the definition - if it
/// changes here, the `iobase=` in that script changes with it.
const DEBUG_EXIT_PORT: u16 = 0xf4;

/// What the kernel is reporting about its own self-tests.
///
/// The numbers are constrained by how `isa-debug-exit` works: QEMU exits
/// with `(value << 1) | 1`, so no write can ever produce exit code 0.
/// Success therefore cannot be spelled "0" the way a normal program would
/// spell it, and picking values that don't collide with QEMU's own error
/// exit codes (1, 2, ...) or with `timeout`'s 124 is what makes the
/// script's `case` statement unambiguous.
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum ExitCode {
    /// Arrives at the host as exit code 33.
    Success = 0x10,
    /// Arrives at the host as exit code 35.
    Failed = 0x11,
}

/// Asks QEMU to terminate with a code derived from `code`.
///
/// Returns normally on real hardware (see the module docs), so callers
/// must not treat this as `-> !`.
pub fn exit(code: ExitCode) {
    // Safety: 0xf4 is not a port any real device this kernel drives uses,
    // and this is the only code in the kernel that touches it. On QEMU
    // with `-device isa-debug-exit` it is that device; anywhere else the
    // write is discarded by an unclaimed-port bus cycle rather than
    // faulting, which is exactly the fallback behaviour documented above.
    unsafe {
        let mut port = Port::new(DEBUG_EXIT_PORT);
        port.write(code as u32);
    }
}
