//! Serial (UART) output.
//!
//! This is the kernel's entire debugging story for now: no text renderer
//! on the framebuffer yet, no logging subsystem, nothing structured. Just
//! a byte stream out COM1 that QEMU is already listening on (see the
//! `-serial stdio` flag in `runner/src/main.rs`), and on real hardware,
//! whatever's plugged into the physical serial port - which is also
//! exactly why this exists first, before anything fancier: it's the one
//! debugging channel that works even when the framebuffer, the scheduler,
//! or memory management are all still broken.

use lazy_static::lazy_static;
use spin::Mutex;
use uart_16550::SerialPort;
use x86_64::instructions::interrupts;

lazy_static! {
    /// The first legacy COM port (COM1 / I/O port 0x3F8) - the
    /// conventional serial console both QEMU and real BIOS-era hardware
    /// expose by default, so no additional configuration is needed to
    /// make output show up.
    pub static ref SERIAL1: Mutex<SerialPort> = {
        let mut serial_port = unsafe {
            // Safety: 0x3F8 is the standard, fixed I/O port address for
            // COM1 on x86 - not something read from untrusted input or
            // computed at runtime. No other code in this kernel touches
            // this port, so there's no aliasing/conflict to worry about.
            SerialPort::new(0x3F8)
        };
        serial_port.init();
        Mutex::new(serial_port)
    };
}

#[doc(hidden)]
pub fn _print(args: core::fmt::Arguments) {
    use core::fmt::Write;

    // No interrupt handling exists yet (that's the next milestone after
    // this one), so this is technically a no-op today. It's included now
    // anyway because forgetting it later - after interrupts exist - is
    // exactly the kind of thing that causes a hard-to-reproduce garbled
    // log line under load, and it costs nothing to have it right from the
    // start.
    interrupts::without_interrupts(|| {
        SERIAL1
            .lock()
            .write_fmt(args)
            .expect("writing to the serial port failed");
    });
}

/// Writes to the serial console, but only if `cap` hasn't been revoked -
/// the capability-gated counterpart to the unconditional `_print` above.
///
/// The existing `serial_print!`/`serial_println!` macros stay
/// unconditional on purpose: they're the kernel Core's own diagnostic
/// voice (boot progress, panics), and gating the kernel's own ability to
/// report what's happening behind a capability it would have to already
/// be functioning correctly to present is circular. This function is a
/// separate, additional entry point for code that *isn't* Core - a
/// future Realm-hosted task, for instance - which is exactly the
/// distinction ARCHITECTURE.md's Realm Core vs. Realm Shell split is
/// about: Core doesn't need to ask permission to speak; nothing else
/// should be able to write to a shared resource like this console
/// without one.
pub fn write_with_capability(
    cap: &crate::security::capability::Capability<crate::security::capability::SerialWrite>,
    args: core::fmt::Arguments,
) -> Result<(), crate::security::capability::CapabilityError> {
    if cap.is_revoked() {
        return Err(crate::security::capability::CapabilityError::Revoked);
    }

    _print(args);
    Ok(())
}

/// Prints to the serial console, no trailing newline. Mirrors `print!`.
///
/// Deliberately no trailing `;` inside this arm: leaving it out is what
/// lets `serial_println!` (and any other caller) use this in expression
/// position - e.g. as the value of a `match` arm - without hitting
/// `semicolon_in_expressions_from_macros`, which newer compilers treat as
/// a hard error rather than the warning it used to be.
#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::drivers::serial::_print(format_args!($($arg)*))
    };
}

/// Prints to the serial console with a trailing newline. Mirrors `println!`.
#[macro_export]
macro_rules! serial_println {
    () => ($crate::serial_print!("\n"));
    ($fmt:expr) => ($crate::serial_print!(concat!($fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => ($crate::serial_print!(
        concat!($fmt, "\n"), $($arg)*
    ));
}
