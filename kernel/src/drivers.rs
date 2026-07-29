//! Device drivers. Currently just the serial console in `serial` -
//! expected to grow storage, network, and GPU drivers as ARCHITECTURE.md
//! section 6's Driver Strategy gets underway. Keyboard input currently
//! lives inside `arch::x86_64::interrupts` rather than here, since on
//! this architecture it's delivered through the legacy PIC as a
//! CPU-level interrupt rather than through any bus a driver would
//! normally enumerate - worth revisiting if/when a USB HID stack makes
//! keyboard input arrive a different way.

pub mod serial;
