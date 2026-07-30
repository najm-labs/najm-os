//! PCI bus enumeration.
//!
//! The first driver in this kernel that *discovers* hardware rather than
//! assuming it. Everything before this - the serial port at 0x3F8, the
//! PIT at 0x40, the PS/2 controller at 0x60 - lives at an address fixed
//! by thirty-year-old convention, and the driver simply knows it. That
//! works for the legacy ISA devices and for nothing else: a disk
//! controller, a network card, a GPU, and a USB host controller are all
//! PCI devices whose addresses are assigned at boot and can only be found
//! by asking.
//!
//! This is therefore the prerequisite for ARCHITECTURE.md section 6's
//! driver strategy, and it is deliberately just the enumeration half:
//! walk the bus, identify what is present, report it. No device is
//! claimed, no BAR is mapped, no interrupt is routed. Those are per-device
//! decisions, and building the framework for them before there is a
//! second device to generalize from would be inventing an abstraction
//! from one example.
//!
//! ## Configuration access: the legacy mechanism, deliberately
//!
//! PCI configuration space is reached either through two I/O ports
//! (0xCF8 address, 0xCFC data - "mechanism 1", universal since 1993) or
//! through a memory-mapped region whose base address is published in the
//! ACPI MCFG table. This uses mechanism 1, for the same reason the kernel
//! uses the 8259 PIC rather than the APIC: the memory-mapped path
//! requires an ACPI table parser, which is a substantial subsystem, and
//! it buys access to configuration registers beyond offset 0xFF that
//! nothing here needs yet.
//!
//! The limitation that comes with that choice, stated rather than
//! discovered later: mechanism 1 cannot see PCI Express extended
//! configuration space (offsets 0x100-0xFFF), and it cannot address
//! segment groups beyond the first. Neither matters for enumeration on a
//! single-segment machine, and both become reasons to revisit this when
//! ACPI parsing exists.
//!
//! ## Enumeration strategy
//!
//! A brute-force scan of all 256 buses x 32 devices x 8 functions, which
//! is 65,536 configuration reads. That sounds wasteful and is: the
//! correct approach is a recursive scan that only descends into buses
//! behind a bridge that reports one. The brute-force version is used here
//! because it is *obviously correct* - it cannot miss a device because of
//! a bridge-configuration subtlety - and because 65,536 port reads take
//! single-digit milliseconds, once, at boot. If that ever shows up in a
//! boot-time measurement, the recursive scan is the fix.

use crate::serial_println;
use alloc::vec::Vec;
use x86_64::instructions::port::Port;

const CONFIG_ADDRESS: u16 = 0xCF8;
const CONFIG_DATA: u16 = 0xCFC;

/// A device found on the bus.
#[derive(Debug, Clone, Copy)]
pub struct Device {
    pub bus: u8,
    pub slot: u8,
    pub function: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    /// Broad category - storage, network, display, and so on.
    pub class: u8,
    /// Refinement within the class.
    pub subclass: u8,
    /// Refinement within the subclass, e.g. which of several register
    /// interfaces a storage controller presents.
    pub prog_if: u8,
}

impl Device {
    /// A human-readable description of what this device is.
    ///
    /// Covers only the classes this project has a reason to care about
    /// and says "unknown" for the rest, rather than embedding the full
    /// PCI class code table. A complete table would be several hundred
    /// lines of data that nothing reads, and its only use would be making
    /// the boot log look more thorough than the kernel actually is.
    pub fn describe(&self) -> &'static str {
        match (self.class, self.subclass) {
            (0x01, 0x01) => "IDE storage controller",
            (0x01, 0x06) => "SATA controller (AHCI)",
            (0x01, 0x08) => "NVMe controller",
            (0x01, _) => "storage controller",
            (0x02, _) => "network controller",
            (0x03, _) => "display controller",
            (0x04, 0x01) => "audio device",
            (0x04, _) => "multimedia controller",
            (0x06, 0x00) => "host bridge",
            (0x06, 0x01) => "ISA bridge",
            (0x06, 0x04) => "PCI-to-PCI bridge",
            (0x06, _) => "bridge",
            (0x0C, 0x03) => "USB controller",
            (0x0C, _) => "serial bus controller",
            _ => "unknown device class",
        }
    }
}

/// Reads a 32-bit word from a device's configuration space.
///
/// `offset` must be 4-byte aligned; the hardware ignores the low two bits
/// of the address register, so an unaligned offset would silently read
/// the aligned word containing it - a wrong answer that looks like a
/// right one.
fn read_config(bus: u8, slot: u8, function: u8, offset: u8) -> u32 {
    debug_assert!(
        offset % 4 == 0,
        "PCI config offsets must be 4-byte aligned - the hardware ignores the low bits, so an \
         unaligned read silently returns the wrong field"
    );

    // Bit 31 is the "enable configuration cycle" flag; without it the
    // write to 0xCF8 is ignored and the subsequent read of 0xCFC returns
    // whatever was last on the bus.
    let address = (1u32 << 31)
        | ((bus as u32) << 16)
        | ((slot as u32) << 11)
        | ((function as u32) << 8)
        | (offset as u32 & 0xFC);

    // Safety: 0xCF8/0xCFC are the architecturally fixed PCI configuration
    // ports on every x86 machine since 1993, and this function is the
    // only code in the kernel that touches them. A configuration *read*
    // has no side effects on the device - it is the one PCI operation
    // that is safe to perform on hardware whose identity is not yet
    // known, which is what makes enumeration possible at all.
    unsafe {
        let mut address_port: Port<u32> = Port::new(CONFIG_ADDRESS);
        let mut data_port: Port<u32> = Port::new(CONFIG_DATA);
        address_port.write(address);
        data_port.read()
    }
}

/// Reads one function's identity, or `None` if nothing is there.
fn probe(bus: u8, slot: u8, function: u8) -> Option<Device> {
    let id = read_config(bus, slot, function, 0x00);
    let vendor_id = (id & 0xFFFF) as u16;

    // 0xFFFF is what the bus returns when nothing responds - it is the
    // pulled-up state of the data lines, not a real vendor. Checking it
    // is how absence is detected; there is no "is anything here?" query.
    if vendor_id == 0xFFFF {
        return None;
    }

    let class_word = read_config(bus, slot, function, 0x08);

    Some(Device {
        bus,
        slot,
        function,
        vendor_id,
        device_id: (id >> 16) as u16,
        class: (class_word >> 24) as u8,
        subclass: (class_word >> 16) as u8,
        prog_if: (class_word >> 8) as u8,
    })
}

/// Whether a device is multi-function, from its header type register.
///
/// Checked rather than assumed, because probing functions 1-7 of a
/// single-function device is not merely wasteful: the specification says
/// such a device may respond to those probes with an alias of function 0,
/// which would report the same device up to eight times.
fn is_multifunction(bus: u8, slot: u8) -> bool {
    let header = read_config(bus, slot, 0, 0x0C);
    ((header >> 16) as u8) & 0x80 != 0
}

/// Walks the whole bus and returns everything present.
pub fn enumerate() -> Vec<Device> {
    let mut devices = Vec::new();

    for bus in 0..=255u8 {
        for slot in 0..32u8 {
            let Some(device) = probe(bus, slot, 0) else {
                continue;
            };
            devices.push(device);

            if is_multifunction(bus, slot) {
                for function in 1..8u8 {
                    if let Some(device) = probe(bus, slot, function) {
                        devices.push(device);
                    }
                }
            }
        }
    }

    devices
}

/// Enumerates and reports, returning how many devices were found.
pub fn init() -> usize {
    let devices = enumerate();

    for device in &devices {
        serial_println!(
            "Najm Kernel:   {:02x}:{:02x}.{} [{:04x}:{:04x}] {} (class {:02x}:{:02x}:{:02x})",
            device.bus,
            device.slot,
            device.function,
            device.vendor_id,
            device.device_id,
            device.describe(),
            device.class,
            device.subclass,
            device.prog_if
        );
    }

    devices.len()
}
