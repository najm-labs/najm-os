//! Launches the bootable Najm Kernel disk image under QEMU.
//!
//! Kept deliberately simple: no config file, no argument parsing library,
//! just enough flag-handling to toggle KVM acceleration off when needed
//! (e.g. inside a VM, or a container without /dev/kvm access) and to keep
//! serial output visible for whenever the kernel gains a serial driver.

use std::process::Command;

fn main() {
    let bios_image = env!("BIOS_IMAGE");

    let args: Vec<String> = std::env::args().collect();
    let no_kvm = args.iter().any(|a| a == "--no-kvm");

    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.arg("-drive").arg(format!("format=raw,file={bios_image}"));

    // Redirect the kernel's (future) serial output to this terminal instead
    // of a virtual serial port nobody's watching. No-op today since the
    // kernel doesn't write to serial yet, but wiring it up now means the
    // very first `serial_println!` the kernel gains will just work.
    cmd.arg("-serial").arg("stdio");

    // Without this, a triple fault (the classic outcome of an early kernel
    // bug) silently reboots QEMU in a loop instead of stopping so you can
    // see what happened.
    cmd.arg("-no-reboot");

    cmd.arg("-m").arg("256M");

    if !no_kvm {
        // Hardware-accelerated virtualization. On the Ryzen 5 4600G this
        // needs AMD-V (SVM Mode) enabled in the BIOS/UEFI and the kvm_amd
        // kernel module loaded - see GETTING_STARTED.md. Without it QEMU
        // falls back to software emulation (TCG), which still works, just
        // much slower.
        cmd.arg("-enable-kvm");
        // The CPU model matters independently of the accelerator. QEMU's
        // default `qemu64` model exposes neither SMEP nor SMAP, so the
        // kernel's memory protections would be silently unavailable and
        // the boot log would say so on every run - an accurate report of
        // a needlessly weakened machine. `host` passes the real CPU's
        // features through; `max` is the TCG equivalent.
        cmd.arg("-cpu").arg("host");
    } else {
        cmd.arg("-cpu").arg("max");
    }

    eprintln!("Running: {cmd:?}");

    let status = cmd.status().unwrap_or_else(|err| {
        panic!(
            "failed to launch qemu-system-x86_64: {err}\n\
             Is QEMU installed? On Arch: sudo pacman -S qemu-full"
        )
    });

    std::process::exit(status.code().unwrap_or(1));
}
