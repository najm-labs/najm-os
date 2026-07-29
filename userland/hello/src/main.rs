//! The first real userland program for Najm OS.
//!
//! Everything that ran at Ring 3 before this was hand-encoded machine
//! code - three bytes in `usermode.rs`, then a slightly longer sequence
//! assembled byte-by-byte in `runner/build.rs`. Those proved the
//! mechanisms (privilege transition, ELF parsing, the syscall ABI) but
//! they could never grow into anything: every new instruction had to be
//! encoded by hand and every constant duplicated by eye.
//!
//! This is a compiled Rust program instead. It has no runtime, no
//! standard library, and no way to affect anything except through
//! `int 0x80` - which is the entire point. If it can print, it's because
//! the kernel's `write` syscall works; if it exits with the status the
//! kernel reports, the `exit` syscall and the return-to-supervisor path
//! work end to end for real code rather than for a payload built to
//! flatter them.
//!
//! What it deliberately does *not* have yet: any way to receive
//! arguments or environment (the kernel passes none), a heap, or a
//! `main` distinct from `_start` (nothing sets up a runtime to call one).

#![no_std]
#![no_main]

mod syscall;

/// Written to at runtime so it lands in `.bss` rather than `.data`.
///
/// This tests the loader rather than the syscall interface: the buffer
/// must be mapped, writable, and zeroed before first use. Note that it
/// does *not* reach `loader.rs`'s `p_memsz > p_filesz` zero-fill branch,
/// despite `.bss` being a NOBITS section - lld extends `p_filesz` to
/// cover it, so the zeroes are file-backed. See the note in `linker.ld`;
/// the hand-encoded ELF in `runner/build.rs` is what still covers that
/// branch.
static mut MESSAGE_BUFFER: [u8; 64] = [0; 64];

#[no_mangle]
pub extern "C" fn _start() -> ! {
    syscall::write(b"[userland] hello from a real, compiled Rust program at Ring 3\n");

    // Several distinct writes rather than one, so the boot log shows
    // unambiguously that repeated syscalls work - a single successful
    // syscall could be a fluke of whatever state the transition left
    // behind, three in a row with different contents cannot.
    let lines: [&[u8]; 3] = [
        b"[userland] line 1 - syscalls are repeatable\n",
        b"[userland] line 2 - arguments arrive intact\n",
        b"[userland] line 3 - .rodata is mapped and readable\n",
    ];
    for line in lines {
        syscall::write(line);
    }

    // Build a message in .bss and print it back, proving the zero-filled
    // region is genuinely mapped and writable.
    let written = build_bss_message();
    syscall::write(written);

    // Deliberately hand the kernel a pointer it must refuse: the kernel's
    // own heap base. A program proving its *valid* pointers work says
    // nothing about whether invalid ones are caught, and "the kernel
    // refuses to read its own memory on my behalf" is the more important
    // of the two properties. The kernel should log a rejection and return
    // an error rather than printing anything.
    let refused = syscall::write_raw(0x_4444_4444_0000, 8);
    if refused > 0x_ffff_ffff_0000_0000 {
        syscall::write(b"[userland] good: the kernel refused to read its own heap for me\n");
    } else {
        syscall::write(b"[userland] BAD: the kernel accepted a kernel-memory pointer\n");
    }

    // 7 is arbitrary, but it has to survive the whole round trip - the
    // kernel prints what it received, so a mismatch would be visible
    // rather than silent.
    syscall::exit(7);
}

/// Fills `MESSAGE_BUFFER` with a message and returns the written slice.
fn build_bss_message() -> &'static [u8] {
    const TEXT: &[u8] = b"[userland] line 4 - .bss is mapped, writable, and read as zero\n";

    // Safety: single-threaded program with no interrupts of its own, and
    // this is the only code that ever touches `MESSAGE_BUFFER`. The
    // pointer is taken with `addr_of_mut!` rather than by referencing the
    // static directly, which would create a `&mut` to a mutable static.
    unsafe {
        let buffer = core::ptr::addr_of_mut!(MESSAGE_BUFFER) as *mut u8;

        // Verify the region really does read as zero before writing to
        // it. If the loader had mapped the page without the segment's
        // contents landing correctly, this would be reading whatever the
        // frame allocator handed over last - stale kernel data, which
        // would be both a correctness bug and an information leak worth
        // catching loudly.
        let was_zeroed = (0..TEXT.len()).all(|i| buffer.add(i).read() == 0);

        core::ptr::copy_nonoverlapping(TEXT.as_ptr(), buffer, TEXT.len());

        if !was_zeroed {
            return b"[userland] BAD: .bss was not zero-filled before use\n";
        }

        core::slice::from_raw_parts(buffer, TEXT.len())
    }
}

/// Required by `#![no_std]`. Reports through the same syscall interface
/// the rest of the program uses, then exits with a distinctive status so
/// a panic is never mistaken for a clean run.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Deliberately no formatting of `_info`: `core::fmt` in a program
    // with a 16 KiB stack and no allocator is a real risk of faulting
    // *inside* the panic handler, which would replace a clear message
    // with a confusing one.
    syscall::write(b"[userland] PANIC\n");
    syscall::exit(101);
}
