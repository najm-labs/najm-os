//! Najm Kernel - entry point.
//!
//! Milestone 10: a first ELF64 loader (loader.rs). The `runner` crate's
//! build script (runner/build.rs) hand-builds a minimal ELF64 binary and
//! attaches it to the boot image as a ramdisk; the bootloader maps that
//! ramdisk into memory (`BOOTLOADER_CONFIG`'s `ramdisk_memory` request
//! below), and `loader::load_and_run` parses it, maps its `PT_LOAD`
//! segments as user-accessible pages, and transitions to Ring 3 at its
//! declared entry point via `arch::x86_64::usermode::enter_usermode_at` -
//! the same underlying transition mechanism milestone 9 proved works,
//! now driven by a real (if minimal) ELF file instead of hand-copied
//! bytes at a hardcoded address. Still no filesystem, no dynamic linking,
//! and no toolchain for compiling arbitrary Rust programs into something
//! this loader can run - just proof that parse-map-jump works end to end.
//!
//! Milestone 9's hardcoded usermode test (`arch/x86_64/usermode.rs`'s
//! `run_test`) and milestone 8's Realm prototype + cooperative scheduler
//! (realm.rs, sched/task.rs) are all still fully present and
//! independently verified working (see their own test logs) - only one
//! `-> !` ending can run per boot, so see the comment at the call site in
//! `kernel_main` for why the others are commented out rather than
//! removed.
//!
//! The capability primitive (security/capability.rs), memory management
//! (mm/memory.rs, mm/allocator.rs), CPU exception handling
//! (arch/x86_64/gdt.rs, arch/x86_64/interrupts.rs), and hardware
//! interrupts (also arch/x86_64/interrupts.rs) from earlier milestones
//! are all still in place and still tested live on every boot, up
//! through the point where this milestone's test takes over.
//!
//! ## Module layout
//!
//! Organized around subsystem, not milestone order, as of this point in
//! the project - `arch/x86_64` for anything tied to this specific CPU
//! architecture (with room for `arch/aarch64` later, see
//! ARCHITECTURE.md's mobile vision), `mm` for memory management, `sched`
//! for scheduling, `security` for the capability primitive, `drivers`
//! for device drivers, and `realm`/`loader` kept at the top level since
//! they genuinely sit *across* those subsystems rather than inside any
//! one of them.

#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

extern crate alloc;

mod arch;
mod drivers;
mod loader;
mod mm;
mod realm;
mod sched;
mod security;

use alloc::vec::Vec;
use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::info::{FrameBuffer, PixelFormat};
use bootloader_api::{entry_point, BootInfo};
use core::panic::PanicInfo;
use x86_64::VirtAddr;

/// Requests that the bootloader map all physical memory into our virtual
/// address space at some offset it chooses (`Mapping::Dynamic`), rather
/// than the default of not mapping it at all. `memory::init` needs this
/// mapping to reach arbitrary physical frames - including page tables
/// that aren't mapped anywhere else yet - which is what makes creating
/// new page table entries for the heap possible in the first place.
///
/// Also requests the same `Dynamic` mapping for the ramdisk
/// (`ramdisk_memory`) - the `runner` crate's build script embeds a small
/// test ELF binary as a ramdisk (see `runner/build.rs`), and without this
/// the bootloader wouldn't map it into memory at all, leaving
/// `boot_info.ramdisk_addr` `None` regardless of whether a ramdisk was
/// actually attached to the disk image.
pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config.mappings.ramdisk_memory = Mapping::Dynamic;
    config
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    serial_println!("Najm Kernel: entry point reached");

    // Order matters: the double fault handler's dedicated stack (set up
    // in gdt::init) has to exist in the TSS *before* the IDT that
    // references it gets loaded.
    arch::x86_64::gdt::init();
    arch::x86_64::interrupts::init();
    serial_println!("Najm Kernel: GDT and IDT installed");

    // A deliberate, live self-test: this triggers a breakpoint exception
    // on purpose. If the IDT is wired up correctly, `breakpoint_handler`
    // (see interrupts.rs) prints a line and execution resumes normally
    // right here, immediately after.
    x86_64::instructions::interrupts::int3();
    serial_println!("Najm Kernel: resumed after breakpoint exception (IDT confirmed working)");

    // Another live self-test, same philosophy: `interrupts::init()` just
    // enabled hardware interrupts (PIC remapped, `sti` executed), but
    // that doesn't prove the timer IRQ is actually reaching
    // `timer_interrupt_handler` - only watching the tick counter actually
    // move does. `hlt` between checks means this costs nothing while
    // waiting; the CPU is genuinely idle until the next interrupt wakes
    // it, timer or otherwise.
    let starting_ticks = arch::x86_64::interrupts::timer_ticks();
    while arch::x86_64::interrupts::timer_ticks() < starting_ticks + 3 {
        x86_64::instructions::hlt();
    }
    serial_println!(
        "Najm Kernel: timer interrupt confirmed working ({} ticks observed)",
        arch::x86_64::interrupts::timer_ticks()
    );
    serial_println!("Najm Kernel: keyboard interrupt handler installed - click the QEMU window and type to test");

    let physical_memory_offset = VirtAddr::new(
        boot_info
            .physical_memory_offset
            .into_option()
            .expect(
                "bootloader did not report a physical memory offset - \
                 check that BOOTLOADER_CONFIG requests physical memory mapping",
            ),
    );

    // Safety: this is the only place `memory::init` is ever called, and
    // `physical_memory_offset` is exactly the value the bootloader just
    // reported above - not guessed, computed, or reused.
    let mut mapper = unsafe { mm::memory::init(physical_memory_offset) };
    // Safety: `boot_info.memory_regions` comes directly from the
    // bootloader's own memory probing during boot - trusted here for the
    // same reason the rest of BootInfo already is.
    let mut frame_allocator =
        unsafe { mm::memory::BootInfoFrameAllocator::init(&boot_info.memory_regions) };

    mm::allocator::init_heap(&mut mapper, &mut frame_allocator)
        .expect("heap initialization failed");
    serial_println!(
        "Najm Kernel: heap mapped and initialized ({} KiB)",
        mm::allocator::HEAP_SIZE / 1024
    );

    // Another live self-test, same philosophy as the breakpoint one
    // above: don't just trust that `init_heap` returning `Ok` means the
    // heap actually works - allocate something that genuinely requires
    // the global allocator and would panic immediately if it were
    // misconfigured, and print the result to prove it end-to-end.
    let heap_test: Vec<u32> = (0..10).map(|i| i * i).collect();
    serial_println!("Najm Kernel: heap allocation test: {:?}", heap_test);
    drop(heap_test);

    // First live test of the capability system: issue a token, use it
    // successfully, revoke it, then prove the *same identity* (a derived
    // copy, not the original) is blocked afterward - the actual security
    // property this mechanism exists for, not just that a struct with the
    // right shape compiles.
    {
        use security::capability::{Capability, SerialWrite, TimerRead};

        let cap = Capability::<SerialWrite>::issue();
        let cap_copy = cap.derive();

        drivers::serial::write_with_capability(
            &cap,
            format_args!("Najm Kernel: capability-gated write succeeded\n"),
        )
        .expect("a freshly issued capability should not start out revoked");

        cap.revoke();

        match drivers::serial::write_with_capability(
            &cap_copy,
            format_args!("Najm Kernel: BUG - this write should have been blocked\n"),
        ) {
            Ok(()) => serial_println!(
                "Najm Kernel: CAPABILITY SYSTEM FAILURE - a revoked capability's derived copy still worked"
            ),
            Err(err) => serial_println!(
                "Najm Kernel: capability system confirmed working - derived copy correctly blocked ({})",
                err
            ),
        }

        // Same proof, second right: TimerRead is a completely different
        // capability type from SerialWrite, gating a different piece of
        // kernel state - this is what actually demonstrates the pattern
        // generalizes, rather than happening to work once for the one
        // right it was built against.

        let timer_cap = Capability::<TimerRead>::issue();
        let timer_cap_copy = timer_cap.derive();
        match arch::x86_64::interrupts::ticks_with_capability(&timer_cap) {
            Ok(ticks) => serial_println!(
                "Najm Kernel: TimerRead capability confirmed working - {} ticks observed",
                ticks
            ),
            Err(err) => serial_println!(
                "Najm Kernel: CAPABILITY SYSTEM FAILURE - freshly issued TimerRead capability was rejected ({})",
                err
            ),
        }
        timer_cap.revoke();
        match arch::x86_64::interrupts::ticks_with_capability(&timer_cap_copy) {
            Ok(_) => serial_println!(
                "Najm Kernel: CAPABILITY SYSTEM FAILURE - a revoked TimerRead capability still worked"
            ),
            Err(err) => serial_println!(
                "Najm Kernel: TimerRead revocation confirmed working - read correctly blocked ({})",
                err
            ),
        }
    }

    match boot_info.framebuffer.as_mut() {
        Some(framebuffer) => paint_framebuffer(framebuffer),
        None => serial_println!(
            "Najm Kernel: bootloader provided no framebuffer, skipping paint"
        ),
    }

    serial_println!("Najm Kernel: initialization complete, starting task scheduler");

    // Live proof of cooperative multitasking: three independent stacks
    // that alternate execution by voluntarily yielding to each other.
    // Round-robin scheduling means their output should interleave in
    // strict A, B, C order per round (A0, B0, C0, A1, B1, C1, ...) rather
    // than running one fully to completion before the next starts - that
    // interleaving *is* the test. Three tasks rather than two specifically
    // exercises that the ready queue's FIFO ordering holds across more
    // than a single pair - a scheduler that happened to work for exactly
    // two tasks by coincidence would be a real (if narrow) risk worth
    // ruling out before building anything more on top of this.
    // Spawned *first*, so `start()` runs it first and it is the task
    // holding the CPU while A/B/C are waiting - see `task_spinner` for
    // what that proves.
    sched::task::spawn(task_spinner);
    sched::task::spawn(task_a);
    sched::task::spawn(task_b);
    sched::task::spawn(task_c);

    // First Realm-flavored tasks: each carries its own, distinct
    // capability profile via realm.rs, instead of sharing capabilities
    // declared in this function like the earlier capability self-test
    // did. Spawned *alongside* task_a/b/c above, not replacing them - if
    // anything about this newer, more involved context-passing mechanism
    // misbehaves, the already-proven scheduler test above is unaffected
    // and still demonstrates the core mechanism works, which keeps any
    // failure isolated to what's actually new here.
    //
    // The capability profiles themselves are deliberately different per
    // Realm, matching ARCHITECTURE.md's description of Vault having
    // restricted access to introspection-style APIs: Gaming gets both
    // rights, Home gets serial output only, and Vault gets timer access
    // but *not* SerialWrite.
    use security::capability::{Capability, SerialWrite, TimerRead};

    realm::spawn(
        "Gaming Realm",
        Some(Capability::<SerialWrite>::issue()),
        Some(Capability::<TimerRead>::issue()),
    );
    realm::spawn(
        "Vault Realm",
        None,
        Some(Capability::<TimerRead>::issue()),
    );
    realm::spawn(
        "Home Realm",
        Some(Capability::<SerialWrite>::issue()),
        None,
    );

    // NOTE ON WHAT ACTUALLY RUNS THIS BOOT: this used to be a list of
    // mutually-exclusive endings picked by commenting two of them out,
    // because `usermode::run_test` and `loader::load_and_run` were both
    // `-> !` and only one thing can be "the last thing that happens" per
    // boot. Now that Ring 3 programs return (see `usermode::run_program`),
    // both of those run in sequence below, every boot, with no manual
    // editing required to check either one.
    //
    // `sched::task::start()` is the one ending still left out, because it
    // genuinely is still `-> !` - the cooperative scheduler has no
    // "all tasks finished, resume the boot context" path. The Realm and
    // task spawning above therefore still runs every boot (proving the
    // spawn path and the per-Realm capability profiles are constructed
    // correctly) while the tasks themselves stay queued, unrun. That's a
    // real remaining gap, not a passing detail - see the milestone 6/7/8
    // logs for the evidence that the scheduler itself works when started.

    // Milestone 9's hand-written Ring 3 payload, run first: it is the
    // narrower of the two tests (three hand-assembled bytes at a fixed
    // address, no ELF parsing involved), so if the Ring 3 machinery
    // itself has regressed, this isolates that from anything the ELF
    // loader might be doing wrong.
    let usermode_exit = arch::x86_64::usermode::run_test(&mut mapper, &mut frame_allocator);
    report_program_exit(
        "hand-written Ring 3 payload",
        usermode_exit,
        arch::x86_64::usermode::ProgramExit::GeneralProtectionFault,
    );

    let ramdisk_addr = boot_info
        .ramdisk_addr
        .into_option()
        .expect("bootloader did not report a ramdisk address - check that BOOTLOADER_CONFIG requests ramdisk mapping and that runner/build.rs attached one");
    let ramdisk_len = boot_info.ramdisk_len as usize;

    // Safety: `ramdisk_addr` is a virtual address the bootloader itself
    // already mapped read-accessible for exactly `ramdisk_len` bytes
    // (per bootloader_api's own documentation of this field) - not a
    // physical address needing offset translation, and not a region this
    // kernel constructed or guessed at itself.
    let ramdisk: &[u8] =
        unsafe { core::slice::from_raw_parts(ramdisk_addr as *const u8, ramdisk_len) };

    serial_println!(
        "Najm Kernel: ramdisk found at {:#x}, {} bytes - starting ELF loader",
        ramdisk_addr,
        ramdisk_len
    );

    let exit = loader::load_and_run(ramdisk, &mut mapper, &mut frame_allocator);
    // Status 7 is what `userland/hello`'s `_start` passes to `exit`. If
    // the ramdisk is instead the hand-encoded fallback from
    // runner/build.rs (built when USERLAND_PATH isn't set), that one
    // exits with 42 - so a mismatch reported here is the fastest way to
    // notice the boot image was built without the userland crate.
    report_program_exit(
        "ELF-loaded program",
        exit,
        arch::x86_64::usermode::ProgramExit::Exited(7),
    );

    // Proof the kernel is not merely *reached* but genuinely healthy
    // afterwards: hardware interrupts still have to be enabled (they are
    // restored explicitly in `run_program` - see the comment there on why
    // they'd otherwise stay masked forever), and the heap still has to
    // work. Both are things a botched return path would plausibly break
    // while still managing to print the line above.
    let ticks_before = arch::x86_64::interrupts::timer_ticks();
    while arch::x86_64::interrupts::timer_ticks() < ticks_before + 3 {
        x86_64::instructions::hlt();
    }
    let post_exit_check: Vec<u32> = (0..5).map(|i| i + 100).collect();
    serial_println!(
        "Najm Kernel: post-program health check - timer still ticking ({} ticks), heap still \
         working ({:?})",
        arch::x86_64::interrupts::timer_ticks(),
        post_exit_check
    );

    // The final handoff, and the one ending `kernel_main` still has:
    // `start()` never returns, because the cooperative scheduler has no
    // "every task finished, resume the boot context" path. Everything
    // above this line therefore runs on every boot with nothing commented
    // out - the self-tests, both Ring 3 programs, and the health check -
    // and the scheduler gets the machine afterwards.
    serial_println!("Najm Kernel: handing the CPU to the scheduler");
    sched::task::start();
}

/// Reports how a Ring 3 program ended, and checks it against the outcome
/// that test was actually designed to produce.
///
/// Checking rather than just printing matters because the expected
/// outcomes here are not the intuitive ones:
///
/// - The hand-written payload is *supposed* to end in a general
///   protection fault. Its last instruction is privileged, so a clean
///   exit would mean the CPU stopped enforcing Ring 3 restriction and the
///   isolation this kernel claims became fiction.
/// - The ELF payload is *supposed* to exit cleanly with status 42. A
///   fault there would mean the `exit` syscall silently failed to end the
///   program and execution ran off into its trailing `hlt`.
///
/// Between them the two cover both halves of the return-to-supervisor
/// path. Reaching this function at all is itself the proof that path
/// works: before it existed, a Ring 3 program ending took the whole
/// machine down, and nothing after the transition could ever run.
fn report_program_exit(
    what: &str,
    exit: arch::x86_64::usermode::ProgramExit,
    expected: arch::x86_64::usermode::ProgramExit,
) {
    serial_println!(
        "Najm Kernel: SUPERVISOR RESUMED - the {} ended with {:?}, and the kernel is \
         still running",
        what,
        exit
    );

    if exit == expected {
        serial_println!(
            "Najm Kernel: {} - correct outcome ({:?} is what this payload exists to prove)",
            what,
            expected
        );
    } else {
        serial_println!(
            "Najm Kernel: RING 3 TEST FAILURE - the {} ended with {:?}, but should have \
             ended with {:?}",
            what,
            exit,
            expected
        );
    }
}

/// One of three test tasks proving the scheduler actually switches
/// between independent stacks rather than just running sequentially. See
/// `task_b`, `task_c`, and the call site in `kernel_main` for the full
/// picture.
extern "C" fn task_a() -> ! {
    for i in 0..3 {
        serial_println!("[Task A] iteration {}", i);
        sched::task::yield_now();
    }
    // No further yields after this: with no task-removal mechanism yet
    // (a documented, deliberate limitation - see task.rs), the only way
    // for a finished task to stop consuming CPU time is to park itself
    // here permanently rather than yield into a slot nothing will ever
    // resume it from.
    halt_loop();
}

/// See `task_a` - identical in every respect except which letter it
/// prints, specifically so the interleaving between the two is the only
/// variable being demonstrated.
extern "C" fn task_b() -> ! {
    for i in 0..3 {
        serial_println!("[Task B] iteration {}", i);
        sched::task::yield_now();
    }
    halt_loop();
}

/// See `task_a` and `task_b` - a third, identically-structured task
/// specifically to prove round-robin ordering holds for more than a
/// single pair (see the comment at the `task::spawn` call sites in
/// `kernel_main`).
extern "C" fn task_c() -> ! {
    for i in 0..3 {
        serial_println!("[Task C] iteration {}", i);
        sched::task::yield_now();
    }
    halt_loop();
}

/// How many timer ticks `task_spinner` refuses to give up the CPU for.
/// At the PIT's default rate (~18.2 Hz) this is a little over half a
/// second - long enough that "the other tasks ran during it" is
/// unambiguous, short enough not to pad every boot.
const SPIN_TICKS: u64 = 10;

/// The task that proves preemption is real.
///
/// Unlike A/B/C, this one never calls `yield_now()`. Under the purely
/// cooperative scheduler it would therefore hold the CPU for its entire
/// spin, and tasks A, B and C could not print a single line until it
/// finished - that is precisely what "cooperative" means. So the test is
/// simply: **do A/B/C's lines appear between this task's two messages?**
/// If they do, something took the CPU away from a task that never
/// offered it, which is preemption and cannot be anything else.
///
/// `spin_loop()` rather than `hlt` in the wait loop is deliberate and
/// load-bearing: `hlt` parks the CPU until the next interrupt, which
/// would hand control away for reasons that have nothing to do with the
/// scheduler and make the result meaningless. This has to be a genuinely
/// CPU-bound loop for the test to say anything.
extern "C" fn task_spinner() -> ! {
    let started_at = arch::x86_64::interrupts::timer_ticks();
    serial_println!(
        "[Spinner] starting a {}-tick busy loop and will NOT call yield_now() - \
         any [Task A/B/C] lines below this one can only be the timer preempting me",
        SPIN_TICKS
    );

    while arch::x86_64::interrupts::timer_ticks() < started_at + SPIN_TICKS {
        core::hint::spin_loop();
    }

    serial_println!(
        "[Spinner] busy loop finished after {} ticks",
        arch::x86_64::interrupts::timer_ticks() - started_at
    );
    halt_loop();
}

/// Fills the boot framebuffer with a solid, deliberately-chosen color,
/// resolving the actual channel order/format the bootloader reported
/// instead of assuming one.
///
/// Milestone 1 assumed an RGB-ish layout unconditionally; on the actual
/// test hardware the bootloader reported BGR, so the "blue" fill came out
/// orange. That was still useful as a first proof of life (any uniform
/// color proves the mapping works), but it's not something to leave as
/// technical debt now that fixing it properly is nearly the same amount
/// of code.
fn paint_framebuffer(framebuffer: &mut FrameBuffer) {
    let info = framebuffer.info();
    let bytes_per_pixel = info.bytes_per_pixel;
    let pixel_format = info.pixel_format;
    let buffer = framebuffer.buffer_mut();

    // Target color: a deep blue. Channel order is resolved per-format
    // below rather than assumed.
    let (r, g, b): (u8, u8, u8) = (0x1e, 0x50, 0xff);

    for pixel in buffer.chunks_exact_mut(bytes_per_pixel) {
        match pixel_format {
            PixelFormat::Rgb => {
                pixel[0] = r;
                if bytes_per_pixel > 1 {
                    pixel[1] = g;
                }
                if bytes_per_pixel > 2 {
                    pixel[2] = b;
                }
            }
            PixelFormat::Bgr => {
                pixel[0] = b;
                if bytes_per_pixel > 1 {
                    pixel[1] = g;
                }
                if bytes_per_pixel > 2 {
                    pixel[2] = r;
                }
            }
            PixelFormat::U8 => {
                // Grayscale-only framebuffer: approximate luminance
                // rather than just writing one channel and leaving the
                // rest black.
                pixel[0] = ((r as u16 + g as u16 + b as u16) / 3) as u8;
            }
            _ => {
                // An unrecognized/custom format (e.g. non-standard
                // channel positions). Rather than guess at a layout we
                // don't actually know, write a value that's at least
                // visible in every byte, and say so over serial - this
                // is a real gap to come back to, not something to paper
                // over silently.
                for byte in pixel.iter_mut() {
                    *byte = 0xff;
                }
            }
        }
    }

    serial_println!(
        "Najm Kernel: framebuffer painted ({}x{}, format {:?}, {} bytes/px)",
        info.width,
        info.height,
        pixel_format,
        bytes_per_pixel
    );
}

/// Parks the CPU using the `hlt` instruction instead of busy-spinning.
///
/// `hlt` suspends the core until the next interrupt arrives. Using a bare
/// `loop {}` here would peg a full CPU core at 100% forever, in QEMU and on
/// real hardware alike, for a kernel that (at this stage) has nothing left
/// to do.
pub(crate) fn halt_loop() -> ! {
    loop {
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}

/// Panic handler required by `#![no_std]`.
///
/// This is now a *real* panic handler rather than a silent halt: it
/// reports what went wrong over serial before parking the CPU, so a panic
/// during development is something you can actually diagnose instead of
/// just seeing the machine stop with no explanation.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("Najm Kernel PANIC: {}", info);
    halt_loop()
}
