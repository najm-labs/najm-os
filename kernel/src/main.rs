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
mod fs;
mod graphics;
mod loader;
mod mm;
mod process;
mod realm;
mod sched;
mod security;
mod selftest;
mod syscall;

use alloc::vec::Vec;
use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::info::{FrameBuffer, PixelFormat};
use bootloader_api::{entry_point, BootInfo};
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
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
/// Also constrains **every** dynamic mapping the bootloader makes - the
/// kernel image, its stack, the boot info, the framebuffer, the
/// physical-memory window and the ramdisk - to start at
/// `layout::HIGHER_HALF_START` rather than at the default of 0.
///
/// This is the single line that makes per-process address spaces
/// possible. With dynamic mappings allowed anywhere, the bootloader
/// places kernel structures in the lower half, which is precisely the
/// region each user process needs to own privately; a per-process page
/// table would then have to either share those entries (leaking kernel
/// mappings into every process and making one process's changes visible
/// to all) or drop them on CR3 switch (immediately fatal, since the very
/// next instruction fetch is from unmapped memory). Pinning everything
/// kernel-side above the split means creating an address space is
/// "copy PML4 entries 256..512" and nothing else. See `mm::layout` for
/// the whole map, and `memory::pml4_entries_in_use` for the boot-time
/// check that the bootloader actually honoured this.
pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config.mappings.ramdisk_memory = Mapping::Dynamic;
    config.mappings.dynamic_range_start = Some(mm::layout::HIGHER_HALF_START);
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
    selftest::check(
        "IDT",
        true,
        format_args!("resumed normally after a deliberate breakpoint exception"),
    );

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
    selftest::check(
        "timer IRQ",
        arch::x86_64::interrupts::timer_ticks() > starting_ticks,
        format_args!(
            "tick counter advanced from {} to {}",
            starting_ticks,
            arch::x86_64::interrupts::timer_ticks()
        ),
    );

    let physical_memory_offset = VirtAddr::new(
        boot_info
            .physical_memory_offset
            .into_option()
            .expect(
                "bootloader did not report a physical memory offset - \
                 check that BOOTLOADER_CONFIG requests physical memory mapping",
            ),
    );

    // CPU protections first, and specifically before anything maps a
    // page: `NO_EXECUTE` is bit 63 of a page table entry and is a
    // *reserved bit violation* unless `EFER.NXE` is enabled, so a heap
    // mapped with NX before this ran would fault on first touch. See
    // `arch::x86_64::cpu` for what each protection actually prevents.
    let cpu_features = arch::x86_64::cpu::init();

    // Safety: this is the only place `memory::init` is ever called;
    // `physical_memory_offset` is exactly the value the bootloader just
    // reported above, and `memory_regions` is the bootloader's own memory
    // map - neither is guessed, computed, or reused.
    unsafe { mm::memory::init(physical_memory_offset, &boot_info.memory_regions) };

    serial_println!(
        "Najm Kernel: physical memory mapped at {:#x} (higher half starts at {:#x})",
        physical_memory_offset.as_u64(),
        mm::layout::HIGHER_HALF_START
    );
    mm::allocator::init_heap().expect("heap initialization failed");
    serial_println!(
        "Najm Kernel: heap mapped and initialized ({} KiB at {:#x})",
        mm::allocator::HEAP_SIZE / 1024,
        mm::allocator::HEAP_START
    );

    // Another live self-test, same philosophy as the breakpoint one
    // above: don't just trust that `init_heap` returning `Ok` means the
    // heap actually works - allocate something that genuinely requires
    // the global allocator and would panic immediately if it were
    // misconfigured, and print the result to prove it end-to-end.
    let heap_test: Vec<u32> = (0..10).map(|i| i * i).collect();
    selftest::check(
        "kernel heap",
        heap_test == [0, 1, 4, 9, 16, 25, 36, 49, 64, 81],
        format_args!("allocated and read back {:?}", heap_test),
    );
    drop(heap_test);

    // Drop the identity mapping the bootloader left in the lower half,
    // then verify the address-space split `mm::layout` describes actually
    // holds. Both matter, and for different reasons: the first removes
    // bootloader code that would otherwise be mapped into every future
    // process at a low address, and the second checks that
    // `BOOTLOADER_CONFIG`'s `dynamic_range_start` request was honoured
    // rather than trusting it. If a kernel mapping had landed in the
    // lower half, per-process address spaces would silently share a
    // top-level page table entry with the kernel - a security boundary
    // that stops existing without anything crashing.
    //
    // Safety: nothing is executing from or holding a pointer into the
    // lower half at this point. The kernel image, its stack, the boot
    // info, the framebuffer, the ramdisk and the heap are all in the
    // higher half (verified by the check immediately below), and no user
    // process exists yet.
    // Recorded before any process exists, so "the kernel's address space"
    // and "whatever is currently in CR3" can never be confused - they are
    // the same thing only until the first process runs, and a function
    // that conflated them would restore a process's page tables while
    // believing it had restored the kernel's.
    mm::address_space::record_kernel_root();

    let cleared = unsafe { mm::memory::clear_lower_half_mappings() };
    if !cleared.is_empty() {
        serial_println!(
            "Najm Kernel: dropped {} leftover lower-half PML4 entries {:?} (the bootloader's \
             identity-mapped context-switch stub - dead code that would otherwise be mapped \
             into every user process)",
            cleared.len(),
            cleared
        );
    }

    let (lower_half_entries, higher_half_entries) = mm::memory::pml4_entries_in_use();
    selftest::check(
        "address space split",
        lower_half_entries == 0 && higher_half_entries > 0,
        format_args!(
            "{} lower-half PML4 entries in use (must be 0 - the lower half belongs to user \
             processes), {} higher-half entries (the kernel)",
            lower_half_entries, higher_half_entries
        ),
    );

    // NX is the load-bearing one: without it, `NO_EXECUTE` cannot even be
    // *expressed* in a page table entry (setting bit 63 becomes a
    // reserved-bit violation), so W^X would be unimplementable rather
    // than merely unimplemented. SMEP/SMAP/UMIP are reported but not
    // required - they depend on the CPU model, and QEMU's default
    // `qemu64` exposes none of them, so failing the boot over their
    // absence would make the test suite unrunnable on a default QEMU.
    selftest::check(
        "NX support",
        cpu_features.nx,
        format_args!(
            "execute-disable is {} - SMEP {}, SMAP {}, UMIP {}",
            if cpu_features.nx { "enabled" } else { "MISSING" },
            cpu_features.smep,
            cpu_features.smap,
            cpu_features.umip
        ),
    );

    // A guard page is protective only because nothing maps it, and that
    // guarantee is exactly the kind that dies silently. Walking the page
    // tables to confirm the page below a real, live kernel stack is
    // absent costs one translation and makes the protection falsifiable.
    let guard_check = mm::memory::with_memory(|mapper, frame_allocator| {
        let stack = mm::kstack::allocate(mapper, frame_allocator)
            .expect("could not allocate a kernel stack for the guard page test");
        let unmapped = mm::kstack::guard_page_is_unmapped(&stack, mapper);
        let guard = stack.guard_page();
        mm::kstack::release(stack);
        (unmapped, guard)
    });
    selftest::check(
        "kernel stack guard page",
        guard_check.0,
        format_args!(
            "the page below a kernel stack ({:#x}) is unmapped, so overflow faults instead of \
             corrupting the next allocation",
            guard_check.1
        ),
    );

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

        let blocked = drivers::serial::write_with_capability(
            &cap_copy,
            format_args!("Najm Kernel: BUG - this write should have been blocked\n"),
        );
        selftest::check(
            "capability revocation (SerialWrite)",
            blocked.is_err(),
            format_args!(
                "a derived copy of a revoked capability was {}",
                match &blocked {
                    Ok(()) => "still accepted - revocation does not propagate to derived copies",
                    Err(err) => {
                        let _ = err;
                        "correctly refused"
                    }
                }
            ),
        );

        // Same proof, second right: TimerRead is a completely different
        // capability type from SerialWrite, gating a different piece of
        // kernel state - this is what actually demonstrates the pattern
        // generalizes, rather than happening to work once for the one
        // right it was built against.

        let timer_cap = Capability::<TimerRead>::issue();
        let timer_cap_copy = timer_cap.derive();
        let before_revoke = arch::x86_64::interrupts::ticks_with_capability(&timer_cap);
        selftest::check(
            "capability grant (TimerRead)",
            before_revoke.is_ok(),
            format_args!(
                "a freshly issued token read the tick counter: {:?}",
                before_revoke.as_ref().ok()
            ),
        );

        timer_cap.revoke();
        let after_revoke = arch::x86_64::interrupts::ticks_with_capability(&timer_cap_copy);
        selftest::check(
            "capability revocation (TimerRead)",
            after_revoke.is_err(),
            format_args!(
                "reading through a revoked token {}",
                if after_revoke.is_ok() {
                    "still succeeded"
                } else {
                    "was correctly refused"
                }
            ),
        );
    }

    // Device discovery. Everything before this point talks to hardware at
    // an address fixed by convention - the serial port, the PIT, the PS/2
    // controller. PCI is the first bus this kernel *asks* rather than
    // assumes, which is the prerequisite for ARCHITECTURE.md section 6's
    // driver strategy.
    serial_println!("Najm Kernel: enumerating the PCI bus");
    let pci_devices = drivers::pci::init();
    selftest::check(
        "PCI enumeration",
        pci_devices > 0,
        format_args!(
            "{} device(s) found by walking configuration space - the bus is being discovered, \
             not assumed",
            pci_devices
        ),
    );

    // Wall-clock time. Not decorative: ARCHITECTURE.md section 2e makes
    // Vault Realm eligibility depend on a publisher signature chain, and a
    // chain cannot be checked for expiry or revocation without knowing
    // the date. A trust decision made against an unknown date is not a
    // weaker decision, it is a different one.
    let wall_clock = drivers::rtc::init();
    selftest::check(
        "wall clock",
        wall_clock.is_some(),
        format_args!(
            "the RTC reports {} seconds since the Unix epoch",
            wall_clock.map(|now| now.to_unix_seconds()).unwrap_or(0)
        ),
    );

    drivers::input::init_mouse();

    // The graphics stack. Themes are loaded from the boot archive if one
    // is present, which is the customization layer ARCHITECTURE.md 2c
    // calls the Realm Shell; the trusted path the same section requires
    // is drawn by the compositor from kernel state and is deliberately
    // not reachable from a theme at all.
    let theme = match fs::read_all("/etc/theme.conf") {
        Some(bytes) => {
            let text = alloc::string::String::from_utf8_lossy(&bytes);
            let (theme, applied, rejected) = graphics::theme::Theme::parse(&text);
            serial_println!(
                "Najm Kernel: theme loaded from /etc/theme.conf - {} setting(s) applied, {} \
                 line(s) rejected",
                applied,
                rejected
            );
            theme
        }
        None => {
            serial_println!("Najm Kernel: no /etc/theme.conf, using the built-in theme");
            graphics::theme::Theme::DEFAULT
        }
    };

    match boot_info.framebuffer.as_mut() {
        Some(framebuffer) => {
            let info = framebuffer.info();
            let buffer = framebuffer.buffer_mut();
            // Safety: `buffer` is the framebuffer mapping the bootloader
            // established, writable for its own length, and `info` is the
            // geometry the bootloader reported for exactly that mapping.
            // The `Framebuffer` takes the address rather than the slice so
            // that every write is bounds-checked at the point of writing -
            // see that type's documentation for why that matters for a
            // compositor placing untrusted content.
            let framebuffer = unsafe {
                graphics::framebuffer::Framebuffer::new(
                    buffer.as_mut_ptr() as u64,
                    buffer.len(),
                    info.width,
                    info.height,
                    info.stride * info.bytes_per_pixel,
                    info.bytes_per_pixel,
                    info.pixel_format,
                )
            };
            serial_println!(
                "Najm Kernel: framebuffer {}x{}, {} bytes/px, format {:?}",
                info.width,
                info.height,
                info.bytes_per_pixel,
                info.pixel_format
            );
            graphics::compositor::init(framebuffer, theme);
            graphics::compositor::present();
        }
        None => serial_println!(
            "Najm Kernel: bootloader provided no framebuffer - the compositor is unavailable, \
             which is expected on a headless boot and is reported rather than assumed"
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
    let usermode_exit = arch::x86_64::usermode::run_test();
    report_program_exit(
        "hand-written Ring 3 payload",
        usermode_exit,
        arch::x86_64::usermode::ProgramExit::GeneralProtectionFault,
    );

    // The one test that can actually falsify W^X. Everything else about
    // it - the loader setting NO_EXECUTE, the heap setting NO_EXECUTE,
    // the boot log reporting NX as enabled - would look identical on a
    // kernel where `EFER.NXE` was never set and the bit meant nothing.
    // Only an execution attempt that *fails* is evidence.
    match arch::x86_64::usermode::run_nx_test() {
        Some(exit) => report_program_exit(
            "NO_EXECUTE enforcement",
            exit,
            arch::x86_64::usermode::ProgramExit::PageFault,
        ),
        None => serial_println!(
            "Najm Kernel: skipping the NO_EXECUTE test - this CPU does not support NX, so \
             there is no property here to test (reporting a pass would be a lie)"
        ),
    }

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
        "Najm Kernel: ramdisk found at {:#x}, {} bytes - mounting the boot archive",
        ramdisk_addr,
        ramdisk_len
    );

    // The ramdisk is a NAR archive rather than a bare ELF binary now, so
    // this is a *filesystem* mount rather than a pointer handed to the
    // loader. Everything below loads programs by path.
    let mounted = match fs::mount(ramdisk) {
        Ok(count) => count,
        Err(err) => panic!("could not mount the boot archive: {}", err),
    };
    fs::report();
    selftest::check(
        "boot archive mounted",
        mounted >= 4,
        format_args!(
            "{} paths in the namespace, including directories synthesized from their children",
            mounted
        ),
    );

    // Reading a file the kernel did not produce, through the same code
    // path a syscall uses. Checking the *contents* rather than merely
    // that a read succeeded: a filesystem that returns the right number
    // of wrong bytes looks identical to one that works.
    let motd = fs::read_all("/etc/motd").unwrap_or_default();
    selftest::check(
        "filesystem read",
        motd.starts_with(b"Najm OS:"),
        format_args!(
            "/etc/motd is {} bytes and begins with the expected text",
            motd.len()
        ),
    );

    // The negative half, checked kernel-side as well as from userland: a
    // path with a `..` component must not resolve, whatever it would have
    // resolved to.
    selftest::check(
        "path traversal refused",
        fs::lookup("/etc/../etc/motd").is_none() && fs::lookup("/nonexistent").is_none(),
        format_args!("'/etc/../etc/motd' and '/nonexistent' both resolve to nothing"),
    );

    // Two processes from the same image, each in its own address space.
    //
    // Two rather than one, and deliberately the *same* image: both load
    // at 0x400000, because the loader supports only `ET_EXEC` and that is
    // where the linker script puts them. Before per-process address
    // spaces this was simply impossible - the second `map_to` would fail
    // with "already mapped", because there was one set of page tables and
    // that address was already taken. Two live processes at the same
    // virtual address is therefore not a nice-to-have here; it is the
    // observable difference between "we have address spaces" and "we do
    // not."
    //
    // They also give Ring 3 preemption something to be visible in: they
    // are scheduled alongside the kernel tasks below, and their output
    // interleaves with everything else.
    let frames_free_before = mm::frame_pool::stats().0;

    let hello_image = fs::read_all("/bin/hello")
        .expect("/bin/hello is missing from the boot archive - was USERLAND_PATH set?");

    let first = loader::load_image(&hello_image, "hello")
        .unwrap_or_else(|err| panic!("could not load /bin/hello: {}", err));
    let second = loader::load_image(&hello_image, "hello (second instance)")
        .unwrap_or_else(|err| panic!("could not load /bin/hello a second time: {}", err));

    let first_pid = process::spawn(first, realm::HOME);
    let second_pid = process::spawn(second, realm::GAMING);

    // The graphical program, in the Gaming Realm. That placement is the
    // point: a Gaming Realm gets exclusive fullscreen, and exclusive
    // fullscreen still excludes the Core-reserved trust strip - so this
    // process is the one that would expose ARCHITECTURE.md 2d threat 4 if
    // the reservation were not real.
    let gui_pid = match fs::read_all("/bin/gui") {
        Some(image) => {
            let loaded = loader::load_image(&image, "gui")
                .unwrap_or_else(|err| panic!("could not load /bin/gui: {}", err));
            Some(process::spawn(loaded, realm::GAMING))
        }
        None => {
            serial_println!(
                "Najm Kernel: /bin/gui is not in the boot archive - skipping the compositor \
                 tests"
            );
            None
        }
    };

    // A genuinely different binary, loaded by path out of a namespace
    // that contains several things. This is what makes the filesystem
    // load-bearing: while there was one program and it *was* the ramdisk,
    // "the loader can run a program" and "the loader can run the one
    // thing the ramdisk contains" were the same statement.
    let fstest_pid = match fs::read_all("/bin/fstest") {
        Some(image) => {
            let loaded = loader::load_image(&image, "fstest")
                .unwrap_or_else(|err| panic!("could not load /bin/fstest: {}", err));
            Some(process::spawn(loaded, realm::HOME))
        }
        None => {
            serial_println!(
                "Najm Kernel: /bin/fstest is not in the boot archive - skipping the filesystem \
                 syscall tests (set USERLAND_FSTEST_PATH when building the image)"
            );
            None
        }
    };

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
    selftest::check(
        "kernel alive after Ring 3",
        arch::x86_64::interrupts::timer_ticks() >= ticks_before + 3
            && post_exit_check == [100, 101, 102, 103, 104],
        format_args!(
            "timer still ticking ({}) and heap still working ({:?}) after two user programs \
             ran and died",
            arch::x86_64::interrupts::timer_ticks(),
            post_exit_check
        ),
    );

    // Hand the CPU to the scheduler and take it back once every task has
    // finished. This used to be `sched::task::start()`, which never
    // returned - so nothing could run after the tasks, and the boot had
    // no ending to report. See `run_until_idle` for why that changed.
    // The scheduling-class test: one realtime task that measures its own
    // worst-case wait, against three background tasks that never yield.
    // Spawned last so they queue behind everything else, which is also
    // the least favourable starting position for the realtime task - if
    // its latency bound holds from the back of a full queue, it holds.
    sched::task::spawn_in_class(task_latency_probe, sched::class::SchedClass::Realtime);
    for _ in 0..3 {
        sched::task::spawn_in_class(task_background_hog, sched::class::SchedClass::Background);
    }

    serial_println!("Najm Kernel: handing the CPU to the scheduler");
    sched::task::run_until_idle();

    // Two independent measurements of the same property, which is the
    // point: the probe timed itself, and the scheduler recorded what it
    // dispatched. Either alone could be wrong in a way that flattered the
    // result; agreeing is evidence.
    let realtime_gap = REALTIME_MAX_GAP.load(Ordering::SeqCst);
    let realtime_gap_ms = realtime_gap * 1000 / arch::x86_64::interrupts::TIMER_HZ;
    selftest::check(
        "realtime latency budget",
        realtime_gap <= sched::class::REALTIME_LATENCY_BUDGET_TICKS,
        format_args!(
            "the realtime task's worst wait between turns was {} tick(s) ({} ms) against a budget \
             of {} ({} ms), while three background tasks spun without yielding and a Gaming Realm \
             process shared the realtime class",
            realtime_gap,
            realtime_gap_ms,
            sched::class::REALTIME_LATENCY_BUDGET_TICKS,
            sched::class::REALTIME_LATENCY_BUDGET_TICKS * 1000
                / arch::x86_64::interrupts::TIMER_HZ
        ),
    );

    let stats = sched::task::class_stats();
    for (class, stat) in stats {
        serial_println!(
            "Najm Kernel: scheduler class {:>10} - {} dispatches, worst wait {} tick(s), {} \
             anti-starvation promotions",
            class.name(),
            stat.dispatches,
            stat.max_wait_ticks,
            stat.promotions
        );
    }

    // The other half of the policy, and the one that is easy to leave
    // untested: strict priority alone lets a busy Realtime Realm freeze
    // everything else forever. ARCHITECTURE.md rejects that explicitly.
    // A non-zero promotion count is the aging rule actually rescuing a
    // starved task, not merely being present in the source.
    let background = stats[0].1;
    selftest::check(
        "background work is not starved",
        background.promotions > 0 && background.dispatches > 0,
        format_args!(
            "background tasks were promoted past the realtime task {} time(s) after waiting, and \
             ran {} time(s) in total - deprioritized without being frozen",
            background.promotions, background.dispatches
        ),
    );

    // Both processes must have run to completion, in their own address
    // spaces, at the same virtual addresses.
    let first_exit = process::exit_status(first_pid);
    let second_exit = process::exit_status(second_pid);
    let expected = Some(arch::x86_64::usermode::ProgramExit::Exited(7));
    selftest::check(
        "concurrent processes",
        first_exit == expected && second_exit == expected,
        format_args!(
            "two processes both loaded at {:#x} in separate address spaces exited {:?} and {:?} \
             (expected {:?} each)",
            mm::layout::USER_IMAGE_BASE,
            first_exit,
            second_exit,
            expected
        ),
    );

    // The headline claim of this milestone, checked rather than inferred.
    // ARCHITECTURE.md section 4 recorded "a Ring 3 program cannot
    // currently be preempted" as a real limitation; this is the evidence
    // that it no longer holds. A zero here would mean user programs are
    // still running to completion uninterrupted - which would look
    // identical in every other respect, since they are short.
    selftest::check(
        "Ring 3 preemption",
        arch::x86_64::interrupts::ring3_preemptions() > 0,
        format_args!(
            "the timer took the CPU away from a program executing at Ring 3 {} times",
            arch::x86_64::interrupts::ring3_preemptions()
        ),
    );

    // And their memory must have come back. This is the check that makes
    // "address spaces are torn down" a fact rather than a claim: the
    // frame pool was empty before the processes were built, and every
    // frame in it now was returned by an `AddressSpace::drop`.
    let frames_free_after = mm::frame_pool::stats().0;
    selftest::check(
        "process memory reclaimed",
        frames_free_after > frames_free_before,
        format_args!(
            "the frame pool went from {} free frames to {} after both processes exited - their \
             pages, stacks and page tables were all returned",
            frames_free_before, frames_free_after
        ),
    );

    // The trusted-path checks. These are the ones that matter most in
    // this whole file, because a trusted path that is merely *drawn* and
    // a trusted path that is *protected* look identical on screen.
    if graphics::compositor::stats().1 > 0 {
        // Threat 1 and 4 (ARCHITECTURE.md 2d): no surface may be placed
        // over the reserved strip, in any mode - including the Gaming
        // Realm's exclusive fullscreen, which is precisely where a
        // reserved region is most inconvenient and most necessary.
        selftest::check(
            "trust bar is unreachable by any surface",
            !graphics::compositor::any_surface_overlaps_trust_bar(),
            format_args!(
                "no surface's placement intersects the top {} pixels, which the compositor \
                 reserves for the Core-drawn trust indicator",
                graphics::compositor::TRUST_BAR_HEIGHT
            ),
        );

        // Threat 2: the indicator's contents come from kernel state, and
        // this is checked by reading back what was *actually displayed*
        // rather than what the compositor believes it drew. The
        // difference between those two is exactly where a trusted path
        // fails, so the self-test looks at the framebuffer itself.
        let signature = graphics::compositor::signature_colours();
        let mut signature_matches = true;
        let mut mismatch = 0;
        for (index, expected) in signature.iter().enumerate() {
            let Some((x, y)) = graphics::compositor::signature_block_origin(index) else {
                signature_matches = false;
                break;
            };
            match graphics::compositor::read_pixel(x, y) {
                // Compared with a tolerance rather than exactly: a
                // framebuffer with fewer than 8 bits per channel
                // quantizes on write, so an exact comparison would fail
                // on hardware where the pixel is perfectly correct.
                Some((r, g, b)) => {
                    let close = |a: u8, b: u8| a.abs_diff(b) <= 8;
                    if !(close(r, expected.r) && close(g, expected.g) && close(b, expected.b)) {
                        signature_matches = false;
                        mismatch = index;
                        break;
                    }
                }
                None => {
                    signature_matches = false;
                    break;
                }
            }
        }
        selftest::check(
            "trust bar signature is drawn from Core state",
            signature_matches,
            format_args!(
                "all {} per-boot signature blocks read back from the framebuffer match the \
                 values the kernel generated (first mismatch at block {})",
                signature.len(),
                mismatch
            ),
        );
    }

    if let Some(pid) = gui_pid {
        selftest::check(
            "compositor surfaces",
            process::exit_status(pid)
                == Some(arch::x86_64::usermode::ProgramExit::Exited(23)),
            format_args!(
                "a Gaming Realm process created a fullscreen surface, drew a frame, had a \
                 wrong-sized frame and a surface it does not own both refused, and exited {:?}",
                process::exit_status(pid)
            ),
        );
    }

    if let Some(pid) = fstest_pid {
        selftest::check(
            "filesystem syscalls",
            process::exit_status(pid)
                == Some(arch::x86_64::usermode::ProgramExit::Exited(11)),
            format_args!(
                "a second, different binary loaded by path exercised open/read/seek/readdir/stat \
                 and every refusal check, exiting {:?}",
                process::exit_status(pid)
            ),
        );
    }

    for (pid, name, state) in process::snapshot() {
        serial_println!("Najm Kernel: process {} ({}) - {:?}", pid, name, state);
    }
    selftest::check(
        "preemption",
        PREEMPTIONS_OBSERVED.load(Ordering::SeqCst) > 0,
        format_args!(
            "{} task iterations ran while a task that never calls yield_now() held the CPU",
            PREEMPTIONS_OBSERVED.load(Ordering::SeqCst)
        ),
    );
    selftest::check(
        "scheduler drained",
        sched::task::task_count() == 0,
        format_args!(
            "every spawned task ran to completion and exited; {} remain queued",
            sched::task::task_count()
        ),
    );

    epilogue()
}

/// The end of a boot: report the verdict, then stop.
///
/// Split out of `kernel_main` because it is the one part that behaves
/// differently on real hardware than under the emulator, and that
/// difference should be readable in one place rather than inferred. Under
/// QEMU with `-device isa-debug-exit` the machine terminates with an exit
/// code `scripts/boot-test.sh` interprets. Anywhere else the port write
/// does nothing and control falls through to `halt_loop`, which is the
/// correct behaviour for a physical machine: finishing a self-test is not
/// a reason to power off.
fn epilogue() -> ! {
    let (surfaces, frames, rejected_commits) = graphics::compositor::stats();
    serial_println!(
        "Najm Kernel: compositor - {} surface(s) live, {} frame(s) presented, {} commit(s) \
         rejected",
        surfaces,
        frames,
        rejected_commits
    );

    let (queued, dropped) = drivers::input::stats();
    let (pointer_x, pointer_y) = drivers::input::pointer_position();
    serial_println!(
        "Najm Kernel: input - {} event(s) queued, {} dropped, pointer at ({}, {})",
        queued,
        dropped,
        pointer_x,
        pointer_y
    );


    serial_println!(
        "Najm Kernel: {} syscalls dispatched, {} timer ticks ({} ms of uptime)",
        syscall::count(),
        arch::x86_64::interrupts::timer_ticks(),
        arch::x86_64::interrupts::uptime_ms()
    );

    let (heap_used, heap_free) = mm::allocator::heap_stats();
    let (stacks_live, stacks_ever, stack_capacity) = mm::kstack::stats();
    serial_println!(
        "Najm Kernel: heap at end of boot - {} KiB used, {} KiB free; kernel stacks - {} live, \
         {} slots ever used of {}",
        heap_used / 1024,
        heap_free / 1024,
        stacks_live,
        stacks_ever,
        stack_capacity
    );

    let all_passed = selftest::report();

    drivers::qemu::exit(if all_passed {
        drivers::qemu::ExitCode::Success
    } else {
        drivers::qemu::ExitCode::Failed
    });

    serial_println!(
        "Najm Kernel: no debug-exit device responded (this is real hardware, not QEMU) - halting"
    );
    halt_loop()
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

    selftest::check(
        what,
        exit == expected,
        format_args!(
            "ended with {:?} ({:?} is the outcome this payload exists to prove)",
            exit, expected
        ),
    );
}

/// Set while `task_spinner` is inside its non-yielding busy loop.
///
/// This is what turns the preemption test from something a human reads
/// off a log into something the kernel checks itself. Before, the
/// evidence for preemption was "do `[Task A]` lines appear between the
/// spinner's two messages?" - a real proof, but one that only exists in
/// the eye of whoever is reading. Now A, B and C each look at this flag
/// when they run: if it is set, the only way they could be executing is
/// that something took the CPU away from a task that never offered it.
static SPINNER_ACTIVE: AtomicBool = AtomicBool::new(false);

/// How many times a task observed itself running while `SPINNER_ACTIVE`
/// was set. Any value above zero is preemption; zero means the scheduler
/// silently degraded to cooperative-only.
static PREEMPTIONS_OBSERVED: AtomicU32 = AtomicU32::new(0);

/// Records that this task is running, and whether it did so while the
/// spinner held the CPU.
fn note_scheduled(who: &str, iteration: u32) {
    let preempted_the_spinner = SPINNER_ACTIVE.load(Ordering::SeqCst);
    if preempted_the_spinner {
        PREEMPTIONS_OBSERVED.fetch_add(1, Ordering::SeqCst);
    }
    serial_println!(
        "[{}] iteration {}{}",
        who,
        iteration,
        if preempted_the_spinner {
            " (running while the spinner never yielded - this line is preemption)"
        } else {
            ""
        }
    );
}

/// One of three test tasks proving the scheduler actually switches
/// between independent stacks rather than just running sequentially. See
/// `task_b`, `task_c`, and the call site in `kernel_main` for the full
/// picture.
extern "C" fn task_a() -> ! {
    for i in 0..3 {
        note_scheduled("Task A", i);
        sched::task::yield_now();
    }
    // `exit_task`, not `halt_loop`. A parked task stays in the ready
    // queue forever, gets scheduled, and burns a slice doing nothing -
    // and, more importantly, means the scheduler can never observe that
    // everything finished, which is what `run_until_idle` needs in order
    // to hand control back for the boot summary.
    sched::task::exit_task();
}

/// See `task_a` - identical in every respect except which letter it
/// prints, specifically so the interleaving between the two is the only
/// variable being demonstrated.
extern "C" fn task_b() -> ! {
    for i in 0..3 {
        note_scheduled("Task B", i);
        sched::task::yield_now();
    }
    sched::task::exit_task();
}

/// See `task_a` and `task_b` - a third, identically-structured task
/// specifically to prove round-robin ordering holds for more than a
/// single pair (see the comment at the `task::spawn` call sites in
/// `kernel_main`).
extern "C" fn task_c() -> ! {
    for i in 0..3 {
        note_scheduled("Task C", i);
        sched::task::yield_now();
    }
    sched::task::exit_task();
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

    SPINNER_ACTIVE.store(true, Ordering::SeqCst);
    while arch::x86_64::interrupts::timer_ticks() < started_at + SPIN_TICKS {
        core::hint::spin_loop();
    }
    SPINNER_ACTIVE.store(false, Ordering::SeqCst);

    serial_println!(
        "[Spinner] busy loop finished after {} ticks",
        arch::x86_64::interrupts::timer_ticks() - started_at
    );
    sched::task::exit_task();
}

/// How many ticks the realtime latency probe runs for.
///
/// Deliberately longer than `class::STARVATION_LIMIT_TICKS`, so the
/// anti-starvation promotion is actually exercised rather than merely
/// present. A probe that finished before the limit would leave the most
/// important half of the policy - that a busy Realtime Realm does not
/// freeze everything else - completely untested, and the boot log would
/// look identical either way.
const LATENCY_PROBE_TICKS: u64 = sched::class::STARVATION_LIMIT_TICKS + 20;

/// The largest gap, in ticks, the realtime probe ever observed between
/// two consecutive turns on the CPU.
///
/// Measured by the task itself rather than read out of the scheduler's
/// own bookkeeping, on purpose: two independent measurements of the same
/// property agreeing is evidence, whereas a scheduler grading its own
/// homework is not.
static REALTIME_MAX_GAP: AtomicU64 = AtomicU64::new(0);

/// Set when the latency probe finishes, so the background hogs know to
/// stop. Without it they would spin until the machine was turned off, and
/// the boot would never reach its summary.
static LATENCY_TEST_DONE: AtomicBool = AtomicBool::new(false);

/// A realtime task that measures how long it is ever kept waiting.
///
/// It never sleeps and never blocks - it busy-waits for the tick counter
/// to move, which means it is always ready to run. The question it
/// answers is therefore exactly the one a game asks: "when I am ready,
/// how long until I get the CPU?" Anything above a tick or two would mean
/// the Realtime class is not delivering the bound `sched::class`
/// documents.
extern "C" fn task_latency_probe() -> ! {
    sched::task::set_current_class(sched::class::SchedClass::Realtime);

    let started = arch::x86_64::interrupts::timer_ticks();
    let mut last_seen = started;

    while arch::x86_64::interrupts::timer_ticks() < started + LATENCY_PROBE_TICKS {
        let now = arch::x86_64::interrupts::timer_ticks();
        if now > last_seen {
            let gap = now - last_seen;
            REALTIME_MAX_GAP.fetch_max(gap, Ordering::SeqCst);
            last_seen = now;
        }
        core::hint::spin_loop();
    }

    LATENCY_TEST_DONE.store(true, Ordering::SeqCst);
    serial_println!(
        "[Latency probe] realtime task finished after {} ticks - worst gap between turns was {} \
         tick(s)",
        LATENCY_PROBE_TICKS,
        REALTIME_MAX_GAP.load(Ordering::SeqCst)
    );
    sched::task::exit_task();
}

/// A background task that wants all the CPU it can get and never yields.
///
/// Three of these run alongside the realtime probe. They are the
/// contention: without them the probe would be the only runnable task and
/// its latency would be trivially zero, which would prove nothing at all.
extern "C" fn task_background_hog() -> ! {
    sched::task::set_current_class(sched::class::SchedClass::Background);

    // A hard tick limit as well as the flag, so a bug in the probe cannot
    // turn these into an infinite loop that hangs the boot. A test that
    // can hang the machine it is testing is worse than no test.
    let started = arch::x86_64::interrupts::timer_ticks();
    let deadline = started + LATENCY_PROBE_TICKS * 3;

    while !LATENCY_TEST_DONE.load(Ordering::SeqCst)
        && arch::x86_64::interrupts::timer_ticks() < deadline
    {
        core::hint::spin_loop();
    }

    sched::task::exit_task();
}

// `paint_framebuffer` used to live here: it filled the screen with a
// solid colour, resolving the hardware's channel order so the fill was
// the colour it claimed to be. It has been replaced by the graphics stack
// in `crate::graphics`, which does the same format resolution properly
// and then draws something meaningful on top of it.
//
// The one thing worth carrying forward is why the format resolution
// existed at all: the original version assumed an RGB byte order, and on
// the test hardware the bootloader reported BGR, so "blue" came out
// orange. That is now handled in `graphics::framebuffer::set_pixel` for
// every pixel rather than once for a fill.

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
