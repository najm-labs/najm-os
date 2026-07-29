# Getting Started: Building & Booting Najm OS on Arch Linux

This guide is written specifically for your setup: **Arch Linux + Hyprland**,
on a **Ryzen 5 4600G / ASUS TUF B550M-PLUS GAMING WIFI II**. A couple of
steps below (the KVM/BIOS section especially) call out that hardware
directly, since virtualization behavior depends on it.

---

## 1. Install dependencies

```bash
sudo pacman -S --needed rustup base-devel qemu-full
```

- **rustup** — manages the Rust toolchain. Do **not** install `rust` from
  the `extra` repo alongside this; having both installed causes `PATH`
  conflicts between the two. If you already have `rust` installed via
  pacman, remove it first: `sudo pacman -R rust`.
- **qemu-full** — includes `qemu-system-x86_64` plus firmware packages
  (OVMF) you won't need yet for this milestone (we boot BIOS-style, not
  UEFI) but will want later.
- **base-devel** — provides the linker (`ld`) and other build essentials
  Cargo needs even for a freestanding target.

After installing rustup, initialize it once:

```bash
rustup default stable
```

You do **not** need to manually install a nightly toolchain or the
`x86_64-unknown-none` target — the `rust-toolchain.toml` file at the repo
root does that automatically the first time you build. rustup will detect
it and fetch what's needed.

---

## 2. Enable KVM acceleration (matters for your specific board)

QEMU works without hardware acceleration, but it's dramatically slower.
Your Ryzen 5 4600G supports AMD-V (AMD's virtualization extension, what KVM
calls "SVM"), but **on many ASUS B550 boards, SVM Mode ships disabled in
the UEFI by default.**

**Check whether it's already enabled:**

```bash
LC_ALL=C lscpu | grep -i virtualization
```

If you see `Virtualization: AMD-V`, it's enabled — skip to the next step.
If you see nothing, you need to enable it in the UEFI:

1. Reboot and enter the UEFI (Del key on most ASUS boards at boot).
2. Go to **Advanced Mode** (F7) → **Advanced** tab → **CPU Configuration**.
3. Find **SVM Mode** and set it to **Enabled**.
4. Save and exit (F10).

**Check the kernel module is loaded:**

```bash
lsmod | grep kvm_amd
```

If it's missing:

```bash
sudo modprobe kvm_amd
```

**Check `/dev/kvm` is accessible to your user:**

```bash
ls -l /dev/kvm
groups | grep kvm
```

If your user isn't in the `kvm` group:

```bash
sudo usermod -aG kvm $USER
```

Then **log out and back in** (or reboot) for the group change to take
effect — this is a common gotcha, a new terminal alone isn't enough.

---

## 3. Build and boot

From the repo root:

```bash
make run
```

This does four things, in order:

1. Builds the kernel (`kernel/`) for the freestanding `x86_64-unknown-none`
   target. First run will be slow — rustup is fetching the nightly
   toolchain and precompiled `core`/`alloc` for that target.
2. Builds the userland test program (`userland/hello/`) for the same
   target. It's a separate crate, and a separate `make` target
   (`make userland`), specifically so a failure there is reported as a
   userland failure rather than looking like a kernel one.
3. Packages the compiled kernel binary into a bootable BIOS disk image,
   with the userland binary attached as a ramdisk (`runner/build.rs`,
   using the `bootloader` crate). Both paths are passed in from the
   Makefile via `KERNEL_PATH` / `USERLAND_PATH` rather than having the
   build script invoke `cargo` itself, which would deadlock on the
   package-cache lock.
4. Launches `qemu-system-x86_64` pointed at that image, with KVM
   acceleration enabled.

### What success looks like

A QEMU window opens — under Hyprland this appears as a normal floating
window, no special Wayland configuration needed — and fills with a solid
blue-ish color. The window is no longer where the interesting output is,
though: **the real result is the serial log printed to the terminal you
ran `make run` from.** Every milestone's self-test reports there, in
order, ending with the scheduler's tasks interleaving.

Worth reading for specifically, since each line is a test that could
fail:

- `resumed after breakpoint exception` — the IDT works.
- `capability system confirmed working` and `TimerRead revocation
  confirmed working` — a revoked capability is genuinely refused, not
  merely nominally revoked.
- `SUPERVISOR RESUMED ... GeneralProtectionFault` — a Ring 3 program
  executed a privileged instruction, was terminated on its own, and the
  kernel kept running.
- `[userland] ...` lines — a real compiled Rust program is running at
  Ring 3 and making syscalls.
- `syscall write REJECTED` — the kernel refused to read its own heap on
  a user program's behalf.
- `SUPERVISOR RESUMED ... Exited(7)` — that program exited cleanly and
  the kernel got control back.
- `[Task A] iteration 0` appearing *between* the `[Spinner]` start and
  finish lines — preemption. The spinner never yields, so nothing else
  could have run otherwise.

Any line containing `FAILURE` or `MISALIGNED` is a real problem, not
noise — the self-tests are written to say so loudly rather than to pass
quietly.

### If something goes wrong

**QEMU window flashes and immediately closes / reboots in a loop:**
This is a triple fault — the CPU hit an unrecoverable error early enough
that there's no handler yet (we haven't set up interrupt handling). The
`-no-reboot` flag in `runner/src/main.rs` should turn this into a hard
stop instead of a loop; if you still see looping, run with QEMU's
interrupt logging to see what happened:

```bash
KERNEL_PATH=$(pwd)/kernel/target/x86_64-unknown-none/debug/najm-kernel \
  cargo run --manifest-path runner/Cargo.toml -- \
  2>&1 | tee /tmp/qemu.log
```

(Full `-d int` interrupt tracing can be added to `runner/src/main.rs`
temporarily if needed — it's noisy, so it's not on by default.)

**"failed to launch qemu-system-x86_64":**
Check it's actually installed: `which qemu-system-x86_64`. If missing,
re-run step 1.

**Build fails fetching crates:**
`bootloader_api` and `bootloader` pull in a handful of transitive
dependencies from crates.io on first build. This needs network access;
if you're behind a restrictive firewall/VPN, that's the first thing to
check.

---

## 4. Iterating

- `make check` — fast type-check only, no image build, no QEMU. Use this
  constantly while writing kernel code; it's much faster than a full run.
- `make userland` — builds just the Ring 3 test program.
- `make run-no-kvm` — boots without `-enable-kvm`, using QEMU's software
  emulation (TCG) instead. Useful to sanity-check that a bug isn't
  KVM-specific.
- `make clean` — wipes all three crates' `target/` directories.

### Capturing the serial log without a QEMU window

For scripted or repeated runs it's easier to read the serial output from
a file than from a terminal sharing stdout with QEMU. Note that
`-serial stdio` does **not** work together with `-display none` — it
produces no output at all, which looks exactly like a kernel that
crashed before printing. Use `-serial file:` instead:

```bash
qemu-system-x86_64 \
  -drive format=raw,file=$(find runner/target/debug/build -name najm-bios.img | head -1) \
  -serial file:/tmp/najm-serial.log \
  -display none -no-reboot -m 256M -enable-kvm
```

The kernel never shuts the machine down on its own, so run this under
`timeout 20` and read the log afterwards. Give each run its own log path:
two QEMU instances writing the same `-serial file:` target silently
truncate each other's output, which is another failure that looks like a
dead kernel.

### Editor setup (optional but recommended)

If you're using an editor with `rust-analyzer` (Neovim + a Rust LSP config
is a common Hyprland-adjacent setup), point it at the kernel's target
explicitly so it doesn't try to type-check `kernel/` against your host
platform. Add to your rust-analyzer config:

```json
{
  "rust-analyzer.cargo.target": "x86_64-unknown-none",
  "rust-analyzer.check.command": "check"
}
```

---

## What comes after this milestone

This gets you a booting "hello, colored screen" kernel — deliberately the
smallest possible working slice. The next milestones, in order (see
`ARCHITECTURE.md`):

1. ~~A serial driver, so the kernel can print debug output to the terminal
   instead of only proving life via a solid color.~~ Done — see
   `kernel/src/drivers/serial.rs` and the `serial_println!` macro.
2. ~~A proper panic handler that reports *why* it panicked over serial,
   instead of just halting silently.~~ Done, same milestone as above.
3. ~~Interrupt handling (IDT setup) — required before anything resembling
   a scheduler is possible.~~ Done — see `kernel/src/arch/x86_64/gdt.rs` and
   `kernel/src/arch/x86_64/interrupts.rs`. CPU exceptions (breakpoint, page fault,
   general protection fault, double fault) are now caught and reported
   over serial instead of silently triple-faulting the machine.
4. ~~Memory management (a physical frame allocator, then a heap), which
   the Realm isolation primitive in ARCHITECTURE.md ultimately depends
   on.~~ Done — see `kernel/src/mm/memory.rs` and `kernel/src/mm/allocator.rs`.
   `Box`, `Vec`, and `String` all work kernel-wide now.
5. ~~Hardware interrupts (PIC remapping, timer, keyboard) — the mechanism
   a preemptive scheduler will eventually hook into.~~ Done — see the PIC
   setup in `kernel/src/arch/x86_64/interrupts.rs`. The timer ticks silently in the
   background; type into the QEMU window after boot to see the keyboard
   interrupt handler echo characters over serial.
6. ~~A first scheduler.~~ Done, in the cooperative-only sense — see
   `kernel/src/sched/task.rs`. Two test tasks alternate execution via
   hand-written x86_64 context switching. This is deliberately a stepping
   stone, not the final design: nothing preempts a task yet, it only ever
   gives up the CPU by calling `yield_now()` itself.
7. ~~A first capability token primitive.~~ Done — see
   `kernel/src/security/capability.rs` and its live demonstration against
   `serial::write_with_capability` in `kernel_main`. A token can be
   issued, delegated, and revoked; revocation is proven to actually block
   use afterward, not just assumed correct.
8. ~~Connect the scheduler and the capability primitive.~~ Done — see
   `kernel/src/realm.rs`. Tasks now carry their own, distinct capability
   profile on a heap-allocated context, passed through the scheduler via
   a small assembly trampoline (`Task::new_with_context` in
   `kernel/src/sched/task.rs`) rather than reaching for values in a `static`.
   Three Realm-flavored tasks (Gaming, Vault, Home) each get a different
   capability profile, matching ARCHITECTURE.md's description of Vault
   having restricted introspection access.
9. ~~A first proof that Ring 3 (user-mode execution) works.~~ Done — see
   `kernel/src/arch/x86_64/usermode.rs`. Three hand-written machine code bytes run at
   Ring 3 on a dedicated user-accessible page: a software-interrupt
   syscall through the IDT, then a privileged instruction that must fault
   - proving Ring 3 restriction is real CPU enforcement, not an assumed
   property. Still not a process model: no ELF loader, no filesystem, no
   way yet to run anything other than this one hand-written test payload.
10. ~~A first ELF64 loader.~~ Done — see `kernel/src/loader.rs`. The
    `runner` crate's build script (`runner/build.rs`) hand-builds a
    minimal ELF64 binary and attaches it to the boot image as a ramdisk;
    the kernel parses it, maps its `PT_LOAD` segments as user-accessible
    pages, and transitions to Ring 3 at its declared entry point - the
    same underlying mechanism milestone 9 proved, now driven by a real
    (if minimal) ELF file.
11. ~~A return-to-supervisor path.~~ Done — see
    `usermode::run_program` and `interrupts::end_or_halt_after_fault`.
    Entering Ring 3 used to be a one-way door: both transitions were
    `-> !`, so a faulting user program had nowhere to hand control back
    to and the fault handlers halted the *entire machine* regardless of
    whether the kernel or a mere program had misbehaved. Now a Ring 0
    resume point is saved before the transition (the same save-registers-
    and-RSP trick `sched/task.rs` already used), and both the `exit`
    syscall and a Ring 3 fault return through it. A Ring 0 fault still
    halts, because that one genuinely is unrecoverable. Two Ring 3
    programs now run and die in a single boot with the kernel alive
    afterwards.
12. ~~Real syscall arguments.~~ Done — see `interrupts::syscall_entry`
    and `syscall_dispatch`. `int 0x80` previously did one fixed thing and
    ignored its registers; it now takes a syscall number in RAX and up to
    three arguments in RDI/RSI/RDX. This required replacing the
    `extern "x86-interrupt"` handler with a hand-written naked entry stub,
    because that calling convention makes no guarantee the caller's
    registers survive the compiler's prologue. `write` and `exit` are
    implemented. Every user pointer is validated against the page tables
    before the kernel dereferences it (see ARCHITECTURE.md section 3b) -
    the test program deliberately hands the kernel a pointer to its own
    heap and is refused. The entry stub's stack alignment is reported in
    the boot log rather than merely asserted in a comment.
13. ~~A real userland toolchain.~~ Done — see `userland/hello/`. A
    `no_std`, `no_main` Rust crate, linked by `linker.ld` into a
    fixed-address non-PIE `ET_EXEC` binary with exactly one `PT_LOAD`
    segment (both constraints come from what `loader.rs` supports), built
    by the Makefile and handed to `runner`'s build script via
    `USERLAND_PATH`. It prints through the `write` syscall, reads its own
    `.rodata` and `.bss`, gets a kernel pointer refused, and exits with a
    status the kernel reports back. The hand-encoded ELFs in
    `runner/build.rs` are kept as a fallback, and remain the only thing
    covering the loader's `.bss` zero-fill branch - see the note in
    `linker.ld`.
14. ~~Preemption.~~ Done — see `sched::task::preempt` and the timer
    handler. A task that never calls `yield_now()` is now switched away
    from anyway. `yield_now` and the cooperative path still work exactly
    as before; preemption is an addition, not a replacement. RFLAGS
    became part of a task's saved context (otherwise a resumed task would
    inherit the *switcher's* interrupt state, and a new task would start
    with interrupts masked and never be preemptible), and every
    acquisition of the scheduler lock outside an interrupt handler now
    runs with interrupts disabled, since a tick arriving mid-critical-
    section would deadlock against a lock holder that can never run
    again. A Ring 3 program still cannot be preempted - see
    ARCHITECTURE.md section 4 for why, and what it needs.

### What one boot now proves

`kernel_main` used to have several endings commented out, because only
one `-> !` call could be "the last thing that happens" per boot and
checking a different one meant editing the source. Now every self-test
above runs in sequence on every boot, unedited: the breakpoint and timer
checks, the heap, both capability demonstrations, the hand-written Ring 3
payload, the compiled userland program, a post-program health check that
the kernel is still genuinely alive, and finally the scheduler - which is
also the first time the three Realm-profile tasks actually *execute*
rather than merely being spawned.

Next up: a minimal filesystem (so programs can be loaded from something
richer than a single build-time ramdisk), separate address spaces per
Realm (which is simultaneously what allows reclaiming a terminated
program's memory, preempting Ring 3 code, and enforcing ownership rather
than mere privilege on syscall pointers), per-segment page permissions
and W^X in the ELF loader, and the Realm Assignment verification
ARCHITECTURE.md section 2e describes.
