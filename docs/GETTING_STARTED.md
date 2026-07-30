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

15. ~~A higher-half kernel and the address-space split.~~ Done - see
    `abi/src/layout.rs`. Every kernel mapping moved above
    `0xffff_8000_0000_0000`, so the entire lower half belongs to user
    processes. This was the prerequisite for everything below it. Also
    introduced `abi/` (the shared kernel/userland contract, replacing
    three copies of the syscall numbers) and `scripts/boot-test.sh`,
    which makes `make test` a real pass/fail rather than something a
    human reads.
16. ~~NX, W^X, SMEP/SMAP/UMIP, and guard pages.~~ Done - see
    `kernel/src/arch/x86_64/cpu.rs`. The ELF loader derives page
    permissions from `p_flags` and refuses any segment asking for write
    and execute together; kernel stacks moved into `mm::kstack`, where
    each has an unmapped page beneath it. Proven by `run_nx_test`, which
    jumps into a `NO_EXECUTE` page from Ring 3 and requires a fault.
17. ~~Per-process address spaces.~~ Done - see
    `kernel/src/mm/address_space.rs`. Each process gets a PML4 whose
    higher half is copied from the kernel's and whose lower half is its
    own. Closes three separately-documented gaps at once: Realm memory
    isolation, ownership (not merely privilege) on syscall pointers, and
    reclaiming a terminated program's memory.
18. ~~Processes, and Ring 3 preemption.~~ Done - see
    `kernel/src/process.rs`. A process is an address space plus a kernel
    stack plus a scheduler task, and being a task is what makes it
    preemptible. ARCHITECTURE.md section 4's recorded limitation - that a
    Ring 3 program could not be preempted - no longer holds.
19. ~~A filesystem.~~ Done - see `kernel/src/fs.rs` and
    `abi/src/archive.rs`. The ramdisk is a NAR archive rather than one
    bare binary, served zero-copy, with `open`/`read`/`close`/`seek`/
    `stat`/`readdir` syscalls. Paths containing `..` are rejected rather
    than normalized.
20. ~~Realm scheduling classes.~~ Done - see `kernel/src/sched/class.rs`.
    Three classes, each with a quantum as well as a priority, plus
    rate-limited anti-starvation promotion. The realtime latency is
    *measured* on every boot and asserted against a budget.
21. ~~Device drivers.~~ Done - PCI enumeration, the CMOS real-time clock,
    and an input event queue with a PS/2 mouse. See `kernel/src/drivers/`.
22. ~~The compositor and the trusted path.~~ Done - see
    `kernel/src/graphics/`. Implements ARCHITECTURE.md 2c and 2d,
    including the reserved strip no Realm can address in any mode, the
    per-boot signature drawn from Core state, and a theme system that can
    change the trust bar's colours and nothing else.
23. ~~Mirage: running a Windows binary.~~ Done - see
    `kernel/src/mirage/`. A PE32+ image is relocated, has its imports
    bound to ABI-translation thunks, and runs at Ring 3. Four Win32
    functions, against Wine's tens of thousands - see that module's docs
    for exactly where the line is.
24. ~~Capability-gated IPC.~~ Done - see `kernel/src/ipc.rs`. Named
    ports carrying copied messages, with creating a port and connecting
    to one gated as separate rights - creating claims a name in a global
    namespace, which is how a service gets impersonated. Bounded queues
    that refuse rather than block or drop, and ports reclaimed when their
    owner exits, without which restarting a service would fail.
25. ~~Window layout modes.~~ Done - see `graphics::compositor::LayoutMode`.
    Two modes on one desktop: **floating**, where windows have positions
    and may overlap, and **tiling**, which packs them to fill the screen
    with no overlap using the dwindle split Hyprland defaults to. **F1**
    toggles. It is the same compositor, the same trust bar and the same
    Realms in both - tiling changes where windows go, not what they are.
    A Gaming Realm's exclusive fullscreen ignores both and still cannot
    reach the trust strip.
26. ~~Najm Store package verification.~~ Done - see `kernel/src/store.rs`
    and `docs/APP_SDK.md`. SHA-256 integrity checking against FIPS
    180-4's own vectors, and ARCHITECTURE.md 2e's Realm assignment
    policy: elevation is a credential, not a declaration, and the
    unimplemented signature verifier fails *closed*.

### What one boot now proves

`make test` boots the system headless, runs **37 self-tests**, and exits
with a verdict. Every one of them is a live check against real hardware
behaviour rather than a claim in a comment:

- The address-space split holds, and the bootloader's leftover identity
  mapping is gone.
- NX, SMEP, SMAP and UMIP are active, and NX is *proven* by a Ring 3 jump
  into a non-executable page faulting.
- A kernel stack's guard page is genuinely unmapped, checked by walking
  the page tables.
- Two processes run from the same image at the same virtual address in
  separate address spaces - impossible before per-process page tables -
  and their memory comes back when they exit.
- The timer preempts a program running at Ring 3, counted rather than
  inferred from output ordering.
- A realtime task's worst wait is measured twice independently and
  checked against a budget, while background tasks are shown to be
  deprioritized without being frozen.
- A second, different binary loaded *by path* exercises the filesystem,
  and every refusal - a missing file, a `..` in a path, a write to a
  read-only filesystem, a directory read as a file - is checked for the
  specific error it should produce.
- The compositor's reserved strip is unreachable by any surface, and the
  trust signature is verified by reading pixels back *out* of the
  framebuffer.
- Tiling produces three non-overlapping rectangles, all below the trust
  strip, and the toggle works in both directions.
- A Windows PE binary runs and exits with a status that only survives if
  relocation, import binding and calling-convention translation all
  worked.
- A tampered package is rejected, and every package requesting the Vault
  Realm is placed in Home.

Any line containing `FAILURE`, `MISALIGNED`, `PANIC` or `BAD:` is a real
problem. That vocabulary is reserved - code that *correctly rejects*
something must not use it, or a passing test reads as a broken kernel.

### What comes next

The gaps that block the most, in the order they block it:

1. **Persistence.** The filesystem is read-only and lives in the boot
   image. Nothing any program writes survives a reboot, because there is
   nowhere to write it. This needs a disk driver (AHCI) and a writable
   filesystem, and it blocks the Store, the app SDK and ordinary use
   equally.
2. **Blocking IPC.** Ports work (`kernel/src/ipc.rs`), but `recv` on an
   empty queue returns `EAGAIN` rather than sleeping, because there is no
   wait queue and no way to wake a task on an event. Clients poll, which
   is correct and wasteful. Fixing it means a sleep/wake primitive in the
   scheduler - and that is also what `sleep_ticks` and a faithful
   `Sleep()` in Mirage need, so it unblocks three things at once.
3. **Ed25519**, without which no package can ever be elevated to Vault.
4. **Mirage's API surface.** Four functions. See `docs/APP_SDK.md` for
   why this is both the highest-value and the longest-running item.
5. **SMP.** Everything here is single-core, and several locks are correct
   only because of it - `mm::allocator`'s interrupts-off critical section
   in particular buys nothing against a second core.
