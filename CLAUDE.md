# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Najm OS: a bare-metal x86_64 hybrid kernel in Rust (`#![no_std]`, `#![no_main]`), built around "Realms" — kernel-level isolated execution domains (Gaming / Vault / Home) with per-Realm capability sets and scheduler classes. `docs/ARCHITECTURE.md` is the design authority; read it before changing the capability model, scheduler, syscall boundary, or Realm shape. `docs/GETTING_STARTED.md` holds the numbered milestone list and is the running record of what actually works. `docs/APP_SDK.md` covers how applications are meant to be built and what the Store enforces.

## Commands

```bash
make test         # THE ONE THAT MATTERS: build, boot headless, run every self-test, exit with a verdict
make run          # build kernel + userland (debug) + package boot image + launch QEMU
make check        # fast cargo check of the kernel only — use constantly while iterating
make build        # compile the kernel, no QEMU
make userland     # compile the Ring 3 test program only
make run-release  # release profile (LTO), then QEMU
make run-no-kvm   # QEMU with software emulation (TCG) instead of -enable-kvm
make clean        # cleans all three crates' target/ dirs
```

Manual equivalent of `make run` (the `runner` build script *requires* `KERNEL_PATH` and does not build anything itself; `USERLAND_PATH` is optional — without it the ramdisk falls back to a hand-encoded ELF):

```bash
cargo build --manifest-path kernel/Cargo.toml --target x86_64-unknown-none
cargo build --manifest-path userland/hello/Cargo.toml --target x86_64-unknown-none
KERNEL_PATH=$(pwd)/kernel/target/x86_64-unknown-none/debug/najm-kernel \
USERLAND_PATH=$(pwd)/userland/hello/target/x86_64-unknown-none/debug/najm-hello \
  cargo run --manifest-path runner/Cargo.toml
```

**There is no `cargo test`, and there never will be** — no host to run on, no harness to link. Verification is live self-tests inside `kernel_main`, and `make test` is the entry point: it boots headless, the kernel counts its own checks via `crate::selftest`, prints a `SELF-TEST SUMMARY`, and shuts the machine down with a verdict through QEMU's `isa-debug-exit` device. Exit status is the answer; `scripts/boot-test.sh` also scans the log independently, so a check that printed a failure but forgot to count it still fails the run.

When adding a mechanism, add a self-test that would visibly fail if it were broken, and **prove the negative case**: a revoked capability must be *rejected*; the Ring 3 payload's `hlt` must *fault*; a `NO_EXECUTE` page must fault when jumped into; a tampered package must be *refused*. Several real bugs in this codebase were found only by a negative test — and one of them was a negative test that passed vacuously for a while, so check that a failing check can actually fail.

**`FAILURE`, `MISALIGNED`, `PANIC` and `BAD:` are reserved vocabulary.** The harness fails a run on sight of any of them. Code that *correctly rejects* something must not use those words, or a passing test reads as a broken kernel (see the comment in `kernel/src/store.rs` where exactly that happened).

To capture serial output headlessly, use `-serial file:<path>` — **`-serial stdio` silently produces nothing when combined with `-display none`**, which looks identical to a kernel that died before printing. Give each run a unique log path; concurrent QEMU instances writing the same file truncate each other. See the recipe in `docs/GETTING_STARTED.md`.

For rust-analyzer, set `"rust-analyzer.cargo.target": "x86_64-unknown-none"` or it type-checks `kernel/` against the host.

## Crate layout

`abi/` is the kernel/userland contract — syscall numbers, error codes, boundary structs, the virtual address map, and the boot archive format. It is dependency-free and compiled into the kernel, every userland program, *and* the runner's build script, so there is exactly one definition of each. `userland/najm-std/` wraps the syscall interface for userland programs. `kernel/` and the `userland/*` programs target bare-metal `x86_64-unknown-none`; `runner/` is an ordinary host binary. They are separate Cargo projects with separate `Cargo.lock` files on purpose (see the comments in `runner/Cargo.toml`) — the Makefile is what stitches them together. Both bare-metal crates are built *first* and their output paths passed to `runner`'s build script via env vars, rather than having that build script invoke `cargo` itself (nested cargo contends for the package-cache lock). `runner/build.rs` packages the kernel ELF into a bootable BIOS image and attaches the userland binary as a **ramdisk**; `runner/src/main.rs` just shells out to `qemu-system-x86_64`.

Note that Cargo discovers `.cargo/config.toml` from the **cwd**, not the manifest path — so `kernel/.cargo/config.toml` is ignored by repo-root `make` invocations, which is why the Makefile passes `--target` explicitly and why `userland/hello` puts its linker flags in `build.rs` instead of a config file.

## Version pinning — three pins that move together

`rust-toolchain.toml` (`nightly-2026-06-01`), `kernel/Cargo.toml`'s `x86_64 = "=0.15.2"` / `bootloader_api = "=0.11.15"`, and `runner/Cargo.toml`'s `bootloader = "=0.11.15"` are coupled. `x86_64` ≥ 0.15.3 implements `Step::forward_overflowing`/`backward_overflowing`, which only exist on newer nightlies — old nightly + new `x86_64` gives E0407, new nightly + old `x86_64` gives E0046. **Never bump one of these independently**; changing the toolchain channel means revisiting all the crate pins in the same commit. The exact-version pins exist specifically to stop a re-resolve from silently reintroducing the breakage.

## Kernel architecture

Modules are organized by subsystem, not milestone: `arch/x86_64` (GDT/TSS, IDT + PIC, syscall entry, Ring 3 transition — with `arch.rs` as the seam for a future `arch/aarch64`), `mm` (frame allocator + heap + user-pointer validation), `sched` (preemptive tasks), `security` (capabilities), `drivers` (serial). `realm.rs` and `loader.rs` sit at the top level because they cut *across* those subsystems.

Boot flow in `kernel_main`, in a fixed order — each step depends on the one before it, and the ordering constraints are the interesting part:

1. `gdt::init()` → `interrupts::init()`. GDT first: the double-fault handler's IST stack must exist in the TSS before the IDT referencing it loads. The PIT is programmed to 100 Hz before `sti`, so no tick arrives at the old rate.
2. `cpu::init()` — **before any page is mapped.** `NO_EXECUTE` is a reserved-bit violation unless `EFER.NXE` is set, so a heap mapped NX before this would fault on first touch. Every feature is CPUID-probed; enabling a CR4 bit the CPU lacks is a #GP at boot.
3. `memory::init` → `address_space::record_kernel_root()` → `allocator::init_heap()`. The kernel root is captured before any process exists, so "the kernel's address space" and "whatever is in CR3" can never be confused.
4. `clear_lower_half_mappings()` — drops the bootloader's identity-mapped context-switch stub, which would otherwise be dead executable code in every process forever. Then the address-space split is verified.
5. PCI, RTC, mouse; theme loaded from `/etc/theme.conf`; compositor initialized.
6. Boot-context Ring 3 self-tests: the hand-written payload (expects a GP fault) and the NX test (expects a page fault).
7. Mount the boot archive, verify `/apps/*.najm`, then spawn processes: two from `/bin/hello`, `/bin/gui` (Gaming), `/bin/fstest`, and `/bin/hello.exe` through Mirage.
8. `sched::task::run_until_idle()` — runs every task and **returns** when they have all exited, which is what makes an end-of-boot verdict possible. `start()` still exists as the one-way handoff a finished OS would use.
9. `epilogue()` — reports, then shuts down via `isa-debug-exit` (a no-op on real hardware, where it falls through to `halt_loop`).

Expected Ring 3 outcomes are asserted via `report_program_exit` — note a GP fault is the *pass* condition for the hand-written payload.

### Fixed virtual address map

Hardcoded, non-overlapping ranges. Any new fixed range must be checked against these:

**The map now lives in one place: `abi/src/layout.rs`.** Do not add a fixed address anywhere else — that file documents the rules, and the reason it exists is that scattered `const`s stopped being checkable once the address space acquired two halves with different ownership.

The split is load-bearing: **the kernel occupies the higher half (PML4 256-511) and nothing else does; every user process owns the lower half.** That is what makes an address space "allocate a PML4 and copy 256 entries", and `BOOTLOADER_CONFIG`'s `dynamic_range_start` is what puts the bootloader's own mappings above the line. A boot self-test counts the entries in each half and fails if any kernel mapping landed low.

Task stacks come from `mm::kstack`, not the heap — each is a slot in a dedicated virtual region with an **unmapped guard page** beneath it. A heap allocation cannot have one (the memory below it is another live allocation), so stack overflow used to corrupt something unrelated. TSS stacks use `gdt::AlignedStack` because a bare `[u8; N]` has alignment 1 and the syscall stub's `call` alignment is derived from RSP0.

### Capability model

`Capability<R>` in `security/capability.rs` is phantom-typed over uninhabited marker types (`SerialWrite`, `TimerRead`) — one marker per right. `issue()` is `pub(crate)`: that's the unforgeability boundary. Duplication is `derive()`, not `Clone`/`Copy`, so every delegation is grep-able. Revocation is by shared `id` in a global `BTreeSet`, so it's a *runtime* check and it revokes every derived copy at once — the documented, deliberate gap versus the compile-time guarantee that you can't call a gated function without presenting a token. Attenuation (a narrower derived right) is not implemented yet.

The pattern for gating something: add a `*_with_capability` wrapper taking `&Capability<R>` that checks `is_revoked()` and returns `Result<_, CapabilityError>` (see `drivers::serial::write_with_capability`, `interrupts::ticks_with_capability`). Prefer a required token parameter over a runtime permission lookup.

`realm.rs` gives each Realm *task* its own `RealmContext` carrying `Option<Capability<…>>` per right — a missing capability is an argument that *doesn't exist*, not a check that could be bypassed.

A Ring 3 **process** cannot hold a Rust value, so its rights are a kernel-side bitmask on `RealmProfile`, consulted by `syscall::require`. That is genuinely weaker than the typed tokens and `realm.rs` says so rather than blurring them: what keeps it honest is that the process never holds the mask, cannot present it, and cannot modify it.

ARCHITECTURE.md §2e's Realm Assignment verification **is** implemented, in `store.rs`: a package's manifest states what it *wants* and never what it *gets*. Signature verification is unimplemented and **fails closed**, so nothing can be elevated to Vault — an unfinished trust check must fail in that direction, and a self-test asserts it.

### Scheduler

Preemptive *and* cooperative: `yield_now()` for voluntary switches, `preempt()` from the timer handler for involuntary ones. Both go through `plan_switch` + `context_switch`. This is the riskiest code in the tree — bugs here are silent stack corruption, not compile errors.

- `context_switch` and `task_trampoline` are `#[unsafe(naked)]` with hand-written `naked_asm!`; a normal prologue/epilogue would corrupt the stack layout they own.
- **RFLAGS is part of a task's context** (`pushfq`/`popfq` in `context_switch`). Without it a resumed task inherits the switcher's interrupt state, and a new task starts with IF clear and can never be preempted.
- `Task::new` fabricates an initial 8-slot stack frame (entry point as return address, `INITIAL_RFLAGS`, 6 zeroed callee-saved slots) that `context_switch`'s `ret` cannot distinguish from a real one. `Task::new_with_context` points the return address at `task_trampoline` and stashes the context pointer in **r12** and the real entry point in **r13** — the trampoline moves r12→rdi and `jmp`s r13. That register convention is arbitrary but must match on both sides. The slot count also sets entry alignment: 8 slots leaves RSP ≡ 8 (mod 16) at task entry, which is what SysV requires *after* a call.
- Stacks are `alloc::alloc` with an explicit 16-byte-aligned `Layout`, not `Vec<u8>` — SysV ABI alignment.
- **Every `SCHEDULER` lock acquisition outside an interrupt handler must run with interrupts disabled**, or a tick arriving mid-section deadlocks `preempt` against a holder that can never run again. `yield_now` uses a bare `disable()` rather than `without_interrupts` deliberately: the latter re-enables at the end of the block, i.e. inside the window between releasing the lock and calling `context_switch`, where a preemption would corrupt the not-yet-running target task.
- The lock is dropped *before* `context_switch`; holding it across the switch deadlocks the next task to switch.
- `Box<Task>` (not bare `Task`) in the ready queue keeps heap addresses stable while raw pointers into a `Task` are live across `VecDeque` operations.
- No task removal / no exit path: a finished task parks in `halt_loop()`, and its `RealmContext` leaks. Known limitation, not a bug to fix incidentally.

### Ring 3, syscalls, and the ELF loader

`loader.rs` parses ELF64 by raw offsets (no crate), accepts only `ET_EXEC` + `EM_X86_64` little-endian, maps `PT_LOAD` segments as `PRESENT | WRITABLE | USER_ACCESSIBLE`, zero-fills `p_memsz > p_filesz` (.bss), maps a 4-page user stack, then `run_program`. All bounds/overflow checks are up-front asserts. It is explicitly **not** hardened for untrusted input, and there's no W^X (no `NO_EXECUTE` flags anywhere).

The loaded program is `userland/hello` (a real `no_std` crate) when `USERLAND_PATH` is set, else a hand-encoded ELF from `runner/build.rs`. The hand-encoded ones are kept deliberately: they're the only thing that reaches the loader's `.bss` zero-fill branch, since lld extends `p_filesz` to cover trailing NOBITS sections.

Ring 3 entry/exit is a **round trip**: `usermode::run_program` → naked `enter_usermode_and_wait` (saves 6 callee-saved regs + RSP into `SUPERVISOR_RSP`, builds an `iretq` frame, **zeroes all GPRs** so no kernel state leaks into Ring 3) → program runs → `end_program` → naked `return_to_supervisor` (restores that stack and `ret`s). `iretq` is chosen over `syscall`/`sysret` because selectors are explicit rather than implied by the STAR MSR. Both fault handlers and the `exit` syscall use this path when `rpl() == Ring3`; a Ring 0 fault still halts. `run_program` restores IF afterwards because that path never executes `iretq`.

Syscalls are `int 0x80` (IDT vector 0x80, **DPL 3** — required, or Ring 3 faults before the handler runs), installed via `set_handler_addr` because `syscall_entry` is naked. It **must** be naked: `extern "x86-interrupt"` makes no guarantee the caller's registers survive the prologue. ABI is RAX=number, RDI/RSI/RDX=args, RAX=return. The 9 pushes in the stub are what make RSP 16-aligned at the `call` — change the count and redo the arithmetic; `check_syscall_stack_alignment` reports it in the boot log.

**Any user pointer crossing the syscall boundary must go through `mm::memory::user_range_is_accessible` before being dereferenced.** The CPU's USER_ACCESSIBLE check does not apply to Ring 0 reads, so an unvalidated pointer is an arbitrary kernel-memory read primitive. See ARCHITECTURE.md §3b.

## Conventions

- **Every `unsafe` block carries a `// Safety:` comment naming the invariant that makes it sound.** This is enforced consistently throughout; match it.
- Comments here explain *why*, including rejected alternatives and known gaps, and they're unusually dense. Preserve that register — when something is a deliberate stepping stone or a known limitation, say so in the comment rather than leaving it to be rediscovered.
- Error types are enums implementing `Display` (`CapabilityError`); no stringly-typed errors. Panics only for genuinely unrecoverable kernel states.
- `serial_println!` (exported from `drivers/serial.rs`) is the kernel's unconditional diagnostic voice — distinct from capability-gated writes. Both exist for a reason; don't collapse them.
- `panic = "abort"` in all profiles; the panic handler reports over serial then `halt_loop()`s. Park with `hlt`, never a bare `loop {}` — except where a busy loop is the point (`task_spinner` uses `spin_loop()` precisely because `hlt` would invalidate the preemption test).
- `serial_println!` wraps its format string in `concat!`, so captured-identifier syntax (`"{x}"`) does **not** work — pass positionally (`"{}", x`).
- Cast function items through `as *const ()` before an integer (`f as *const () as u64`), or the `function_casts_as_integer` lint fires.
- `#[unsafe(naked)]` + `naked_asm!` is the correct syntax on this toolchain — not `#[naked]` + `asm!`, and no feature gate needed.
- When unsure of a pinned crate's API, read the real source rather than docs.rs: `curl -sL https://static.crates.io/crates/<name>/<name>-<version>.crate | tar xz`.
- When a milestone lands, update the numbered list in `docs/GETTING_STARTED.md` (strike through the completed item with a pointer to the code) and the status line in `README.md`. That record is how the project tracks what's actually proven working.

## Things that will bite you

Learned the hard way in this codebase; each cost a debugging session.

- **TSS RSP0 must be the stack pointer at the moment of Ring 3 entry, not the task's stack top.** A task inside a Ring 3 program is already using the top of its kernel stack — `run_program`'s frame and its callers live there and must survive, because returning from Ring 3 means returning *into* them. Pointing RSP0 at the top puts the next syscall's interrupt frame directly on top of them. `enter_usermode_and_wait` writes it; `Task::kernel_rsp0` restores it across preemption.
- **Any lock taken outside an interrupt handler must run with interrupts disabled**, or a tick can deadlock against a holder that can never be scheduled again. This includes the global allocator, which is why `mm::allocator::InterruptSafeHeap` exists.
- **A syscall handler may never reach a `panic!` a user program controls.** `yield` routed into `yield_now()`, which panics when no task is current — a routine state — making a kernel panic available to any program in one instruction.
- **CR0.WP means the kernel cannot write a read-only page either.** Loaders map writable, fill, then re-protect.
- **`copy_from_user` caps at 1 MiB** because it allocates a buffer sized by a caller-chosen length. For transfers into a buffer the kernel already sized (a framebuffer commit), use `copy_from_user_into` — do not raise the cap.
- **`with_memory` is not reentrant.** A nested call deadlocks with interrupts off, which is an unrecoverable hang. Functions called from inside it take `mapper`/`frame_allocator` as parameters instead.
- **Negative tests can pass vacuously.** The seek test compared two buffers that were both all zeroes and passed for as long as reading was broken; the tamper test corrupted a payload *before* hashing it, so the "tampered" package verified perfectly. Check that a failing check can actually fail.
