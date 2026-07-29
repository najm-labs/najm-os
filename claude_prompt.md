# Najm OS — Continuation Brief for Claude Code

You're continuing an existing from-scratch x86_64 kernel project written in
Rust, called **Najm OS**. This is a real, working, incrementally-verified
codebase — not a scaffold. Read this whole brief before touching anything,
then read `docs/ARCHITECTURE.md`, `docs/GETTING_STARTED.md`, and
`README.md` in the repo itself. Every milestone described in those files
has been individually boot-tested in QEMU and its output verified against
what the code should actually produce — this project's whole philosophy is
"prove it, don't assume it," and you should keep that up.

**You have something I (the assistant that got this project to this point)
didn't have: a real terminal with real QEMU/KVM access on the developer's
own machine.** Use it constantly. Build after every meaningful change. Boot
it. Read the serial output. If something doesn't match what you expected,
that's a bug — find it and fix it before moving on, don't just note it and
keep going. Leave the tree in a state where `make run` boots clean with no
new warnings and no regressions in any existing self-test, every single
time you finish a piece of work.

## Environment

- Arch Linux + Hyprland, Ryzen 5 4600G, KVM available (`-enable-kvm`
  already wired into `runner/src/main.rs`).
- `rust-toolchain.toml` pins a specific nightly (`nightly-2026-06-01`) for
  a real, load-bearing reason — see "Known pitfalls" below before you
  touch it.
- `make run` builds the kernel, builds the disk image (with the
  `runner` crate), and boots it in QEMU with serial output on stdio.
  `make check` is a fast type-check-only loop for iterating without a
  full image build. Read the `Makefile`, it's short.

## Current state (verified working, in order)

1. Boots via the `bootloader` crate (BIOS), paints the framebuffer
   correctly for whatever pixel format the hardware/QEMU reports.
2. Serial output (`serial_println!`/`serial_print!` macros) and a real
   panic handler.
3. GDT/TSS (with a dedicated double-fault IST stack) and IDT — CPU
   exceptions are caught and diagnosed, not silent triple faults.
4. Physical frame allocator + kernel heap (`Box`/`Vec`/`String` work).
5. Hardware interrupts: legacy 8259 PIC remapped, timer tick counter,
   PS/2 keyboard driver.
6. A cooperative task scheduler with hand-written x86_64 context
   switching (`sched/task.rs`) — proven with three interleaving tasks.
7. A capability-token security model (`security/capability.rs`) —
   unforgeable, issued/derived/revoked, revocation proven to actually
   block use, demonstrated against two independent rights.
8. A first Realm prototype (`realm.rs`) — tasks that carry their own
   distinct capability profile on a heap-allocated context, matching
   ARCHITECTURE.md's Gaming/Vault/Home split (Vault deliberately lacks
   the SerialWrite right, matching its "no introspection APIs" design).
9. Ring 3 (user-mode) execution proven for real: GDT user segments, TSS
   RSP0, an IRETQ-based transition (`arch/x86_64/usermode.rs`), verified
   by a hand-written payload that makes a syscall (`int 0x80`) and then
   deliberately executes a privileged instruction that correctly faults.
10. A minimal ELF64 loader (`loader.rs`) — parses `PT_LOAD` segments from
    a bootloader-provided ramdisk (built by `runner/build.rs`, currently
    two hand-encoded test ELFs — one exercises `.bss` zero-fill), maps
    them user-accessible, and transitions to Ring 3 at the real entry
    point.

I just finished a **security/correctness audit** of the whole codebase and
fixed what I found:
- `loader.rs` didn't validate program-header-table bounds before reading
  — a malformed ELF could panic on a raw slice-index OOB. Fixed with an
  explicit upfront bounds check and clear assertion messages.
- `p_vaddr + p_memsz` could overflow, under-mapping a segment while a
  later write still used the un-wrapped size — a possible OOB write.
  Fixed with `checked_add`, hard-erroring instead of wrapping.
- `mm/memory.rs`'s frame allocator recomputed and re-walked its entire
  iterator chain from scratch on *every* `allocate_frame()` call — O(n²)
  over the allocator's lifetime. Rewritten as an O(1)-amortized cursor
  (`region_index` + `next_addr`).
- Stale comment in `drivers/serial.rs` claiming "no interrupts exist yet"
  — false since milestone 5; fixed.
- **The one I did *not* fix, and am handing to you as priority #1**:
  `page_fault_handler`/`general_protection_fault_handler` in
  `arch/x86_64/interrupts.rs` halt the *entire machine* regardless of
  whether the fault happened in kernel code (Ring 0 — genuinely fatal,
  correct to halt) or in a Ring 3 program (Ring 3 — in a real OS this
  should terminate *only* that program). I added privilege-level logging
  so the distinction is at least visible, but didn't fix the underlying
  issue, because fixing it properly requires infrastructure that doesn't
  exist yet: `usermode::run_test`/`loader::load_and_run` are both `-> !`
  and never return, so there's currently no supervisor context to return
  *to* after a Ring 3 program dies. See "Priority 1" below.

## What to do this session, in priority order

Work through these in order; each one meaningfully depends on the one(s)
before it, and each should be fully build-tested-verified before you move
to the next. If you run out of session budget partway through, stop at a
clean, working checkpoint — never leave the tree mid-refactor and broken.

### Priority 1 — Return-to-supervisor path (fixes the audit gap above)

Give the kernel a real way to run a Ring 3 program and get control back
afterward, whether it exits cleanly or faults. Concretely:

- Add an `exit` syscall (pick a number, e.g. 0) alongside the existing
  `int 0x80` stub in `arch/x86_64/interrupts.rs`'s `syscall_handler`.
- Before transitioning to Ring 3, save a "resume point" for the Ring 0
  side — the same conceptual trick `sched/task.rs`'s `context_switch`
  already uses (save callee-saved registers + RSP before switching away,
  restore them to resume later). You likely want a dedicated,
  Ring3-round-trip-specific naked function pair (`enter_and_wait_for_exit`
  or similar) rather than shoehorning this into the existing
  general-purpose task scheduler — a Ring 3 program isn't a cooperative
  kernel task, it's a fundamentally different kind of context.
- Wire the exit syscall and (this is the important part) the two fault
  handlers to use this same "return to the saved Ring 0 point" mechanism
  when the fault occurred at `rpl() == PrivilegeLevel::Ring3` — instead
  of unconditionally calling `halt_loop()`. A Ring 0 fault should still
  halt (it's genuinely fatal); a Ring 3 fault should now report what
  happened and return control to whoever called `loader::load_and_run`.
- This changes `loader::load_and_run`'s signature — it stops being `-> !`
  and starts returning something meaningful (exit code, or a
  fault-reason enum) to its caller in `kernel_main`.
- **Test this explicitly and don't skip it**: after this works, boot the
  kernel, load the *faulting* test ELF (the existing `hlt`-triggering
  one), and confirm the log shows the fault, shows Ring 3 was correctly
  identified, and shows `kernel_main` *regaining control* and continuing
  to run something afterward (even if that's just printing "program
  exited/faulted, continuing" and then halting cleanly) — not the whole
  machine going dark. That observable difference is the actual proof
  this works, the same way every earlier milestone in this project has
  had a concrete, checkable proof rather than "should work."

### Priority 2 — Real syscall arguments

Right now `int 0x80` does exactly one thing regardless of what's in any
register. Give it real argument passing:

- Register convention: RAX = syscall number, RDI/RSI/RDX = args 1-3
  (matching Linux's own convention loosely, for familiarity — not
  because compatibility matters yet).
- **This needs a fully naked `int 0x80` handler**, not an
  `extern "x86-interrupt" fn` one — the x86-interrupt calling convention
  does *not* guarantee general-purpose registers are readable via inline
  `asm!` at the top of the function body; only what's declared in
  `InterruptStackFrame` is well-defined. Save RAX/RDI/RSI/RDX explicitly
  in hand-written assembly, `call` into a normal Rust dispatcher function
  with them as SysV64 arguments, then `iretq`. **Watch stack alignment
  carefully** — RSP must be 16-byte aligned immediately before the
  `call` instruction; the hardware's own interrupt-entry pushes (SS,
  RSP, RFLAGS, CS, RIP = 40 bytes) plus whatever you push yourself will
  determine this, and getting it wrong is a silent-corruption bug, not a
  compile error. Test this specifically — e.g. have the dispatcher do
  something that would visibly break if the stack were misaligned
  (SSE-using code, or just very deliberately verify against known-good
  reference implementations of syscall entry stubs for x86_64 if you
  want a sanity check on the exact push/pop sequence).
- Implement at minimum: `write` (number/args TBD by you — buffer
  pointer + length, writes through the existing
  `drivers::serial::write_with_capability`-style path or directly, your
  call) and `exit` (from Priority 1, now taking an actual exit code
  argument).
- Update the userland test payload(s) in `runner/build.rs` (or move to
  Priority 3's real toolchain and write it there instead — your call on
  ordering, but don't do both redundantly) to actually pass real
  arguments to `write` and verify the kernel receives them correctly.

### Priority 3 — A real userland toolchain

Replace (or supplement — keep what still demonstrates something distinct)
the hand-encoded ELF bytes in `runner/build.rs` with an actual compiled
Rust program:

- New Cargo project, e.g. `userland/hello/`, `#![no_std] #![no_main]`,
  targeting `x86_64-unknown-none` (same target the kernel already uses —
  no need to invent a new target JSON).
- It needs its own linker configuration to produce a fixed-address
  `ET_EXEC` binary the existing loader can load (loader.rs currently
  only supports `ET_EXEC`, no PIE/dynamic linking — either keep that
  constraint and give userland programs a fixed link address via linker
  flags/script, or extend loader.rs for PIE if you'd rather go that
  route, but that's meaningfully more work for not much benefit at this
  stage).
- A minimal `_start`, a panic handler (can be trivial — loop/hlt, or use
  the new `exit` syscall from Priority 2 to terminate cleanly), and thin
  syscall wrapper functions (`unsafe fn write(...)`, `fn exit(...) -> !`)
  around `int 0x80`.
- Update `runner/build.rs` to `cargo build` this crate for
  `x86_64-unknown-none` and feed *its* output ELF to `set_ramdisk`
  instead of (or alongside, if you keep both for comparison) the
  hand-encoded ones. Update the `Makefile` if the build orchestration
  needs it (the userland crate build likely needs to happen before
  `runner`'s build.rs runs, similar to how the kernel itself is built
  before `runner`).
- Write something in the userland program that's obviously distinguishing
  — e.g. a small loop calling `write` a few times with different
  messages — so the test output is unambiguous.

### Priority 4 — Preemptive scheduling

Hook the timer interrupt (already firing, already counting ticks in
`arch/x86_64/interrupts.rs`) into a real context switch, so a task that
never calls `yield_now()` still gets preempted.

- The core difficulty: the timer interrupt handler currently is (and,
  for the exception-safety reasons already established in this project,
  probably should stay) an `extern "x86-interrupt" fn`, which means you
  don't get to manually control the full save/restore sequence the way
  `sched/task.rs`'s `context_switch` does. The standard technique is to
  modify the *interrupt return frame itself* — instead of blindly
  `iretq`-ing back to whatever was interrupted, rewrite the frame's
  RIP/RSP (and potentially CS/SS if crossing privilege levels) to point
  at the next task before the handler returns. Research this pattern
  specifically (it's well-documented in OS-dev references under
  "preemptive multitasking" / "modifying the interrupt stack frame") — 
  don't guess at the exact mechanics, verify against a reliable
  reference before writing naked assembly for it, the same discipline
  this project has used throughout for anything touching raw registers.
- Keep `yield_now()` and the cooperative path working — preemption should
  be an *addition* (a task can still yield early), not a replacement.
- Test with a task that deliberately spins in a tight loop *without*
  ever calling `yield_now()`, and confirm the other tasks still get CPU
  time — that's the actual proof preemption works, not just that the
  timer handler compiles.

### Priority 5 — Full regression pass + cleanup

Once the above is in place:

- Re-verify every earlier milestone's self-test still passes exactly as
  documented (breakpoint, timer, heap allocation, both capability
  demonstrations, the three Realm-profile tasks, the ELF loader
  including the `.bss` test) — `kernel_main` currently has several of
  these commented out at any given time because only one `-> !` ending
  could run per boot; now that Priority 1 makes `load_and_run` return
  instead of diverging, reconsider whether `kernel_main` should run
  *several* of these in sequence in one boot rather than picking one via
  comments. That would actually be a meaningful improvement in its own
  right - fewer manual "comment this back in to check" steps for anyone
  working on this later.
- `cargo build`/`cargo check` on the kernel target should be free of
  warnings, or every remaining warning should have an explicit
  `#[allow(...)]` with a one-line justification comment, matching this
  project's existing style (see `sched/task.rs`'s `start()` or
  `arch/x86_64/usermode.rs`'s `run_test()` for the pattern already in
  use).
- Update `README.md`'s status line, `docs/GETTING_STARTED.md`'s milestone
  list, and `docs/ARCHITECTURE.md` if you made any real architectural
  decisions (the Realm Assignment section, section 2e, is the template
  for how this project documents "here's a real gap we found and the
  reasoning behind how we're closing it" — match that tone: honest about
  what's still not solved, not just what's newly done).
- End the session with a clear, honest summary: what's now verified
  working (with the actual boot log excerpts proving it, the same way
  every milestone in this project's history has been proven), and what's
  still open/deferred, exactly like the "Next up" sections already
  present in `docs/GETTING_STARTED.md`.

## Known pitfalls (save yourself the time it took to find these)

- **Never use a floating semver range for `x86_64`, `bootloader`, or
  `bootloader_api`.** They're pinned to exact versions
  (`x86_64 = "=0.15.2"` in `kernel/Cargo.toml`;
  `bootloader_api = "=0.11.15"` in `kernel/Cargo.toml`;
  `bootloader = "=0.11.15"` in `runner/Cargo.toml`) because newer
  releases of `x86_64` implement extra `Step` trait methods
  (`forward_overflowing`/`backward_overflowing`) that only exist on
  nightly compilers *newer* than the one pinned in
  `rust-toolchain.toml`, and the `bootloader` crate's own internal
  BIOS/UEFI stage builds pull in `x86_64` transitively - a new
  `bootloader` patch release can silently pull in an incompatible
  `x86_64` version even with zero changes on our side. If you ever bump
  `rust-toolchain.toml`'s nightly date, all three of these pins need
  revisiting together in the same change, never independently.
- Our own `serial_println!`/`serial_print!` macros wrap their format
  string in `concat!(...)`. Rust's captured-identifier format syntax
  (`"{some_var}"`) does **not** work through a `concat!`-produced format
  string — pass values positionally (`"{}", some_var`) instead, or you'll
  get a compile error about `format_args!` not being able to capture
  variables from macro-expanded literals.
- Casting a bare function name (not a function-pointer-typed value)
  directly to an integer triggers the `function_casts_as_integer` lint on
  this compiler. Cast through `as *const ()` first, e.g.
  `some_fn as *const () as usize as u64` — see `sched/task.rs` for the
  established pattern.
- `#[unsafe(naked)]` + `naked_asm!` (not the older `#[naked]` +
  `asm!`) is correct, stable syntax on this pinned toolchain — no
  `#![feature(naked_functions)]` needed.
- Any IDT gate you want Ring 3 code to invoke via `int 0xNN` needs
  `.set_privilege_level(x86_64::PrivilegeLevel::Ring3)` explicitly when
  registering the handler — IDT gates default to DPL 0, and Ring 3 code
  hitting a DPL-0 gate faults immediately, before your handler ever runs.
- If you ever touch the GDT again: reloading it means the CPU's other
  segment registers (SS especially) may still hold selector values whose
  *meaning* changed when the table underneath them changed. This project
  hit a real bug from exactly this — see the git history / the
  commentary in `arch/x86_64/gdt.rs` around `SS::set_reg`.
- TSS `privilege_stack_table[0]` (RSP0) must be a valid, mapped stack
  before *any* Ring 3 → Ring 0 transition can happen safely - without it,
  the first such transition (a fault, an interrupt, a syscall) has
  nowhere valid to push its frame and triple-faults.
- When in doubt about an unfamiliar crate API (especially anything in
  the `x86_64`, `bootloader`, `bootloader_api`, `pic8259`, or
  `pc-keyboard` crates), don't guess from memory or docs.rs — download
  the exact pinned version's source from
  `https://static.crates.io/crates/<name>/<name>-<version>.crate`,
  extract it, and grep the real source. This project got burned more
  than once by APIs that looked like they should work a certain way but
  didn't, and every time, five minutes reading the real source would
  have caught it before a wasted build cycle.

## Style this project has kept consistently — please keep matching it

- Every `unsafe` block has a `// Safety:` comment explaining the specific
  invariant that makes it sound, not a generic "this is safe because..."
  hand-wave.
- Comments explain *why*, especially why a simpler-looking alternative
  was rejected, not just *what* the code does.
- Deliberate limitations are stated explicitly in comments/docs rather
  than left implicit — if you leave something unfinished or simplified,
  say so in the code, the way `loader.rs`'s module doc says outright
  "this should never be pointed at untrusted input" instead of pretending
  otherwise.
- Prefer keeping an old, already-proven test/code path present-but-unused
  (with a comment explaining why) over deleting it when adding a new one
  that supersedes it for the moment — this project's git history is full
  of exactly that pattern and it's been genuinely useful for isolating
  regressions.

Good luck — this has been a genuinely fun project to build. Make it
proud.