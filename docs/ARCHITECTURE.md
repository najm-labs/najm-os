# Najm OS — Architecture

This document describes the technical design of Najm Kernel and the Realm isolation model. It is a living document and will evolve as implementation reveals what the theory got wrong.

## 1. Kernel Design: Hybrid, Not Monolithic, Not Microkernel

Najm Kernel is a **hybrid kernel**. This is a deliberate trade-off, not a default choice:

- **Pure monolithic** (Linux-style): everything shares an address space. Fast, but Realm isolation would have to be implemented entirely in userspace tooling (namespaces/cgroups-equivalent), which is exactly the model we're trying to improve on — isolation becomes a convention, not a guarantee.
- **Pure microkernel** (seL4-style): maximal isolation via IPC between minimal kernel services. Provably secure, but IPC overhead directly taxes Gaming Realm's latency budget, which defeats the point of the gaming-focused Realm.
- **Hybrid (chosen)**: a minimal privileged core (scheduler, memory manager, capability enforcement, IPC) runs in kernel space for performance. Non-critical subsystems (most drivers, filesystem logic where possible) run in isolated, restartable service processes. Realm boundaries are enforced by the privileged core, not emulated by services running on top of it.

## 2. The Realm Primitive

A Realm is defined by three kernel-enforced properties:

1. **Memory isolation boundary** — a Realm has its own address space region; no implicit sharing with other Realms.
2. **Capability token** — an unforgeable, kernel-issued token enumerating exactly which syscalls, devices, and IPC endpoints a Realm may access. Modeled after capability-based security systems (seL4, Fuchsia's Zircon), not POSIX UID/GID.
3. **Scheduler class** — each Realm type is bound to a scheduler policy, not just a priority number:
   - **Gaming Realm** → real-time-leaning class, bounded worst-case latency, preferential access to CPU cores reserved at boot.
   - **Vault Realm** → standard fair-share class, but with stricter syscall auditing and no access to introspection APIs (no ability to be read/injected by other Realms).
   - **Home Realm** → standard fair-share class, broad but fully auditable capability set.

Realms differ from Linux containers in that isolation is a kernel data structure, not a composition of namespaces + cgroups + seccomp applied by userspace tooling. There is no way to construct a Realm with an incomplete or misconfigured boundary — the kernel will not schedule a Realm without a valid capability token.

## 2b. Realm Lifecycle: On-Demand, Not Installed

A Realm *type* (Gaming, Vault, Home) is kernel code — always present, zero runtime cost if unused, in the same sense that Linux's `SCHED_FIFO` real-time class costs nothing on a machine that never uses it. A Realm *instance* is different: it is created on demand when a process that needs those guarantees launches, and torn down when the last process using it exits.

This matters concretely: a user who never launches a game never causes a Gaming Realm instance to exist, and pays no scheduling, memory, or resource cost for a Realm type they don't use — there is nothing to "install" or "uninstall." The only things that follow a conventional install/uninstall model are optional userspace add-ons layered on top of a Realm (an anti-cheat compatibility shim, a specific DRM client) — ordinary package management, not a kernel-level concern.

## 2c. Realm Core vs. Realm Shell

Kernel-enforced guarantees (scheduling class, capability isolation, memory boundaries — "Realm Core") and user-facing personalization (themes, layout, presets, per-workload UI like a game-mode overlay — "Realm Shell") are deliberately different layers, for two reasons:

1. **Maintainability.** UI/personalization needs change constantly and shouldn't require kernel changes or re-auditing kernel code. A single shared Shell renderer is used across all three Realm types — one codebase, audited once — rather than three separate theming engines per Realm.
2. **Security.** The Shell layer is not exempt from the Core's isolation — it runs *inside* each Realm's existing capability boundary, using that Realm's own capability token, rather than as a separate privileged service with its own rules. Concretely: Gaming Realm's and Home Realm's preset/theme storage are isolated from each other exactly as strictly as any other resource those Realms touch, and Vault Realm's Shell config is walled off the same way. A convenience layer that quietly bypassed Realm boundaries would undo the isolation the rest of this document exists to guarantee.

**A specific threat this raises, and how it's handled:** if theming is fully flexible, a malicious application inside Home Realm could visually mimic Vault Realm's UI to trick a user into treating it as trusted (an OS-level phishing attack). Vault Realm's Shell is required to render at least one UI element that is *not* themeable — generated directly by the kernel/Core layer rather than any Shell configuration — so that a user has a signal that no software running in another Realm can reproduce or spoof, analogous to a browser's non-spoofable lock/URL chrome for HTTPS. See section 2d for why this needs to be more carefully scoped than it first sounds.

## 2d. Realm Shell: Threat Model & Trusted Path

The trust-indicator idea in 2c is a real, working pattern — it's essentially what Qubes OS does with per-domain colored window borders, drawn by a trusted window manager so that untrusted domains can't fake them. But Qubes' own documentation and security history show exactly where a naive version of this breaks, and those lessons apply directly here:

| # | Threat | Mitigation Najm OS requires |
|---|---|---|
| 1 | A malicious Realm can draw a convincing fake trust indicator *inside its own window content* — Qubes' guidance literally warns that an untrusted app can draw its own fake "trusted" prompt inside its window. | The trust indicator must be rendered *outside* any Realm's window content, by a region no Realm's drawing calls can ever touch. |
| 2 | If the indicator is drawn by the Shell (userspace, even if "trusted"), a Shell compromise can forge it. | The indicator is drawn by the Core/compositor layer directly, not by the Shell — the Shell has no capability to influence it at all, not even a restricted one. |
| 3 | Qubes had a real 2016 vulnerability (window-manager state tracking bug in how the X11 `override_redirect` flag was handled) that let a malicious app spoof window ownership despite the design being sound in principle. | The mechanism that decides "which Realm owns this region of the screen" must be verified by the kernel/compositor itself on every frame, not inferred from a flag or message an application can influence. |
| 4 | **Exclusive fullscreen — Gaming Realm's default mode for lowest latency — hands a Realm the entire framebuffer, leaving no space for any indicator to be drawn.** This is the biggest structural gap: it's a hole precisely where the highest-risk Realm normally operates. | The compositor reserves a hardware overlay plane (or an equivalent always-on-top compositing guarantee) for the trust indicator that persists even when a Realm has exclusive scanout access — the same way Windows' Secure Attention Sequence (Ctrl+Alt+Del) is designed so no application can intercept or suppress it. |
| 5 | A single shared Shell renderer codebase means one vulnerability (e.g. a font-parsing bug) is reachable from every Realm's Shell instance. | Shared *code*, never a shared *running process* — each Realm's Shell instance is its own process with its own capability token and address space, so a code bug still requires a separate exploit per Realm rather than one exploit compromising all three at once. |
| 6 | Theme/preset files (especially community-contributed ones, e.g. controller/UI profiles) are untrusted input parsed by a privileged-ish process — a classic RCE vector regardless of language. | Preset/theme parsing happens in a sandboxed subprocess with a minimal capability set, independent of Rust's memory safety (which helps but doesn't stop logic bugs). |
| 7 | Realms sharing the physical GPU can leak information to each other via rendering timing/resource contention even with perfect capability isolation in software. | Tracked as a known, currently-unsolved limitation (open question, section 7) rather than something this design claims to fully solve — flagged explicitly instead of silently assumed away. |

None of this restricts what Shell theming/presets can look like — colors, layout, fonts, per-Realm UI personality all stay fully flexible. What it constrains is narrow and specific: the one non-negotiable trust signal lives entirely in the Core, is exempt from theming by construction (not by convention), and is designed to survive the exact failure modes that have broken equivalent mechanisms in real systems before.

## 2e. Realm Assignment & Trust Bootstrapping

Sections 2c/2d establish that a Realm's *trust indicator* can't be forged from inside another Realm. That guarantee is worthless on its own if the *decision of which Realm an application actually runs in* can be manipulated - a threat distinct from anything covered above, because it happens before Realm Core's isolation is even engaged: at install time, when something decides "this package becomes a Vault Realm instance" or "a Home Realm instance."

**The threat:** if that decision is based on anything the application itself supplies - a manifest field declaring `realm: vault`, a runtime API call requesting elevated placement, or even an unverified prompt the user can be talked through - any application, malicious or not, can request Vault Realm placement and receive both its isolation *and* its non-spoofable trust badge without having earned either. This is a distinct failure mode from UI spoofing (2d): the badge itself stays unforgeable, but it ends up faithfully displaying trust for something that was never actually vetted. A convincing fake Adobe installer requesting Vault placement would get exactly the same badge a real one would.

**Why the obvious fixes don't work:**

| Approach | Failure |
|---|---|
| Realm declared in the package's own manifest | Any author writes `realm: vault`; zero verification |
| User chooses at install time | Social-engineerable, and most users have no basis to judge correctly either way |
| Kernel heuristically detects "sensitive" apps (DRM usage, payment APIs, etc.) | Gameable by design, and a legitimate app that doesn't trip the heuristic is wrongly denied Vault placement |

**The approach Najm OS takes**, following the same pattern established for capability tokens themselves (unforgeable, issued only by a trusted authority - see section 3) and matching how real systems solve the identical problem (Apple's Developer Program identity verification behind every code-signing certificate; Windows' publisher-authenticated Trusted Signing): **Vault Realm eligibility is a credential, not a declaration.**

- **Default is always Home Realm.** An application with no verified publisher credential gets Home Realm placement, full stop - including one that explicitly asks for Vault. Elevated trust must be earned before installation, never assumed at installation.
- **Vault eligibility requires a signature chain rooted in a publisher identity verified in advance** - through a Najm app store review process, or a recognized external certificate authority - not anything checked at install time against the package's own claims about itself.
- **The non-spoofable trust indicator (2d) must reflect the verified publisher, not just Realm membership.** Achieving Vault Realm placement and displaying Vault's trust badge should mean "this is a verified build from a specific, checkable publisher identity," not merely "this software asked to run somewhere with stricter isolation and was granted it." Realm Core's isolation and the trust badge's meaning are two different guarantees that happen to be visually combined - conflating them is exactly how this class of vulnerability hides.

This is a policy and provisioning-layer problem, not something Realm Core's kernel-level mechanisms can solve by themselves - no amount of capability-token or memory-isolation rigor helps if the decision feeding into it was never verified in the first place. It's recorded here specifically so that whatever installer/package-manager work happens later is built against this requirement from the start, rather than defaulting to the convenient-but-wrong "ask the package what it wants to be."

## 3. Capability-Based Security Model

Every resource access — memory, device I/O, IPC — requires presenting a capability token. Tokens are:

- **Unforgeable**: created only by the kernel, never constructed by userspace.
- **Delegatable but attenuable**: a Realm can grant a subset of its own capabilities to a child process, but never more than it holds itself (no privilege escalation via delegation).
- **Revocable**: the kernel can invalidate a capability at any time (used for Vault Realm's tamper response, and for dynamic resource reclamation from Gaming Realm when it's not foregrounded).

Where possible, capability checks are expressed in Rust's type system (e.g. a function that touches GPU memory requires a `GpuCapability` token as a parameter, not a runtime permission check), turning missing-permission-check bugs into compile errors rather than runtime vulnerabilities.

## 3b. The Syscall Boundary

Section 3 describes capability tokens as the mechanism controlling access to resources. That model has a gap that only becomes reachable once Ring 3 code exists, and it is worth stating precisely because it is easy to assume the hardware already handles it.

**The threat:** the `USER_ACCESSIBLE` bit in the page tables is checked by the CPU only for accesses made *at* Ring 3. When a user program calls `write(ptr, len)` and the kernel dereferences `ptr` at Ring 0 on its behalf, no hardware check applies at all — the kernel is allowed to read anything. A syscall that trusts the pointer it was handed is therefore an arbitrary kernel-memory read primitive handed out to every user program: pass a pointer to the kernel heap, a page table, or another program's pages and the kernel will faithfully read and return it. Nothing about memory safety in Rust prevents this; the read is perfectly well-defined, just catastrophically wrong.

This is the same class of problem as section 2e's — a boundary that looks enforced because *some* mechanism nearby enforces something, when the specific check that matters was never actually made.

**The approach Najm OS takes:** every user-supplied pointer crossing the syscall boundary is validated in software before it is dereferenced, by walking the active page tables and requiring `PRESENT | USER_ACCESSIBLE` at **every** level, not just the leaf entry (a leaf marked user-accessible beneath a parent that isn't is not reachable from Ring 3, and treating it as if it were would reintroduce the hole). Non-canonical addresses and ranges that wrap the address space are rejected rather than allowed to panic the kernel — trading an information leak for a denial of service is not a fix. See `mm::memory::user_range_is_accessible`.

Two related decisions follow the same reasoning:

- **Registers are zeroed before every Ring 3 entry.** Otherwise a program begins life able to read whatever the kernel last left in the register file. This was not hypothetical — the first boot log after the syscall ABI landed showed a test payload arriving with the kernel's own RFLAGS constant and internal addresses still in its registers.
- **A program's starting state is defined, not incidental.** Zeroing is what makes "what does a program see at `_start`?" a documented answer rather than a detail of which function happened to run last.

**What this does *not* yet solve, stated plainly:** the check validates *mapping and privilege*, not *ownership*. With one kernel-wide address space and no per-program page tables, any page belonging to any user program would pass the check for any other. Only one program runs at a time today, so the gap is not currently reachable — but it closes properly only when address spaces become per-Realm, which is the same missing piece that prevents reclaiming a terminated program's memory (section 2). Both are recorded here so that whatever builds per-Realm address spaces is built knowing these two depend on it.

## 4. Scheduler Design

The scheduler is capability-aware and Realm-class-aware:

Preemption itself now exists (a timer interrupt can take the CPU from a task that never yields), but with one restriction worth recording because it constrains what comes next: **a Ring 3 program cannot currently be preempted.** A timer interrupt taken in Ring 0 leaves its frame on the interrupted task's own kernel stack, so switching stacks parks the whole thing safely; one taken from Ring 3 lands on the single shared TSS RSP0 stack, which the next Ring 3 entry reuses. Preempting a user program therefore needs its register state saved somewhere it owns — per-program context that doesn't exist yet. Until then a Ring 3 program runs to completion, which is fine while only one runs at a time and is not fine the moment Realms host concurrent user workloads.

- Gaming Realm threads get a bounded-latency scheduling class with reserved core affinity, configured at boot or on Realm creation.
- Background services and Home Realm workloads are deprioritized while a Gaming Realm is in the foreground, without being frozen entirely (avoiding the "everything else stutters" problem of naive priority boosting).
- Vault Realm gets standard fair-share scheduling — performance is not its priority, integrity is.

Exact scheduling algorithm (e.g. EEVDF-inspired vs. a custom design) is an open implementation question — see open issues.

## 5. Anti-Cheat / Attestation Strategy

Kernel-level integrity attestation for Gaming Realm is a **prerequisite for**, not a **guarantee of**, third-party anti-cheat compatibility. The design goal:

- Secure boot chain + TPM-backed measurement of the Gaming Realm's kernel-facing surface, so a remote party (a game server) can verify the Realm hasn't been tampered with.
- This does not mean EAC/BattlEye will run unmodified on Najm OS — that requires vendor cooperation. The architecture aims to make that cooperation *technically feasible*, nothing more.

## 6. Driver Strategy

PCI enumeration exists (`kernel/src/drivers/pci.rs`) - the first bus this kernel discovers rather than assumes, and the prerequisite for everything below. Also implemented: the CMOS real-time clock, a PS/2 keyboard and mouse feeding an event queue, and the PIT reprogrammed to a known 100 Hz.

Writing a full driver stack from scratch is not realistic for this project's timeline. Planned approach, in order of investigation priority:

1. A compatibility shim for a constrained subset of Linux driver interfaces, where license and design permit.
2. Native drivers only for performance-critical paths (GPU, input, storage) where a shim's overhead would compromise Gaming Realm's latency guarantees.
3. Everything else deferred until the above is stable.

This is explicitly the highest-risk part of the project and where outside contribution matters most.

## 7. Open Questions

- Exact IPC mechanism and its performance characteristics under Gaming Realm latency constraints. The syscall numbers are reserved (`abi/src/lib.rs`) and nothing implements them yet, which is why every service that should be a separate process is currently inside the kernel.
- **Persistence.** The filesystem is read-only and lives in the boot image. This blocks the Store, the app SDK and ordinary use equally, and is the single most useful thing to build next.
- Whether filesystem logic lives in the privileged core or as an isolated service (trade-off between crash-resilience and I/O latency).
- GPU passthrough mechanism for Gaming Realm without a full virtualization layer.
- Timing/resource-contention side-channels between Realms sharing the same physical GPU during concurrent rendering (see section 2d, threat #7) — capability isolation in software doesn't fully close this, and it isn't solved by this design yet.

Proposals and RFCs for any of the above are welcome — see [CONTRIBUTING.md](../CONTRIBUTING.md).
