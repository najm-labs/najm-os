# Najm OS

**A hybrid kernel operating system written in Rust, built around isolated execution domains called Realms.**

Najm OS is designed from the ground up to solve a problem no mainstream OS solves well: running latency-critical gaming workloads, security-critical paid software, and general-purpose user applications on the *same machine* without any of them compromising the others' performance, security, or integrity guarantees.

> **Status:** Early development, and further along than that phrase
> usually implies. The kernel boots in QEMU with **33 self-tests passing
> on every boot** (`make test`), and each of them checks real hardware
> behaviour rather than a claim in a comment.
>
> Working today: a higher-half kernel with **per-process address spaces**;
> **NX, W^X, SMEP, SMAP and UMIP** enforced, with NX proven by a Ring 3
> jump into a non-executable page faulting; **preemptive scheduling with
> Realm classes** whose worst-case latency is measured and asserted;
> **Ring 3 preemption**; a **read-only filesystem** with real file
> syscalls; **PCI enumeration**, a real-time clock, keyboard and mouse; a
> **compositor with the non-spoofable trusted path** ARCHITECTURE.md
> section 2d specifies; **Mirage**, which runs a Windows PE binary
> natively; and **Najm Store** package verification implementing
> ARCHITECTURE.md 2e's rule that Realm elevation is a credential rather
> than a declaration.
>
> Not working, listed because a status section that only lists successes
> is marketing: **nothing persists** (the filesystem is read-only and
> lives in the boot image), there is **no IPC**, **no SMP**, Mirage
> implements **four Win32 functions** against Wine's tens of thousands,
> and package signature verification is **unimplemented and fails
> closed** - so no package can currently be elevated to Vault.
>
> See [ARCHITECTURE.md](./docs/ARCHITECTURE.md) for the design,
> [GETTING_STARTED.md](./docs/GETTING_STARTED.md) to build and run it,
> [APP_SDK.md](./docs/APP_SDK.md) for how applications are meant to be
> built, and [CONTRIBUTING.md](./CONTRIBUTING.md) to get involved.

---

## Why Najm OS

Every existing OS makes a trade-off Najm OS refuses to accept:

- **Linux** is excellent for development and servers, but desktop gaming performance and anti-cheat compatibility remain second-class.
- **Windows** dominates gaming, but its scheduler, driver model, and general architecture are not optimized for development workflows or strict application sandboxing.
- **macOS** offers tight hardware/software integration for productivity work, but is closed, inflexible, and not a gaming platform.

Najm OS does not attempt to be strictly better than all three at everything — that's not a credible engineering claim for a single project. Instead, it introduces a kernel-level primitive, the **Realm**, that lets a single machine host multiple *purpose-built execution environments*, each with its own scheduling policy, resource limits, and capability set — enforced by the kernel, not bolted on by userspace tooling.

## Core Concept: Realms

A **Realm** is an isolated execution domain defined at the kernel level. Unlike Linux containers (namespaces + cgroups layered on top of a general-purpose kernel), Realms are a first-class kernel abstraction with their own scheduler class, capability token, and memory isolation boundary.

Najm OS ships with three reference Realm types:

| Realm | Purpose | Kernel-level guarantees |
|---|---|---|
| **Gaming Realm** | Gaming workloads | Real-time/low-latency scheduling priority, reduced background service interference, kernel-level integrity attestation for anti-cheat compatibility |
| **Vault Realm** | Paid/commercial applications (e.g. Adobe, DAW software) | Strict capability isolation, tamper-resistant execution, restricted inter-realm communication |
| **Home Realm** | General-purpose user environment | Standard Linux-like userspace experience, broad but auditable system privileges |

Realms are not containers with a new name — they are a distinct architectural primitive with different isolation, scheduling, and security guarantees than process-level or namespace-level isolation can provide. See [ARCHITECTURE.md](./docs/ARCHITECTURE.md) for the full design rationale.

## Why Rust

- **Memory safety without a garbage collector** — critical for kernel code, where a GC pause is not an option and a null-pointer dereference is a security incident.
- **Zero-cost abstractions** — safety guarantees are enforced at compile time, not at runtime, so Gaming Realm's latency budget isn't taxed by the language itself.
- **Strong type system** — the capability-based security model (see ARCHITECTURE.md) is expressed and enforced through Rust's type system wherever possible, turning entire classes of privilege-escalation bugs into compile errors.

## Project Goals (in order of priority)

1. A minimal, bootable hybrid kernel with working memory management and a preemptible scheduler.
2. A working Realm isolation primitive — even a single functioning Realm boundary is a meaningful milestone.
3. Capability-based security model for inter-Realm and Realm-to-hardware access control.
4. Gaming Realm: low-latency scheduler class + GPU passthrough.
5. Vault Realm: hardened execution + attestation.
6. Home Realm: general-purpose userspace compatible enough for daily development use.

## Non-Goals (for now)

- Full driver parity with Linux. This is the single biggest practical obstacle to a new OS and will be tackled incrementally, likely via a compatibility layer rather than a full driver rewrite.
- Anti-cheat vendor partnerships. Kernel-level attestation will be designed to make this *possible*, not guaranteed.
- Feature parity with Windows/macOS on day one, or ever, on every axis.

## Vision Beyond Desktop

The near-term focus is a bootable desktop kernel with working Realm isolation — that's what all of the current milestones build toward. But the architecture is being kept deliberately open to three longer-term directions, so that near-term decisions don't quietly foreclose them:

- **Server use** (a Linux-alternative for server workloads). Realm Core's capability model and scheduling classes aren't desktop-specific concepts — they're just as relevant to isolating server workloads from each other. The current code already handles "no framebuffer present" correctly (see `paint_framebuffer`'s `None` branch in `kernel/src/main.rs`) — not because headless/server operation was explicitly planned for yet, but because it turned out to be the same code path as "the bootloader didn't hand us one," which is a reassuring sign the design isn't accidentally desktop-only.
- **AI agent hosting**, potentially as a fourth Realm type ("Agent Realm"). An AI agent that can execute code, touch files, and make network calls is exactly the kind of workload the capability model was built for: fine-grained, revocable permissions ("read only this directory," "reach only this host") instead of coarse process-level trust. Its scheduling needs (strict resource quotas against runaway/looping agents) are distinct from Gaming's (latency) and Vault's (tamper-resistance), which is a reasonable signal it'd be its own Realm type rather than a variant of an existing one.
- **Mobile.** Interestingly, the existing three-Realm model maps onto mobile fairly directly without needing new concepts: banking/payment apps are a Vault Realm use case if anything more than on desktop, mobile games are Gaming Realm, and everyday apps are Home Realm. What mobile *does* require that isn't free: full aarch64 (ARM) target support alongside x86_64 — a different architecture, not just a different form factor, with its own boot process and no shared code with the current bootloader path — and power/battery consumption as a first-class scheduling dimension alongside latency and isolation, not something bolted on afterward.

None of this changes what's being built right now. It's recorded here so that architectural choices made early (capability model shape, scheduler class design, what counts as a "Realm") are made with these directions in view, rather than accidentally closing them off and having to be revisited later.

## Building & Running

See [GETTING_STARTED.md](./docs/GETTING_STARTED.md) for how to build the kernel and boot it in QEMU. The short version: `make run` from the repo root, once you have `rustup` and `qemu-full` installed.

## Getting Involved

This project is open source specifically so it can grow faster than one person can build it — driver support, scheduler tuning, and security review all benefit enormously from outside expertise. See [CONTRIBUTING.md](./CONTRIBUTING.md) for how to get started, and [ARCHITECTURE.md](./docs/ARCHITECTURE.md) to understand the design before proposing changes.

## On the Name

"Najm" (نجم) is Arabic for "star." The kernel sits at the center — like a star — with each Realm orbiting it as its own self-contained environment, bound by the kernel's gravity but distinct in composition.

## License

See [LICENSE](./LICENSE).
# najm-os
