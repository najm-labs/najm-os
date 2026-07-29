# Contributing to Najm OS

Thanks for considering contributing. This is a kernel project — the bar for correctness is higher than typical application code, but that shouldn't be intimidating: small, well-scoped contributions are exactly how a project like this grows.

## Before You Start

1. **Read [ARCHITECTURE.md](./docs/ARCHITECTURE.md) first.** It explains *why* the kernel is designed the way it is (hybrid kernel, capability-based security, the Realm primitive). PRs that conflict with the documented architecture without an accompanying discussion/RFC will likely be redirected there first.
2. **Check open issues and discussions** before starting significant work, to avoid duplicate effort.
3. **For anything larger than a bug fix** (new subsystem, scheduler changes, capability model changes), open an RFC-style issue first. Kernel code is expensive to unwind once merged — cheap to discuss up front.

## What This Project Needs Most

Roughly in order of current priority:

1. **Core kernel work**: memory management, scheduler implementation, boot process.
2. **Realm isolation primitive**: capability token implementation, Realm boundary enforcement.
3. **Driver work**: this is the highest-risk, highest-need area — see the Driver Strategy section in ARCHITECTURE.md.
4. **Security review**: adversarial review of the capability model is extremely valuable even before there's much code to attack.
5. **Documentation and testing infrastructure.**

## Development Setup

- Rust toolchain via `rustup`, not your distro's package manager — kernel work requires nightly features and a `no_std` custom target.
- Target: `x86_64-unknown-none` (bare-metal, no host OS underneath).
- QEMU for testing without physical hardware.

(A full `SETUP.md` with exact toolchain versions and build steps will be added once the initial bootable skeleton lands — see open issues for current status.)

## Code Standards

- **No `unsafe` without a comment justifying it.** In kernel code `unsafe` is sometimes unavoidable, but every block must explain the invariant that makes it sound.
- **Capability checks belong in the type system wherever possible** — see ARCHITECTURE.md section 3. If you find yourself writing a runtime permission check that could be a required token parameter instead, prefer the type-level version.
- **No stringly-typed error handling.** Use proper `enum`-based error types; kernel panics from unhandled error paths are not acceptable outside of genuinely unrecoverable states.
- Format with `rustfmt` and lint with `clippy` before opening a PR. CI will enforce this once set up.

## Pull Request Process

1. Fork, branch, and make your change against `main`.
2. Include a clear description of *why*, not just *what* — especially for anything touching the scheduler or capability model.
3. Add or update tests where the change is testable outside real hardware (unit tests for capability logic, scheduler simulation, etc.).
4. Expect review to be thorough. This is normal for kernel code, not a sign your contribution is unwelcome.

## Reporting Security Issues

Do **not** open a public issue for a security vulnerability. See [SECURITY.md](./SECURITY.md) for responsible disclosure instructions.

## Questions

Open a Discussion thread if you're not sure where something fits, or if you want feedback on an idea before investing time in it.
