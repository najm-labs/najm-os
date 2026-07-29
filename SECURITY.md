# Security Policy

Najm OS is kernel-level software with an explicit security model (capability-based isolation between Realms — see [ARCHITECTURE.md](./docs/ARCHITECTURE.md)). Vulnerabilities here have serious real-world impact: a broken Realm boundary could mean a compromised Gaming Realm reading Vault Realm memory, or a capability escalation bypassing the entire isolation model.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Until a dedicated security contact/email is established (early-stage project — see open issues for status), report privately via GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability) feature on this repository, if enabled, or contact a maintainer directly through a private channel rather than a public one.

Please include:

- A clear description of the vulnerability and its impact (which Realm guarantee it breaks, and how).
- Steps to reproduce, or a minimal proof-of-concept if possible.
- Any suggested mitigation, if you have one.

## What Counts as a Security Issue Here

Given the project's current stage (pre-boot, early architecture), most "security issues" right now will be **design flaws**, not exploitable code:

- A gap in the capability model that would allow privilege escalation between Realms.
- A scheduler design that could allow one Realm to starve or observe another (timing side-channels included).
- A flaw in the attestation approach described in ARCHITECTURE.md section 5.

These are just as valuable to report privately as a code-level bug would be in a more mature codebase.

## Response Process

This is an early-stage, community-driven project without a dedicated security team yet. Reports will be acknowledged as promptly as possible by whoever is maintaining the project at the time, and this document will be updated with formal response-time commitments once the project has the infrastructure to support them.

## Disclosure

Coordinated disclosure is expected: please give maintainers reasonable time to address a report before any public disclosure. Exact timelines will be formalized as the project matures.
