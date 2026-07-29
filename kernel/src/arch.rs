//! Architecture-specific code, isolated behind this module boundary so a
//! future second architecture - aarch64, per ARCHITECTURE.md's "Vision
//! Beyond Desktop" section on mobile support - has a clear, established
//! seam to slot into (`arch::aarch64`, as a sibling of `arch::x86_64`)
//! rather than requiring a retroactive split of code that quietly
//! assumed x86_64 everywhere.

pub mod x86_64;
