//! Everything in this module is specific to the x86_64 architecture -
//! GDT/TSS layout, IDT and interrupt vector numbers, the IRETQ-based
//! Ring 3 transition, and anything else tied to this CPU architecture's
//! own instruction set and data structures. Code outside `arch::x86_64`
//! should not need to know these details; code inside it should not
//! assume anything a second architecture (see `arch.rs`) wouldn't also
//! need to provide.
//!
//! Named to match this dependency's own crate name (`x86_64`) rather
//! than avoiding the collision - `crate::arch::x86_64` and the external
//! `x86_64` crate never actually conflict in practice, since Rust
//! resolves a bare `use x86_64::...` against the extern prelude first,
//! not against sibling or ancestor module names.

pub mod cpu;
pub mod gdt;
pub mod interrupts;
pub mod usermode;
