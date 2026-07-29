//! Re-export of the shared virtual address map.
//!
//! The map itself lives in the `najm-abi` crate (`najm_abi::layout`),
//! because it is not a kernel implementation detail: a userland program's
//! linker script has to agree with it about where images load, and a
//! program that wants to probe the kernel/user boundary has to agree with
//! it about where that boundary is. Two copies of an address map is
//! exactly the kind of duplication that stays correct right up until it
//! silently doesn't.
//!
//! This module exists so kernel code can keep saying `mm::layout::…`,
//! which reads correctly at the call sites - the address map *is* part of
//! memory management from the kernel's point of view, even though it is
//! defined somewhere both sides can see.

pub use najm_abi::layout::*;
