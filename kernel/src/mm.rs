//! Memory management: physical frame allocation (`memory`) and the
//! kernel heap built on top of it (`allocator`). Named `mm`, not spelled
//! out, to match the naming convention most kernel codebases (Linux
//! included) already use for this exact subsystem - familiar at a glance
//! to anyone who's read kernel source before.

pub mod address_space;
pub mod allocator;
pub mod frame_pool;
pub mod kstack;
pub mod layout;
pub mod memory;
