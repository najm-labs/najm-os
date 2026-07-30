//! Security primitives. Currently just the capability token system in
//! `capability` - expected to grow the Realm Assignment verification
//! machinery ARCHITECTURE.md section 2e describes (publisher signature
//! checking, trust-tier bookkeeping) as a sibling here once there's an
//! installer/package layer for it to actually verify.

pub mod capability;
pub mod sha256;
