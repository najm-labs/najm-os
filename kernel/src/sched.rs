//! Task scheduling. Currently just the cooperative scheduler in `task` -
//! expected to grow a preemptive path, and eventually the per-Realm
//! scheduling classes ARCHITECTURE.md section 4 describes, as siblings
//! here rather than as a rewrite of `task` itself.

pub mod task;
