//! A first, minimal Realm prototype.
//!
//! ARCHITECTURE.md describes three Realm types - Gaming, Vault, Home -
//! distinguished by scheduling class and capability profile, not just by
//! name. This is the first code that actually gives a task a *specific,
//! different* set of capabilities depending on which Realm it belongs to -
//! not a full Realm (there's no separate address space, no distinct
//! scheduler class yet, and none of the ARCHITECTURE.md section 2e
//! Realm Assignment verification - the `name` field below is trusted
//! outright, exactly the gap that section describes), but the first
//! place a task's capability set is genuinely its own, carried on its
//! own heap-allocated context, rather than a value borrowed from a
//! `static` in `main.rs`.

use crate::security::capability::{Capability, SerialWrite, TimerRead};
use crate::serial_println;
use crate::sched::task;
use alloc::boxed::Box;

/// What a Realm-flavored task actually carries: its name (diagnostics
/// only - nothing here verifies it, see the module docs above) and
/// whichever capabilities this specific Realm profile was granted at
/// spawn time.
///
/// Deliberately concrete - named fields per right - rather than a
/// generic bag of capabilities. A real Realm eventually needs arbitrary,
/// extensible capability sets, but that needs either type erasure
/// (`Box<dyn Any>`) or an enum covering every right, and building that
/// machinery before there's a second consumer of it would be guessing at
/// a shape rather than discovering one from real use.
/// A Realm's identity and rights, in the form a *process* can be given.
///
/// This is deliberately not the same thing as [`RealmContext`], and the
/// difference is worth being precise about, because it looks like
/// duplication and is not.
///
/// `RealmContext` holds typed `Capability<R>` tokens. That is the
/// stronger mechanism - a function requiring a token cannot be called
/// without one, so a missing right is a value that does not exist rather
/// than a check that could be skipped. It works because the holder is
/// *kernel code*, which can be handed a Rust value.
///
/// A Ring 3 process cannot hold a Rust value. Its rights have to be
/// something the kernel consults on its behalf when it makes a syscall,
/// which means a runtime lookup keyed by identity - a bitmask. That is
/// genuinely weaker, and pretending otherwise would be the kind of
/// security theatre this project's documentation exists to avoid. What
/// keeps it honest is that the bitmask is *kernel-side*: the process
/// never holds it, cannot present it, and cannot modify it. It is
/// capability-*based* access control in the sense that rights are
/// per-process and unforgeable, without the compile-time guarantee that
/// only applies within the kernel.
#[derive(Debug, Clone, Copy)]
pub struct RealmProfile {
    /// Diagnostic name. Still trusted outright - see the module docs and
    /// ARCHITECTURE.md section 2e, which describes the verification that
    /// has to sit in front of this and does not exist yet.
    pub name: &'static str,
    /// One of `najm_abi::realm_kind`.
    pub kind: u64,
    /// Bitmask of `najm_abi::capability_bits`.
    pub capabilities: u64,
}

impl RealmProfile {
    /// Whether this Realm holds `right`, one of the
    /// `najm_abi::capability_bits` constants.
    pub fn allows(&self, right: u64) -> bool {
        self.capabilities & right == right
    }
}

/// The default any application gets, per ARCHITECTURE.md section 2e:
/// elevated placement is a credential earned in advance, never a request
/// honoured at install time. Broad but fully auditable.
pub const HOME: RealmProfile = RealmProfile {
    name: "Home Realm",
    kind: najm_abi::realm_kind::HOME,
    capabilities: najm_abi::capability_bits::SERIAL_WRITE
        | najm_abi::capability_bits::TIMER_READ
        | najm_abi::capability_bits::FILE_READ
        // Both IPC rights: a Home Realm application offering a service to
        // other applications is ordinary, not privileged.
        | najm_abi::capability_bits::IPC_CREATE
        | najm_abi::capability_bits::IPC_CONNECT
        | najm_abi::capability_bits::SURFACE_CREATE
        | najm_abi::capability_bits::INPUT_READ,
};

/// Bounded-latency scheduling and exclusive scanout. Note what it does
/// *not* get: `FILE_WRITE` and `PROCESS_SPAWN`. A game needs the CPU and
/// the screen; it does not need to write arbitrary files or launch
/// arbitrary programs, and the Realm that gets the most privileged
/// treatment from the scheduler is exactly the one where a narrow
/// capability set matters most.
pub const GAMING: RealmProfile = RealmProfile {
    name: "Gaming Realm",
    kind: najm_abi::realm_kind::GAMING,
    capabilities: najm_abi::capability_bits::SERIAL_WRITE
        | najm_abi::capability_bits::TIMER_READ
        | najm_abi::capability_bits::FILE_READ
        | najm_abi::capability_bits::SURFACE_CREATE
        | najm_abi::capability_bits::INPUT_READ
        | najm_abi::capability_bits::EXCLUSIVE_SCANOUT,
};

/// Integrity over performance. No `SERIAL_WRITE` (the console is a shared
/// resource other Realms observe), no `INPUT_READ` (an input stream is an
/// introspection channel), no `SURFACE_CREATE` from other Realms' point
/// of view. Its window is drawn by the compositor with a trust indicator
/// no other Realm can reproduce - see ARCHITECTURE.md section 2d.
pub const VAULT: RealmProfile = RealmProfile {
    name: "Vault Realm",
    kind: najm_abi::realm_kind::VAULT,
    capabilities: najm_abi::capability_bits::TIMER_READ
        | najm_abi::capability_bits::FILE_READ
        | najm_abi::capability_bits::FILE_WRITE
        | najm_abi::capability_bits::SURFACE_CREATE,
};

/// The compositor and other Core-adjacent services. Not assignable to an
/// installed application by any path - it is listed so a process can
/// observe that it is running in it, never request it.
/// Unconstructed by design: nothing may be *placed* in this Realm yet,
/// which is the point. It is defined so a process can observe it and so
/// the compositor can name it, never so an installer can request it.
#[allow(dead_code)]
pub const SYSTEM: RealmProfile = RealmProfile {
    name: "System Realm",
    kind: najm_abi::realm_kind::SYSTEM,
    capabilities: u64::MAX,
};

pub struct RealmContext {
    pub name: &'static str,
    pub serial_cap: Option<Capability<SerialWrite>>,
    pub timer_cap: Option<Capability<TimerRead>>,
}

/// Spawns a task carrying its own `RealmContext` rather than one that
/// reaches for capabilities declared in `main.rs`. Whatever
/// `serial_cap`/`timer_cap` this is called with *is* that task's entire
/// capability profile - there is no other channel for it to acquire
/// more, which is the actual property this milestone demonstrates.
pub fn spawn(
    name: &'static str,
    serial_cap: Option<Capability<SerialWrite>>,
    timer_cap: Option<Capability<TimerRead>>,
) {
    let context = Box::new(RealmContext {
        name,
        serial_cap,
        timer_cap,
    });

    // `Box::into_raw` hands ownership off to the task itself - it's
    // reconstructed with `Box::from_raw` at the top of
    // `realm_task_entry` and lives for as long as that task runs. There
    // is no matching cleanup for a task that halts instead of properly
    // exiting (see task.rs's documented lack of a task-removal
    // mechanism) - this leaks the context in that case, the same
    // already-documented limitation as the rest of task lifecycle right
    // now, not a new one introduced here.
    let context_ptr = Box::into_raw(context) as *mut u8;

    task::spawn_with_context(realm_task_entry, context_ptr);
}

extern "C" fn realm_task_entry(context_ptr: *mut u8) -> ! {
    // Safety: `context_ptr` is exactly what `spawn` passed to
    // `task::spawn_with_context` above, which came from `Box::into_raw`
    // on a `RealmContext` - the same type being reconstructed here, and
    // this is the only place that happens for this particular pointer.
    let context = unsafe { Box::from_raw(context_ptr as *mut RealmContext) };

    for i in 0..3 {
        // Every line below goes through the kernel Core's own
        // unconditional `serial_println!` to *report* what happened -
        // that's Core's diagnostic voice, not this task exercising a
        // right it might not have. The thing actually being tested is
        // which branch runs: `Some(cap)` only exists to reach into if
        // `spawn` was called with one, so a Realm profile that wasn't
        // granted a capability has no value to present here at all -
        // not a check that could be bypassed, an argument that doesn't
        // exist.
        match &context.serial_cap {
            Some(cap) => {
                let _ = crate::drivers::serial::write_with_capability(
                    cap,
                    format_args!(
                        "[{}] iteration {}: wrote via its own SerialWrite capability\n",
                        context.name, i
                    ),
                );
            }
            None => serial_println!(
                "[{}] iteration {}: has no SerialWrite capability - cannot write, by construction",
                context.name,
                i
            ),
        }

        match &context.timer_cap {
            Some(cap) => match crate::arch::x86_64::interrupts::ticks_with_capability(cap) {
                Ok(ticks) => serial_println!(
                    "[{}] iteration {}: read {} ticks via its own TimerRead capability",
                    context.name,
                    i,
                    ticks
                ),
                Err(err) => serial_println!(
                    "[{}] iteration {}: TimerRead capability rejected ({})",
                    context.name,
                    i,
                    err
                ),
            },
            None => serial_println!(
                "[{}] iteration {}: has no TimerRead capability - cannot read ticks, by construction",
                context.name,
                i
            ),
        }

        task::yield_now();
    }

    // Exiting rather than parking means this task's stack is freed and
    // the scheduler can eventually observe that nothing is left to run.
    // The `RealmContext` this task owns is dropped here too, on the way
    // out - `Box::from_raw` above took ownership of it, so letting it
    // fall out of scope at the end of the task is what reclaims it.
    // Before `exit_task` existed, a finished Realm task parked forever
    // and leaked its context; that is now genuinely fixed rather than
    // documented.
    drop(context);
    task::exit_task();
}
