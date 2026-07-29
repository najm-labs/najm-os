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

    crate::halt_loop();
}
