//! Capability-based security: the core primitive.
//!
//! ARCHITECTURE.md commits to capability tokens rather than POSIX
//! UID/GID - unforgeable, kernel-issued permissions, checked by the type
//! system wherever possible instead of as runtime "is this process
//! allowed to" lookups scattered through the code. This is the first
//! concrete implementation of that primitive, demonstrated against
//! something the kernel already does unconditionally today - writing to
//! the serial port (see `serial::write_with_capability`) - specifically
//! so the demonstration is grounded in real, already-working code rather
//! than a hypothetical.
//!
//! One honest limitation, stated up front rather than discovered later:
//! *revocation* of an already-issued capability is necessarily a runtime
//! check, not a compile-time one. Rust's type system has no mechanism to
//! retroactively invalidate a value that already exists in memory - once
//! code holds a `Capability<R>`, the compiler can't un-hand it back. What
//! the type system *does* guarantee is that nothing can call a
//! capability-gated function without first presenting a token of the
//! right type - there's no fallback path that skips the check, because
//! requiring the argument *is* the check. Revocation sits on top of that
//! as an explicit, documented runtime layer, not a weaker version of the
//! same guarantee.

use alloc::collections::BTreeSet;
use core::fmt;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

/// Marker type for the right to write to the kernel's serial console.
/// Uninhabited on purpose (no variants) - it only ever appears as a type
/// parameter, `Capability<SerialWrite>`, and is never itself constructed.
/// Future rights (memory regions, devices, IPC endpoints) follow the same
/// pattern: one marker type per distinct right.
pub enum SerialWrite {}

/// Marker type for the right to read the timer tick counter
/// (`interrupts::timer_ticks`). A second, deliberately unrelated right to
/// `SerialWrite` - proving this pattern generalizes to more than the one
/// thing it was first demonstrated against matters more than the
/// specific right chosen; this one was picked because `timer_ticks()`
/// already existed and already had no access control on it at all,
/// exactly like `serial::_print` did before `write_with_capability`.
pub enum TimerRead {}

static NEXT_CAPABILITY_ID: AtomicU64 = AtomicU64::new(0);

/// IDs of capabilities that have been explicitly revoked. Checked by
/// every function that exercises a capability's right - see the safety
/// note in the module docs above on why this has to be a runtime lookup.
static REVOKED: Mutex<BTreeSet<u64>> = Mutex::new(BTreeSet::new());

/// A specific, unforgeable grant of the right `R`.
///
/// "Unforgeable" is enforced structurally, not by convention: the only
/// way to produce one is `issue()`, which is `pub(crate)` - nothing
/// outside this crate can create a `Capability` out of thin air. Once
/// Realms exist as their own compilation/trust boundary (see
/// ARCHITECTURE.md section 3), this `pub(crate)` line is exactly where
/// that boundary needs to sit.
pub struct Capability<R> {
    id: u64,
    _right: PhantomData<R>,
}

impl<R> Capability<R> {
    /// Issues a brand new capability for right `R`. Kernel-Core-only by
    /// construction (`pub(crate)`) - see the struct docs above.
    pub(crate) fn issue() -> Self {
        let id = NEXT_CAPABILITY_ID.fetch_add(1, Ordering::Relaxed);
        Capability {
            id,
            _right: PhantomData,
        }
    }

    /// Delegates a copy of this capability to be held elsewhere.
    ///
    /// Named `derive`, not `clone`: `Capability` deliberately doesn't
    /// implement `Clone`/`Copy`, so every duplication is a visible,
    /// grep-able call site rather than something that happens silently
    /// via `#[derive(Clone)]` on a struct someone glances past.
    ///
    /// This is real delegation but not yet real *attenuation* - the
    /// copy carries exactly the same right as the original, not a
    /// narrower one. ARCHITECTURE.md's "delegatable but attenuable"
    /// language is only half-implemented here; true attenuation (e.g.
    /// downgrading a hypothetical read-write right to read-only) needs
    /// per-right logic this single-right capability doesn't have a
    /// reason to grow yet, and is a real gap to come back to, not a
    /// finished feature being undersold.
    pub fn derive(&self) -> Self {
        Capability {
            id: self.id,
            _right: PhantomData,
        }
    }

    /// Permanently revokes this capability - and, because `derive()`
    /// copies share the same `id` rather than minting a distinct
    /// sub-identity, every other outstanding copy derived from it too.
    /// Revocation is all-or-nothing for now; per-copy revocation is
    /// future work that needs derived capabilities to carry their own
    /// identity, not just their parent's.
    pub fn revoke(self) {
        REVOKED.lock().insert(self.id);
    }

    /// Whether this specific capability (by shared `id`, so this also
    /// reflects revocation of any capability it was derived from, or
    /// that was derived from it) has been revoked.
    pub fn is_revoked(&self) -> bool {
        REVOKED.lock().contains(&self.id)
    }
}

/// Returned when an operation is attempted with a capability that's been
/// revoked. Deliberately just one variant for now - this grows real
/// structure (which right was missing, which Realm attempted it) once
/// there's more than a single capability type to report about.
#[derive(Debug)]
pub enum CapabilityError {
    Revoked,
}

impl fmt::Display for CapabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CapabilityError::Revoked => write!(f, "capability has been revoked"),
        }
    }
}
