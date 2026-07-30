//! Scheduling classes: what "Gaming Realm" actually means to the
//! scheduler.
//!
//! ARCHITECTURE.md section 2 says a Realm is defined by three
//! kernel-enforced properties, and that the third is a *scheduler class,
//! not just a priority number*. Until now that was the one of the three
//! with no implementation behind it: every task went into one FIFO queue
//! and got one tick of CPU, whatever Realm it belonged to. A Gaming Realm
//! task and a background indexer were treated identically.
//!
//! ## What a class is, and why not a priority number
//!
//! A priority number answers "who goes first". That is necessary and not
//! sufficient, because the property a game actually needs is not "runs
//! first" but **bounded worst-case latency**: a guarantee about how long
//! it can be made to wait, which depends on how long *other* tasks are
//! allowed to hold the CPU, not on how the queue is ordered.
//!
//! So a class carries two numbers, and the second is the interesting one:
//!
//! | Class | Runs before | Quantum | Worst-case wait behind one peer |
//! |---|---|---|---|
//! | [`Realtime`](SchedClass::Realtime) | everything | 1 tick (10 ms) | 10 ms |
//! | [`Normal`](SchedClass::Normal) | Background | 3 ticks (30 ms) | 30 ms |
//! | [`Background`](SchedClass::Background) | nothing | 6 ticks (60 ms) | 60 ms |
//!
//! A short quantum costs throughput (more context switches per second)
//! and buys latency. That trade is exactly backwards for a background
//! job, which wants to be left alone to finish, and exactly right for a
//! game, which would rather be interrupted often than made to wait once.
//!
//! ## Preemption is immediate across classes
//!
//! A `Realtime` task becoming ready does not wait for the running task's
//! quantum to expire - it takes the CPU at the next tick. Without that,
//! the latency figure above would be "your quantum plus whatever the
//! task that happened to be running was entitled to", which is a bound
//! set by the *lowest* priority task on the system. That is not a
//! guarantee; it is a hope.
//!
//! ## Starvation, and why aging is not optional
//!
//! Strict priority means a busy Gaming Realm can starve everything else
//! forever. ARCHITECTURE.md is explicit that this is not acceptable -
//! background work should be "deprioritized while a Gaming Realm is in
//! the foreground, without being frozen entirely", precisely to avoid the
//! "everything else stutters" failure of naive priority boosting.
//!
//! [`STARVATION_LIMIT_TICKS`] is what implements that: a task that has
//! been ready and not run for that long is promoted ahead of higher
//! classes for one dispatch. It is a blunt instrument compared to a
//! proper deadline scheduler (EEVDF and friends), and it is chosen for
//! being *comprehensible* - the guarantee it makes is "nothing waits more
//! than half a second", which can be stated, tested, and reasoned about
//! at a glance. The exact algorithm remains an open question in
//! ARCHITECTURE.md section 4; this closes the gap between "no classes at
//! all" and that eventual design.

use crate::arch::x86_64::interrupts::TIMER_HZ;

/// How a task's CPU time is governed.
///
/// Ordered so that a larger discriminant means higher priority, which
/// lets the scheduler compare classes with `>` rather than a match arm
/// that would need updating every time a class is added.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum SchedClass {
    /// Work that should happen when nothing else wants the CPU: indexing,
    /// prefetching, telemetry. Long quantum, lowest priority.
    Background = 0,
    /// The default. Home and Vault Realms, and every kernel task.
    Normal = 1,
    /// Bounded-latency work: the Gaming Realm, and the compositor, which
    /// has to present a frame on time or the latency guarantee it exists
    /// to serve is meaningless.
    Realtime = 2,
}

impl SchedClass {
    /// How many timer ticks a task of this class may hold the CPU before
    /// being preempted, absent anything more urgent becoming ready.
    ///
    /// At [`TIMER_HZ`] = 100 these are 10, 30 and 60 milliseconds.
    pub const fn quantum_ticks(self) -> u64 {
        match self {
            SchedClass::Realtime => 1,
            SchedClass::Normal => 3,
            SchedClass::Background => 6,
        }
    }

    /// The worst-case time, in milliseconds, that a task of this class
    /// can be kept waiting by a single peer of the same class.
    ///
    /// Derived from the quantum rather than stated independently, so the
    /// documented guarantee and the enforced behaviour cannot drift
    /// apart - a comment claiming 10 ms next to a quantum that had been
    /// changed to 5 ticks would be worse than no comment.
    #[allow(dead_code)]
    pub const fn worst_case_wait_ms(self) -> u64 {
        self.quantum_ticks() * 1000 / TIMER_HZ
    }

    pub const fn name(self) -> &'static str {
        match self {
            SchedClass::Realtime => "realtime",
            SchedClass::Normal => "normal",
            SchedClass::Background => "background",
        }
    }

    /// The scheduling class a Realm's processes run in.
    ///
    /// This is the line that connects ARCHITECTURE.md's Realm model to
    /// the scheduler. Note that Vault is `Normal`, not lower: its
    /// document says "performance is not its priority, integrity is",
    /// which means *not privileged*, not *penalized* - a Vault Realm that
    /// ran at background priority would be sluggish for the user in
    /// exactly the situations where they are doing something they care
    /// about.
    pub const fn for_realm(kind: u64) -> SchedClass {
        match kind {
            najm_abi::realm_kind::GAMING => SchedClass::Realtime,
            najm_abi::realm_kind::SYSTEM => SchedClass::Realtime,
            najm_abi::realm_kind::VAULT => SchedClass::Normal,
            _ => SchedClass::Normal,
        }
    }
}

/// How long a ready task may go unscheduled before it is promoted ahead
/// of higher-priority classes for one dispatch.
///
/// 50 ticks is half a second at [`TIMER_HZ`]. That number is a policy
/// choice with a stateable consequence: **no ready task on this system
/// waits more than half a second**, no matter how busy a Realtime Realm
/// is. Whether half a second is the right bound is a question about
/// perceived responsiveness rather than about correctness, and it is
/// deliberately one constant so it can be argued about in one place.
pub const STARVATION_LIMIT_TICKS: u64 = 50;

/// The minimum gap between two anti-starvation promotions.
///
/// Without this, the anti-starvation rule has a failure mode that only
/// appears with more than a couple of waiting tasks, and it is not
/// obvious from reading the rule: when the starvation limit expires,
/// *every* task that has been waiting becomes eligible at the same
/// moment, and they are each promoted in turn on consecutive ticks. Ten
/// starved tasks means ten consecutive donated ticks, so a realtime
/// task's worst-case wait is not "one rescue" but "however many tasks
/// happened to be waiting" - which is exactly the kind of bound that
/// holds in testing and collapses under load.
///
/// Rate-limiting the rescues fixes it without changing the guarantee they
/// provide. A starved task still runs; it may simply have to wait a few
/// more ticks for its turn among the other starved tasks. What is bounded
/// now is the cost to the realtime class: at most one donated tick in
/// every five, i.e. at most 20% of the CPU, regardless of how many tasks
/// are queued.
pub const PROMOTION_INTERVAL_TICKS: u64 = 5;

/// The worst wait a `Realtime` task is allowed to suffer under the boot
/// self-test's load, in ticks. Enforced by a self-test, not merely
/// documented.
///
/// This is a *budget*, and the distinction from a derived bound is worth
/// being exact about, because the number is workload-dependent and
/// pretending otherwise would make it meaningless. Three things add to
/// the wait, and all three are legitimate:
///
/// - **Other realtime tasks.** A Gaming Realm process and the compositor
///   are both realtime and share the class round-robin, each holding a
///   quantum.
/// - **Anti-starvation rescues.** A promoted task runs for exactly one
///   tick (see `Task::promoted`) and rescues are rate-limited to one in
///   [`PROMOTION_INTERVAL_TICKS`], so this contributes at most 20%.
/// - **Long Ring 0 work in a realtime peer.** The dominant term, and the
///   interesting one. A full-screen recomposite writes close to a million
///   pixels to framebuffer device memory one at a time; in an unoptimized
///   debug build that is tens of milliseconds. It *is* preemptible - it
///   runs at Ring 0 with interrupts enabled and the timer takes the CPU
///   away on schedule - but the task doing it is a realtime peer, so the
///   time it legitimately gets is time the probe waits.
///
/// 8 ticks (80 ms) is what that adds up to across the boot's full
/// workload, measured twice independently: the probe times itself, and
/// the scheduler records what it dispatched.
///
/// **This is not a good number for gaming, and the useful thing is to say
/// so rather than defend it.** 80 ms is five frames at 60 Hz. The three
/// fixes, in the order they would help most: damage-tracked compositing
/// so a frame redraws only what changed instead of the whole screen; a
/// higher [`TIMER_HZ`], which is nearly free; and genuine deadline
/// scheduling, which ARCHITECTURE.md section 4 already lists as an open
/// question. What this milestone establishes is that the number exists,
/// is measured, and fails the build when it regresses - which is the
/// prerequisite for any of those being worth doing.
pub const REALTIME_LATENCY_BUDGET_TICKS: u64 = 8;

/// Per-class scheduling statistics, for the boot report and the latency
/// self-test.
#[derive(Debug, Clone, Copy, Default)]
pub struct ClassStats {
    /// How many times a task of this class was dispatched.
    pub dispatches: u64,
    /// The longest any task of this class waited between becoming ready
    /// and being given the CPU, in ticks.
    ///
    /// This is the number the whole module exists to keep small for
    /// `Realtime`, and it is measured rather than assumed - a scheduler
    /// that *claims* bounded latency and one that delivers it produce
    /// identical code until something measures the wait.
    pub max_wait_ticks: u64,
    /// How many times a task of this class was promoted past a
    /// higher-priority class because it had waited too long. A non-zero
    /// value here is the anti-starvation guarantee doing its job; a value
    /// that grows without bound would mean the system is oversubscribed.
    pub promotions: u64,
}
