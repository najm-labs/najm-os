//! The kernel's own test bookkeeping.
//!
//! This project has no `cargo test` and never will in the usual sense:
//! there is no host to run tests on, no test harness to link against, and
//! the things worth testing (a privilege transition, a page table walk, a
//! context switch) only mean anything on real or emulated hardware.
//! Verification is therefore *live*, inside `kernel_main`, printed to
//! serial. That was already true before this module existed.
//!
//! What this adds is the part that was missing: a **verdict**. Previously
//! every self-test printed its own result in its own words, and deciding
//! whether a boot was good meant a human reading forty lines of log and
//! knowing which ones mattered. That does not scale past the point where
//! someone stops reading carefully, which is exactly when a regression
//! slips through.
//!
//! So every check now goes through one of the functions below, which:
//!
//! 1. prints a uniform, greppable line (`[ ok ]` / `[FAIL]`),
//! 2. counts it, and
//! 3. contributes to a single summary line at the end of the boot.
//!
//! Failures print the word `FAILURE`, which is the vocabulary
//! `scripts/boot-test.sh` scans for, and the summary line is what that
//! script requires to have been printed at all - a boot that dies halfway
//! through fails not because anything printed `FAILURE` but because the
//! summary never appeared. Both halves matter: the first catches a broken
//! mechanism, the second catches a kernel that never got far enough to
//! test one.
//!
//! Deliberately *not* a `#[test]`-style registry of test functions to be
//! discovered and run. Ordering is load-bearing in a kernel - the heap
//! cannot be tested before it is mapped, Ring 3 cannot be tested before
//! the GDT is loaded - so the sequence stays explicit in `kernel_main`
//! where it can be read, rather than hidden behind an attribute macro
//! that would run things in link order.

use crate::serial_println;
use core::sync::atomic::{AtomicU32, Ordering};

static PASSED: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);

/// Records the outcome of one check.
///
/// `detail` is printed either way, not just on failure. A passing test
/// that prints *what it observed* ("42 ticks", "mapped at 0x400000")
/// stays useful as a description of how the system actually behaved;
/// one that prints only "ok" is a claim with no evidence behind it, and
/// this project's boot log is meant to be evidence.
pub fn check(name: &str, passed: bool, detail: core::fmt::Arguments) {
    if passed {
        PASSED.fetch_add(1, Ordering::Relaxed);
        serial_println!("[ ok ] {} - {}", name, detail);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        // The literal word FAILURE is what scripts/boot-test.sh greps
        // for. Keep it on this line even though the summary also counts
        // the failure: a log tail that got truncated should still show
        // the failure, and a summary that somehow undercounts should
        // still be contradicted by the individual lines.
        serial_println!("[FAIL] {} - FAILURE: {}", name, detail);
    }
}

/// Convenience wrapper for the common "these two values must match"
/// shape, so the comparison and the reporting can't disagree about which
/// value was expected - a real hazard when both are written out by hand
/// at each call site.
#[allow(dead_code)]
pub fn check_eq<T: PartialEq + core::fmt::Debug>(name: &str, actual: T, expected: T) {
    let passed = actual == expected;
    if passed {
        check(name, true, format_args!("{:?} as expected", actual));
    } else {
        check(
            name,
            false,
            format_args!("expected {:?}, got {:?}", expected, actual),
        );
    }
}

/// How many checks have failed so far. Read by the epilogue to decide
/// which exit code to hand QEMU.
#[allow(dead_code)]
pub fn failures() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// Prints the one line `scripts/boot-test.sh` requires to consider a boot
/// complete, and reports whether everything passed.
///
/// Separated from the shutdown itself (`epilogue` in main.rs) so that the
/// summary is still printed on real hardware, where there is no
/// debug-exit device to shut anything down with.
pub fn report() -> bool {
    let passed = PASSED.load(Ordering::Relaxed);
    let failed = FAILED.load(Ordering::Relaxed);

    serial_println!(
        "Najm Kernel: SELF-TEST SUMMARY - {} passed, {} failed, {} total",
        passed,
        failed,
        passed + failed
    );

    failed == 0
}
