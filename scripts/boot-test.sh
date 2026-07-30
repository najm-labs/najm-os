#!/usr/bin/env bash
#
# Headless boot test: build everything, boot it under QEMU with no window,
# capture the serial log, and decide pass/fail from what the kernel's own
# self-tests printed.
#
# This is the closest thing this project has to `cargo test`, and it is
# deliberately built the same way the self-tests themselves are: the
# kernel says out loud what it proved, and this script only judges. It
# does not know what any individual test means - it looks for the failure
# vocabulary the kernel is contractually required to use (FAILURE,
# MISALIGNED, PANIC, EXCEPTION at Ring 0) and for the end-of-run summary
# line that only prints if the kernel got all the way through.
#
# Two things here exist because of specific traps documented in
# docs/GETTING_STARTED.md:
#
#   * `-serial file:` rather than `-serial stdio`. Combined with
#     `-display none`, stdio silently produces *nothing*, which looks
#     exactly like a kernel that died before printing a single byte.
#   * A unique log path per run. Two QEMU instances pointed at the same
#     `-serial file:` target truncate each other's output - another
#     failure that reads as a dead kernel.
#
# The kernel shuts the machine down itself when its self-tests finish, via
# QEMU's isa-debug-exit device (see kernel/src/drivers/qemu.rs). The
# `timeout` below is therefore a backstop for a *hang*, not the normal way
# a run ends - if a run only ever ends by timing out, that is itself a
# finding.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TARGET="x86_64-unknown-none"
PROFILE="${PROFILE:-debug}"
TIMEOUT_SECS="${TIMEOUT_SECS:-90}"
LOG_DIR="${LOG_DIR:-$REPO_ROOT/.boot-logs}"
mkdir -p "$LOG_DIR"
LOG="$LOG_DIR/serial-$(date +%s)-$$.log"

RELEASE_FLAG=()
if [ "$PROFILE" = "release" ]; then
    RELEASE_FLAG=(--release)
fi

echo "==> building kernel ($PROFILE)"
cargo build --manifest-path kernel/Cargo.toml --target "$TARGET" "${RELEASE_FLAG[@]}" || exit 1

echo "==> building userland ($PROFILE)"
for crate_dir in userland/*/; do
    [ -f "$crate_dir/Cargo.toml" ] || continue
    cargo build --manifest-path "$crate_dir/Cargo.toml" --target "$TARGET" "${RELEASE_FLAG[@]}" || exit 1
done

echo "==> packaging boot image"
KERNEL_PATH="$REPO_ROOT/kernel/target/$TARGET/$PROFILE/najm-kernel" \
USERLAND_PATH="$REPO_ROOT/userland/hello/target/$TARGET/$PROFILE/najm-hello" \
USERLAND_FSTEST_PATH="$REPO_ROOT/userland/fstest/target/$TARGET/$PROFILE/najm-fstest" \
    cargo build --manifest-path runner/Cargo.toml "${RELEASE_FLAG[@]}" || exit 1

IMAGE="$(find runner/target -name najm-bios.img -newermt '-1 hour' 2>/dev/null | head -1)"
if [ -z "$IMAGE" ]; then
    IMAGE="$(find runner/target -name najm-bios.img 2>/dev/null | head -1)"
fi
if [ -z "$IMAGE" ]; then
    echo "FAIL: no boot image was produced under runner/target" >&2
    exit 1
fi

# KVM is a large speedup but is not available everywhere (nested virt, CI
# containers, /dev/kvm permissions). Detect rather than require: a boot
# test that cannot run at all is worse than a slow one.
#
# The CPU model matters as much as the accelerator here. QEMU's default
# `qemu64` model exposes neither SMEP nor SMAP, so a kernel that enables
# them correctly and a kernel that does not would produce identical logs
# under it - the security self-tests would be vacuously satisfied. `-cpu
# host` (KVM) and `-cpu max` (TCG) both expose the full feature set, which
# is what makes those checks mean anything.
ACCEL=()
if [ -r /dev/kvm ] && [ -w /dev/kvm ] && [ "${NO_KVM:-0}" != "1" ]; then
    ACCEL=(-enable-kvm -cpu host)
else
    ACCEL=(-cpu max)
fi

echo "==> booting (image: $IMAGE, log: $LOG)"
timeout --foreground "$TIMEOUT_SECS" qemu-system-x86_64 \
    -drive "format=raw,file=$IMAGE" \
    -serial "file:$LOG" \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    -display none \
    -no-reboot \
    -m 512M \
    "${ACCEL[@]}"
QEMU_STATUS=$?

echo
echo "==================== serial log ===================="
cat "$LOG" 2>/dev/null
echo "===================================================="
echo

FAILED=0

if [ "$QEMU_STATUS" -eq 124 ]; then
    echo "FAIL: the kernel never shut the machine down - timed out after ${TIMEOUT_SECS}s." >&2
    echo "      (a hang, or the self-test epilogue was never reached)" >&2
    FAILED=1
fi

# isa-debug-exit reports `(value << 1) | 1`, so the kernel's SUCCESS code
# 0x10 arrives as 33 and its FAILURE code 0x11 as 35. Anything else is
# QEMU itself failing, which is reported separately below.
case "$QEMU_STATUS" in
    33) : ;;                       # kernel-reported success
    35) echo "FAIL: the kernel reported its own self-tests as failed." >&2; FAILED=1 ;;
    124) : ;;                      # already reported above
    0) : ;;                        # no debug-exit device write; fall through to log scanning
    *) echo "FAIL: qemu exited with status $QEMU_STATUS." >&2; FAILED=1 ;;
esac

# Independent of the exit code: scan the log for the failure vocabulary.
# The exit code alone would trust the kernel's own bookkeeping; this
# catches a test that printed a failure but forgot to count it.
if grep -qE 'FAILURE|MISALIGNED|PANIC|BAD:' "$LOG" 2>/dev/null; then
    echo "FAIL: the serial log contains failure markers:" >&2
    grep -nE 'FAILURE|MISALIGNED|PANIC|BAD:' "$LOG" >&2
    FAILED=1
fi

if ! grep -q 'SELF-TEST SUMMARY' "$LOG" 2>/dev/null; then
    echo "FAIL: the kernel never printed its self-test summary - it did not finish." >&2
    FAILED=1
fi

if [ "$FAILED" -eq 0 ]; then
    grep 'SELF-TEST SUMMARY' "$LOG"
    echo "PASS"
fi
exit "$FAILED"
