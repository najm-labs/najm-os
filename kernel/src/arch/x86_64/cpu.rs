//! CPU feature detection and the hardware protections this kernel turns
//! on.
//!
//! Everything here is a memory-protection mechanism the x86_64 hardware
//! already implements and that is **off by default**. That last part is
//! the reason this module exists as its own file rather than three lines
//! in `kernel_main`: each of these is a mitigation whose absence is
//! invisible. Nothing crashes, nothing warns, and every test still
//! passes on a kernel with all of them disabled - right up until the day
//! one of them was the thing standing between a bug and an exploit.
//!
//! ## What gets enabled, and what each one actually stops
//!
//! | Feature | Without it | With it |
//! |---|---|---|
//! | **NX** (EFER.NXE) | Every mapped page is executable. The `NO_EXECUTE` page-table bit does not merely have no effect - setting it is a *reserved bit violation* and faults. So W^X cannot even be expressed. | Data pages can be marked non-executable, which is what makes W^X below mean anything. |
//! | **W^X** (page flags) | A stack, a heap, or a `.data` section is executable. An attacker who can write bytes anywhere can execute them there. | Writable implies non-executable; executable implies read-only. Code injection needs a separate mapping step. |
//! | **SMEP** (CR4.SMEP) | Ring 0 can execute instructions from a user page. A kernel bug that redirects execution to an attacker-chosen address gets to run attacker-written code *at Ring 0* - the classic `ret2usr` escalation. | The CPU faults on any Ring 0 instruction fetch from a user-accessible page, turning that entire class of privilege escalation into a fault. |
//! | **SMAP** (CR4.SMAP) | Ring 0 can read and write user pages freely, so a missing pointer check is silently harmless-looking. | Ring 0 access to user pages faults unless explicitly permitted for one window ([`with_user_access`]). A forgotten validation now fails loudly the first time it runs. |
//! | **UMIP** (CR4.UMIP) | Ring 3 can execute `sgdt`/`sidt`/`sldt`/`str`/`smsw` and read out the addresses of the GDT, IDT and TSS - a free defeat of any address-space layout randomization the kernel might do. | Those instructions fault at Ring 3. |
//! | **CR0.WP** | Ring 0 writes ignore the read-only page bit. The kernel can silently overwrite its own `.rodata` and any page it deliberately mapped read-only. | Read-only means read-only for the kernel too. |
//!
//! ## SMAP is the one with a cost, and it is worth paying
//!
//! SMEP, UMIP and WP are free: turn them on and correct code never
//! notices. SMAP is different - it breaks every legitimate kernel access
//! to user memory too, which is exactly the point. Copying a syscall's
//! buffer has to become an explicit, bracketed operation
//! ([`with_user_access`], which sets and clears the AC flag around it)
//! rather than an ordinary pointer dereference.
//!
//! That is a feature and not a tax. The bracket makes "the kernel is
//! deliberately touching user memory here" a visible, greppable event.
//! Any *other* dereference of a user pointer - the kind that happens
//! because someone forgot a check - now faults immediately rather than
//! working correctly ninety-nine times and leaking kernel memory the
//! hundredth. It converts a review problem into a hardware one.
//!
//! ## Detection, not assumption
//!
//! Every feature here is probed via CPUID and skipped if absent, because
//! this kernel has to boot on hardware that does not have them: SMAP
//! arrived with Broadwell (2014), UMIP with Cannon Lake (2017), and QEMU's
//! default `qemu64` CPU model exposes neither. Enabling a CR4 bit the CPU
//! does not implement is a general protection fault at boot, i.e. a
//! kernel that does not start - the worst possible way to fail at
//! *adding security*. What is reported in the boot log is what was
//! actually enabled, never what was requested.

use crate::serial_println;
use core::arch::x86_64::__cpuid_count;
use core::sync::atomic::{AtomicBool, Ordering};

/// Which protections this CPU implements, as probed at boot.
#[derive(Debug, Clone, Copy, Default)]
pub struct Features {
    /// Execute-disable paging bit (`NO_EXECUTE`). Universal on x86_64 in
    /// practice, but probed rather than assumed because enabling
    /// `EFER.NXE` without it is undefined.
    pub nx: bool,
    /// Supervisor Mode Execution Prevention.
    pub smep: bool,
    /// Supervisor Mode Access Prevention.
    pub smap: bool,
    /// User-Mode Instruction Prevention.
    pub umip: bool,
}

/// Whether SMAP was actually enabled.
///
/// Read on every user-memory access, so it is an atomic rather than
/// living inside a lock: [`with_user_access`] runs in syscall paths and
/// must not be able to block.
static SMAP_ENABLED: AtomicBool = AtomicBool::new(false);

/// Probes CPUID for the features above.
pub fn detect() -> Features {
    // Leaf 0x8000_0001 is the AMD-defined extended feature leaf that
    // Intel also implements; EDX bit 20 is NX. Guarding on the maximum
    // supported extended leaf first, because CPUID on an unsupported leaf
    // does not fail - it returns whatever the highest supported leaf
    // returns, which would be a plausible-looking wrong answer.
    //
    // `__cpuid_count` is safe on this target - the instruction is
    // unprivileged and always defined - but the *results* are not
    // self-describing, which is why every leaf is checked for support
    // before its value is used. CPUID on an unsupported leaf does not
    // fail; it returns whatever the highest supported leaf returns, which
    // would be a plausible-looking wrong answer.
    let max_extended = __cpuid_count(0x8000_0000, 0).eax;
    let nx = if max_extended >= 0x8000_0001 {
        __cpuid_count(0x8000_0001, 0).edx & (1 << 20) != 0
    } else {
        false
    };

    // Leaf 7 subleaf 0 carries the structured extended feature flags.
    // Same guard: leaf 7 only exists if leaf 0 says the maximum basic
    // leaf reaches it.
    let max_basic = __cpuid_count(0, 0).eax;
    let (smep, smap, umip) = if max_basic >= 7 {
        let leaf7 = __cpuid_count(7, 0);
        (
            leaf7.ebx & (1 << 7) != 0,
            leaf7.ebx & (1 << 20) != 0,
            leaf7.ecx & (1 << 2) != 0,
        )
    } else {
        (false, false, false)
    };

    Features {
        nx,
        smep,
        smap,
        umip,
    }
}

/// Enables every detected protection, and reports what actually happened.
///
/// Must run **before** any page is mapped with `NO_EXECUTE`: setting bit
/// 63 of a page table entry while `EFER.NXE` is clear is a reserved-bit
/// violation, which faults on access rather than being ignored. In
/// practice that means this is one of the first things `kernel_main`
/// does, before `init_heap`.
pub fn init() -> Features {
    use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};
    use x86_64::registers::model_specific::{Efer, EferFlags};

    let features = detect();

    if features.nx {
        // Safety: `nx` was just confirmed via CPUID, and this only sets
        // NXE - every other EFER bit (notably LME and LMA, which are what
        // keep the CPU in long mode) is preserved by `update`'s
        // read-modify-write. Clearing either of those would reset the
        // machine.
        unsafe {
            Efer::update(|flags| flags.insert(EferFlags::NO_EXECUTE_ENABLE));
        }
    }

    // CR0.WP: makes the kernel itself respect read-only page mappings.
    // The bootloader generally sets this already; setting it
    // unconditionally costs nothing and removes the dependency on that
    // remaining true. Without it, every read-only mapping this kernel
    // makes - `.rodata`, a code page after W^X, a shared page mapped
    // read-only into a Realm - is advisory as far as Ring 0 is concerned.
    //
    // Safety: WRITE_PROTECT is architecturally defined on every x86_64
    // CPU and needs no probe. `update` preserves PG and PE, which must
    // stay set.
    unsafe {
        Cr0::update(|flags| flags.insert(Cr0Flags::WRITE_PROTECT));
    }

    // Safety for all three below: each bit is set only after CPUID
    // reported the corresponding feature. Setting a CR4 bit the CPU does
    // not implement raises a general protection fault, which this early
    // in boot means a machine that never starts.
    if features.smep {
        unsafe {
            Cr4::update(|flags| flags.insert(Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION));
        }
    }

    if features.smap {
        unsafe {
            Cr4::update(|flags| flags.insert(Cr4Flags::SUPERVISOR_MODE_ACCESS_PREVENTION));
        }
        // Recorded before anything can touch user memory, so
        // `with_user_access` is never wrong about whether the AC flag
        // needs managing.
        SMAP_ENABLED.store(true, Ordering::SeqCst);
    }

    if features.umip {
        unsafe {
            Cr4::update(|flags| flags.insert(Cr4Flags::USER_MODE_INSTRUCTION_PREVENTION));
        }
    }

    serial_println!(
        "Najm Kernel: CPU protections - NX {}, SMEP {}, SMAP {}, UMIP {}, CR0.WP on",
        enabled_str(features.nx),
        enabled_str(features.smep),
        enabled_str(features.smap),
        enabled_str(features.umip)
    );

    if !features.smep || !features.smap {
        // Said plainly rather than left to be noticed. A CPU model
        // without these is a perfectly valid target, but a boot log that
        // does not distinguish "this kernel does not implement SMAP" from
        // "this CPU does not have SMAP" is a log that lets a real
        // regression hide behind a hardware limitation.
        serial_println!(
            "Najm Kernel: NOTE - this CPU does not expose {}{}. That is a property of the CPU \
             model, not of this kernel; QEMU's default `qemu64` model omits both. Boot with \
             `-cpu host` (KVM) or `-cpu max` (TCG) to exercise them.",
            if features.smep { "" } else { "SMEP " },
            if features.smap { "" } else { "SMAP" }
        );
    }

    features
}

fn enabled_str(enabled: bool) -> &'static str {
    if enabled {
        "on"
    } else {
        "unavailable"
    }
}

/// Whether SMAP is active, and therefore whether [`with_user_access`] has
/// any work to do.
pub fn smap_enabled() -> bool {
    SMAP_ENABLED.load(Ordering::SeqCst)
}

/// Runs `f` with the CPU temporarily permitted to touch user memory.
///
/// This is the *only* sanctioned way for kernel code to read or write a
/// user page. With SMAP enabled, any access outside this bracket faults;
/// with SMAP unavailable, this is a plain call and the discipline is
/// maintained by convention instead of by hardware. Writing every user
/// access through it either way means the same code is correct on both
/// kinds of machine, and that turning SMAP on does not require an audit
/// of every call site.
///
/// The AC (Alignment Check) flag in RFLAGS is what SMAP repurposes as the
/// "supervisor may touch user pages right now" switch: `stac` sets it,
/// `clac` clears it. The window is deliberately as small as a single
/// closure - anything that runs inside it is running with the protection
/// suspended, so the closure should contain a copy and nothing else.
///
/// Interrupts are *not* disabled here, and that is safe by construction
/// rather than by luck: AC lives in RFLAGS, which the CPU saves and
/// restores across an interrupt, so a handler that fires inside this
/// window runs with the caller's AC value restored on `iretq` and its own
/// AC state determined by the interrupt gate. It cannot leak the
/// permission to unrelated kernel code.
#[inline]
pub fn with_user_access<T>(f: impl FnOnce() -> T) -> T {
    if !smap_enabled() {
        return f();
    }

    // Safety: `stac`/`clac` are legal at Ring 0 on any CPU that reports
    // SMAP, which `smap_enabled` has just confirmed. The pair is balanced
    // on every path out of this function - `f` cannot unwind, because
    // this kernel is built with `panic = "abort"`, so there is no
    // early-exit path that could leave AC set.
    unsafe {
        core::arch::asm!("stac", options(nomem, nostack));
    }
    let result = f();
    unsafe {
        core::arch::asm!("clac", options(nomem, nostack));
    }
    result
}
