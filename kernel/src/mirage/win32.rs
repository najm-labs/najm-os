//! The Win32 API surface Mirage implements, and the ABI translation that
//! makes calling it possible.
//!
//! This is the part of Mirage that corresponds to Wine's `kernel32.dll`
//! reimplementation. It is four functions. Wine's is tens of thousands
//! across dozens of DLLs, built over thirty years, and that ratio is the
//! honest measure of the distance between this and running a real game.
//!
//! What is *not* different is the mechanism, and that is worth being
//! precise about because it is the part that would otherwise have to be
//! invented later. Each entry below is a genuine Win32 function
//! reimplemented in terms of a native Najm OS syscall, bound to the
//! image's import table at load time through a generated stub that
//! translates calling conventions. Adding a fifth function is adding a
//! row to a table. Adding the five hundredth is the same work five
//! hundred times - which is the actual shape of the problem, and much
//! better than the problem being "invent a new architecture".
//!
//! ## The calling convention gap
//!
//! | | 1st arg | 2nd | 3rd | 4th | number |
//! |---|---|---|---|---|---|
//! | **Microsoft x64** (what a PE uses) | RCX | RDX | R8 | R9 | - |
//! | **Najm syscall** | RDI | RSI | RDX | - | RAX |
//!
//! The overlap is worse than no overlap would be: RDX appears in both
//! lists in different positions, so a naive pass-through would silently
//! deliver the second Windows argument as the third native one and
//! produce a plausible wrong answer rather than an obvious failure.
//!
//! The thunk therefore moves registers in an order that reads each before
//! anything overwrites it - RDX is copied to RSI *before* R8 is copied to
//! RDX - which is the same hazard, and the same solution, as the syscall
//! entry stub's own argument shuffle.
//!
//! ## Where these run
//!
//! In the *process's* address space, at Ring 3, on a page mapped
//! read-execute. Not in the kernel. A Windows binary's imports resolving
//! to kernel addresses would mean an `int 0x80` was not even needed to
//! cross the boundary - the call itself would have crossed it.

use najm_abi::sys;

/// What a Win32 import is bound to.
pub struct Thunk {
    /// The name as it appears in the PE's import table. Case-sensitive,
    /// because PE imports are.
    pub name: &'static str,
    /// The Najm syscall the thunk issues.
    pub syscall: u64,
    /// How many arguments to translate from the Windows convention.
    pub args: u8,
    /// What the function is, for the boot log - and, more usefully, a
    /// place to record where the reimplementation is *approximate*, which
    /// several of these are.
    pub note: &'static str,
}

/// Every Win32 function Mirage implements.
///
/// Deliberately a flat table rather than a match: it is data, the
/// interesting operation on it is "how many are there and which",
/// and adding one should be adding a line rather than editing control
/// flow.
pub static THUNKS: &[Thunk] = &[
    Thunk {
        name: "ExitProcess",
        syscall: sys::EXIT,
        args: 1,
        note: "exact - the exit code maps directly onto Najm's exit status",
    },
    Thunk {
        name: "GetTickCount",
        syscall: sys::UPTIME_MS,
        args: 0,
        note: "exact in meaning - milliseconds since boot - though Najm's clock has 10 ms \
               resolution rather than Windows's ~15.6 ms",
    },
    Thunk {
        name: "Sleep",
        syscall: sys::YIELD,
        args: 1,
        note: "APPROXIMATE - yields the CPU rather than sleeping for the requested duration. A \
               program that calls Sleep in a loop to pace itself will run far too fast. Correct \
               behaviour needs a timer-backed sleep, which is a real syscall to add rather than \
               a thunk to change",
    },
    Thunk {
        name: "OutputDebugStringA",
        syscall: sys::WRITE_CSTR,
        args: 1,
        note: "exact for the common case - writes a NUL-terminated string to the console. \
               Windows delivers it to an attached debugger instead, which is a difference in \
               destination rather than in behaviour",
    },
];

/// Finds the thunk for an imported name.
pub fn lookup(name: &str) -> Option<&'static Thunk> {
    THUNKS.iter().find(|thunk| thunk.name == name)
}

/// Bytes reserved per thunk in the generated page.
///
/// Fixed rather than packed, so a thunk's address is
/// `base + index * STRIDE` - an arithmetic identity rather than a running
/// total that the writer and the reader could compute differently.
pub const THUNK_STRIDE: usize = 32;

/// Emits the machine code for one thunk.
///
/// The sequence, for a three-argument call:
///
/// ```text
///   mov rdi, rcx      ; Windows arg 1 -> Najm arg 1
///   mov rsi, rdx      ; Windows arg 2 -> Najm arg 2   (before RDX is overwritten)
///   mov rdx, r8       ; Windows arg 3 -> Najm arg 3
///   mov rax, imm32    ; syscall number
///   int 0x80
///   ret
/// ```
///
/// The order of the first three is load-bearing. RDX is the second
/// Windows argument *and* the third native one, so copying R8 into RDX
/// before RDX has been read would deliver the third argument twice and
/// lose the second - a wrong answer that looks entirely plausible.
///
/// Argument registers beyond the call's actual arity are not touched. A
/// zero-argument function still leaves whatever was in RDI, and that is
/// correct: the kernel ignores arguments a syscall does not take, and
/// zeroing them would cost instructions to accomplish nothing.
pub fn generate_thunk(thunk: &Thunk) -> [u8; THUNK_STRIDE] {
    let mut code = [0x90u8; THUNK_STRIDE]; // NOP-filled, so any stray
                                           // entry point falls through to
                                           // the `ret` rather than into
                                           // whatever follows.
    let mut at = 0;
    let mut emit = |bytes: &[u8], at: &mut usize| {
        code[*at..*at + bytes.len()].copy_from_slice(bytes);
        *at += bytes.len();
    };

    // Read-before-overwrite order: RCX, then RDX, then R8.
    if thunk.args >= 1 {
        emit(&[0x48, 0x89, 0xCF], &mut at); // mov rdi, rcx
    }
    if thunk.args >= 2 {
        emit(&[0x48, 0x89, 0xD6], &mut at); // mov rsi, rdx
    }
    if thunk.args >= 3 {
        emit(&[0x4C, 0x89, 0xC2], &mut at); // mov rdx, r8
    }

    emit(&[0x48, 0xC7, 0xC0], &mut at); // mov rax, imm32 (sign-extended)
    emit(&(thunk.syscall as u32).to_le_bytes(), &mut at);
    emit(&[0xCD, 0x80], &mut at); // int 0x80

    // `ret`, not a fall-through. A Win32 function returns to its caller;
    // only `ExitProcess` never comes back, and that is the kernel's
    // decision rather than something this stub should encode - a thunk
    // that assumed it would let a future non-terminating mapping of the
    // same name run off the end of the page.
    emit(&[0xC3], &mut at);

    code
}

/// Reports the implemented surface at boot.
///
/// Printing the *approximations* alongside the exact ones is the point.
/// A compatibility layer whose log says only "4 functions available"
/// invites the reader to assume all four are faithful, and one of these
/// is not.
pub fn report() {
    crate::serial_println!(
        "Najm Kernel: Mirage implements {} Win32 function(s):",
        THUNKS.len()
    );
    for thunk in THUNKS {
        crate::serial_println!(
            "Najm Kernel:   {}({} arg{}) -> syscall {} - {}",
            thunk.name,
            thunk.args,
            if thunk.args == 1 { "" } else { "s" },
            thunk.syscall,
            thunk.note
        );
    }
}
