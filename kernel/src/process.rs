//! Processes: a Ring 3 program with its own address space, its own
//! kernel stack, its own capability set, and a lifecycle.
//!
//! Before this module, "running a user program" meant `kernel_main`
//! calling into Ring 3 and waiting for it to come back. That is a
//! *program execution*, not a process: there was one at a time, it could
//! not be preempted, it had no identity, its memory was never reclaimed,
//! and nothing could ask about it or wait for it.
//!
//! A process here is the composition of four things that already existed
//! separately:
//!
//! | Piece | Comes from | What it provides |
//! |---|---|---|
//! | Address space | `mm::address_space` | Private lower half; teardown reclaims it |
//! | Kernel stack | `mm::kstack` | Somewhere for its interrupt frames to land, with a guard page |
//! | Scheduler task | `sched::task` | It is preemptible, and it interleaves with everything else |
//! | Capability set | `security::capability` via `realm` | What it is allowed to ask the kernel for |
//!
//! The important consequence is the third one. A Ring 3 program used to
//! be unpreemptible for a specific mechanical reason: a timer interrupt
//! taken from Ring 3 switches to the stack named by TSS RSP0, and while
//! that was one fixed buffer shared by everything, parking the program by
//! switching RSP would strand its interrupt frame on a stack the next
//! Ring 3 entry immediately reused. Now that each process is a task with
//! its own kernel stack, and the scheduler points RSP0 at the current
//! task's stack on every switch, the frame lands on memory the process
//! owns - so preempting it is exactly as safe as preempting a kernel
//! task, and `timer_interrupt_handler` no longer has to refuse.
//!
//! ## What a process still is not
//!
//! - **No threads.** One process, one task, one Ring 3 context. Threads
//!   would need per-thread stacks within a shared address space, which is
//!   a change to this struct rather than a new subsystem, but it is not
//!   done.
//! - **No fork.** `spawn` loads a fresh image; it does not duplicate an
//!   address space. Copy-on-write is the natural way to add it and needs
//!   frame refcounting that `mm::frame_pool` does not have.
//! - **No signals**, and no way for one process to affect another except
//!   through IPC.

use crate::arch::x86_64::usermode::{self, ProgramExit};
use crate::mm::address_space::AddressSpace;
use crate::realm::RealmProfile;
use crate::sched::task;
use crate::serial_println;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

/// Process ids start at 1 so that 0 can mean "no process" without needing
/// an `Option` at every boundary that crosses into userland, where
/// `Option` does not exist.
static NEXT_PID: AtomicU64 = AtomicU64::new(1);

/// How a process ended, once it has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// Created but not yet scheduled.
    Ready,
    /// Currently executing, or waiting to be resumed.
    Running,
    /// Finished, carrying how it finished.
    Exited(ProgramExit),
}

/// The kernel's record of one process.
///
/// Deliberately *not* the thing the scheduler holds. The scheduler owns a
/// `Task`; this table owns the process's identity and metadata. Keeping
/// them separate means a process's exit status survives its task, which
/// is what makes `wait` possible at all - a design where the record died
/// with the task would have nothing left to report.
pub struct Process {
    pub pid: u64,
    pub name: String,
    pub profile: RealmProfile,
    pub state: ProcessState,
    /// Open files, indexed by descriptor.
    ///
    /// A `Vec<Option<_>>` rather than a map, because descriptors are
    /// small dense integers by definition and the lowest free one is what
    /// `open` must return. Descriptors 0, 1 and 2 are permanently `None`
    /// here - they are the console, handled without a table entry, so
    /// that a process cannot close stdout and have descriptor 1 handed
    /// back out as a file.
    files: Vec<Option<OpenFile>>,
}

/// One open file: which node, and how far through it the reader is.
///
/// The seek position lives here rather than in the `Node` because a node
/// is shared - two processes opening the same path get the same node and
/// must not share a cursor.
#[derive(Debug, Clone, Copy)]
pub struct OpenFile {
    pub node: crate::fs::Node,
    pub position: usize,
    /// The path this descriptor was opened with.
    ///
    /// Carried rather than re-derived from the node, which was the
    /// original design and was wrong in a way worth recording: every
    /// directory node is `(offset 0, length 0, is_directory)`, so they
    /// are *indistinguishable by value*. A reverse lookup by node
    /// therefore returned whichever directory the map happened to hold
    /// first - `readdir("/etc")` listed the contents of `/`. The bug did
    /// not look like a bug, because the answer was a real directory
    /// listing of a real directory.
    ///
    /// A fixed-size inline buffer rather than a `String`, so that an
    /// `OpenFile` stays `Copy` and the descriptor table needs no
    /// allocation per open.
    path: [u8; najm_abi::archive::MAX_PATH],
    path_len: usize,
}

impl OpenFile {
    pub fn new(node: crate::fs::Node, path: &str) -> Option<OpenFile> {
        let bytes = path.as_bytes();
        if bytes.len() > najm_abi::archive::MAX_PATH {
            return None;
        }
        let mut buffer = [0u8; najm_abi::archive::MAX_PATH];
        buffer[..bytes.len()].copy_from_slice(bytes);
        Some(OpenFile {
            node,
            position: 0,
            path: buffer,
            path_len: bytes.len(),
        })
    }

    pub fn path(&self) -> &str {
        // Valid UTF-8 by construction: it was built from a `&str`.
        core::str::from_utf8(&self.path[..self.path_len]).unwrap_or("")
    }
}

static PROCESSES: Mutex<BTreeMap<u64, Process>> = Mutex::new(BTreeMap::new());

/// Everything the process task needs, handed to it through the
/// scheduler's context pointer.
///
/// Boxed and passed as a raw pointer because that is the only channel
/// `task::spawn_with_context` provides - the context register convention
/// in `Task::new_with_context`. Reclaimed by `Box::from_raw` at the top
/// of `process_entry`, which is the one place it is ever reconstructed.
struct ProcessContext {
    pid: u64,
    entry: u64,
    stack_top: u64,
    /// The process's address space. Owned by this context, and therefore
    /// dropped - and its frames reclaimed - when the process's task ends.
    /// This is where "a terminated program's memory is reclaimed" is
    /// actually implemented: it is a `Drop`, not a cleanup routine that
    /// someone has to remember to call.
    address_space: AddressSpace,
}

/// An image ready to be turned into a process: parsed, but not yet given
/// an address space.
pub struct LoadedImage {
    pub name: String,
    pub entry: u64,
    pub stack_top: u64,
    pub address_space: AddressSpace,
}

/// Creates a process from an already-loaded image and schedules it.
///
/// Returns its pid immediately; the process has not run yet. That
/// asymmetry is deliberate - a `spawn` that waited for the child to start
/// would make it impossible to launch two processes and let the scheduler
/// interleave them, which is the whole point of processes being tasks.
pub fn spawn(image: LoadedImage, profile: RealmProfile) -> u64 {
    let pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);

    x86_64::instructions::interrupts::without_interrupts(|| {
        PROCESSES.lock().insert(
            pid,
            Process {
                pid,
                name: image.name.clone(),
                profile: profile.clone(),
                state: ProcessState::Ready,
                files: Vec::new(),
            },
        );
    });

    let context = Box::new(ProcessContext {
        pid,
        entry: image.entry,
        stack_top: image.stack_top,
        address_space: image.address_space,
    });

    serial_println!(
        "Najm Kernel: process {} ({}) created - entry {:#x}, stack top {:#x}, Realm {}",
        pid,
        image.name,
        image.entry,
        image.stack_top,
        profile.name
    );

    // `Box::into_raw` hands ownership to the task. `process_entry`
    // reconstructs it, and the `Drop` at the end of that function is what
    // tears the address space down.
    let context_ptr = Box::into_raw(context) as *mut u8;
    // Safety: `context_ptr` was produced by `Box::into_raw` on the line
    // above and nothing has consumed it yet, so it points at a live,
    // correctly-typed `ProcessContext`. The root frame has to be read out
    // here, while the pointer is still known-good, because the scheduler
    // needs it before the task's entry point ever runs.
    let root = unsafe { (*(context_ptr as *mut ProcessContext)).address_space.root_frame() };
    // The Realm decides the scheduling class. This is the line that
    // makes ARCHITECTURE.md's claim - that a Realm is defined partly by a
    // *scheduler class, not just a priority number* - true of the running
    // system rather than only of the document.
    let class = crate::sched::class::SchedClass::for_realm(profile.kind);
    task::spawn_process(process_entry, context_ptr, root, pid, class);

    pid
}

/// The body of every process's task.
///
/// Runs at Ring 0 on the task's own kernel stack, switches into the
/// process's address space, drops to Ring 3, and takes control back when
/// the program ends - however it ends.
extern "C" fn process_entry(context_ptr: *mut u8) -> ! {
    // Safety: `context_ptr` is exactly what `spawn` passed to
    // `task::spawn_process`, produced by `Box::into_raw` on a
    // `ProcessContext`, and this is the only place that pointer is ever
    // reconstructed.
    let context = unsafe { Box::from_raw(context_ptr as *mut ProcessContext) };

    set_state(context.pid, ProcessState::Running);

    // The scheduler already loaded this process's address space into CR3
    // as part of switching to this task (see `sched::task::perform_switch`),
    // so there is deliberately no CR3 write here. Doing it again would be
    // harmless but would also imply the scheduler could not be trusted to
    // have done it - and if that were true, every *preemption* of this
    // process would be broken too, which no amount of re-loading here
    // could fix.

    // Safety: `entry` and `stack_top` were validated and mapped by the
    // loader when this image's address space was built, and that address
    // space is the one currently active.
    let exit = unsafe { usermode::run_program(context.entry, context.stack_top) };

    serial_println!(
        "Najm Kernel: process {} ended with {:?}",
        context.pid,
        exit
    );
    set_state(context.pid, ProcessState::Exited(exit));

    // Dropping the context drops the `AddressSpace`, which returns every
    // frame the process owned - its pages, its stack, and the page tables
    // that reached them - to `mm::frame_pool`.
    //
    // The order here is load-bearing. The address space must be dropped
    // *before* `exit_task`, because `exit_task` never returns. But the
    // CPU is still running with that address space in CR3, so it is
    // switched back to the kernel's first - freeing the page tables the
    // CPU is currently translating through would work right up until the
    // next TLB miss.
    //
    // Safety: the kernel root is recorded at boot and is live for the
    // machine's lifetime; the kernel's own higher half is identical in
    // both spaces, so this code and its stack stay mapped across the
    // switch.
    unsafe {
        crate::mm::address_space::restore(crate::mm::address_space::kernel_root());
    }
    drop(context);

    task::exit_task();
}

fn set_state(pid: u64, state: ProcessState) {
    x86_64::instructions::interrupts::without_interrupts(|| {
        if let Some(process) = PROCESSES.lock().get_mut(&pid) {
            process.state = state;
        }
    });
}

/// How `pid` ended, or `None` if it has not ended (or never existed).
pub fn exit_status(pid: u64) -> Option<ProgramExit> {
    x86_64::instructions::interrupts::without_interrupts(|| {
        match PROCESSES.lock().get(&pid)?.state {
            ProcessState::Exited(exit) => Some(exit),
            _ => None,
        }
    })
}

/// A snapshot of the process table, for the boot report.
///
/// Returns owned data rather than lending a guard: the caller wants to
/// print it, and printing takes the serial lock, and holding two locks to
/// produce a log line is how a deadlock gets introduced for no reason.
pub fn snapshot() -> Vec<(u64, String, ProcessState)> {
    x86_64::instructions::interrupts::without_interrupts(|| {
        PROCESSES
            .lock()
            .values()
            .map(|p| (p.pid, p.name.clone(), p.state))
            .collect()
    })
}

/// How many processes have been created since boot.
pub fn count() -> u64 {
    NEXT_PID.load(Ordering::Relaxed) - 1
}

/// The Realm profile of the process currently on the CPU, if any.
///
/// This is what every capability-gated syscall consults. It returns
/// `None` when no process is current - which happens for the boot-path
/// Ring 3 self-tests - and callers must treat that as "no rights", not as
/// "unrestricted". Defaulting the other way would make the *absence* of a
/// process the most privileged state in the system.
pub fn current_profile() -> Option<RealmProfile> {
    let pid = crate::sched::task::current_pid();
    if pid == 0 {
        return None;
    }
    x86_64::instructions::interrupts::without_interrupts(|| {
        PROCESSES.lock().get(&pid).map(|p| p.profile)
    })
}

/// Runs `f` against the current process's descriptor table.
///
/// Returns `None` if there is no current process, for the same reason
/// `current_profile` does: a context with no process has no descriptor
/// table, and inventing one would let boot-path code accumulate state
/// that nothing ever cleans up.
fn with_files<T>(f: impl FnOnce(&mut Vec<Option<OpenFile>>) -> T) -> Option<T> {
    let pid = crate::sched::task::current_pid();
    if pid == 0 {
        return None;
    }
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut table = PROCESSES.lock();
        let process = table.get_mut(&pid)?;
        Some(f(&mut process.files))
    })
}

/// Records an open file and returns its descriptor.
///
/// Always the lowest free slot, which is the POSIX contract and, more
/// practically, what keeps descriptor numbers small and dense enough for
/// a `Vec` to be the right structure.
pub fn open_file(file: OpenFile) -> Option<u64> {
    with_files(|files| {
        // Descriptors 0-2 are reserved for the console and never live in
        // this table, so the search starts past them - see the comment on
        // `Process::files`.
        let reserved = najm_abi::fd::FIRST_DYNAMIC as usize;
        while files.len() < reserved {
            files.push(None);
        }

        // The search starts *at* the first dynamic descriptor, not at
        // zero. Starting at zero was a real bug: slots 0-2 are padded
        // into the table as `None` so the indices line up, and
        // `position` dutifully returned index 0 - so `open` handed out
        // descriptor 0, which `read` then treats as stdin and answers
        // with "end of input". Every file read returned zero bytes, and
        // every negative test that expected a *refusal* got a plausible
        // `Ok(0)` instead. The descriptor was wrong; nothing else was.
        if let Some(offset) = files[reserved..].iter().position(|slot| slot.is_none()) {
            let index = reserved + offset;
            files[index] = Some(file);
            return index as u64;
        }
        files.push(Some(file));
        (files.len() - 1) as u64
    })
}

/// Looks up an open file by descriptor.
pub fn get_file(descriptor: u64) -> Option<OpenFile> {
    with_files(|files| files.get(descriptor as usize).copied().flatten()).flatten()
}

/// Updates an open file's seek position.
pub fn set_file_position(descriptor: u64, position: usize) -> bool {
    with_files(|files| match files.get_mut(descriptor as usize) {
        Some(Some(file)) => {
            file.position = position;
            true
        }
        _ => false,
    })
    .unwrap_or(false)
}

/// Closes a descriptor, reporting whether it was open.
///
/// Reporting matters: silently succeeding on a double close hides a real
/// bug in the caller, and in a system where descriptors are reused it is
/// the bug that eventually closes someone else's file.
pub fn close_file(descriptor: u64) -> bool {
    with_files(|files| match files.get_mut(descriptor as usize) {
        Some(slot @ Some(_)) => {
            *slot = None;
            true
        }
        _ => false,
    })
    .unwrap_or(false)
}
