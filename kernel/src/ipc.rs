//! Inter-process communication: named ports carrying messages.
//!
//! ARCHITECTURE.md's hybrid-kernel argument rests on this. The whole
//! claim is that non-critical subsystems run as "isolated, restartable
//! service processes" rather than inside the privileged core - and until
//! now nothing could be a separate process, because there was no way to
//! reach one. Every service in this kernel is in the kernel for exactly
//! that reason, not because it belongs there.
//!
//! ## Why message-copying and not shared memory
//!
//! Shared memory is faster and is the wrong default here. Two processes
//! sharing a page means either can change data the other is in the middle
//! of reading, which turns every service into a time-of-check /
//! time-of-use problem - the receiver validates a request, and the sender
//! rewrites it before the receiver acts. The only robust answer is for
//! the receiver to copy anything it intends to trust, at which point the
//! copy has happened anyway and the shared page has bought nothing except
//! the opportunity to forget it.
//!
//! So a message is copied out of the sender and into the kernel at
//! `send`, and out of the kernel into the receiver at `recv`. Two copies
//! for a small message is cheap; the property it buys is that a message,
//! once sent, is immutable. Shared memory remains the right answer for
//! *bulk* transfer - a video frame, a texture - and that wants a separate
//! mechanism with explicit handoff, not this one relaxed.
//!
//! ## Bounded, and what happens at the bound
//!
//! Every queue has a fixed depth and every message a maximum size, both
//! enforced kernel-side. Without them a sender can make the kernel
//! allocate without limit by never being read from - a denial of service
//! that needs no bug, just a loop.
//!
//! When a queue is full, `send` **fails with `EAGAIN` rather than
//! blocking or dropping**. Each alternative is worse in a specific way:
//! blocking makes a slow receiver able to hang every one of its clients,
//! and dropping makes a protocol silently lossy, which callers discover
//! at the worst possible time. Failing loudly leaves the policy where it
//! belongs - with the sender, which is the only party that knows whether
//! a message is worth retrying.
//!
//! ## Capability-gated on both sides, asymmetrically
//!
//! Creating a port and connecting to one are different rights
//! (`IPC_CREATE`, `IPC_CONNECT`), because they are different powers.
//! Creating one claims a name in a global namespace, which is how a
//! service is impersonated; connecting only lets you talk to something
//! that already chose to listen. A Realm that should be able to *use*
//! services without *being* one - which is most of them - gets only the
//! second.
//!
//! ## What this is not
//!
//! - **No blocking receive.** `recv` returns `EAGAIN` on an empty queue
//!   rather than sleeping, because there is no wait queue and no way to
//!   wake a task on an event yet. A client polls, which is correct and
//!   wasteful. Fixing it means a sleep/wake primitive in the scheduler.
//! - **No reply correlation.** A message is bytes; matching a response to
//!   a request is the protocol's problem, not this layer's.
//! - **No handle passing.** A message cannot carry a capability, so a
//!   service cannot delegate a right to a client. That is the natural
//!   next step and it is genuinely missing.

use crate::serial_println;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

/// The longest a port name may be. Bounded for the same reason paths are:
/// it is untrusted input used as a map key, and an unbounded one is an
/// allocation a caller controls.
pub const MAX_NAME: usize = 64;

/// The largest single message. Deliberately small - this is a control
/// channel, not a bulk transport, and a mechanism that can carry a
/// megabyte invites being used to carry megabytes.
pub const MAX_MESSAGE: usize = 4096;

/// How many messages a port will hold before `send` starts failing.
pub const QUEUE_DEPTH: usize = 32;

/// How many ports may exist at once, across the whole system.
const MAX_PORTS: usize = 128;

static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

struct Port {
    handle: u64,
    name: String,
    /// The process that created it. Only the owner may receive; a
    /// connector may only send. Without that asymmetry, any process able
    /// to connect could drain a service's inbox and read requests
    /// intended for it.
    owner: u64,
    queue: VecDeque<Message>,
    /// Messages refused because the queue was full, so a service that is
    /// falling behind is visible rather than merely slow.
    dropped: u64,
}

/// One message, with who sent it.
///
/// The sender's pid is recorded by the *kernel* at send time, not carried
/// in the payload. A service that trusted a sender identity out of the
/// message body would be trusting the one field an attacker fully
/// controls.
pub struct Message {
    pub from: u64,
    pub bytes: Vec<u8>,
}

static PORTS: Mutex<BTreeMap<u64, Port>> = Mutex::new(BTreeMap::new());

/// Why an IPC operation failed. Mapped onto `najm_abi::err` numbers by
/// the syscall layer; kept as its own enum so the reasons are named
/// rather than being bare integers at the point they are produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcError {
    /// The name is empty, too long, or contains a NUL.
    BadName,
    /// A port with that name already exists.
    NameTaken,
    /// No port with that name.
    NotFound,
    /// The handle is not one this process may use.
    BadHandle,
    /// The message is larger than `MAX_MESSAGE`.
    TooLarge,
    /// The queue is full, or - on receive - empty.
    WouldBlock,
    /// Too many ports exist system-wide.
    Exhausted,
}

/// Whether a port name is acceptable.
///
/// Same posture as path validation: reject rather than repair. A name is
/// a key in a global namespace, and two spellings of one name is how a
/// service gets impersonated by something that registered the variant
/// nobody thought to normalize.
fn name_is_valid(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && !name.contains(&0)
        // Printable ASCII only. A name containing control characters
        // would render as something else entirely in any log or UI that
        // showed it, which is the whole trick behind homograph-style
        // impersonation.
        && name.iter().all(|&byte| (0x21..=0x7e).contains(&byte))
}

/// Creates a port under `name`, owned by `owner`.
pub fn create(owner: u64, name: &[u8]) -> Result<u64, IpcError> {
    if !name_is_valid(name) {
        return Err(IpcError::BadName);
    }
    let name = String::from_utf8_lossy(name).into_owned();

    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut ports = PORTS.lock();
        if ports.len() >= MAX_PORTS {
            return Err(IpcError::Exhausted);
        }
        if ports.values().any(|port| port.name == name) {
            return Err(IpcError::NameTaken);
        }

        let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
        ports.insert(
            handle,
            Port {
                handle,
                name,
                owner,
                queue: VecDeque::new(),
                dropped: 0,
            },
        );
        Ok(handle)
    })
}

/// Finds a port by name, for a process that wants to send to it.
///
/// Returns the same handle the owner holds. That is safe because the
/// handle alone confers nothing: every operation re-checks what the
/// calling process is allowed to do with it, and receiving is owner-only.
/// A design where the handle *was* the authority would need per-connector
/// handles, which is the right shape once messages can carry capabilities
/// and is not needed before then.
pub fn connect(name: &[u8]) -> Result<u64, IpcError> {
    if !name_is_valid(name) {
        return Err(IpcError::BadName);
    }
    let name = String::from_utf8_lossy(name).into_owned();

    x86_64::instructions::interrupts::without_interrupts(|| {
        PORTS
            .lock()
            .values()
            .find(|port| port.name == name)
            .map(|port| port.handle)
            .ok_or(IpcError::NotFound)
    })
}

/// Queues a message.
pub fn send(from: u64, handle: u64, bytes: Vec<u8>) -> Result<usize, IpcError> {
    if bytes.len() > MAX_MESSAGE {
        return Err(IpcError::TooLarge);
    }

    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut ports = PORTS.lock();
        let port = ports.get_mut(&handle).ok_or(IpcError::BadHandle)?;

        if port.queue.len() >= QUEUE_DEPTH {
            port.dropped += 1;
            // Refused, not dropped. See the module docs: a lossy channel
            // is discovered by its users at the worst possible time, and
            // the sender is the only party that knows whether this
            // particular message is worth retrying.
            return Err(IpcError::WouldBlock);
        }

        let length = bytes.len();
        port.queue.push_back(Message { from, bytes });
        Ok(length)
    })
}

/// Takes the oldest message, if the caller owns the port.
pub fn recv(receiver: u64, handle: u64) -> Result<Message, IpcError> {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut ports = PORTS.lock();
        let port = ports.get_mut(&handle).ok_or(IpcError::BadHandle)?;

        // Owner-only. Without this, any process that could connect could
        // drain a service's inbox and read requests meant for it - which
        // would make "connect" a strictly more powerful right than
        // "create", exactly inverting the intent.
        if port.owner != receiver {
            return Err(IpcError::BadHandle);
        }

        port.queue.pop_front().ok_or(IpcError::WouldBlock)
    })
}

/// Destroys a port, if the caller owns it.
pub fn close(owner: u64, handle: u64) -> Result<(), IpcError> {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut ports = PORTS.lock();
        match ports.get(&handle) {
            Some(port) if port.owner == owner => {
                ports.remove(&handle);
                Ok(())
            }
            // A non-owner closing a port would be a denial of service
            // available to anything that could guess a small integer.
            _ => Err(IpcError::BadHandle),
        }
    })
}

/// Destroys every port a process owned.
///
/// Called when a process exits. Without it a dead service's name stays
/// claimed forever, so restarting it - the entire point of "isolated,
/// restartable service processes" - would fail with `NameTaken`.
pub fn close_all_for(owner: u64) {
    x86_64::instructions::interrupts::without_interrupts(|| {
        PORTS.lock().retain(|_, port| port.owner != owner);
    });
}

/// `(live ports, total queued messages, total refused sends)`.
pub fn stats() -> (usize, usize, u64) {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let ports = PORTS.lock();
        (
            ports.len(),
            ports.values().map(|port| port.queue.len()).sum(),
            ports.values().map(|port| port.dropped).sum(),
        )
    })
}

/// Prints the live ports, so a service that failed to start is visible as
/// an absent name rather than as a client that mysteriously cannot
/// connect.
pub fn report() {
    for (handle, name, owner, queued) in x86_64::instructions::interrupts::without_interrupts(|| {
        PORTS
            .lock()
            .values()
            .map(|port| (port.handle, port.name.clone(), port.owner, port.queue.len()))
            .collect::<Vec<_>>()
    }) {
        serial_println!(
            "Najm Kernel:   port {} '{}' owned by pid {}, {} message(s) queued",
            handle,
            name,
            owner,
            queued
        );
    }
}
