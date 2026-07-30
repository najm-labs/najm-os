//! Input: keyboard and mouse, as an event queue rather than an echo.
//!
//! The keyboard handler used to decode a scancode and print the character
//! straight to the serial console. That is the right amount of machinery
//! for proving an IRQ arrives and nothing more - the keystroke was
//! *consumed by the act of observing it*, so no program could ever
//! receive one.
//!
//! What input actually needs is a queue: the interrupt handler does the
//! minimum work required to turn a hardware event into a record and
//! returns, and whoever wants the event reads it later, at Ring 3,
//! through a syscall. That split matters for a reason beyond tidiness -
//! an interrupt handler runs with interrupts disabled and holds up
//! everything else on the machine, so anything it does is charged
//! directly against the Gaming Realm's latency budget.
//!
//! ## Why a fixed-size ring and not a growable queue
//!
//! Events are produced in an interrupt handler. A growable queue would
//! mean allocating there, which takes the heap lock, which the
//! interrupted code may already hold - the deadlock
//! `mm::allocator::InterruptSafeHeap` exists to prevent. A fixed ring
//! allocates nothing and cannot fail.
//!
//! It can *overflow*, and the choice of what to do then is a real one:
//! this drops the **oldest** event. For input that is the right way
//! round - if a program has fallen far enough behind that 256 events have
//! queued, the recent ones describe where the mouse is now and the old
//! ones describe where it was a second ago. Dropping the newest would
//! leave the pointer stuck in the past. Drops are counted, so a program
//! that cares can tell it missed something rather than silently
//! interpreting a discontinuity as a real movement.
//!
//! ## PS/2, not USB
//!
//! Same reasoning as the PIC over the APIC: a USB HID stack needs a host
//! controller driver, enumeration, transfer scheduling and a HID report
//! parser - a subsystem in its own right - and every machine and emulator
//! still exposes PS/2 emulation for exactly this reason. This is the
//! correct thing to build first, and the thing to replace once there is a
//! reason to.

use crate::serial_println;
use najm_abi::{input_kind, InputEvent};
use spin::Mutex;
use x86_64::instructions::port::Port;

/// PS/2 controller ports.
const PS2_DATA: u16 = 0x60;
const PS2_STATUS: u16 = 0x64;
const PS2_COMMAND: u16 = 0x64;

/// How many events the ring holds. 256 is roughly two seconds of
/// vigorous mouse movement at the PS/2 mouse's default 100 reports per
/// second - enough that a program has to be genuinely stalled to lose
/// anything, small enough to be a fixed allocation.
const QUEUE_CAPACITY: usize = 256;

struct EventQueue {
    events: [InputEvent; QUEUE_CAPACITY],
    head: usize,
    len: usize,
    /// Events discarded because the queue was full. Exposed so a program
    /// can distinguish "the pointer jumped" from "I missed the movement
    /// in between", which are different facts and lead to different
    /// behaviour.
    dropped: u64,
}

static QUEUE: Mutex<EventQueue> = Mutex::new(EventQueue {
    events: [InputEvent {
        kind: 0,
        code: 0,
        x: 0,
        y: 0,
    }; QUEUE_CAPACITY],
    head: 0,
    len: 0,
    dropped: 0,
});

/// The pointer's current position, tracked here because the PS/2 mouse
/// reports *relative* movement and every consumer wants an absolute
/// position. Clamped to the framebuffer's bounds at push time.
static POINTER: Mutex<(u64, u64)> = Mutex::new((0, 0));

/// Screen bounds for clamping the pointer, set once the framebuffer is
/// known. Zero means "not yet known", in which case the pointer is not
/// clamped at all - which is correct, since clamping to a guessed size
/// would confine the cursor to a region that does not match the screen.
static BOUNDS: Mutex<(u64, u64)> = Mutex::new((0, 0));

/// Records the screen size the pointer should be clamped to.
pub fn set_bounds(width: u64, height: u64) {
    *BOUNDS.lock() = (width, height);
    *POINTER.lock() = (width / 2, height / 2);
}

/// Appends an event, dropping the oldest if the ring is full.
///
/// Called from interrupt handlers, so it allocates nothing and takes only
/// this module's own lock. Note it does *not* disable interrupts: it is
/// already running in one, and the only other caller path
/// (`set_bounds`) runs at boot before any input arrives.
fn push(event: InputEvent) {
    let mut queue = QUEUE.lock();
    if queue.len == QUEUE_CAPACITY {
        // Drop the oldest. See the module docs for why this direction and
        // not the other.
        queue.head = (queue.head + 1) % QUEUE_CAPACITY;
        queue.len -= 1;
        queue.dropped += 1;
    }
    let tail = (queue.head + queue.len) % QUEUE_CAPACITY;
    queue.events[tail] = event;
    queue.len += 1;
}

/// Removes and returns up to `out.len()` events, oldest first.
pub fn poll(out: &mut [InputEvent]) -> usize {
    let mut queue = QUEUE.lock();
    let count = core::cmp::min(out.len(), queue.len);
    for slot in out.iter_mut().take(count) {
        *slot = queue.events[queue.head];
        queue.head = (queue.head + 1) % QUEUE_CAPACITY;
        queue.len -= 1;
    }
    count
}

/// `(queued, dropped)`.
pub fn stats() -> (usize, u64) {
    let queue = QUEUE.lock();
    (queue.len, queue.dropped)
}

/// The pointer's current absolute position.
pub fn pointer_position() -> (u64, u64) {
    *POINTER.lock()
}

/// Scancode set 1 for F1, the layout-toggle hotkey.
const SCANCODE_F1: u64 = 0x3B;

/// Set when the layout hotkey is pressed, drained by the compositor.
///
/// A flag rather than a direct call, because this is set inside an
/// interrupt handler and the compositor is behind a lock that `present`
/// holds for close to a million pixel writes. An IRQ that took that lock
/// would spin forever whenever it interrupted a task already holding it.
/// An atomic cannot deadlock.
static LAYOUT_TOGGLE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Consumes a pending layout-toggle request.
pub fn take_layout_toggle() -> bool {
    LAYOUT_TOGGLE.swap(false, core::sync::atomic::Ordering::SeqCst)
}

/// Called from the keyboard IRQ with a raw scancode.
///
/// Scancode set 1: a byte with the high bit clear is a press, with it set
/// is a release of the same key. Extended (0xE0-prefixed) scancodes are
/// currently reported as two separate events rather than being combined,
/// which is a real limitation - it means the arrow keys are
/// indistinguishable from the numeric keypad. Recorded rather than
/// silently mishandled; combining them needs a small state machine that
/// is worth writing when something actually reads arrow keys.
pub fn on_scancode(scancode: u8) {
    let released = scancode & 0x80 != 0;
    let code = (scancode & 0x7F) as u64;

    // Hotkeys are consumed by the system, not delivered to applications.
    // That is the correct direction and it matters for more than tidiness:
    // a key combination that switches the window layout must work even
    // when the focused window is a fullscreen Gaming Realm process that
    // would otherwise receive every key. The same reasoning is why
    // Ctrl+Alt+Del is intercepted below the application layer on Windows.
    if !released && code == SCANCODE_F1 {
        LAYOUT_TOGGLE.store(true, core::sync::atomic::Ordering::SeqCst);
        return;
    }

    push(InputEvent {
        kind: if released {
            input_kind::KEY_UP
        } else {
            input_kind::KEY_DOWN
        },
        code,
        x: 0,
        y: 0,
    });
}

/// Mouse packet assembly state.
///
/// The PS/2 mouse sends three bytes per report and there is no framing:
/// the only way to know which byte is which is to count them. That means
/// a single lost byte desynchronizes the stream permanently, which is why
/// `on_mouse_byte` validates the first byte's always-set bit and
/// resynchronizes rather than trusting the count.
static MOUSE_STATE: Mutex<([u8; 3], usize)> = Mutex::new(([0; 3], 0));

/// Called from the mouse IRQ with one byte of a three-byte packet.
pub fn on_mouse_byte(byte: u8) {
    let packet = {
        let mut state = MOUSE_STATE.lock();
        let (buffer, index) = &mut *state;

        // Bit 3 of the first byte is architecturally always 1. If it is
        // not, this is not a first byte, which means the stream has
        // desynchronized - discard and wait for one that is. Without this
        // check a single dropped byte would misinterpret every subsequent
        // packet forever, and the symptom would be a pointer that moves
        // erratically rather than an error.
        if *index == 0 && byte & 0x08 == 0 {
            return;
        }

        buffer[*index] = byte;
        *index += 1;

        if *index < 3 {
            return;
        }
        *index = 0;
        *buffer
    };

    let flags = packet[0];

    // Movement is a 9-bit signed value: 8 bits in the data byte plus a
    // sign bit in the flags. Sign-extending by hand because the sign lives
    // in a different byte from the magnitude.
    let mut dx = packet[1] as i32;
    let mut dy = packet[2] as i32;
    if flags & 0x10 != 0 {
        dx -= 256;
    }
    if flags & 0x20 != 0 {
        dy -= 256;
    }

    // Overflow bits set means the mouse moved further than the packet can
    // express. The magnitude is meaningless in that case, so the whole
    // packet is dropped rather than acted on - a large wrong movement is
    // worse than a missed one.
    if flags & 0xC0 != 0 {
        return;
    }

    let (max_x, max_y) = *BOUNDS.lock();
    let (x, y) = {
        let mut pointer = POINTER.lock();
        // Y is inverted: the mouse reports "up" as positive, screens
        // number rows downward.
        let new_x = (pointer.0 as i64 + dx as i64).max(0);
        let new_y = (pointer.1 as i64 - dy as i64).max(0);
        pointer.0 = if max_x > 0 {
            (new_x as u64).min(max_x.saturating_sub(1))
        } else {
            new_x as u64
        };
        pointer.1 = if max_y > 0 {
            (new_y as u64).min(max_y.saturating_sub(1))
        } else {
            new_y as u64
        };
        *pointer
    };

    if dx != 0 || dy != 0 {
        push(InputEvent {
            kind: input_kind::POINTER_MOTION,
            code: 0,
            x,
            y,
        });
    }

    // Button state is a level, not an edge, so transitions have to be
    // derived by comparing against the previous report.
    static PREVIOUS_BUTTONS: Mutex<u8> = Mutex::new(0);
    let buttons = flags & 0x07;
    let mut previous = PREVIOUS_BUTTONS.lock();
    let changed = buttons ^ *previous;
    if changed != 0 {
        push(InputEvent {
            kind: if buttons & changed != 0 {
                input_kind::POINTER_BUTTON_DOWN
            } else {
                input_kind::POINTER_BUTTON_UP
            },
            code: changed as u64,
            x,
            y,
        });
    }
    *previous = buttons;
}

/// Waits for the PS/2 controller's input buffer to drain before writing.
///
/// Bounded, because a machine with no PS/2 controller at all leaves the
/// status register reading 0xFF forever, and an unbounded wait would hang
/// the boot on hardware whose only fault is not having a device this
/// kernel considers optional.
fn wait_writable() -> bool {
    for _ in 0..100_000 {
        // Safety: 0x64 is the fixed PS/2 status port; reading it has no
        // side effects.
        let status: u8 = unsafe { Port::new(PS2_STATUS).read() };
        if status & 0x02 == 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// Enables the PS/2 mouse on the controller's second port.
///
/// Returns whether it worked. A machine without a mouse is not an error -
/// it is a machine without a mouse - so this reports and continues rather
/// than failing the boot.
pub fn init_mouse() -> bool {
    // Safety: 0x60/0x64 are the fixed PS/2 data and command ports, and
    // this sequence is the standard enable procedure: enable the auxiliary
    // device, read-modify-write the configuration byte to unmask its
    // interrupt, then tell the mouse itself to start reporting. Each
    // command is preceded by a bounded wait for the controller to be
    // ready, so a missing controller stalls this function rather than the
    // machine.
    unsafe {
        let mut command: Port<u8> = Port::new(PS2_COMMAND);
        let mut data: Port<u8> = Port::new(PS2_DATA);

        // Enable the auxiliary (mouse) port.
        if !wait_writable() {
            return false;
        }
        command.write(0xA8);

        // Read the configuration byte, set bit 1 (auxiliary interrupt
        // enable), write it back. Read-modify-write rather than writing a
        // constant: the other bits configure the *keyboard*, which is
        // already working, and overwriting them would break it.
        if !wait_writable() {
            return false;
        }
        command.write(0x20);
        let mut status: u8 = data.read();
        status |= 0x02;
        if !wait_writable() {
            return false;
        }
        command.write(0x60);
        if !wait_writable() {
            return false;
        }
        data.write(status);

        // Tell the mouse to start sending reports. 0xD4 routes the next
        // byte to the mouse rather than the keyboard.
        if !wait_writable() {
            return false;
        }
        command.write(0xD4);
        if !wait_writable() {
            return false;
        }
        data.write(0xF4);
    }

    serial_println!("Najm Kernel: PS/2 mouse enabled - motion and button events are queued");
    true
}

/// Reads the byte the PS/2 controller has pending.
pub fn read_data_port() -> u8 {
    // Safety: 0x60 is the fixed PS/2 data port. Reading it consumes the
    // pending byte, which is exactly what an IRQ handler must do - leaving
    // it unread means the controller never raises another interrupt.
    unsafe { Port::new(PS2_DATA).read() }
}
