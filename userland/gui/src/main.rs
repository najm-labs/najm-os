//! A graphical Najm OS program.
//!
//! Exercises the compositor end to end: ask which Realm this is, get a
//! surface, draw into it, hand the frame over, read input. It runs in the
//! Gaming Realm, which means the compositor gives it exclusive fullscreen
//! - and that is the interesting part, because "exclusive fullscreen"
//! here still excludes the Core-reserved trust strip. This program cannot
//! reach those pixels no matter what coordinates it uses, which is
//! ARCHITECTURE.md 2d threat 4 being enforced rather than described.
//!
//! As with the other test programs, `good:` and `BAD:` lines are real
//! assertions - the boot harness fails the run on `BAD:`.

#![no_std]
#![no_main]

use najm_abi::{InputEvent, RealmInfo, SurfaceInfo};
use najm_std as sys;

/// Exit status meaning every check passed. Distinct from the other test
/// programs so the kernel's report identifies which one finished.
const SUCCESS: u32 = 23;

/// The largest frame this program will draw, in pixels.
///
/// A fixed buffer because there is no heap: a Ring 3 program here has a
/// stack and its own static data and nothing else. This is `.bss`, so it
/// costs nothing in the boot image - the ELF records it as memory to
/// reserve rather than bytes to store.
const MAX_PIXELS: usize = 1280 * 800;
static mut FRAME: [u32; MAX_PIXELS] = [0; MAX_PIXELS];

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let _ = sys::write(b"[gui] graphical program starting\n");

    let mut realm = RealmInfo::default();
    if sys::realm_info(&mut realm).is_err() {
        let _ = sys::write(b"[gui] BAD: realm_info failed\n");
        sys::exit(1);
    }

    let _ = sys::write(b"[gui] running in realm kind ");
    sys::write_u64(realm.kind);
    let _ = sys::write(b" as pid ");
    sys::write_u64(realm.pid);
    let _ = sys::write(b"\n");

    // A Gaming Realm must hold exclusive scanout; every Realm that is not
    // one must not. Checking both directions matters - a capability
    // system where everything is granted looks identical to one that
    // works, from inside a process that happens to be privileged.
    let has_scanout = realm.capabilities & najm_abi::capability_bits::EXCLUSIVE_SCANOUT != 0;
    if realm.kind == najm_abi::realm_kind::GAMING && has_scanout {
        let _ = sys::write(b"[gui] good: the Gaming Realm holds EXCLUSIVE_SCANOUT\n");
    } else if realm.kind != najm_abi::realm_kind::GAMING && !has_scanout {
        let _ = sys::write(b"[gui] good: a non-Gaming Realm does not hold EXCLUSIVE_SCANOUT\n");
    } else {
        let _ = sys::write(b"[gui] BAD: EXCLUSIVE_SCANOUT does not match the Realm\n");
    }

    let Ok(surface) = sys::surface_create(800, 600) else {
        let _ = sys::write(b"[gui] BAD: surface_create failed\n");
        sys::exit(2);
    };

    // The size the compositor actually gave, which is not necessarily the
    // size requested - a Gaming Realm gets the whole content area. A
    // program that assumed its request was honoured would commit a buffer
    // of the wrong length and be refused.
    let mut info = SurfaceInfo::default();
    if sys::surface_info(surface, &mut info).is_err() {
        let _ = sys::write(b"[gui] BAD: surface_info failed\n");
        sys::exit(3);
    }

    let _ = sys::write(b"[gui] surface is ");
    sys::write_u64(info.width);
    let _ = sys::write(b"x");
    sys::write_u64(info.height);
    let _ = sys::write(b"\n");

    let pixels = (info.width * info.height) as usize;
    if pixels > MAX_PIXELS {
        let _ = sys::write(b"[gui] BAD: the surface is larger than this program can draw\n");
        sys::exit(4);
    }

    draw_frame(info);

    // Safety: single-threaded program, and this is the only code that
    // touches FRAME. `addr_of_mut!` avoids forming a `&mut` to a mutable
    // static.
    let frame = unsafe {
        core::slice::from_raw_parts(core::ptr::addr_of!(FRAME) as *const u32, pixels)
    };

    match sys::surface_commit(surface, frame) {
        Ok(_) => {
            let _ = sys::write(b"[gui] good: a frame was accepted and presented\n");
        }
        Err(_) => {
            let _ = sys::write(b"[gui] BAD: surface_commit was refused\n");
        }
    }

    check_refusals(surface, pixels);
    drain_input();

    sys::exit(SUCCESS);
}

/// Paints a gradient with a grid, so the frame is unmistakably *this
/// program's* output rather than a cleared buffer that happens to be a
/// colour.
fn draw_frame(info: SurfaceInfo) {
    let width = info.width as usize;
    let height = info.height as usize;

    for y in 0..height {
        for x in 0..width {
            // A diagonal gradient, computed in integer arithmetic - there
            // is no floating point available and no reason to want any.
            let r = ((x * 255) / width.max(1)) as u32;
            let b = ((y * 255) / height.max(1)) as u32;
            let g = 0x30u32;

            // A grid every 64 pixels, which makes any clipping or stride
            // mistake in the compositor immediately visible as a bend or
            // a shear rather than as a slightly-wrong colour.
            let on_grid = x % 64 == 0 || y % 64 == 0;
            let colour = if on_grid {
                0x00FF_FFFF
            } else {
                (r << 16) | (g << 8) | b
            };

            // Safety: `x < width` and `y < height`, and the caller has
            // already checked `width * height <= MAX_PIXELS`.
            unsafe {
                let frame = core::ptr::addr_of_mut!(FRAME) as *mut u32;
                frame.add(y * width + x).write(colour);
            }
        }
    }
}

/// The negative half: things the compositor must refuse.
fn check_refusals(surface: u64, pixels: usize) {
    // A frame of the wrong length. Accepting a short buffer would leave
    // the rest of the surface holding whatever was there before - and
    // surface buffers are reused between processes, so "whatever was
    // there before" can be another program's pixels.
    // Safety: a real slice, deliberately one element short.
    let short = unsafe {
        core::slice::from_raw_parts(core::ptr::addr_of!(FRAME) as *const u32, pixels - 1)
    };
    match sys::surface_commit(surface, short) {
        Err(_) => {
            let _ = sys::write(b"[gui] good: a frame of the wrong size was refused\n");
        }
        Ok(_) => {
            let _ = sys::write(b"[gui] BAD: a frame of the wrong size was accepted\n");
        }
    }

    // A surface id this process does not own. The kernel must not
    // distinguish "no such surface" from "not yours" - telling them apart
    // would be an oracle for enumerating other processes' windows.
    // Safety: a real slice of the right length for *this* program's
    // surface; only the id is wrong, which is what is being tested.
    let frame =
        unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(FRAME) as *const u32, pixels) };
    match sys::surface_commit(surface + 1000, frame) {
        Err(_) => {
            let _ = sys::write(b"[gui] good: committing to a surface this process does not own was refused\n");
        }
        Ok(_) => {
            let _ = sys::write(b"[gui] BAD: committed to a surface belonging to nobody\n");
        }
    }
}

/// Drains whatever input has queued, proving the path exists.
///
/// Under an automated boot there is usually nothing to read, and that is
/// not a failure - it is an empty queue. What is being checked is that
/// polling an empty queue returns cleanly rather than erroring or
/// blocking forever.
fn drain_input() {
    let mut events = [InputEvent::default(); 16];
    match sys::input_poll(&mut events) {
        Ok(count) => {
            let _ = sys::write(b"[gui] good: input_poll returned cleanly with ");
            sys::write_u64(count);
            let _ = sys::write(b" event(s)\n");
        }
        Err(_) => {
            let _ = sys::write(b"[gui] BAD: input_poll failed\n");
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    let _ = sys::write(b"[gui] PANIC\n");
    sys::exit(101);
}
