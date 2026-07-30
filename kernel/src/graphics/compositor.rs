//! The compositor, and the trusted path it exists to protect.
//!
//! This module implements ARCHITECTURE.md sections 2c and 2d. Those
//! sections are unusually specific about what the mechanism has to
//! survive, because they were written against the failure modes that have
//! broken equivalent mechanisms in real systems - Qubes OS's per-domain
//! window borders in particular. Each of those threats maps to something
//! concrete here, so they are listed against their mitigations rather
//! than described in the abstract:
//!
//! | Threat (ARCHITECTURE.md 2d) | What this module does |
//! |---|---|
//! | 1. A Realm draws a fake trust indicator inside its own window | Every surface is clipped to [`content_region`], which excludes the trust bar. A Realm cannot address those pixels; there is no coordinate it can pass that reaches them. |
//! | 2. A compromised Shell forges the indicator | The bar is drawn by [`present`] from kernel state, after every surface, every frame. No syscall can influence its contents - there is not even a restricted one. |
//! | 3. Ownership inferred from a flag an application can influence | Which Realm owns the focused surface is read from the *process table* at draw time, not from anything the surface carries. A process cannot relabel itself. |
//! | 4. Exclusive fullscreen leaves no room for the indicator | [`FULLSCREEN`](SurfaceMode::Fullscreen) still clips to `content_region`. "Fullscreen" means the whole content area, which is the whole screen minus the reserved strip - the strip is not available to give away. |
//! | 5. One Shell bug is reachable from every Realm | Not addressed here: the Shell is userland and does not exist yet. Recorded rather than claimed. |
//! | 6. Theme files are untrusted input parsed by a privileged process | Partly addressed - see `graphics::theme`, which parses in the kernel today and says plainly that it should not. |
//! | 7. GPU side channels between Realms | Not addressed. There is no GPU driver, and the design does not claim to solve it. |
//!
//! ## The part that makes the badge unforgeable
//!
//! Clipping stops a Realm from drawing *in* the bar. It does not stop one
//! from drawing a convincing copy of the bar inside its own window and
//! hoping the user looks at the wrong one - the oldest UI spoofing
//! attack there is, and the reason a browser's padlock moved into
//! browser chrome that pages cannot reach.
//!
//! So the bar carries a [`boot_signature`]: a short sequence of colours
//! derived at boot from the CPU timestamp counter, drawn into the bar
//! every frame, and **never exposed through any syscall**. A process
//! cannot read it, so it cannot reproduce it, so a fake bar is
//! distinguishable from the real one by a user who has seen the real one
//! this session. This is the same principle as a bank asking you to pick
//! a personal image at signup: the secret is not that the attacker cannot
//! draw a picture, it is that they cannot draw *your* picture.
//!
//! Honest limitation: this only helps a user who notices. It is a
//! mitigation, not a proof, and the load-bearing protection remains the
//! clipping.

use super::font;
use super::framebuffer::{Colour, Framebuffer};
use super::theme::Theme;
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

/// Height of the Core-reserved strip at the top of the screen, in pixels.
///
/// No surface may be placed in it and no surface may draw into it, in any
/// mode, ever. That is the whole point: a region no Realm can address is
/// the only place a trust signal can live where it cannot be forged from
/// inside a window.
pub const TRUST_BAR_HEIGHT: usize = 20;

/// How a surface occupies the screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceMode {
    /// A window at a position, with a border drawn in its Realm's accent
    /// colour.
    Windowed,
    /// The whole content area. Note this is *not* the whole screen - see
    /// threat 4 above. A Gaming Realm gets every pixel it is possible to
    /// give it, and the reserved strip is not one of them.
    Fullscreen,
}

/// One process's drawable region.
///
/// The pixel buffer lives in the kernel, and `surface_commit` copies into
/// it. That is one copy more than a design where the compositor reads the
/// process's memory directly, and it is deliberate: reading a live user
/// buffer while compositing means the contents can change halfway through
/// a frame (tearing, at best) and means the compositor is dereferencing
/// user memory on a path where SMAP would otherwise have caught a missing
/// check. The copy makes the frame a snapshot and confines user-memory
/// access to one validated call.
pub struct Surface {
    pub id: u64,
    pub pid: u64,
    /// Cached at creation from the process's Realm. Read from the process
    /// table rather than supplied by the process - see threat 3.
    pub realm_kind: u64,
    pub title: String,
    pub x: usize,
    pub y: usize,
    pub width: usize,
    pub height: usize,
    pub mode: SurfaceMode,
    pixels: Vec<u32>,
}

impl Surface {
    /// Bytes a committed frame for this surface must be.
    pub fn frame_bytes(&self) -> usize {
        self.width * self.height * 4
    }
}

struct CompositorState {
    framebuffer: Option<Framebuffer>,
    surfaces: Vec<Surface>,
    next_surface_id: u64,
    /// Which surface has keyboard focus, and therefore whose Realm the
    /// trust bar names.
    focused: Option<u64>,
    theme: Theme,
    /// The per-boot colour sequence described in the module docs. Never
    /// leaves the kernel.
    signature: [Colour; SIGNATURE_BLOCKS],
    frames: u64,
    /// The tick of the last full recomposite, used to rate-limit them.
    last_present_tick: u64,
    /// Counts surface commits that tried to exceed their own bounds.
    /// Non-zero means a program is misbehaving, and the log should say so
    /// rather than the compositor silently coping.
    rejected_commits: u64,
}

/// How many colour blocks the boot signature has.
///
/// Six blocks from a palette of eight is about 260,000 combinations -
/// far more than enough that guessing is hopeless, and few enough that a
/// person can recognize the pattern at a glance without studying it.
/// Recognition, not entropy, is the binding constraint here: a signature
/// nobody can remember protects nobody.
const SIGNATURE_BLOCKS: usize = 6;

static COMPOSITOR: Mutex<CompositorState> = Mutex::new(CompositorState {
    framebuffer: None,
    surfaces: Vec::new(),
    next_surface_id: 1,
    focused: None,
    theme: Theme::DEFAULT,
    signature: [Colour::rgb(0, 0, 0); SIGNATURE_BLOCKS],
    frames: 0,
    last_present_tick: 0,
    rejected_commits: 0,
});

/// The palette the boot signature is drawn from. Deliberately
/// high-contrast and few: colours a person can name and remember.
const SIGNATURE_PALETTE: [Colour; 8] = [
    Colour::rgb(0xE6, 0x39, 0x46), // red
    Colour::rgb(0xF7, 0x9D, 0x1E), // orange
    Colour::rgb(0xFF, 0xD1, 0x66), // yellow
    Colour::rgb(0x4C, 0xC9, 0x7C), // green
    Colour::rgb(0x2E, 0xC4, 0xB6), // teal
    Colour::rgb(0x3A, 0x86, 0xFF), // blue
    Colour::rgb(0x9B, 0x5D, 0xE5), // violet
    Colour::rgb(0xF1, 0x5B, 0xB5), // pink
];

/// Sets up the compositor against the boot framebuffer.
pub fn init(framebuffer: Framebuffer, theme: Theme) {
    // The signature's entropy comes from the timestamp counter, which
    // varies between boots by however long the firmware took. That is a
    // weak source and it is the right one available here: this kernel has
    // no entropy pool, no RDRAND check, and no stored seed. What matters
    // is that a *process* cannot predict or read it, and a process has no
    // way to observe the boot's TSC at this point - it did not exist yet.
    //
    // It is emphatically not a cryptographic secret and is not used as
    // one. If this value were ever load-bearing for anything but visual
    // recognition, it would need a real entropy source first.
    //
    // Safety: `_rdtsc` reads the timestamp counter, an unprivileged
    // instruction available on every x86_64 CPU.
    let seed = unsafe { core::arch::x86_64::_rdtsc() };

    let mut signature = [Colour::rgb(0, 0, 0); SIGNATURE_BLOCKS];
    let mut state = seed;
    for block in signature.iter_mut() {
        // A small xorshift so consecutive blocks do not simply walk the
        // palette in order - the low bits of a TSC read are correlated
        // enough that using them directly would produce visibly similar
        // signatures across boots.
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *block = SIGNATURE_PALETTE[(state % SIGNATURE_PALETTE.len() as u64) as usize];
    }

    let mut compositor = COMPOSITOR.lock();
    compositor.framebuffer = Some(framebuffer);
    compositor.theme = theme;
    compositor.signature = signature;

    crate::drivers::input::set_bounds(framebuffer.width as u64, framebuffer.height as u64);
}

/// The region surfaces may occupy: the screen minus the reserved strip.
///
/// Every placement and every draw goes through this. It is a function
/// rather than a constant so that there is exactly one definition of
/// "where a Realm may put pixels" - two definitions that could disagree
/// is precisely how threat 4 gets reintroduced by someone adding a
/// fullscreen path that computes the bounds itself.
pub fn content_region(framebuffer: &Framebuffer) -> (usize, usize, usize, usize) {
    (
        0,
        TRUST_BAR_HEIGHT,
        framebuffer.width,
        framebuffer.height.saturating_sub(TRUST_BAR_HEIGHT),
    )
}

/// Creates a surface for `pid`, returning its id.
pub fn create_surface(
    pid: u64,
    realm_kind: u64,
    title: &str,
    width: usize,
    height: usize,
    mode: SurfaceMode,
) -> Option<u64> {
    let mut compositor = COMPOSITOR.lock();
    let framebuffer = compositor.framebuffer?;
    let (content_x, content_y, content_width, content_height) = content_region(&framebuffer);

    let (x, y, width, height) = match mode {
        SurfaceMode::Fullscreen => (content_x, content_y, content_width, content_height),
        SurfaceMode::Windowed => {
            let width = width.min(content_width);
            let height = height.min(content_height);
            // Cascade windows so a second one is visibly a second one
            // rather than exactly covering the first.
            let index = compositor.surfaces.len();
            let x = (content_x + 40 + index * 30).min(content_x + content_width - width);
            let y = (content_y + 30 + index * 26)
                .min(content_y + content_height.saturating_sub(height));
            (x, y, width, height)
        }
    };

    if width == 0 || height == 0 {
        return None;
    }

    // A cap on total surface memory. Without it, a process asking for a
    // surface the size of the address space is an out-of-memory kill of
    // the *kernel* requested through an ordinary syscall.
    let pixels = width.checked_mul(height)?;
    if pixels > MAX_SURFACE_PIXELS {
        return None;
    }

    let id = compositor.next_surface_id;
    compositor.next_surface_id += 1;

    compositor.surfaces.push(Surface {
        id,
        pid,
        realm_kind,
        title: String::from(title),
        x,
        y,
        width,
        height,
        mode,
        pixels: alloc::vec![0u32; pixels],
    });

    // The newest surface takes focus, which is what a user expects from a
    // window that just appeared.
    compositor.focused = Some(id);

    Some(id)
}

/// The largest surface that may be created, in pixels. Four bytes each,
/// so this is a 32 MiB ceiling - larger than any sensible full-screen
/// buffer at the resolutions this kernel handles, and small enough that
/// a program cannot exhaust the heap by asking.
const MAX_SURFACE_PIXELS: usize = 8 * 1024 * 1024;

/// Replaces a surface's contents with `pixels`, which must be exactly the
/// surface's size.
///
/// Requires an exact length rather than accepting a short buffer.
/// Accepting one would mean the rest of the frame is whatever was there
/// before, which for a surface that has just changed size is *another
/// process's* former pixels - the surface buffer is reused. Exactness is
/// what makes that impossible to reach accidentally.
pub fn commit_surface_from_user(id: u64, pid: u64, ptr: u64, len: usize) -> bool {
    let mut compositor = COMPOSITOR.lock();

    let Some(surface) = compositor.surfaces.iter_mut().find(|s| s.id == id) else {
        return false;
    };
    if surface.pid != pid || len != surface.pixels.len() * 4 {
        compositor.rejected_commits += 1;
        return false;
    }

    // The user's bytes go straight into the surface's pixel buffer, with
    // no intermediate kernel allocation. A frame is megabytes; allocating
    // a second copy of one per commit would double the peak heap usage of
    // the whole graphics path for no benefit, and the surface buffer is
    // exactly the right size by construction.
    //
    // Safety: `Vec<u32>`'s buffer is `len * 4` bytes and is more strictly
    // aligned than `u8` requires, so viewing it as a byte slice is sound.
    // The slice does not outlive the borrow of `surface`.
    let dest = unsafe {
        core::slice::from_raw_parts_mut(
            surface.pixels.as_mut_ptr() as *mut u8,
            surface.pixels.len() * 4,
        )
    };

    if !crate::mm::memory::copy_from_user_into(ptr, dest) {
        // The frame is now partially written, which is visible as tearing
        // for one frame and nothing worse - the buffer was already this
        // process's own pixels, so a failed copy cannot expose anyone
        // else's data. Counted so a program handing the kernel bad
        // pointers is visible rather than silently producing glitches.
        compositor.rejected_commits += 1;
        return false;
    }

    true
}

/// The in-kernel variant, for callers that already hold the pixels.
#[allow(dead_code)]
pub fn commit_surface(id: u64, pid: u64, pixels: &[u32]) -> bool {
    let mut compositor = COMPOSITOR.lock();

    let Some(surface) = compositor.surfaces.iter_mut().find(|s| s.id == id) else {
        return false;
    };

    // Ownership, checked here rather than assumed from the descriptor.
    // Without it, any process could redraw any other process's window by
    // guessing a small integer.
    if surface.pid != pid {
        compositor.rejected_commits += 1;
        return false;
    }

    if pixels.len() != surface.pixels.len() {
        compositor.rejected_commits += 1;
        return false;
    }

    surface.pixels.copy_from_slice(pixels);
    true
}

/// Removes every surface belonging to `pid`.
///
/// Called when a process exits. Without it a dead process's window would
/// stay on screen forever, and - worse - its surface id would stay valid,
/// so a later process reusing the id would inherit its pixels.
pub fn remove_surfaces_for(pid: u64) {
    let mut compositor = COMPOSITOR.lock();
    compositor.surfaces.retain(|surface| surface.pid != pid);
    if let Some(focused) = compositor.focused {
        if !compositor.surfaces.iter().any(|s| s.id == focused) {
            compositor.focused = compositor.surfaces.last().map(|s| s.id);
        }
    }
}

/// A surface's geometry, for `surface_info`.
pub fn surface_geometry(id: u64, pid: u64) -> Option<(usize, usize)> {
    let compositor = COMPOSITOR.lock();
    compositor
        .surfaces
        .iter()
        .find(|s| s.id == id && s.pid == pid)
        .map(|s| (s.width, s.height))
}

/// Draws one frame: background, every surface, the pointer, then the
/// trust bar.
///
/// The order is the security property. The trust bar is drawn **last**,
/// unconditionally, from kernel state - so even if a surface somehow
/// wrote outside its clip, the bar would be redrawn over it before the
/// frame was visible. Drawing it first and relying on clipping alone
/// would make correctness depend on a single check rather than on a check
/// plus an overwrite.
/// Draws a frame if one has not already been drawn this tick.
///
/// A full recomposite is close to a million writes to framebuffer device
/// memory, which is tens of milliseconds of Ring 0 work in a debug build.
/// Doing that once per `surface_commit` means a process that commits
/// twice in a tick pays for two full screens of drawing, and - because
/// the process doing it is typically a realtime one - charges that time
/// against every other realtime task's latency.
///
/// Rate-limiting to one composite per tick bounds it. Nothing is lost:
/// the display cannot show two frames within one tick anyway, so the
/// skipped composite would have been overwritten before a photon left
/// the screen.
///
/// This is a rate limit, not damage tracking. The real fix is to redraw
/// only what changed, which needs per-surface dirty rectangles; see
/// `sched::class::REALTIME_LATENCY_BUDGET_TICKS` for why that matters.
pub fn present_throttled() {
    let now = crate::arch::x86_64::interrupts::timer_ticks();
    {
        let mut compositor = COMPOSITOR.lock();
        if compositor.frames > 0 && compositor.last_present_tick == now {
            return;
        }
        compositor.last_present_tick = now;
    }
    present();
}

pub fn present() {
    let mut compositor = COMPOSITOR.lock();
    let Some(framebuffer) = compositor.framebuffer else {
        return;
    };

    let theme = compositor.theme;
    let (_, content_y, content_width, content_height) = content_region(&framebuffer);

    framebuffer.fill_rect(0, content_y, content_width, content_height, theme.desktop);

    // Surfaces, oldest first, so the newest is on top.
    for surface in &compositor.surfaces {
        let accent = theme.accent_for_realm(surface.realm_kind);

        // Clipped to the content region on every axis. This is the line
        // that implements threats 1 and 4: there is no coordinate a
        // surface can hold that reaches the reserved strip, in any mode.
        let x_start = surface.x.max(0);
        let y_start = surface.y.max(content_y);
        let x_end = (surface.x + surface.width).min(content_width);
        let y_end = (surface.y + surface.height).min(content_y + content_height);

        for row in y_start..y_end {
            for column in x_start..x_end {
                let local_x = column - surface.x;
                let local_y = row - surface.y;
                let pixel = surface.pixels[local_y * surface.width + local_x];
                framebuffer.set_pixel(
                    column,
                    row,
                    Colour::rgb(
                        ((pixel >> 16) & 0xFF) as u8,
                        ((pixel >> 8) & 0xFF) as u8,
                        (pixel & 0xFF) as u8,
                    ),
                );
            }
        }

        // A border in the Realm's accent colour. This is *not* the trust
        // indicator - a Realm could draw an identical rectangle inside
        // its own content. It is a convenience for telling windows apart,
        // and calling it anything more would be exactly the mistake
        // ARCHITECTURE.md 2d threat 1 describes.
        if surface.mode == SurfaceMode::Windowed && x_end > x_start && y_end > y_start {
            framebuffer.stroke_rect(
                x_start,
                y_start,
                x_end - x_start,
                y_end - y_start,
                accent,
            );
        }
    }

    draw_pointer(&framebuffer, theme);

    let focused_realm = compositor
        .focused
        .and_then(|id| compositor.surfaces.iter().find(|s| s.id == id))
        .map(|s| s.realm_kind);
    let signature = compositor.signature;
    draw_trust_bar(&framebuffer, theme, focused_realm, &signature);

    compositor.frames += 1;
}

fn draw_pointer(framebuffer: &Framebuffer, theme: Theme) {
    let (x, y) = crate::drivers::input::pointer_position();
    let (x, y) = (x as usize, y as usize);

    // A simple arrow: a diagonal wedge. Drawn with an outline so it stays
    // visible over content of any colour - a single-colour cursor
    // disappears against a background that happens to match it, which is
    // a genuinely common way for a pointer to become unusable.
    for row in 0..12usize {
        for column in 0..(12 - row) {
            if column > row + 6 {
                continue;
            }
            let edge = column == 0 || column == 11 - row || row == 11;
            framebuffer.set_pixel(
                x + column,
                y + row,
                if edge { theme.pointer_edge } else { theme.pointer_fill },
            );
        }
    }
}

/// Draws the Core-owned trust bar.
///
/// Everything in here comes from kernel state. There is no argument a
/// process can influence, which is the point of threat 2: a compromised
/// Shell has nothing to compromise, because it is never consulted.
fn draw_trust_bar(
    framebuffer: &Framebuffer,
    theme: Theme,
    focused_realm: Option<u64>,
    signature: &[Colour],
) {
    framebuffer.fill_rect(0, 0, framebuffer.width, TRUST_BAR_HEIGHT, theme.trust_bar);

    // A hairline under the bar, so the boundary between Core-owned and
    // Realm-owned pixels is visible rather than inferred.
    framebuffer.fill_rect(0, TRUST_BAR_HEIGHT - 1, framebuffer.width, 1, theme.trust_bar_edge);

    let (label, accent) = match focused_realm {
        Some(kind) => (realm_label(kind), theme.accent_for_realm(kind)),
        None => ("NAJM OS", theme.trust_bar_text),
    };

    // A swatch of the focused Realm's accent, then its name.
    framebuffer.fill_rect(6, 5, 10, 10, accent);
    draw_text(framebuffer, 22, 7, label, theme.trust_bar_text);

    // The boot signature, right-aligned. See the module docs for what it
    // is for and, just as importantly, what it is not.
    let block = 10usize;
    let gap = 3usize;
    let total = signature.len() * (block + gap);
    let mut x = framebuffer.width.saturating_sub(total + 8);
    for colour in signature {
        framebuffer.fill_rect(x, 5, block, 10, *colour);
        x += block + gap;
    }
}

fn realm_label(kind: u64) -> &'static str {
    match kind {
        najm_abi::realm_kind::GAMING => "GAMING REALM",
        najm_abi::realm_kind::VAULT => "VAULT REALM - VERIFIED PUBLISHER",
        najm_abi::realm_kind::SYSTEM => "SYSTEM",
        _ => "HOME REALM",
    }
}

/// Draws `text` at a position using the 5x7 font.
pub fn draw_text(framebuffer: &Framebuffer, x: usize, y: usize, text: &str, colour: Colour) {
    let mut cursor = x;
    for character in text.chars() {
        let glyph = font::glyph(character);
        for (column, bits) in glyph.iter().enumerate() {
            for row in 0..font::GLYPH_HEIGHT {
                if bits & (1 << row) != 0 {
                    framebuffer.set_pixel(cursor + column, y + row, colour);
                }
            }
        }
        cursor += font::ADVANCE;
    }
}

/// `(surfaces, frames presented, rejected commits)`.
pub fn stats() -> (usize, u64, u64) {
    let compositor = COMPOSITOR.lock();
    (
        compositor.surfaces.len(),
        compositor.frames,
        compositor.rejected_commits,
    )
}

/// Whether any surface's *placement* overlaps the reserved strip.
///
/// A self-test hook. Clipping at draw time is what actually protects the
/// strip, but a surface whose geometry claims to include it would mean
/// the placement logic had a hole, and clipping would be the only thing
/// standing between that and a forged trust bar. Defence in depth is
/// worth having; knowing whether the outer layer still works is worth
/// more.
pub fn any_surface_overlaps_trust_bar() -> bool {
    let compositor = COMPOSITOR.lock();
    compositor
        .surfaces
        .iter()
        .any(|surface| surface.y < TRUST_BAR_HEIGHT)
}

/// Reads back the framebuffer pixel at `(x, y)`, for self-tests.
///
/// Reading the framebuffer is unusual - it is write-mostly device memory
/// and reads from it can be slow - but it is the only way to check what
/// was *actually displayed* rather than what the compositor believes it
/// drew, and the difference between those two is exactly where a trusted
/// path fails.
pub fn read_pixel(x: usize, y: usize) -> Option<(u8, u8, u8)> {
    use bootloader_api::info::PixelFormat;

    let compositor = COMPOSITOR.lock();
    let framebuffer = compositor.framebuffer?;
    if x >= framebuffer.width || y >= framebuffer.height {
        return None;
    }

    let offset = y * framebuffer.stride + x * framebuffer.bytes_per_pixel;
    // Safety: the offset is within the framebuffer mapping, checked by
    // the bounds test above against the geometry the bootloader reported.
    let bytes = unsafe {
        let base = framebuffer_base(&framebuffer) as *const u8;
        (
            base.add(offset).read_volatile(),
            if framebuffer.bytes_per_pixel > 1 {
                base.add(offset + 1).read_volatile()
            } else {
                0
            },
            if framebuffer.bytes_per_pixel > 2 {
                base.add(offset + 2).read_volatile()
            } else {
                0
            },
        )
    };

    Some(match framebuffer.format() {
        PixelFormat::Bgr => (bytes.2, bytes.1, bytes.0),
        _ => (bytes.0, bytes.1, bytes.2),
    })
}

fn framebuffer_base(framebuffer: &Framebuffer) -> u64 {
    // `Framebuffer` keeps its base private so that writes go through
    // `set_pixel`'s bounds check. The self-test read-back path is the one
    // legitimate exception, and routing it through a named function keeps
    // that exception greppable.
    framebuffer.base_address()
}

/// The colours currently in the trust bar's signature, for the self-test
/// that checks the drawn pixels match.
pub fn signature_colours() -> [Colour; SIGNATURE_BLOCKS] {
    COMPOSITOR.lock().signature
}

/// Where the signature blocks are drawn, so a self-test can look at the
/// right pixels rather than hardcoding coordinates that would silently
/// drift out of step with `draw_trust_bar`.
pub fn signature_block_origin(index: usize) -> Option<(usize, usize)> {
    let compositor = COMPOSITOR.lock();
    let framebuffer = compositor.framebuffer?;
    let block = 10usize;
    let gap = 3usize;
    let total = SIGNATURE_BLOCKS * (block + gap);
    let x = framebuffer.width.saturating_sub(total + 8) + index * (block + gap);
    Some((x + block / 2, 5 + block / 2))
}
