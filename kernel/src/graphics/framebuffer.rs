//! The framebuffer: turning pixels into something the hardware displays.
//!
//! The kernel already painted the screen a solid colour at boot, which
//! proved the mapping worked and nothing else. This is the layer
//! everything visual sits on: a pixel format that is *resolved* rather
//! than assumed, and primitives that clip rather than trusting their
//! callers.
//!
//! ## Format is discovered, not assumed
//!
//! The very first version of the boot paint wrote an RGB byte order
//! unconditionally, and on the actual test hardware the bootloader
//! reported BGR - so the "blue" fill came out orange. That was a harmless
//! and instructive bug, and it is the reason nothing here assumes a
//! layout: the channel order and the bytes per pixel both come from what
//! the bootloader reported.
//!
//! ## Clipping is the caller's protection, not their responsibility
//!
//! Every primitive here clips to the framebuffer's bounds internally. A
//! design where the caller is responsible for staying in bounds is one
//! where a single arithmetic mistake writes past the end of the
//! framebuffer mapping - into whatever the bootloader placed after it. In
//! a compositor whose whole job is to place *untrusted* content at
//! coordinates that content influences, that is not a hypothetical.

use bootloader_api::info::PixelFormat;

/// A colour, independent of how the hardware stores it.
///
/// Kept as separate channels rather than a packed `u32` precisely because
/// packing is format-dependent - the whole point of this type is to defer
/// that decision to the moment of writing, where the format is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Colour {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Colour {
    pub const fn rgb(r: u8, g: u8, b: u8) -> Colour {
        Colour { r, g, b }
    }

    /// Parses `#rrggbb` or `rrggbb`.
    ///
    /// Returns `None` rather than a default colour on malformed input.
    /// Themes are user-supplied text (see `graphics::theme`), and silently
    /// substituting black for a typo produces a UI that looks broken with
    /// no indication of why.
    pub fn parse_hex(text: &str) -> Option<Colour> {
        let text = text.strip_prefix('#').unwrap_or(text);
        if text.len() != 6 {
            return None;
        }
        let channel = |at: usize| u8::from_str_radix(&text[at..at + 2], 16).ok();
        Some(Colour {
            r: channel(0)?,
            g: channel(2)?,
            b: channel(4)?,
        })
    }

    /// Blends towards `other` by `amount` in 0..=255.
    ///
    /// Integer arithmetic throughout: there is no floating point in this
    /// kernel's interrupt-adjacent paths, and introducing it in a
    /// compositor would mean saving and restoring SSE state across
    /// context switches for the sake of a lerp.
    #[allow(dead_code)]
    pub fn blend(self, other: Colour, amount: u8) -> Colour {
        let mix = |a: u8, b: u8| {
            (((a as u16) * (255 - amount as u16) + (b as u16) * amount as u16) / 255) as u8
        };
        Colour {
            r: mix(self.r, other.r),
            g: mix(self.g, other.g),
            b: mix(self.b, other.b),
        }
    }
}

/// Everything needed to write a pixel, captured once at boot.
///
/// Holds the raw address rather than a `&'static mut [u8]` so that the
/// bounds check on every write is visible at the point of the write. A
/// slice would move that check to construction time and make it
/// invisible afterwards, which is the opposite of what code handling
/// attacker-influenced coordinates wants.
#[derive(Debug, Clone, Copy)]
pub struct Framebuffer {
    base: u64,
    pub width: usize,
    pub height: usize,
    /// Bytes per row, which may exceed `width * bytes_per_pixel` when the
    /// hardware pads rows for alignment. Using `width` where `stride` is
    /// meant produces a picture that shears diagonally - a distinctive
    /// enough symptom to be worth naming.
    pub stride: usize,
    pub bytes_per_pixel: usize,
    format: PixelFormat,
    len: usize,
}

impl Framebuffer {
    /// # Safety
    /// `base` must be the address the bootloader mapped the framebuffer
    /// at, writable for `len` bytes, and the geometry must be what the
    /// bootloader reported for it.
    pub unsafe fn new(
        base: u64,
        len: usize,
        width: usize,
        height: usize,
        stride: usize,
        bytes_per_pixel: usize,
        format: PixelFormat,
    ) -> Framebuffer {
        Framebuffer {
            base,
            width,
            height,
            stride,
            bytes_per_pixel,
            format,
            len,
        }
    }

    /// Packs a colour into this hardware's byte order and writes it.
    ///
    /// Silently ignores out-of-bounds coordinates rather than clamping
    /// them. Clamping would draw a pixel somewhere the caller did not ask
    /// for - which, for a compositor placing untrusted content, means a
    /// window able to paint on the screen edge by asking for a
    /// coordinate outside it.
    #[inline]
    pub fn set_pixel(&self, x: usize, y: usize, colour: Colour) {
        if x >= self.width || y >= self.height {
            return;
        }
        let offset = y * self.stride + x * self.bytes_per_pixel;
        if offset + self.bytes_per_pixel > self.len {
            return;
        }

        // Safety: `offset + bytes_per_pixel` was just checked against the
        // mapping's length, and `base` is the writable framebuffer
        // mapping the bootloader established. Writes are byte-at-a-time
        // through a raw pointer rather than through a slice because the
        // framebuffer is device memory that may be write-combining, and
        // constructing a `&mut [u8]` over it would assert exclusivity
        // this code cannot guarantee against the display controller.
        unsafe {
            let pixel = (self.base as *mut u8).add(offset);
            match self.format {
                PixelFormat::Rgb => {
                    pixel.write_volatile(colour.r);
                    if self.bytes_per_pixel > 1 {
                        pixel.add(1).write_volatile(colour.g);
                    }
                    if self.bytes_per_pixel > 2 {
                        pixel.add(2).write_volatile(colour.b);
                    }
                }
                PixelFormat::Bgr => {
                    pixel.write_volatile(colour.b);
                    if self.bytes_per_pixel > 1 {
                        pixel.add(1).write_volatile(colour.g);
                    }
                    if self.bytes_per_pixel > 2 {
                        pixel.add(2).write_volatile(colour.r);
                    }
                }
                PixelFormat::U8 => {
                    // Grayscale. Rec. 601 luma weights rather than a flat
                    // average: a flat average makes blue look as bright as
                    // green, which on a monochrome display turns a
                    // deliberate colour distinction into no distinction.
                    let luma = ((colour.r as u32 * 77
                        + colour.g as u32 * 150
                        + colour.b as u32 * 29)
                        >> 8) as u8;
                    pixel.write_volatile(luma);
                }
                _ => {
                    // An unrecognized layout. Writing *something* visible
                    // in every byte is better than writing nothing, since
                    // a blank screen is indistinguishable from a kernel
                    // that never got this far - but it is guesswork, and
                    // the boot log says so rather than pretending
                    // otherwise.
                    for byte in 0..self.bytes_per_pixel {
                        pixel.add(byte).write_volatile(colour.g);
                    }
                }
            }
        }
    }

    /// Fills a rectangle, clipped to the screen.
    pub fn fill_rect(&self, x: usize, y: usize, width: usize, height: usize, colour: Colour) {
        let x_end = (x + width).min(self.width);
        let y_end = (y + height).min(self.height);
        for row in y..y_end {
            for column in x..x_end {
                self.set_pixel(column, row, colour);
            }
        }
    }

    /// Draws a one-pixel outline, clipped to the screen.
    pub fn stroke_rect(&self, x: usize, y: usize, width: usize, height: usize, colour: Colour) {
        if width == 0 || height == 0 {
            return;
        }
        self.fill_rect(x, y, width, 1, colour);
        self.fill_rect(x, y + height - 1, width, 1, colour);
        self.fill_rect(x, y, 1, height, colour);
        self.fill_rect(x + width - 1, y, 1, height, colour);
    }

    #[allow(dead_code)]
    pub fn clear(&self, colour: Colour) {
        self.fill_rect(0, 0, self.width, self.height, colour);
    }

    pub fn format(&self) -> PixelFormat {
        self.format
    }

    /// The framebuffer's base address.
    ///
    /// Exposed only for the compositor's self-test read-back path, which
    /// needs to check what was *actually displayed* rather than what the
    /// compositor believes it drew - the difference between those two
    /// being exactly where a trusted path fails. Every other access goes
    /// through `set_pixel`, which bounds-checks; routing the one
    /// exception through a named accessor keeps it greppable.
    pub fn base_address(&self) -> u64 {
        self.base
    }
}
