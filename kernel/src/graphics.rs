//! The graphics stack: framebuffer, font, theming, and the compositor.
//!
//! Organized so that the security boundary is visible in the module list
//! rather than buried inside one file:
//!
//! - `framebuffer` - putting a pixel on the screen, with the hardware's
//!   real format and internal clipping.
//! - `font` - a 5x7 bitmap font, chosen over a scalable one because
//!   parsing TrueType in the kernel is exactly the threat
//!   ARCHITECTURE.md 2d guards against.
//! - `theme` - everything a user may customize.
//! - `compositor` - everything they may not, including the Core-drawn
//!   trusted path.
//!
//! The split between the last two is the point. ARCHITECTURE.md 2c calls
//! them the Realm Shell and the Realm Core and requires the trust
//! indicator to come from the Core "rather than any Shell configuration".
//! Keeping them in separate files with a one-way dependency - the
//! compositor reads a theme, a theme knows nothing about the compositor -
//! is what makes that structural rather than a rule someone has to
//! remember.

pub mod compositor;
pub mod font;
pub mod framebuffer;
pub mod theme;
