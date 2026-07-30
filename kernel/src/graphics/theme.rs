//! Theming: the customization ARCHITECTURE.md 2c calls the "Realm Shell",
//! and the boundary that keeps it from touching the "Realm Core".
//!
//! Section 2c is explicit that theming should be *fully flexible* -
//! colours, layout, fonts, per-Realm personality - and that exactly one
//! thing is exempt: the trust indicator, which must be "generated
//! directly by the kernel/Core layer rather than any Shell
//! configuration". Both halves matter, and it is easy to implement one
//! and quietly lose the other.
//!
//! So this file is deliberately two lists. Everything in [`Theme`] is
//! themeable. The trust bar's *contents* - the Realm name, the boot
//! signature, the fact that it is drawn at all - are not here, cannot be
//! reached from here, and are not read from any file. What a theme may
//! change about the trust bar is its background and text colour, which is
//! cosmetic: a theme can make it dark or light, and cannot make it say
//! something else, cannot move it, and cannot remove it.
//!
//! ## Parsed in the kernel, which is wrong, and said so
//!
//! ARCHITECTURE.md 2d threat 6 is specific: theme files are untrusted
//! input, community-contributed themes are a realistic distribution
//! model, and parsing them in a privileged process is a classic
//! remote-code-execution vector *regardless of language* - Rust's memory
//! safety helps with one class of bug and does nothing about logic ones.
//! The document requires theme parsing to happen in a sandboxed
//! subprocess with a minimal capability set.
//!
//! This parses in the kernel, which does not meet that requirement. The
//! mitigations that make it defensible *for now*: the format is
//! key-and-hex-colour with no nesting, no lengths, no references and no
//! includes; every value is bounds-checked; an unparseable line is
//! skipped rather than causing a failure; and the file comes from the
//! boot archive rather than from a user directory, so today it is only as
//! untrusted as the boot image itself. None of that is the required
//! sandbox, and this comment exists so the gap is a known debt rather
//! than an assumption someone later has to rediscover.

use super::framebuffer::Colour;

/// The complete set of themeable colours.
///
/// A flat struct of named fields rather than a map from string keys, so
/// that a theme referring to a colour that does not exist is a parse-time
/// no-op rather than a lookup that silently returns a default at draw
/// time - and so that adding a colour to the system is a compile error at
/// every place that has to supply one.
#[derive(Debug, Clone, Copy)]
pub struct Theme {
    /// Behind all windows.
    pub desktop: Colour,
    /// The Core-reserved strip's background. Cosmetic only - see the
    /// module docs on what a theme may and may not change about it.
    pub trust_bar: Colour,
    /// The hairline separating Core-owned pixels from Realm-owned ones.
    pub trust_bar_edge: Colour,
    pub trust_bar_text: Colour,
    /// Per-Realm accent colours, used for window borders and the trust
    /// bar's Realm swatch.
    pub accent_home: Colour,
    pub accent_gaming: Colour,
    pub accent_vault: Colour,
    pub accent_system: Colour,
    pub pointer_fill: Colour,
    pub pointer_edge: Colour,
}

impl Theme {
    /// The built-in theme, used when no theme file is present or when one
    /// fails to parse.
    ///
    /// A `const` rather than a `Default` impl because the compositor's
    /// `static` initializer needs it in const context - and because a
    /// theme that can be constructed at compile time cannot fail to
    /// exist, which means there is always something to fall back to.
    pub const DEFAULT: Theme = Theme {
        desktop: Colour::rgb(0x10, 0x14, 0x1C),
        trust_bar: Colour::rgb(0x06, 0x08, 0x0C),
        trust_bar_edge: Colour::rgb(0x2A, 0x33, 0x44),
        trust_bar_text: Colour::rgb(0xE8, 0xEE, 0xF7),
        accent_home: Colour::rgb(0x3A, 0x86, 0xFF),
        accent_gaming: Colour::rgb(0xF7, 0x25, 0x85),
        accent_vault: Colour::rgb(0x4C, 0xC9, 0x7C),
        accent_system: Colour::rgb(0xFF, 0xD1, 0x66),
        pointer_fill: Colour::rgb(0xFF, 0xFF, 0xFF),
        pointer_edge: Colour::rgb(0x1A, 0x1A, 0x1A),
    };

    /// The accent colour for a Realm kind.
    pub fn accent_for_realm(&self, kind: u64) -> Colour {
        match kind {
            najm_abi::realm_kind::GAMING => self.accent_gaming,
            najm_abi::realm_kind::VAULT => self.accent_vault,
            najm_abi::realm_kind::SYSTEM => self.accent_system,
            _ => self.accent_home,
        }
    }

    /// Parses a theme file, returning it alongside how many settings were
    /// applied and how many lines were rejected.
    ///
    /// Starts from [`DEFAULT`](Theme::DEFAULT) and overrides what the
    /// file names, rather than requiring a complete theme. A theme that
    /// has to specify every colour is one that breaks whenever a colour
    /// is added to the system, and the failure would be an unreadable UI
    /// on someone else's machine.
    ///
    /// Format, deliberately trivial:
    ///
    /// ```text
    /// # comments run to end of line
    /// desktop = #101420
    /// accent.gaming = #f72585
    /// ```
    pub fn parse(text: &str) -> (Theme, usize, usize) {
        let mut theme = Theme::DEFAULT;
        let mut applied = 0;
        let mut rejected = 0;

        for line in text.lines() {
            let line = line.trim();

            // A comment is a line that *starts* with `#`, not everything
            // after the first `#` anywhere on the line.
            //
            // That distinction is the whole bug this format walked into.
            // Stripping inline comments is the obvious thing to write,
            // and in this format it is wrong, because `#` is also how a
            // colour is spelled: `desktop = #0d1117` becomes
            // `desktop =` with the value cut off. Every line of a
            // perfectly valid theme was rejected, and the fallback theme
            // rendered correctly - so the screen looked right and only
            // the "0 settings applied" count said otherwise.
            //
            // Inline comments are therefore not supported, and cannot be
            // without giving the format more structure (quoting, or a
            // different comment marker) than a colour list should need.
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let Some((key, value)) = line.split_once('=') else {
                rejected += 1;
                continue;
            };
            let key = key.trim();
            let Some(colour) = Colour::parse_hex(value.trim()) else {
                rejected += 1;
                continue;
            };

            let slot = match key {
                "desktop" => &mut theme.desktop,
                "trust_bar" => &mut theme.trust_bar,
                "trust_bar.edge" => &mut theme.trust_bar_edge,
                "trust_bar.text" => &mut theme.trust_bar_text,
                "accent.home" => &mut theme.accent_home,
                "accent.gaming" => &mut theme.accent_gaming,
                "accent.vault" => &mut theme.accent_vault,
                "accent.system" => &mut theme.accent_system,
                "pointer.fill" => &mut theme.pointer_fill,
                "pointer.edge" => &mut theme.pointer_edge,
                // An unknown key is rejected and counted, not ignored
                // silently. A theme with a typo'd key that appeared to
                // load successfully would have the author looking at the
                // wrong thing entirely.
                _ => {
                    rejected += 1;
                    continue;
                }
            };
            *slot = colour;
            applied += 1;
        }

        (theme, applied, rejected)
    }
}
