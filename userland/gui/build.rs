//! Points the linker at `linker.ld` and forces a non-PIE link.
//!
//! Done from a build script rather than a `.cargo/config.toml` because of
//! how Cargo discovers configuration: it walks up from the *current
//! working directory*, not from the manifest path. A
//! `userland/hello/.cargo/config.toml` would therefore be silently
//! ignored by the repo-root `make` invocation that actually builds this
//! crate - the same reason the Makefile passes `--target` explicitly for
//! the kernel instead of relying on `kernel/.cargo/config.toml`. A build
//! script runs with `CARGO_MANIFEST_DIR` set no matter where it was
//! invoked from, so the linker script is found either way.

use std::env;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set by cargo");

    // An absolute path, for the same cwd-independence reason as above.
    println!("cargo:rustc-link-arg=-T{manifest_dir}/linker.ld");

    // `x86_64-unknown-none` sets `position-independent-executables: true`,
    // which produces an ET_DYN image with R_X86_64_RELATIVE relocations
    // in .rela.dyn that something is expected to apply at load time.
    // Nothing does - kernel/src/loader.rs asserts ET_EXEC precisely
    // because it has no relocation processing - so the resulting binary
    // would be rejected outright, and would silently misbehave if it
    // weren't. `-no-pie` is what makes the linker resolve every address
    // at link time against the fixed base in linker.ld instead.
    println!("cargo:rustc-link-arg=-no-pie");

    println!("cargo:rerun-if-changed=linker.ld");
}
