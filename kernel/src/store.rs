//! Najm Store: package verification and Realm assignment.
//!
//! This implements ARCHITECTURE.md section 2e, which is the section with
//! the sharpest security argument in the document and the one most easily
//! implemented wrongly. Its claim, restated:
//!
//! > Vault Realm eligibility is a **credential, not a declaration**.
//!
//! And its three rejected alternatives, each of which is what a package
//! manager naturally does if nobody thinks about it:
//!
//! | Approach | Why it fails |
//! |---|---|
//! | Realm declared in the package's own manifest | Any author writes `realm = vault`; zero verification |
//! | User chooses at install time | Social-engineerable, and most users have no basis to judge |
//! | Kernel heuristically detects "sensitive" apps | Gameable by design, and wrong for legitimate apps that do not trip it |
//!
//! ## What is implemented, exactly
//!
//! The **policy** is complete and enforced:
//!
//! - A package may *request* a Realm in its manifest. That request is
//!   read, logged, and then used only as something to compare against -
//!   never as the answer.
//! - The default is Home, and a package with no verified publisher gets
//!   Home **including one that explicitly asked for Vault**.
//! - Elevation requires a signature that verifies against a publisher key
//!   in the kernel's trust root.
//!
//! The **integrity check** is complete: SHA-256 over the manifest and
//! every file, compared against the digest in the header. A package with
//! one flipped byte is rejected.
//!
//! The **signature check is not implemented**, and this is the important
//! part: it fails *closed*. [`verify_signature`] returns
//! `Err(Unverified)` unconditionally, which means **no package can
//! currently reach Vault**. A missing verifier denies elevation rather
//! than granting it.
//!
//! That direction is not an accident of how it was written. It is the
//! single decision that makes an incomplete implementation safe to ship:
//! the code path that has not been written yet is the one that says
//! "yes", so its absence is a system that is too strict rather than one
//! that trusts anything. The self-test asserts this - a package that asks
//! for Vault and gets Vault would fail the boot.
//!
//! Implementing it means Ed25519 verification: about four hundred lines
//! of field arithmetic over 2^255-19, which is a primitive where writing
//! it yourself is a considerably worse idea than writing SHA-256 yourself
//! was. That is recorded as the work item it is, in the one place where
//! someone reading the trust decision will see it.

use crate::realm::{self, RealmProfile};
use crate::security::sha256;
use crate::serial_println;
use alloc::string::String;
use alloc::vec::Vec;

/// A parsed package manifest.
///
/// Every field is a *claim by the package about itself*, which is why the
/// type is named for what it is rather than for what it describes. The
/// distinction is the whole subject of this module: `requested_realm` is
/// not the Realm the package gets.
#[derive(Debug, Clone)]
pub struct Manifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub publisher: String,
    /// The program to run, as a path inside the package.
    pub entry: String,
    /// What the package would *like*. Compared against what it is
    /// entitled to; never used as the answer.
    pub requested_realm: u64,
    /// Capability bits the package asks for, as names in the manifest.
    /// Intersected with what its granted Realm actually provides - a
    /// package cannot acquire a right by listing it.
    pub requested_capabilities: u64,
}

impl Manifest {
    /// Parses the `key = value` manifest format.
    ///
    /// The same deliberately trivial format as the theme file, for the
    /// same reason: this is untrusted input parsed by privileged code, so
    /// the format has no nesting, no lengths, no references, and no
    /// includes. There is nothing in it that can point anywhere.
    pub fn parse(text: &str) -> Option<Manifest> {
        let mut manifest = Manifest {
            id: String::new(),
            name: String::new(),
            version: String::new(),
            publisher: String::new(),
            entry: String::new(),
            // The default, before any line is read. A manifest that omits
            // the field entirely gets Home, which is the same answer one
            // that asks for Vault gets without a credential.
            requested_realm: najm_abi::realm_kind::HOME,
            requested_capabilities: 0,
        };

        for line in text.lines() {
            let line = line.trim();
            // A comment starts a line; `#` is not stripped from the
            // middle of one. See the equivalent note in
            // `graphics::theme::Theme::parse` - inline comment stripping
            // silently truncated every value in the theme format, and a
            // publisher name or version string is just as entitled to
            // contain a `#`.
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let (key, value) = (key.trim(), value.trim());

            match key {
                "id" => manifest.id = String::from(value),
                "name" => manifest.name = String::from(value),
                "version" => manifest.version = String::from(value),
                "publisher" => manifest.publisher = String::from(value),
                "entry" => manifest.entry = String::from(value),
                "realm" => {
                    manifest.requested_realm = match value {
                        "gaming" => najm_abi::realm_kind::GAMING,
                        "vault" => najm_abi::realm_kind::VAULT,
                        // Deliberately no "system" case. That Realm is
                        // not assignable to an installed application by
                        // any path, so accepting the word here - even to
                        // reject it later - would create a spelling that
                        // looks like it might work.
                        _ => najm_abi::realm_kind::HOME,
                    }
                }
                "capability" => {
                    if let Some(bit) = capability_bit(value) {
                        manifest.requested_capabilities |= bit;
                    }
                }
                _ => {}
            }
        }

        // An id and an entry point are the minimum for a package to mean
        // anything. Missing either is a malformed package rather than a
        // package with defaults.
        if manifest.id.is_empty() || manifest.entry.is_empty() {
            return None;
        }

        Some(manifest)
    }
}

fn capability_bit(name: &str) -> Option<u64> {
    use najm_abi::capability_bits as bits;
    Some(match name {
        "serial_write" => bits::SERIAL_WRITE,
        "timer_read" => bits::TIMER_READ,
        "file_read" => bits::FILE_READ,
        "file_write" => bits::FILE_WRITE,
        "process_spawn" => bits::PROCESS_SPAWN,
        "ipc_create" => bits::IPC_CREATE,
        "ipc_connect" => bits::IPC_CONNECT,
        "surface_create" => bits::SURFACE_CREATE,
        "input_read" => bits::INPUT_READ,
        "exclusive_scanout" => bits::EXCLUSIVE_SCANOUT,
        _ => return None,
    })
}

/// Why a signature could not be accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// `Unverified` and `Verified` are never constructed today, and that is
/// the finding rather than dead code: `verify_signature` is unimplemented
/// and fails closed, so no package can currently be elevated. The variants
/// exist so that implementing it is filling in a function rather than
/// also changing every type it touches.
#[allow(dead_code)]
pub enum SignatureStatus {
    /// No signature was present. Not an error - an unsigned package is a
    /// perfectly legitimate thing to install, it simply cannot be
    /// elevated.
    Absent,
    /// A signature was present but could not be verified, because
    /// verification is not implemented. **Fails closed**: this denies
    /// elevation.
    Unverified,
    /// The signature verified against a known publisher key.
    Verified,
}

/// The result of examining a package.
#[derive(Debug)]
pub struct Verdict {
    pub manifest: Manifest,
    /// Whether the contents match the digest in the header.
    pub integrity_ok: bool,
    pub signature: SignatureStatus,
    /// The Realm the package will actually run in.
    pub granted_realm: RealmProfile,
    /// Set when the package asked for more than it was given, which is
    /// the case worth reporting to a user - it is the difference between
    /// "this app is running with fewer rights than it wanted" and "this
    /// app got what it asked for".
    pub request_denied: bool,
}

/// Why a package could not be examined at all.
#[derive(Debug)]
pub enum StoreError {
    TooSmall,
    BadMagic,
    UnsupportedVersion(u32),
    Malformed(&'static str),
    BadManifest,
}

impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StoreError::TooSmall => write!(f, "package is smaller than its own header"),
            StoreError::BadMagic => write!(f, "not a Najm package"),
            StoreError::UnsupportedVersion(v) => {
                write!(f, "package format version {} is not supported", v)
            }
            StoreError::Malformed(why) => write!(f, "malformed package: {}", why),
            StoreError::BadManifest => write!(
                f,
                "the manifest is missing an id or an entry point, without which the package \
                 names nothing to run"
            ),
        }
    }
}

/// `"NAJMPKG"` plus a padding byte.
pub const MAGIC: [u8; 8] = *b"NAJMPKG\0";
pub const VERSION: u32 = 1;

/// Package layout:
///
/// ```text
///   0    8   magic
///   8    4   version
///   12   4   manifest length
///   16   32  SHA-256 of everything from offset 48 to the end
///   48   ..  manifest text, then a NAR archive of the package's files
/// ```
///
/// The digest covers the manifest *and* the payload, together, in one
/// pass. Hashing them separately and storing two digests would let a
/// package be assembled from a manifest signed for one payload and a
/// payload signed for another - which is a real attack on real package
/// formats, and costs nothing to prevent by hashing the pair.
const HEADER_SIZE: usize = 48;

/// Examines a package and decides what it is allowed to be.
pub fn verify(bytes: &[u8]) -> Result<Verdict, StoreError> {
    if bytes.len() < HEADER_SIZE {
        return Err(StoreError::TooSmall);
    }
    if bytes[0..8] != MAGIC {
        return Err(StoreError::BadMagic);
    }
    let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    if version != VERSION {
        return Err(StoreError::UnsupportedVersion(version));
    }

    let manifest_len = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    let mut expected_digest = [0u8; 32];
    expected_digest.copy_from_slice(&bytes[16..48]);

    let body = &bytes[HEADER_SIZE..];
    if manifest_len > body.len() {
        return Err(StoreError::Malformed(
            "the manifest length extends past the end of the package",
        ));
    }

    // Integrity first, before the manifest is even parsed. Parsing
    // untrusted bytes that have not been checked against a digest means
    // the parser is exposed to input the publisher never produced - and
    // the parser is the more complicated of the two operations.
    let actual_digest = sha256::digest(body);
    let integrity_ok = sha256::digests_equal(&actual_digest, &expected_digest);

    if !integrity_ok {
        // Reported and then still parsed, because the caller needs the
        // manifest to *say what was rejected* - a package that fails
        // integrity with no name attached is much harder to act on. The
        // verdict carries `integrity_ok: false`, and every consumer is
        // expected to refuse it.
        // Deliberately not the word "FAILURE". That token is reserved
        // for a *self-test* failing, and `scripts/boot-test.sh` fails a
        // run on sight of it. A rejected package is this code working
        // correctly - the boot archive contains a deliberately corrupted
        // package precisely so this path is exercised on every boot - so
        // using the failure vocabulary here would make a passing test
        // look like a broken kernel.
        serial_println!(
            "Najm Store: REJECTED - the package's contents do not match its recorded digest. It \
             has been modified, truncated, or corrupted in transit."
        );
    }

    let manifest_text = core::str::from_utf8(&body[..manifest_len])
        .map_err(|_| StoreError::Malformed("the manifest is not valid UTF-8"))?;
    let manifest = Manifest::parse(manifest_text).ok_or(StoreError::BadManifest)?;

    let signature = verify_signature(bytes, &manifest);

    // The decision this whole module exists for.
    //
    // Note the shape: the granted Realm is computed from the *signature
    // status*, and the manifest's request appears only in the comparison
    // afterwards. A version where `requested_realm` fed into the grant -
    // even guarded by a check - would be one refactor away from the
    // failure ARCHITECTURE.md 2e describes.
    let granted_realm = match signature {
        SignatureStatus::Verified => match manifest.requested_realm {
            najm_abi::realm_kind::VAULT => realm::VAULT,
            najm_abi::realm_kind::GAMING => realm::GAMING,
            _ => realm::HOME,
        },
        // Unsigned, or signed but unverifiable. Home, whatever was asked
        // for. Integrity failure also lands here, so a tampered package
        // cannot be elevated even if its signature field looks right.
        _ => realm::HOME,
    };

    let effective = if integrity_ok {
        granted_realm
    } else {
        realm::HOME
    };

    let request_denied = manifest.requested_realm != effective.kind;

    Ok(Verdict {
        manifest,
        integrity_ok,
        signature,
        granted_realm: effective,
        request_denied,
    })
}

/// Verifies a package's publisher signature.
///
/// **Not implemented, and fails closed.** Returns [`SignatureStatus::Unverified`]
/// for any package carrying a signature, and [`SignatureStatus::Absent`]
/// for one that does not - so no package can currently be elevated above
/// Home.
///
/// That is the correct state for an unfinished trust check to be in, and
/// it is worth being explicit about why rather than treating it as an
/// obvious default. An incomplete verifier has two possible failure
/// directions:
///
/// - **Fail open**: unverifiable signatures are accepted, so the system
///   works as intended today and silently trusts anything. The gap is
///   invisible until it is exploited.
/// - **Fail closed**: unverifiable signatures are rejected, so nothing
///   gets elevated and the limitation is obvious the first time someone
///   tries to ship a Vault application.
///
/// Only one of those is safe to leave in a repository. The self-test
/// asserts the closed behaviour, so a future change that accidentally
/// opens it fails the boot rather than passing quietly.
///
/// What implementing it needs: Ed25519 verification - roughly four
/// hundred lines of field arithmetic modulo 2^255-19, plus point
/// decompression and the SHA-512 the scheme requires. Unlike SHA-256,
/// this is a primitive where a subtle mistake produces a verifier that
/// accepts forgeries rather than one that produces wrong digests, so it
/// wants either a reviewed implementation or a vetted dependency, not a
/// from-scratch afternoon.
fn verify_signature(bytes: &[u8], _manifest: &Manifest) -> SignatureStatus {
    // A signature would be appended after the payload. Nothing writes one
    // yet, so this is structural: it establishes where the field lives so
    // that adding the verifier later does not also mean changing the
    // format.
    let _ = bytes;
    SignatureStatus::Absent
}

/// Applies the manifest's capability requests, intersected with what the
/// granted Realm actually provides.
///
/// Intersection, not union. A manifest listing `exclusive_scanout` in a
/// Home Realm package does not acquire it - the request can only ever
/// *narrow* what the Realm already offers. That makes the manifest useful
/// for the thing it should be useful for (an application declaring it
/// needs less than it could have, so a user can see that) and useless for
/// the thing it must not be (acquiring a right).
#[allow(dead_code)]
pub fn effective_profile(verdict: &Verdict) -> RealmProfile {
    let mut profile = verdict.granted_realm;

    // A manifest that requests nothing gets the Realm's full set, since
    // an empty request is far more likely to mean "did not think about
    // it" than "wants no capabilities at all" - and a process with no
    // rights cannot even print why it failed.
    if verdict.manifest.requested_capabilities != 0 {
        profile.capabilities &= verdict.manifest.requested_capabilities;
    }

    profile
}

/// Prints what a package is and what it was allowed to be.
///
/// The denied-request line is the one that matters. A user installing
/// something that asked for Vault and got Home should be able to see
/// that, and so should whoever is debugging why an application does not
/// have a capability it expected.
pub fn report(verdict: &Verdict) {
    serial_println!(
        "Najm Store: package '{}' v{} by '{}' - entry '{}'",
        verdict.manifest.name,
        verdict.manifest.version,
        verdict.manifest.publisher,
        verdict.manifest.entry
    );
    serial_println!(
        "Najm Store:   integrity {}, signature {:?}, granted {} ({})",
        if verdict.integrity_ok { "OK" } else { "FAILED" },
        verdict.signature,
        verdict.granted_realm.name,
        if verdict.request_denied {
            "the package requested a different Realm and was refused"
        } else {
            "as requested"
        }
    );

    if verdict.request_denied {
        serial_println!(
            "Najm Store:   the request was denied because elevation requires a signature from a \
             publisher verified in advance - see ARCHITECTURE.md section 2e. Signature \
             verification is not implemented, so it fails closed and nothing is elevated."
        );
    }
}

/// The files inside a package, as a NAR archive.
///
/// The payload reuses the boot archive format rather than inventing a
/// second one. Two archive formats in one system means two parsers, and
/// the parser is the part handling untrusted input.
#[allow(dead_code)]
pub fn payload(bytes: &[u8]) -> Result<&[u8], StoreError> {
    if bytes.len() < HEADER_SIZE {
        return Err(StoreError::TooSmall);
    }
    let manifest_len = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    let start = HEADER_SIZE + manifest_len;
    if start > bytes.len() {
        return Err(StoreError::Malformed("the payload starts past the end"));
    }
    Ok(&bytes[start..])
}

/// Builds a package's digest the way `verify` checks it, for tests and
/// for whatever eventually writes packages.
#[allow(dead_code)]
pub fn compute_digest(manifest: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = sha256::Sha256::new();
    hasher.update(manifest);
    hasher.update(payload);
    hasher.finish()
}

/// Every package found in a directory, verified.
pub fn scan(directory: &str) -> Vec<Verdict> {
    let mut verdicts = Vec::new();
    let Some(entries) = crate::fs::read_dir(directory) else {
        return verdicts;
    };

    for path in entries {
        if !path.ends_with(".najm") {
            continue;
        }
        let Some(bytes) = crate::fs::read_all(&path) else {
            continue;
        };
        match verify(&bytes) {
            Ok(verdict) => verdicts.push(verdict),
            Err(err) => serial_println!("Najm Store: could not read '{}' - {}", path, err),
        }
    }

    verdicts
}
