//! Mirage: running Windows binaries natively.
//!
//! This is the Proton-equivalent, and the first thing to be clear about
//! is what that phrase does and does not mean - because the gap between
//! them is where every "we support Windows games" claim goes to die.
//!
//! ## What Proton actually is
//!
//! Proton is not an emulator. A Windows x86_64 binary contains the same
//! instructions a Linux one does, and a modern CPU runs them at full
//! speed either way. What a Windows binary *cannot* do on another system
//! is two things:
//!
//! 1. **Be loaded.** It is in PE/COFF format, not ELF - different
//!    headers, different section table, imports resolved through an
//!    Import Address Table rather than a dynamic symbol table.
//! 2. **Call anything.** It calls `CreateFileW`, `Direct3DCreate9`,
//!    `RegOpenKeyEx` - thousands of functions that exist only in
//!    Windows's own DLLs.
//!
//! Wine, and Proton on top of it, solve the first with a PE loader and
//! the second by *reimplementing the API*: their own `kernel32.dll`,
//! `user32.dll`, `d3d11.dll`, translating each call into the host's
//! native equivalent. DXVK translates Direct3D into Vulkan. There is no
//! instruction-level emulation anywhere in it.
//!
//! **Mirage is the same architecture.** This module is the PE loader; the
//! thunk table below is the API reimplementation. The difference between
//! this and Proton is not one of kind. It is that Proton reimplements
//! tens of thousands of functions across three decades of Windows API
//! surface, and this reimplements four.
//!
//! ## What works today, stated exactly
//!
//! A PE32+ executable that imports only from the table in
//! [`win32::THUNKS`] will load, relocate, resolve its imports, and run at
//! Ring 3 in its own address space with W^X enforced - the same isolation
//! any native process gets. It can print, read the clock, yield, and
//! exit.
//!
//! What does not work, and is not close to working: threads, the
//! registry, files, windows, Direct3D, OpenGL, Vulkan, sockets,
//! exceptions, TLS callbacks, delay-loaded imports, forwarded exports,
//! .NET, or anything that calls a function not in that table of four. A
//! real game imports several hundred functions before it draws a pixel.
//!
//! Being precise about that is the point. "We have a Proton equivalent"
//! and "we have the loader and thunk architecture a Proton equivalent is
//! built out of" are very different claims, and only the second is true.
//! The first is what this becomes after a great deal of unglamorous API
//! implementation - which is exactly what Wine has been doing since 1993.
//!
//! ## Why the ABI translation is the interesting part
//!
//! Windows x86_64 and System V x86_64 disagree about where arguments go:
//! Windows passes the first four in RCX, RDX, R8, R9; System V uses RDI,
//! RSI, RDX, RCX, R8, R9. A Windows binary calling into native code
//! without translation passes its first argument where the callee expects
//! its fourth.
//!
//! So each import is bound to a small generated stub - written into the
//! process's own address space, executable and read-only - that shuffles
//! registers into Najm's syscall convention and issues `int 0x80`. That
//! is a genuine, working Win32-to-native ABI translation, and it is the
//! same shape the real thing has: a thunk per import, generated at load
//! time, pointing at an implementation.

pub mod pe;
pub mod win32;

use crate::mm::address_space::AddressSpace;
use crate::mm::layout;
use crate::serial_println;
use alloc::string::String;
use x86_64::structures::paging::{Page, PageTableFlags, Size4KiB};
use x86_64::VirtAddr;

/// Why a PE image could not be prepared for execution.
#[derive(Debug)]
pub enum MirageError {
    /// The file is not a PE32+ image this loader understands.
    NotPe(&'static str),
    /// An import names a function Mirage does not implement. Carries the
    /// name, because "which function" is the only useful part of this
    /// error - it is the work item.
    UnimplementedImport(String),
    /// A structural problem in the image: an offset outside the file, a
    /// section that overlaps another, a relocation pointing nowhere.
    Malformed(&'static str),
    Mapping(crate::mm::address_space::MapError),
    OutOfMemory,
}

impl core::fmt::Display for MirageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MirageError::NotPe(why) => write!(f, "not a loadable PE32+ image: {}", why),
            MirageError::UnimplementedImport(name) => write!(
                f,
                "the image imports '{}', which Mirage does not implement yet. Mirage currently \
                 provides {} functions; a real Windows application imports several hundred",
                name,
                win32::THUNKS.len()
            ),
            MirageError::Malformed(why) => write!(f, "malformed PE image: {}", why),
            MirageError::Mapping(err) => write!(f, "could not map the image: {}", err),
            MirageError::OutOfMemory => write!(f, "out of memory building the address space"),
        }
    }
}

/// Loads a PE32+ image into a fresh address space, ready to run.
///
/// The steps, and why they happen in this order:
///
/// 1. **Parse and validate.** Everything, before anything is mapped, so a
///    malformed image is an error rather than a half-built address space.
/// 2. **Map sections** at [`layout::MIRAGE_IMAGE_BASE`], not at the
///    image's own preferred base. A PE declares where it would like to
///    live, and honouring that would let a crafted image ask to be placed
///    on top of a native program's segments. Relocating is not a
///    limitation here; it is the isolation.
/// 3. **Apply base relocations**, because step 2 moved the image away
///    from the address its absolute references were computed against.
/// 4. **Bind imports** to generated ABI-translation thunks.
/// 5. **Re-protect** to W^X. Sections are mapped writable to be filled in
///    and tightened afterwards, exactly as the ELF loader does and for
///    the same reason - CR0.WP means the kernel cannot write a read-only
///    page either.
pub fn load_image(bytes: &[u8], name: &str) -> Result<crate::process::LoadedImage, MirageError> {
    let image = pe::parse(bytes)?;

    serial_println!(
        "Najm Kernel: Mirage loading '{}' - PE32+ image, {} section(s), {} import(s), preferred \
         base {:#x}, relocating to {:#x}",
        name,
        image.sections.len(),
        image.imports.len(),
        image.preferred_base,
        layout::MIRAGE_IMAGE_BASE
    );

    // Every import is checked *before* an address space is built, so an
    // image that uses an unimplemented function fails with a message
    // naming it rather than after a page of work.
    for import in &image.imports {
        if win32::lookup(&import.name).is_none() {
            return Err(MirageError::UnimplementedImport(import.name.clone()));
        }
    }

    let mut space = AddressSpace::new().ok_or(MirageError::OutOfMemory)?;
    let nx_available = crate::arch::x86_64::cpu::detect().nx;
    let base = layout::MIRAGE_IMAGE_BASE;

    // Map the whole image as one writable region, fill it, then tighten
    // per section. Sections in a PE are rarely page-aligned in the file
    // and often share pages in memory, so mapping them independently
    // would hit the same overlap problem the ELF loader rejects - except
    // that for PE it is the normal case rather than a malformed image.
    let image_pages = image.image_size.div_ceil(4096);
    let load_flags =
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;

    for index in 0..image_pages {
        let page: Page<Size4KiB> =
            Page::containing_address(VirtAddr::new(base + index as u64 * 4096));
        space.map_page(page, load_flags).map_err(MirageError::Mapping)?;
    }

    // Zeroed before anything is copied in. A PE's `SizeOfRawData` is
    // routinely smaller than its `VirtualSize` - that difference is the
    // image's uninitialized data - and the pages come from the frame pool
    // holding whatever the last owner left there. Without this, a Windows
    // binary's uninitialized globals would start out as kernel memory.
    space
        .zero_at(base, image_pages * 4096)
        .map_err(MirageError::Mapping)?;

    // Headers first: a PE image expects its own headers to be readable at
    // its base address, and code that walks its own import table at
    // runtime - which packers and anti-tamper checks routinely do - reads
    // them there.
    let header_bytes = core::cmp::min(image.headers_size, bytes.len());
    space
        .write_at(base, &bytes[..header_bytes])
        .map_err(MirageError::Mapping)?;

    for section in &image.sections {
        if section.raw_size == 0 {
            continue;
        }
        let start = section.raw_offset;
        let end = start + section.raw_size;
        space
            .write_at(base + section.virtual_address as u64, &bytes[start..end])
            .map_err(MirageError::Mapping)?;
    }

    apply_relocations(&mut space, &image, base)?;
    let thunk_base = bind_imports(&mut space, &image, base, nx_available)?;

    // W^X, per section. A PE section carries its own characteristics -
    // executable, readable, writable - exactly as an ELF segment does,
    // and they are honoured the same way. A section asking for write and
    // execute together is refused rather than downgraded: that
    // combination is the signature of a self-modifying packer, and
    // silently dropping one of the two produces a fault somewhere
    // confusing instead of an error here.
    for section in &image.sections {
        let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
        if section.writable && section.executable {
            return Err(MirageError::Malformed(
                "a section requests both write and execute permission; Najm OS enforces W^X, so \
                 a self-modifying or packed image cannot run",
            ));
        }
        if section.writable {
            flags |= PageTableFlags::WRITABLE;
        }
        if !section.executable && nx_available {
            flags |= PageTableFlags::NO_EXECUTE;
        }

        let first = section.virtual_address as u64 / 4096;
        let last = (section.virtual_address as u64 + section.virtual_size.max(1) as u64 - 1) / 4096;
        for index in first..=last {
            let page: Page<Size4KiB> =
                Page::containing_address(VirtAddr::new(base + index * 4096));
            space.protect_page(page, flags).map_err(MirageError::Mapping)?;
        }
    }

    // A stack, non-executable, with the same unmapped guard page beneath
    // it that a native process gets. A Windows binary is not trusted more
    // than a native one - it is trusted considerably less - so it gets
    // exactly the same isolation and none of its own.
    let mut stack_flags =
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
    if nx_available {
        stack_flags |= PageTableFlags::NO_EXECUTE;
    }
    for index in 0..layout::USER_STACK_PAGES {
        let page: Page<Size4KiB> =
            Page::containing_address(VirtAddr::new(layout::USER_STACK_BOTTOM + index * 4096));
        space.map_page(page, stack_flags).map_err(MirageError::Mapping)?;
    }
    space
        .zero_at(
            layout::USER_STACK_BOTTOM,
            (layout::USER_STACK_PAGES * 4096) as usize,
        )
        .map_err(MirageError::Mapping)?;

    serial_println!(
        "Najm Kernel: Mirage bound {} import(s) to ABI-translation thunks at {:#x}; entry {:#x}",
        image.imports.len(),
        thunk_base,
        base + image.entry_rva as u64
    );

    Ok(crate::process::LoadedImage {
        name: String::from(name),
        entry: base + image.entry_rva as u64,
        // The Microsoft x64 ABI requires 32 bytes of "shadow space" above
        // the return address for the callee to spill its register
        // arguments into. Native code does not reserve it and does not
        // need it; a PE entry point assumes it is there, and will write
        // into it. Leaving the space is what stops that write landing on
        // whatever the stack top happened to be.
        stack_top: layout::USER_STACK_TOP - 64,
        address_space: space,
    })
}

/// Rewrites absolute addresses in the image for its new base.
///
/// A PE is compiled against a preferred base address and contains a list
/// of every place it embedded an absolute address. Moving the image means
/// adding the difference at each of those places. Skipping this on a
/// relocated image does not fail loudly - it produces code that jumps to
/// wherever the image *would have been*, which is unmapped, so the
/// symptom is a page fault at a plausible-looking address with no hint of
/// the cause.
fn apply_relocations(
    space: &mut AddressSpace,
    image: &pe::Image,
    base: u64,
) -> Result<(), MirageError> {
    let delta = base.wrapping_sub(image.preferred_base);
    if delta == 0 || image.relocations.is_empty() {
        return Ok(());
    }

    for &rva in &image.relocations {
        let address = base + rva as u64;

        // Read the existing value out of the address space, add the
        // delta, write it back. Reading through the address space rather
        // than from the file buffer matters: the value at that location
        // may already have been written by a section copy, and the file
        // and memory layouts differ.
        let Some(frame) = space.translate(address) else {
            return Err(MirageError::Malformed(
                "a relocation points outside the mapped image",
            ));
        };
        let offset = crate::mm::memory::physical_memory_offset();
        let pointer = (offset + frame.start_address().as_u64() + (address & 0xFFF)) as *mut u64;

        // A relocation within 8 bytes of a page boundary would straddle
        // two frames, and this reads and writes a single `u64` through
        // one translation. Refused rather than silently corrupting the
        // next page - PE relocations are 4-byte aligned in practice, so
        // this is a malformed-image check rather than a limitation.
        if (address & 0xFFF) > 4096 - 8 {
            return Err(MirageError::Malformed(
                "a relocation straddles a page boundary",
            ));
        }

        // Safety: `pointer` addresses eight bytes inside a frame this
        // address space owns, reached through the kernel's own
        // physical-memory window - a kernel mapping, so no SMAP bracket
        // applies. The bounds check above guarantees the access stays
        // within the translated frame.
        unsafe {
            let value = pointer.read_unaligned();
            pointer.write_unaligned(value.wrapping_add(delta));
        }
    }

    Ok(())
}

/// Writes an ABI-translation thunk for each import and points the Import
/// Address Table at it.
///
/// The thunk is the whole compatibility story in eight instructions.
/// Windows x64 passes arguments in RCX, RDX, R8, R9; Najm's syscall ABI
/// uses RDI, RSI, RDX with the number in RAX. Without translation, a
/// Windows binary calling `ExitProcess(3)` would put 3 in RCX, and the
/// kernel would read the exit status out of RDI - which holds whatever
/// the program last left there.
///
/// Returns where the thunks were placed.
fn bind_imports(
    space: &mut AddressSpace,
    image: &pe::Image,
    base: u64,
    nx_available: bool,
) -> Result<u64, MirageError> {
    // The thunks live on their own page immediately after the image, so
    // they can be mapped read-execute independently of any section.
    let thunk_base = base + (image.image_size.div_ceil(4096) * 4096) as u64;
    let page: Page<Size4KiB> = Page::containing_address(VirtAddr::new(thunk_base));

    space
        .map_page(
            page,
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE,
        )
        .map_err(MirageError::Mapping)?;
    space.zero_at(thunk_base, 4096).map_err(MirageError::Mapping)?;

    for (index, import) in image.imports.iter().enumerate() {
        let thunk = win32::lookup(&import.name).ok_or_else(|| {
            MirageError::UnimplementedImport(import.name.clone())
        })?;

        let code = win32::generate_thunk(thunk);
        let address = thunk_base + (index * win32::THUNK_STRIDE) as u64;
        if address + win32::THUNK_STRIDE as u64 > thunk_base + 4096 {
            return Err(MirageError::Malformed(
                "too many imports to fit in one page of thunks",
            ));
        }

        space.write_at(address, &code).map_err(MirageError::Mapping)?;

        // Point the Import Address Table slot at the thunk. This is what
        // an ordinary Windows loader does with the real function's
        // address; the only difference is what the address leads to.
        space
            .write_at(base + import.iat_rva as u64, &address.to_le_bytes())
            .map_err(MirageError::Mapping)?;
    }

    // Read-execute. The thunks are code, and code this loader generated -
    // which makes it exactly the kind of page that must not stay
    // writable, since a writable executable page in a process running an
    // untrusted binary is a gift.
    let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
    if !nx_available {
        // NX unavailable: the page is executable regardless, and marking
        // it read-only is the only half of W^X that can be enforced.
    }
    let _ = nx_available;
    space.protect_page(page, flags).map_err(MirageError::Mapping)?;
    flags |= PageTableFlags::PRESENT;

    Ok(thunk_base)
}
