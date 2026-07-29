//! Build script: turns the already-compiled najm-kernel ELF binary into a
//! bootable BIOS disk image using the `bootloader` crate's image builder.
//!
//! This deliberately does NOT compile the kernel itself. The kernel is a
//! freestanding x86_64-unknown-none binary; this runner crate is a normal
//! hosted binary. Mixing those two builds into one `cargo build` invocation
//! is possible via Cargo's unstable "artifact dependencies" feature, but
//! that requires nightly + an unstable resolver just for this crate too,
//! which is a lot of fragility for a project's very first milestone.
//!
//! Instead: the Makefile at the repo root builds the kernel first, then
//! passes its output path in via the KERNEL_PATH environment variable.
//! `make run` does both steps for you - see the Makefile and
//! GETTING_STARTED.md.

use std::{env, path::PathBuf};

/// Builds the smallest valid ELF64 executable that can prove the
/// kernel's ELF loader actually works: an ELF header, one PT_LOAD
/// program header, and a 3-byte payload (`int 0x80` then `hlt` - the
/// same test instructions `usermode::run_test` already proved work when
/// hand-copied directly; the new thing being tested here is the ELF
/// *parsing and mapping* path, not a new payload).
///
/// Hand-built rather than compiled from a separate Rust crate
/// deliberately: a real userland toolchain (its own target, linker
/// script, panic handler, entry-point convention) is substantial
/// infrastructure in its own right, worth building once there's more
/// than one test program that needs it. Every byte below is standard,
/// stable ELF64 format - unlike the crate-version mismatches this
/// project has hit before, this format doesn't drift.
/// `#[allow(dead_code)]`: no longer called from `main()` - see the
/// comment at the `set_ramdisk` call site for why `build_bss_test_elf`
/// is the active one now. Kept here, still compiled, as the exact
/// reference that produced milestone 10's verified test log.
#[allow(dead_code)]
fn build_test_elf() -> Vec<u8> {
    const LOAD_VADDR: u64 = 0x0040_0000; // conventional, arbitrary fixed user load address
    const PAYLOAD: [u8; 3] = [0xCD, 0x80, 0xF4]; // int 0x80; hlt

    const EHDR_SIZE: u64 = 64;
    const PHDR_SIZE: u64 = 56;
    let payload_offset = EHDR_SIZE + PHDR_SIZE;

    let mut elf = Vec::new();

    // --- ELF64 header (64 bytes) ---
    elf.extend_from_slice(&[0x7F, b'E', b'L', b'F']); // e_ident: magic
    elf.push(2); // EI_CLASS: ELFCLASS64
    elf.push(1); // EI_DATA: ELFDATA2LSB (little-endian)
    elf.push(1); // EI_VERSION
    elf.push(0); // EI_OSABI: System V
    elf.extend_from_slice(&[0u8; 8]); // EI_ABIVERSION + padding (e_ident is 16 bytes total)
    elf.extend_from_slice(&2u16.to_le_bytes()); // e_type: ET_EXEC
    elf.extend_from_slice(&0x3Eu16.to_le_bytes()); // e_machine: EM_X86_64
    elf.extend_from_slice(&1u32.to_le_bytes()); // e_version
    elf.extend_from_slice(&(LOAD_VADDR).to_le_bytes()); // e_entry: payload starts at the segment's own base
    elf.extend_from_slice(&EHDR_SIZE.to_le_bytes()); // e_phoff: program header follows immediately
    elf.extend_from_slice(&0u64.to_le_bytes()); // e_shoff: no section headers
    elf.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    elf.extend_from_slice(&(EHDR_SIZE as u16).to_le_bytes()); // e_ehsize
    elf.extend_from_slice(&(PHDR_SIZE as u16).to_le_bytes()); // e_phentsize
    elf.extend_from_slice(&1u16.to_le_bytes()); // e_phnum: one program header
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
    assert_eq!(
        elf.len() as u64,
        EHDR_SIZE,
        "ELF header size drifted from the field layout above"
    );

    // --- Program header (56 bytes): one PT_LOAD segment ---
    elf.extend_from_slice(&1u32.to_le_bytes()); // p_type: PT_LOAD
    elf.extend_from_slice(&5u32.to_le_bytes()); // p_flags: PF_R | PF_X (readable + executable, not writable)
    elf.extend_from_slice(&payload_offset.to_le_bytes()); // p_offset: file offset of the payload
    elf.extend_from_slice(&LOAD_VADDR.to_le_bytes()); // p_vaddr
    elf.extend_from_slice(&LOAD_VADDR.to_le_bytes()); // p_paddr (unused by the loader, must still be present)
    elf.extend_from_slice(&(PAYLOAD.len() as u64).to_le_bytes()); // p_filesz
    elf.extend_from_slice(&(PAYLOAD.len() as u64).to_le_bytes()); // p_memsz (no .bss - equal to p_filesz)
    elf.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align: page-aligned
    assert_eq!(
        elf.len() as u64,
        EHDR_SIZE + PHDR_SIZE,
        "program header size drifted from the field layout above"
    );

    // --- Payload ---
    elf.extend_from_slice(&PAYLOAD);

    elf
}

/// Builds a second, more demanding test ELF, exercising three things the
/// 3-byte payload above cannot:
///
/// 1. **`.bss` zero-fill.** Its `PT_LOAD` segment declares a memory size
///    *larger* than its file size, forcing the loader to map extra pages
///    purely from `p_memsz` and zero-fill them - the `if p_memsz >
///    p_filesz` path in `loader.rs` that `build_test_elf` never touches
///    at all, since its file and memory sizes are equal. Coverage gaps in
///    an ELF loader are exactly the kind of thing worth catching
///    deliberately rather than noticing only once something real trips
///    over them.
/// 2. **Real syscall arguments.** It calls `write` with a pointer and
///    length in the documented registers, so the kernel's syscall entry
///    stub is proven to receive the values the program actually passed
///    rather than whatever happened to be in those registers.
/// 3. **User pointer validation.** It then deliberately calls `write`
///    with a pointer into the *kernel heap*, which the kernel must
///    refuse. A payload that only ever passes valid pointers would prove
///    nothing about the check that matters most - the one standing
///    between a user program and arbitrary kernel memory.
///
/// It ends by calling `exit`, so its `ProgramExit` is `Exited(42)` rather
/// than a fault - the clean-exit half of the return-to-supervisor path,
/// where `usermode::run_test`'s payload still covers the faulting half.
/// The trailing `hlt` should therefore never execute; if the kernel ever
/// reports a general protection fault for this program, `exit` silently
/// failed to end it.
fn build_syscall_test_elf() -> Vec<u8> {
    const LOAD_VADDR: u64 = 0x0050_0000; // distinct from build_test_elf's 0x400000
    const BSS_OFFSET: u64 = 0x1000; // one page past the code - only valid if p_memsz covers it
    let bss_target = LOAD_VADDR + BSS_OFFSET;

    // Must match the kernel's own syscall numbers (see `SYS_EXIT` /
    // `SYS_WRITE` in kernel/src/arch/x86_64/interrupts.rs). Hand-encoded
    // here because this payload has no way to `use` them - the real fix
    // for that duplication is a userland crate that shares constants,
    // which is the next milestone.
    const SYS_EXIT: u32 = 0;
    const SYS_WRITE: u32 = 1;

    // A kernel address, chosen to be one this program has no business
    // reading: `allocator::HEAP_START`. It is mapped and present, so the
    // only thing that can reject it is the USER_ACCESSIBLE check - which
    // is precisely the property being tested. A merely-unmapped address
    // would be refused for the wrong reason and prove nothing.
    const KERNEL_HEAP_ADDR: u64 = 0x_4444_4444_0000;

    let mut payload = Vec::new();

    // --- Write "OK\n" into the zero-filled .bss region ---
    payload.push(0x48); // REX.W
    payload.push(0xB8); // MOV rax, imm64
    payload.extend_from_slice(&bss_target.to_le_bytes());
    payload.extend_from_slice(&[0xC6, 0x00, b'O']); // MOV byte [rax], 'O'
    payload.extend_from_slice(&[0xC6, 0x40, 0x01, b'K']); // MOV byte [rax+1], 'K'
    payload.extend_from_slice(&[0xC6, 0x40, 0x02, b'\n']); // MOV byte [rax+2], '\n'

    // --- write(ptr = bss_target, len = 3) ---
    payload.extend_from_slice(&[0x48, 0x89, 0xC7]); // MOV rdi, rax    (arg1 = ptr)
    payload.extend_from_slice(&[0x48, 0xC7, 0xC6]); // MOV rsi, imm32  (arg2 = len)
    payload.extend_from_slice(&3u32.to_le_bytes());
    payload.extend_from_slice(&[0x48, 0xC7, 0xC0]); // MOV rax, imm32  (syscall number)
    payload.extend_from_slice(&SYS_WRITE.to_le_bytes());
    payload.extend_from_slice(&[0xCD, 0x80]); // int 0x80

    // --- write(ptr = kernel heap, len = 8) - must be REFUSED ---
    payload.push(0x48); // REX.W
    payload.push(0xBF); // MOV rdi, imm64  (arg1 = a kernel pointer)
    payload.extend_from_slice(&KERNEL_HEAP_ADDR.to_le_bytes());
    payload.extend_from_slice(&[0x48, 0xC7, 0xC6]); // MOV rsi, imm32  (arg2 = len)
    payload.extend_from_slice(&8u32.to_le_bytes());
    payload.extend_from_slice(&[0x48, 0xC7, 0xC0]); // MOV rax, imm32
    payload.extend_from_slice(&SYS_WRITE.to_le_bytes());
    payload.extend_from_slice(&[0xCD, 0x80]); // int 0x80

    // --- exit(42) ---
    payload.extend_from_slice(&[0x48, 0xC7, 0xC7]); // MOV rdi, imm32  (arg1 = status)
    payload.extend_from_slice(&42u32.to_le_bytes());
    payload.extend_from_slice(&[0x48, 0xC7, 0xC0]); // MOV rax, imm32
    payload.extend_from_slice(&SYS_EXIT.to_le_bytes());
    payload.extend_from_slice(&[0xCD, 0x80]); // int 0x80

    // Unreachable if `exit` works, which is exactly why it's here: if
    // this executes, the kernel reports a general protection fault for
    // this program instead of `Exited(42)`, making the failure loud.
    payload.push(0xF4); // hlt

    assert_eq!(
        payload.len(),
        83,
        "hand-encoded payload length drifted from the layout above"
    );

    const EHDR_SIZE: u64 = 64;
    const PHDR_SIZE: u64 = 56;
    let payload_offset = EHDR_SIZE + PHDR_SIZE;
    // p_memsz spans the code plus a full extra page beyond it, so
    // `bss_target` (one page past LOAD_VADDR) falls inside the segment's
    // declared memory range but strictly after its file-backed range.
    let mem_size = BSS_OFFSET + 0x1000;

    let mut elf = Vec::new();

    // --- ELF64 header ---
    elf.extend_from_slice(&[0x7F, b'E', b'L', b'F']);
    elf.push(2); // ELFCLASS64
    elf.push(1); // ELFDATA2LSB
    elf.push(1); // EI_VERSION
    elf.push(0); // EI_OSABI
    elf.extend_from_slice(&[0u8; 8]);
    elf.extend_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    elf.extend_from_slice(&0x3Eu16.to_le_bytes()); // EM_X86_64
    elf.extend_from_slice(&1u32.to_le_bytes());
    elf.extend_from_slice(&LOAD_VADDR.to_le_bytes()); // e_entry
    elf.extend_from_slice(&EHDR_SIZE.to_le_bytes());
    elf.extend_from_slice(&0u64.to_le_bytes());
    elf.extend_from_slice(&0u32.to_le_bytes());
    elf.extend_from_slice(&(EHDR_SIZE as u16).to_le_bytes());
    elf.extend_from_slice(&(PHDR_SIZE as u16).to_le_bytes());
    elf.extend_from_slice(&1u16.to_le_bytes());
    elf.extend_from_slice(&0u16.to_le_bytes());
    elf.extend_from_slice(&0u16.to_le_bytes());
    elf.extend_from_slice(&0u16.to_le_bytes());
    assert_eq!(elf.len() as u64, EHDR_SIZE);

    // --- Program header ---
    elf.extend_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    elf.extend_from_slice(&7u32.to_le_bytes()); // PF_R | PF_W | PF_X - writable this time, for the BSS write
    elf.extend_from_slice(&payload_offset.to_le_bytes());
    elf.extend_from_slice(&LOAD_VADDR.to_le_bytes());
    elf.extend_from_slice(&LOAD_VADDR.to_le_bytes());
    elf.extend_from_slice(&(payload.len() as u64).to_le_bytes()); // p_filesz: just the code
    elf.extend_from_slice(&mem_size.to_le_bytes()); // p_memsz: code + a full extra zero-filled page
    elf.extend_from_slice(&0x1000u64.to_le_bytes());
    assert_eq!(elf.len() as u64, EHDR_SIZE + PHDR_SIZE);

    elf.extend_from_slice(&payload);
    elf
}

fn main() {
    let kernel_path = PathBuf::from(env::var_os("KERNEL_PATH").unwrap_or_else(|| {
        panic!(
            "\n\nKERNEL_PATH is not set.\n\
             The kernel must be built first, then its binary path passed in:\n\n  \
             cargo build --manifest-path kernel/Cargo.toml --target x86_64-unknown-none\n  \
             KERNEL_PATH=$(pwd)/kernel/target/x86_64-unknown-none/debug/najm-kernel \\\n    \
             cargo run --manifest-path runner/Cargo.toml\n\n\
             Or just run `make run` from the repo root, which does this for you.\n\n"
        )
    }));

    if !kernel_path.exists() {
        panic!(
            "KERNEL_PATH is set to {}, but no file exists there. \
             Did the kernel build succeed?",
            kernel_path.display()
        );
    }

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR not set by cargo"));
    let bios_image_path = out_dir.join("najm-bios.img");
    let ramdisk_path = out_dir.join("najm-test.elf");

    // Which program becomes the ramdisk.
    //
    // `USERLAND_PATH` points at a real compiled userland binary (see
    // ../userland/hello), built by the Makefile before this crate the
    // same way the kernel is - and for the same reason: invoking `cargo`
    // from inside a build script means a nested cargo run contending for
    // the same package-cache lock, which the two-crate split documented
    // at the top of this file exists to avoid.
    //
    // Without it, the hand-encoded `build_syscall_test_elf` is used
    // instead. That fallback is not dead weight: it's the only thing
    // that exercises loader.rs's `.bss` zero-fill path
    // (`p_memsz > p_filesz`), which a linker-produced ELF turns out not
    // to reach - see the note in userland/hello/linker.ld. It also keeps
    // `make run` working if the userland crate ever fails to build,
    // which keeps a userland regression from masquerading as a kernel
    // one.
    match env::var_os("USERLAND_PATH") {
        Some(path) => {
            let path = PathBuf::from(path);
            assert!(
                path.exists(),
                "USERLAND_PATH is set to {}, but no file exists there. \
                 Did the userland build succeed?",
                path.display()
            );
            std::fs::copy(&path, &ramdisk_path)
                .expect("failed to copy the userland binary into the ramdisk");
            println!("cargo:rerun-if-changed={}", path.display());
        }
        None => {
            std::fs::write(&ramdisk_path, build_syscall_test_elf())
                .expect("failed to write the test ramdisk ELF");
        }
    }
    println!("cargo:rerun-if-env-changed=USERLAND_PATH");

    bootloader::BiosBoot::new(&kernel_path)
        .set_ramdisk(&ramdisk_path)
        .create_disk_image(&bios_image_path)
        .expect("failed to create bootable BIOS disk image");

    // Exposes the image path to runner's own main.rs via env!() at compile
    // time - this is the standard way build.rs hands data to the crate
    // it's building for.
    println!("cargo:rustc-env=BIOS_IMAGE={}", bios_image_path.display());

    // Re-run this build script if the kernel binary changes, not just if
    // runner's own source changes - otherwise `make run` after editing the
    // kernel would silently boot a stale image.
    println!("cargo:rerun-if-changed={}", kernel_path.display());
    println!("cargo:rerun-if-env-changed=KERNEL_PATH");
}
