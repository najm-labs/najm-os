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
    const LOAD_VADDR: u64 = najm_abi::layout::USER_FALLBACK_IMAGE_BASE;
    // One page past the code, and therefore in the *second* PT_LOAD
    // segment - see the two-segment layout below.
    const BSS_OFFSET: u64 = 0x1000;
    let bss_target = LOAD_VADDR + BSS_OFFSET;

    // Must match the kernel's own syscall numbers (see `SYS_EXIT` /
    // `SYS_WRITE` in kernel/src/arch/x86_64/interrupts.rs). Hand-encoded
    // here because this payload has no way to `use` them - the real fix
    // for that duplication is a userland crate that shares constants,
    // which is the next milestone.
    const SYS_EXIT: u32 = najm_abi::sys::EXIT as u32;
    const SYS_WRITE: u32 = najm_abi::sys::WRITE as u32;
    // `write` takes a file descriptor as its first argument now, so this
    // payload has to pass one where it previously passed the buffer
    // pointer directly.
    const STDOUT: u32 = najm_abi::fd::STDOUT as u32;

    // A kernel address, chosen to be one this program has no business
    // reading: the base of the kernel heap. It is mapped and present, so
    // the only thing that can reject it is the user/supervisor check -
    // which is precisely the property being tested. A merely-unmapped
    // address would be refused for the wrong reason and prove nothing.
    const KERNEL_HEAP_ADDR: u64 = najm_abi::layout::KERNEL_PROBE_ADDRESS;

    let mut payload = Vec::new();

    // --- Write "OK\n" into the zero-filled .bss region ---
    payload.push(0x48); // REX.W
    payload.push(0xB8); // MOV rax, imm64
    payload.extend_from_slice(&bss_target.to_le_bytes());
    payload.extend_from_slice(&[0xC6, 0x00, b'O']); // MOV byte [rax], 'O'
    payload.extend_from_slice(&[0xC6, 0x40, 0x01, b'K']); // MOV byte [rax+1], 'K'
    payload.extend_from_slice(&[0xC6, 0x40, 0x02, b'\n']); // MOV byte [rax+2], '\n'

    // --- write(fd = STDOUT, ptr = bss_target, len = 3) ---
    // Argument registers are RDI, RSI, RDX in that order. `write` gained
    // a leading file-descriptor argument when the syscall ABI moved into
    // the shared `najm-abi` crate, so the buffer pointer now goes in RSI
    // rather than RDI.
    payload.extend_from_slice(&[0x48, 0x89, 0xC6]); // MOV rsi, rax    (arg2 = ptr)
    payload.extend_from_slice(&[0x48, 0xC7, 0xC7]); // MOV rdi, imm32  (arg1 = fd)
    payload.extend_from_slice(&STDOUT.to_le_bytes());
    payload.extend_from_slice(&[0x48, 0xC7, 0xC2]); // MOV rdx, imm32  (arg3 = len)
    payload.extend_from_slice(&3u32.to_le_bytes());
    payload.extend_from_slice(&[0x48, 0xC7, 0xC0]); // MOV rax, imm32  (syscall number)
    payload.extend_from_slice(&SYS_WRITE.to_le_bytes());
    payload.extend_from_slice(&[0xCD, 0x80]); // int 0x80

    // --- write(fd = STDOUT, ptr = kernel heap, len = 8) - must be REFUSED ---
    payload.push(0x48); // REX.W
    payload.push(0xBE); // MOV rsi, imm64  (arg2 = a kernel pointer)
    payload.extend_from_slice(&KERNEL_HEAP_ADDR.to_le_bytes());
    payload.extend_from_slice(&[0x48, 0xC7, 0xC7]); // MOV rdi, imm32  (arg1 = fd)
    payload.extend_from_slice(&STDOUT.to_le_bytes());
    payload.extend_from_slice(&[0x48, 0xC7, 0xC2]); // MOV rdx, imm32  (arg3 = len)
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
        97,
        "hand-encoded payload length drifted from the layout above"
    );

    const EHDR_SIZE: u64 = 64;
    const PHDR_SIZE: u64 = 56;
    const PHDR_COUNT: u64 = 2;
    let payload_offset = EHDR_SIZE + PHDR_SIZE * PHDR_COUNT;

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
    elf.extend_from_slice(&(PHDR_COUNT as u16).to_le_bytes());
    elf.extend_from_slice(&0u16.to_le_bytes());
    elf.extend_from_slice(&0u16.to_le_bytes());
    elf.extend_from_slice(&0u16.to_le_bytes());
    assert_eq!(elf.len() as u64, EHDR_SIZE);

    // --- Program header 1: the code. Read + execute, never writable. ---
    //
    // This was one RWX segment until the kernel started deriving page
    // permissions from p_flags and enforcing W^X. A single writable-and-
    // executable segment is now *refused* at load time, which is the
    // right outcome - it described a program whose code could be
    // rewritten at runtime and whose data could be executed. Splitting it
    // costs one extra program header and a page of padding.
    elf.extend_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    elf.extend_from_slice(&5u32.to_le_bytes()); // PF_R | PF_X
    elf.extend_from_slice(&payload_offset.to_le_bytes());
    elf.extend_from_slice(&LOAD_VADDR.to_le_bytes());
    elf.extend_from_slice(&LOAD_VADDR.to_le_bytes());
    elf.extend_from_slice(&(payload.len() as u64).to_le_bytes()); // p_filesz
    elf.extend_from_slice(&(payload.len() as u64).to_le_bytes()); // p_memsz - no .bss in this one
    elf.extend_from_slice(&0x1000u64.to_le_bytes());

    // --- Program header 2: the .bss page. Read + write, never executable. ---
    //
    // This is the segment that earns this whole hand-encoded file its
    // keep: `p_filesz` is zero while `p_memsz` is a full page, so the
    // loader has to map a page that has no file content behind it *and*
    // zero-fill it. A linker-produced ELF does not reach that branch -
    // lld extends p_filesz to cover trailing NOBITS sections, so the
    // zeroes come from the file (see the note in
    // userland/hello/linker.ld). Without this file, the loader's
    // zero-fill path would be untested, and an untested zero-fill is an
    // information leak: whatever the frame allocator handed over last
    // would be visible to the program.
    elf.extend_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    elf.extend_from_slice(&6u32.to_le_bytes()); // PF_R | PF_W
    elf.extend_from_slice(&payload_offset.to_le_bytes()); // unused: p_filesz is 0
    elf.extend_from_slice(&(LOAD_VADDR + BSS_OFFSET).to_le_bytes());
    elf.extend_from_slice(&(LOAD_VADDR + BSS_OFFSET).to_le_bytes());
    elf.extend_from_slice(&0u64.to_le_bytes()); // p_filesz: nothing in the file
    elf.extend_from_slice(&0x1000u64.to_le_bytes()); // p_memsz: one zero-filled page
    elf.extend_from_slice(&0x1000u64.to_le_bytes());

    assert_eq!(elf.len() as u64, EHDR_SIZE + PHDR_SIZE * PHDR_COUNT);

    elf.extend_from_slice(&payload);
    elf
}

/// Packs a set of `(path, contents)` pairs into a NAR archive.
///
/// The format is defined in `abi/src/archive.rs`, which the kernel parses
/// with - so a change to the layout is a change in one place rather than
/// two implementations that have to be kept in step by hand.
///
/// Directories are synthesized here rather than being listed by the
/// caller: every path's ancestors are added automatically, so a caller
/// adding `/bin/hello` does not have to remember to also declare `/bin`.
/// Forgetting would produce an archive where `readdir("/")` reported
/// nothing while `/bin/hello` was plainly readable - the kind of
/// inconsistency that is confusing precisely because both halves look
/// correct on their own.
fn build_archive(files: &[(&str, Vec<u8>)]) -> Vec<u8> {
    use std::collections::{BTreeMap, BTreeSet};

    const HEADER_SIZE: usize = najm_abi::archive::HEADER_SIZE;
    const ENTRY_SIZE: usize = najm_abi::archive::ENTRY_SIZE;
    const MAX_PATH: usize = najm_abi::archive::MAX_PATH;

    // Every ancestor directory of every file, plus the root.
    let mut directories: BTreeSet<String> = BTreeSet::new();
    directories.insert("/".to_string());
    for (path, _) in files {
        let mut current = *path;
        while let Some(parent) = najm_abi::archive::parent_of(current.as_bytes()) {
            let parent = std::str::from_utf8(parent).expect("archive paths must be UTF-8");
            directories.insert(parent.to_string());
            current = parent;
            if current == "/" {
                break;
            }
        }
    }

    let mut contents: BTreeMap<String, Option<&Vec<u8>>> = BTreeMap::new();
    for directory in &directories {
        contents.insert(directory.clone(), None);
    }
    for (path, data) in files {
        assert!(
            najm_abi::archive::path_is_valid(path.as_bytes()),
            "archive path {path:?} is not valid - it must be absolute, free of '.' and '..' \
             components, and at most {MAX_PATH} bytes"
        );
        assert!(
            contents.insert(path.to_string(), Some(data)).is_none(),
            "archive path {path:?} was added twice"
        );
    }

    let entry_count = contents.len();
    let data_start = HEADER_SIZE + entry_count * ENTRY_SIZE;

    // Lay the data out first so entry offsets are known before the table
    // is written. Two passes rather than back-patching: back-patching an
    // offset is exactly the kind of thing that silently writes to the
    // wrong place after an unrelated layout change.
    let mut blob = Vec::new();
    let mut offsets: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
    for (path, data) in &contents {
        match data {
            Some(bytes) => {
                offsets.insert(path, ((data_start + blob.len()) as u64, bytes.len() as u64));
                blob.extend_from_slice(bytes);
            }
            None => {
                offsets.insert(path, (0, 0));
            }
        }
    }

    let total_len = data_start + blob.len();

    let mut archive = Vec::with_capacity(total_len);
    archive.extend_from_slice(&najm_abi::archive::MAGIC);
    archive.extend_from_slice(&najm_abi::archive::VERSION.to_le_bytes());
    archive.extend_from_slice(&(entry_count as u32).to_le_bytes());
    archive.extend_from_slice(&(total_len as u64).to_le_bytes());
    assert_eq!(archive.len(), HEADER_SIZE, "NAR header size drifted");

    for (path, data) in &contents {
        let (offset, len) = offsets[path.as_str()];
        let flags = if data.is_none() {
            najm_abi::archive::FLAG_DIRECTORY
        } else {
            0
        };

        let entry_start = archive.len();
        archive.extend_from_slice(&offset.to_le_bytes());
        archive.extend_from_slice(&len.to_le_bytes());
        archive.extend_from_slice(&flags.to_le_bytes());
        archive.extend_from_slice(&(path.len() as u32).to_le_bytes());
        archive.extend_from_slice(path.as_bytes());
        // Pad the inline path out to the fixed entry size, so the table
        // stays indexable rather than needing to be walked.
        archive.resize(entry_start + ENTRY_SIZE, 0);
    }

    assert_eq!(archive.len(), data_start, "NAR entry table size drifted");
    archive.extend_from_slice(&blob);
    assert_eq!(archive.len(), total_len, "NAR total length drifted");

    archive
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
    let ramdisk_path = out_dir.join("najm-boot.nar");

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
    // The ramdisk is a NAR archive now, not a bare ELF binary.
    //
    // A single-file ramdisk could carry exactly one program and nothing
    // else - no second binary, no configuration, no assets, and no way
    // for the kernel to answer "what exists?". The archive turns the
    // ramdisk into a namespace; see abi/src/archive.rs for the format and
    // kernel/src/fs.rs for the other end.
    let mut files: Vec<(&str, Vec<u8>)> = Vec::new();

    // The hand-encoded ELF stays, and is now a *file* rather than the
    // whole ramdisk. It remains the only thing that exercises the ELF
    // loader's zero-fill path (`p_memsz > p_filesz`), which a
    // linker-produced binary never reaches - see the note in
    // userland/hello/linker.ld. An untested zero-fill is an information
    // leak, so this is coverage worth keeping rather than legacy worth
    // deleting.
    files.push(("/bin/bss-test", build_syscall_test_elf()));

    // A plain text file, so the filesystem is proven to serve content the
    // kernel did not itself produce, and a `read` syscall has something
    // to return whose exact bytes the test can check.
    files.push((
        "/etc/motd",
        b"Najm OS: Realms are kernel data structures, not conventions.\n".to_vec(),
    ));

    // A second text file in the same directory, so `readdir` returning
    // one entry cannot be mistaken for it working.
    files.push((
        "/etc/version",
        format!("najm-os {}\n", env!("CARGO_PKG_VERSION")).into_bytes(),
    ));

    match env::var_os("USERLAND_PATH") {
        Some(path) => {
            let path = PathBuf::from(path);
            assert!(
                path.exists(),
                "USERLAND_PATH is set to {}, but no file exists there. \
                 Did the userland build succeed?",
                path.display()
            );
            files.push((
                "/bin/hello",
                std::fs::read(&path).expect("failed to read the userland binary"),
            ));
            println!("cargo:rerun-if-changed={}", path.display());
        }
        None => {
            // No compiled userland available. The archive still mounts
            // and `/bin/bss-test` still runs, so a userland build failure
            // degrades the boot rather than breaking it - which keeps a
            // userland regression from looking like a kernel one.
            println!(
                "cargo:warning=USERLAND_PATH is not set; the boot archive will contain no \
                 /bin/hello and the kernel will fall back to /bin/bss-test"
            );
        }
    }

    // A second userland program, if one was built. Its whole purpose is
    // to be a *different* binary from /bin/hello, so that "the loader can
    // run a program" and "the loader can run the program that happens to
    // be the ramdisk" stop being the same statement.
    if let Some(path) = env::var_os("USERLAND_FSTEST_PATH") {
        let path = PathBuf::from(path);
        if path.exists() {
            files.push((
                "/bin/fstest",
                std::fs::read(&path).expect("failed to read the fstest binary"),
            ));
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
    println!("cargo:rerun-if-env-changed=USERLAND_FSTEST_PATH");

    std::fs::write(&ramdisk_path, build_archive(&files))
        .expect("failed to write the boot archive");
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
