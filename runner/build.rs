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


/// Builds a minimal PE32+ executable, by hand, to exercise Mirage.
///
/// Hand-built for the same reason `build_syscall_test_elf` is: producing
/// one with a real toolchain would mean requiring a Windows cross-compiler
/// to build this project, which is a large dependency for a test. Every
/// byte below is standard, stable PE/COFF - the format has not changed in
/// a way that matters since 1999.
///
/// What it exercises, and why each part is here rather than being
/// simplified away:
///
/// - **A relocated base.** Its preferred base is the conventional
///   `0x140000000`; Mirage loads it somewhere else deliberately, so the
///   relocation table has to be applied or the string pointer it passes
///   to `OutputDebugStringA` points into unmapped memory.
/// - **Imports resolved by name**, through a real import descriptor with
///   a lookup table and a separate IAT - the layout an actual linker
///   emits, not a shortcut where the two coincide.
/// - **Two sections with different permissions**, so the W^X path is
///   taken rather than everything landing in one RWX blob.
/// - **The Microsoft x64 calling convention**, so the thunks' register
///   shuffle is genuinely required: the argument goes in RCX, and a
///   loader that passed it straight through would deliver it as the
///   native ABI's fourth argument.
fn build_test_pe() -> Vec<u8> {
    const PREFERRED_BASE: u64 = 0x1_4000_0000;
    const SECTION_ALIGN: u32 = 0x1000;
    const FILE_ALIGN: u32 = 0x200;

    // Layout in memory (RVAs), one page per section.
    const TEXT_RVA: u32 = 0x1000;
    const DATA_RVA: u32 = 0x2000;
    const IMAGE_SIZE: u32 = 0x3000;

    // Layout in the file.
    const HEADERS_SIZE: u32 = FILE_ALIGN;
    const TEXT_RAW: u32 = FILE_ALIGN;
    const DATA_RAW: u32 = FILE_ALIGN * 2;

    // --- .rdata contents, laid out first so .text can reference it -----
    //
    // Everything the program's data section holds, at known offsets from
    // DATA_RVA: the message, the import machinery, and the relocation
    // table. Putting the import tables in the data section rather than
    // their own is what a small linker does, and it keeps the section
    // count down.
    let message = b"[mirage] hello from a Windows PE binary running natively on Najm OS\n\0";
    let message_rva = DATA_RVA;

    let mut data = Vec::new();
    data.extend_from_slice(message);
    while data.len() % 8 != 0 {
        data.push(0);
    }

    // Hint/name entries. Each is a 2-byte hint followed by a
    // NUL-terminated name, which is the structure the import lookup table
    // points at.
    let names: [&[u8]; 2] = [b"OutputDebugStringA", b"ExitProcess"];
    let mut hint_name_rvas = Vec::new();
    for name in names {
        hint_name_rvas.push(DATA_RVA + data.len() as u32);
        data.extend_from_slice(&0u16.to_le_bytes()); // hint
        data.extend_from_slice(name);
        data.push(0);
        if data.len() % 2 != 0 {
            data.push(0);
        }
    }
    while data.len() % 8 != 0 {
        data.push(0);
    }

    // The import lookup table: what the image wants, by name.
    let lookup_rva = DATA_RVA + data.len() as u32;
    for rva in &hint_name_rvas {
        data.extend_from_slice(&(*rva as u64).to_le_bytes());
    }
    data.extend_from_slice(&0u64.to_le_bytes()); // terminator

    // The Import Address Table: where the resolved addresses go. Starts
    // as a copy of the lookup table, which is what a linker emits - the
    // loader overwrites it in place.
    let iat_rva = DATA_RVA + data.len() as u32;
    for rva in &hint_name_rvas {
        data.extend_from_slice(&(*rva as u64).to_le_bytes());
    }
    data.extend_from_slice(&0u64.to_le_bytes()); // terminator

    // The DLL name. Mirage resolves by function name and ignores which
    // DLL claims to provide it, but the field is mandatory and a real
    // image always has one.
    let dll_name_rva = DATA_RVA + data.len() as u32;
    data.extend_from_slice(b"KERNEL32.dll\0");
    while data.len() % 4 != 0 {
        data.push(0);
    }

    // The import descriptor: one entry plus the all-zero terminator.
    let import_dir_rva = DATA_RVA + data.len() as u32;
    data.extend_from_slice(&lookup_rva.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
    data.extend_from_slice(&0u32.to_le_bytes()); // ForwarderChain
    data.extend_from_slice(&dll_name_rva.to_le_bytes());
    data.extend_from_slice(&iat_rva.to_le_bytes());
    data.extend_from_slice(&[0u8; 20]); // terminating descriptor

    // --- .text ---------------------------------------------------------
    //
    // Microsoft x64 convention: first argument in RCX. A loader that did
    // not translate would deliver it where the native ABI expects its
    // fourth argument, so this code is what makes the thunks' register
    // shuffle load-bearing rather than decorative.
    let mut text = Vec::new();

    // sub rsp, 40 - the ABI's 32 bytes of shadow space plus 8 to restore
    // the 16-byte alignment the `call` will consume. Omitting it is the
    // most common way hand-written x64 Windows assembly corrupts its own
    // stack.
    text.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);

    // mov rcx, imm64 <message address>. An absolute address, which is
    // precisely why this image needs a relocation - Mirage does not load
    // it at its preferred base.
    let message_operand_offset = text.len() + 2;
    text.extend_from_slice(&[0x48, 0xB9]);
    text.extend_from_slice(&(PREFERRED_BASE + message_rva as u64).to_le_bytes());

    // call qword ptr [rip + disp32] -> the IAT slot for
    // OutputDebugStringA. Calling *through* the IAT rather than to a
    // fixed address is how every real PE calls an import.
    let call_end = TEXT_RVA as usize + text.len() + 6;
    let disp = iat_rva as i64 - call_end as i64;
    text.extend_from_slice(&[0xFF, 0x15]);
    text.extend_from_slice(&(disp as i32).to_le_bytes());

    // mov ecx, 55 - the exit code, again in the Windows argument register.
    text.extend_from_slice(&[0xB9]);
    text.extend_from_slice(&55u32.to_le_bytes());

    // call qword ptr [rip + disp32] -> ExitProcess, the second IAT slot.
    let call_end = TEXT_RVA as usize + text.len() + 6;
    let disp = (iat_rva + 8) as i64 - call_end as i64;
    text.extend_from_slice(&[0xFF, 0x15]);
    text.extend_from_slice(&(disp as i32).to_le_bytes());

    // Unreachable if ExitProcess works, which is exactly why it is here:
    // reaching it means the exit thunk returned, and `ud2` turns that
    // into an immediate, unmistakable fault rather than execution running
    // off into the zero-filled remainder of the page.
    text.extend_from_slice(&[0x0F, 0x0B]);

    // --- Base relocations ----------------------------------------------
    //
    // One entry, for the absolute address embedded in the `mov rcx`
    // above. Without it the string pointer would still refer to the
    // preferred base, which Mirage does not map - and the symptom would
    // be a page fault at a plausible-looking address rather than
    // anything naming the cause.
    let reloc_rva = DATA_RVA + data.len() as u32;
    let reloc_target = TEXT_RVA + message_operand_offset as u32;
    let reloc_page = reloc_target & !0xFFF;
    data.extend_from_slice(&reloc_page.to_le_bytes());
    data.extend_from_slice(&16u32.to_le_bytes()); // block size: 8 header + 2 entries
    // Type 10 (DIR64) in the high nibble, offset within the page in the low 12 bits.
    data.extend_from_slice(&(((10u16) << 12) | ((reloc_target & 0xFFF) as u16)).to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes()); // ABSOLUTE padding entry
    let reloc_size = 16u32;

    // --- Assemble ------------------------------------------------------
    let mut pe = vec![0u8; HEADERS_SIZE as usize];

    // DOS header: the magic, and `e_lfanew` pointing at the PE header.
    // The 60 bytes between are a real DOS stub in a linker-produced
    // image; nothing reads them here.
    pe[0..2].copy_from_slice(&0x5A4Du16.to_le_bytes()); // "MZ"
    let pe_offset = 0x80usize;
    pe[0x3C..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());

    let mut at = pe_offset;
    let mut put = |pe: &mut Vec<u8>, at: &mut usize, bytes: &[u8]| {
        pe[*at..*at + bytes.len()].copy_from_slice(bytes);
        *at += bytes.len();
    };

    put(&mut pe, &mut at, &0x0000_4550u32.to_le_bytes()); // "PE\0\0"
    put(&mut pe, &mut at, &0x8664u16.to_le_bytes()); // Machine: AMD64
    put(&mut pe, &mut at, &2u16.to_le_bytes()); // NumberOfSections
    put(&mut pe, &mut at, &0u32.to_le_bytes()); // TimeDateStamp
    put(&mut pe, &mut at, &0u32.to_le_bytes()); // PointerToSymbolTable
    put(&mut pe, &mut at, &0u32.to_le_bytes()); // NumberOfSymbols
    put(&mut pe, &mut at, &240u16.to_le_bytes()); // SizeOfOptionalHeader
    put(&mut pe, &mut at, &0x0022u16.to_le_bytes()); // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    let optional_header = at;
    put(&mut pe, &mut at, &0x020Bu16.to_le_bytes()); // PE32+
    put(&mut pe, &mut at, &[14, 0]); // linker version
    put(&mut pe, &mut at, &(text.len() as u32).to_le_bytes()); // SizeOfCode
    put(&mut pe, &mut at, &(data.len() as u32).to_le_bytes()); // SizeOfInitializedData
    put(&mut pe, &mut at, &0u32.to_le_bytes()); // SizeOfUninitializedData
    put(&mut pe, &mut at, &TEXT_RVA.to_le_bytes()); // AddressOfEntryPoint
    put(&mut pe, &mut at, &TEXT_RVA.to_le_bytes()); // BaseOfCode
    put(&mut pe, &mut at, &PREFERRED_BASE.to_le_bytes()); // ImageBase
    put(&mut pe, &mut at, &SECTION_ALIGN.to_le_bytes());
    put(&mut pe, &mut at, &FILE_ALIGN.to_le_bytes());
    put(&mut pe, &mut at, &[6, 0, 0, 0]); // OS version
    put(&mut pe, &mut at, &[0, 0, 0, 0]); // image version
    put(&mut pe, &mut at, &[6, 0, 0, 0]); // subsystem version
    put(&mut pe, &mut at, &0u32.to_le_bytes()); // Win32VersionValue
    put(&mut pe, &mut at, &IMAGE_SIZE.to_le_bytes()); // SizeOfImage
    put(&mut pe, &mut at, &HEADERS_SIZE.to_le_bytes()); // SizeOfHeaders
    put(&mut pe, &mut at, &0u32.to_le_bytes()); // CheckSum
    put(&mut pe, &mut at, &3u16.to_le_bytes()); // Subsystem: console
    put(&mut pe, &mut at, &0x0160u16.to_le_bytes()); // DllCharacteristics: DYNAMIC_BASE | NX_COMPAT
    put(&mut pe, &mut at, &0x100000u64.to_le_bytes()); // SizeOfStackReserve
    put(&mut pe, &mut at, &0x1000u64.to_le_bytes()); // SizeOfStackCommit
    put(&mut pe, &mut at, &0x100000u64.to_le_bytes()); // SizeOfHeapReserve
    put(&mut pe, &mut at, &0x1000u64.to_le_bytes()); // SizeOfHeapCommit
    put(&mut pe, &mut at, &0u32.to_le_bytes()); // LoaderFlags
    put(&mut pe, &mut at, &16u32.to_le_bytes()); // NumberOfRvaAndSizes

    // Data directories. Only import (1) and base relocation (5) are
    // populated; the rest stay zero, which is how a loader knows they are
    // absent rather than empty.
    let directories = at;
    at = directories + 16 * 8;
    let mut directory = |pe: &mut Vec<u8>, index: usize, rva: u32, size: u32| {
        let base = directories + index * 8;
        pe[base..base + 4].copy_from_slice(&rva.to_le_bytes());
        pe[base + 4..base + 8].copy_from_slice(&size.to_le_bytes());
    };
    directory(&mut pe, 1, import_dir_rva, 40);
    directory(&mut pe, 5, reloc_rva, reloc_size);

    assert_eq!(
        at - optional_header,
        240,
        "optional header size drifted from the field layout above"
    );

    // Section table.
    let mut section = |pe: &mut Vec<u8>,
                       at: &mut usize,
                       name: &[u8; 8],
                       virtual_size: u32,
                       virtual_address: u32,
                       raw_size: u32,
                       raw_offset: u32,
                       characteristics: u32| {
        pe[*at..*at + 8].copy_from_slice(name);
        *at += 8;
        pe[*at..*at + 4].copy_from_slice(&virtual_size.to_le_bytes());
        *at += 4;
        pe[*at..*at + 4].copy_from_slice(&virtual_address.to_le_bytes());
        *at += 4;
        pe[*at..*at + 4].copy_from_slice(&raw_size.to_le_bytes());
        *at += 4;
        pe[*at..*at + 4].copy_from_slice(&raw_offset.to_le_bytes());
        *at += 4;
        *at += 12; // relocations and line numbers: none
        pe[*at..*at + 4].copy_from_slice(&characteristics.to_le_bytes());
        *at += 4;
    };

    // .text: read + execute, never writable. .rdata: read + write,
    // because the loader writes resolved addresses into the IAT that
    // lives there - a genuinely writable data section rather than one
    // made writable to avoid thinking about it.
    section(
        &mut pe,
        &mut at,
        b".text\0\0\0",
        text.len() as u32,
        TEXT_RVA,
        text.len().next_multiple_of(FILE_ALIGN as usize) as u32,
        TEXT_RAW,
        0x6000_0020, // CODE | EXECUTE | READ
    );
    section(
        &mut pe,
        &mut at,
        b".rdata\0\0",
        data.len() as u32,
        DATA_RVA,
        data.len().next_multiple_of(FILE_ALIGN as usize) as u32,
        DATA_RAW,
        0xC000_0040, // INITIALIZED_DATA | READ | WRITE
    );

    // Section contents, each padded to the file alignment the header
    // claims. A mismatch here is the kind of thing a loader either
    // tolerates silently or rejects confusingly, so it is made exact.
    pe.resize(TEXT_RAW as usize, 0);
    pe.extend_from_slice(&text);
    pe.resize(DATA_RAW as usize, 0);
    pe.extend_from_slice(&data);
    pe.resize(pe.len().next_multiple_of(FILE_ALIGN as usize), 0);

    pe
}


/// Builds a signed-format Najm package, for the Store's verification
/// path.
///
/// Two are produced at build time: one intact, and one with a single byte
/// of its payload flipped. The second is the important one - a
/// verification routine that has only ever seen valid input is a
/// verification routine nobody has tested.
///
/// Both *request* the Vault Realm. Neither gets it, because neither
/// carries a verified publisher signature, and that is the behaviour
/// ARCHITECTURE.md 2e requires: elevation is a credential, not a
/// declaration. A package asking for Vault and receiving it would be the
/// failure, not the success.
fn build_package(manifest: &str, files: &[(&str, Vec<u8>)], corrupt: bool) -> Vec<u8> {
    let manifest_bytes = manifest.as_bytes();
    let mut payload = build_archive(files);

    // The digest covers the manifest and the payload together, in one
    // pass. Hashing them separately would let a package be assembled from
    // a manifest signed for one payload and a payload signed for another.
    //
    // Computed here, *before* any corruption is applied. Getting that
    // order wrong is not a hypothetical - the first version of this
    // function corrupted the payload first and then hashed it, so the
    // "tampered" package carried a digest of its own tampered contents
    // and verified perfectly. The test passed on a verifier that could
    // not detect tampering at all, which is precisely the failure a
    // negative test exists to catch and precisely the way it can fail to.
    let digest = {
        // A tiny SHA-256, duplicated here rather than shared with the
        // kernel's: the kernel's is `no_std` and lives in a crate the
        // build script cannot link. Keeping them in step is what the
        // kernel's own FIPS test vectors are for - if either drifts, that
        // test fails rather than packages silently failing to verify.
        let mut hasher = Sha256::new();
        hasher.update(manifest_bytes);
        hasher.update(&payload);
        hasher.finish()
    };

    if corrupt {
        // Flip one bit, after the digest was computed - so the package's
        // recorded digest describes what it *was*, not what it now is.
        // As far into the payload as possible, in the file data itself: a
        // corruption in the archive header would be caught by the archive
        // parser before the digest check ever mattered, testing the wrong
        // thing.
        let target = payload.len() - 1;
        payload[target] ^= 0x01;
    }

    let mut package = Vec::new();
    package.extend_from_slice(b"NAJMPKG\0");
    package.extend_from_slice(&1u32.to_le_bytes());
    package.extend_from_slice(&(manifest_bytes.len() as u32).to_le_bytes());
    package.extend_from_slice(&digest);
    package.extend_from_slice(manifest_bytes);
    package.extend_from_slice(&payload);
    package
}

/// SHA-256, for the build script.
///
/// Duplicated from the kernel's implementation because the kernel's is in
/// a `no_std` crate this script cannot link against. The duplication is
/// real and worth naming: two implementations of one hash can drift. What
/// stops that mattering is that the kernel checks itself against FIPS
/// 180-4's own test vectors at every boot, so a divergence shows up as a
/// failed self-test rather than as packages that mysteriously will not
/// verify.
struct Sha256 {
    state: [u32; 8],
    buffer: Vec<u8>,
}

impl Sha256 {
    fn new() -> Sha256 {
        Sha256 {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: Vec::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    fn finish(mut self) -> [u8; 32] {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];

        let length_bits = (self.buffer.len() as u64) * 8;
        self.buffer.push(0x80);
        while self.buffer.len() % 64 != 56 {
            self.buffer.push(0);
        }
        self.buffer.extend_from_slice(&length_bits.to_be_bytes());

        for block in self.buffer.chunks(64) {
            let mut w = [0u32; 64];
            for index in 0..16 {
                w[index] =
                    u32::from_be_bytes(block[index * 4..index * 4 + 4].try_into().unwrap());
            }
            for index in 16..64 {
                let s0 = w[index - 15].rotate_right(7)
                    ^ w[index - 15].rotate_right(18)
                    ^ (w[index - 15] >> 3);
                let s1 = w[index - 2].rotate_right(17)
                    ^ w[index - 2].rotate_right(19)
                    ^ (w[index - 2] >> 10);
                w[index] = w[index - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[index - 7])
                    .wrapping_add(s1);
            }

            let mut v = self.state;
            for index in 0..64 {
                let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
                let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
                let temp1 = v[7]
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[index])
                    .wrapping_add(w[index]);
                let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
                let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
                let temp2 = s0.wrapping_add(maj);
                v[7] = v[6];
                v[6] = v[5];
                v[5] = v[4];
                v[4] = v[3].wrapping_add(temp1);
                v[3] = v[2];
                v[2] = v[1];
                v[1] = v[0];
                v[0] = temp1.wrapping_add(temp2);
            }

            for (slot, value) in self.state.iter_mut().zip(v) {
                *slot = slot.wrapping_add(value);
            }
        }

        let mut digest = [0u8; 32];
        for (index, word) in self.state.iter().enumerate() {
            digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        digest
    }
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

    // A Windows binary, for Mirage. Hand-built for the same reason the
    // ELF above is: requiring a Windows cross-compiler to build this
    // project would be a large dependency for one test.
    files.push(("/bin/hello.exe", build_test_pe()));

    // A plain text file, so the filesystem is proven to serve content the
    // kernel did not itself produce, and a `read` syscall has something
    // to return whose exact bytes the test can check.
    files.push((
        "/etc/motd",
        b"Najm OS: Realms are kernel data structures, not conventions.\n".to_vec(),
    ));

    // A second text file in the same directory, so `readdir` returning
    // one entry cannot be mistaken for it working.
    // A theme file, so the customization layer ARCHITECTURE.md 2c calls
    // the "Realm Shell" is exercised on every boot rather than only
    // existing as a code path. Note what it can and cannot change: the
    // trust bar's colours, yes; its contents, its position, or whether it
    // is drawn at all, no - those come from the Core and are not
    // reachable from a theme.
    files.push((
        "/etc/theme.conf",
        b"# Najm OS theme. Colours only - see kernel/src/graphics/theme.rs\n\
          # for what is themeable and, more importantly, what is not.\n\
          desktop        = #0d1117\n\
          trust_bar      = #05070b\n\
          trust_bar.edge = #30363d\n\
          trust_bar.text = #e6edf3\n\
          accent.home    = #388bfd\n\
          accent.gaming  = #f778ba\n\
          accent.vault   = #3fb950\n\
          accent.system  = #d29922\n\
          pointer.fill   = #ffffff\n\
          pointer.edge   = #161b22\n"
            .to_vec(),
    ));

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

    // The graphical program. Runs in the Gaming Realm, which is what
    // makes it interesting: it gets exclusive fullscreen, and exclusive
    // fullscreen still cannot reach the Core-reserved trust strip.
    if let Some(path) = env::var_os("USERLAND_GUI_PATH") {
        let path = PathBuf::from(path);
        if path.exists() {
            files.push((
                "/bin/gui",
                std::fs::read(&path).expect("failed to read the gui binary"),
            ));
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
    println!("cargo:rerun-if-env-changed=USERLAND_GUI_PATH");

    // Two packages: one intact, one with a flipped byte. Both request the
    // Vault Realm and neither will get it, which is the point - see
    // kernel/src/store.rs and ARCHITECTURE.md 2e.
    let sample_manifest = "\
# A Najm Store package manifest. Everything here is a claim the package
# makes about itself - see kernel/src/store.rs for which claims are
# treated as requests and which are ignored outright.
id        = os.najm.notes
name      = Notes
version   = 1.0.0
publisher = Najm Labs (UNVERIFIED - no signature is attached)
entry     = /bin/notes

# This is a *request*. It is read, logged, and refused, because elevation
# above Home requires a signature from a publisher verified in advance.
realm = vault

capability = file_read
capability = surface_create
";
    let package_files: Vec<(&str, Vec<u8>)> = vec![(
        "/bin/notes",
        b"a placeholder for the packaged program's binary\n".to_vec(),
    )];

    files.push((
        "/apps/notes.najm",
        build_package(sample_manifest, &package_files, false),
    ));
    files.push((
        "/apps/tampered.najm",
        build_package(sample_manifest, &package_files, true),
    ));

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
