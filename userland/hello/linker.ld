/* Linker script for Najm OS userland programs.
 *
 * Two things here are load-bearing, and both exist because of what
 * kernel/src/loader.rs can and cannot do:
 *
 * 1. A FIXED LOAD ADDRESS, and therefore a non-PIE ET_EXEC binary. The
 *    loader supports neither PIE nor relocations nor dynamic linking - it
 *    reads p_vaddr and maps the segment exactly there. Setting `.` to an
 *    absolute address below is what makes that assumption true rather
 *    than merely hoped for.
 *
 * 2. EXACTLY ONE PT_LOAD SEGMENT, declared explicitly in PHDRS. Left to
 *    its own devices the linker emits several PT_LOADs split by access
 *    permission (R, RX, RW). The loader maps each PT_LOAD's pages
 *    independently and would panic with a "page already mapped" error the
 *    moment two segments shared a page - which they easily can, since
 *    nothing forces the linker to give each one a whole page of its own.
 *    Collapsing everything into one RWX segment sidesteps that entirely,
 *    and costs nothing today because the loader maps every user page
 *    writable-and-executable regardless (see the W^X note in
 *    arch/x86_64/usermode.rs). When the loader learns per-segment
 *    permissions, this is the first thing that should change back.
 *
 * The address itself (0x400000) is the conventional x86_64 ET_EXEC load
 * address, and is deliberately distinct from every other fixed range this
 * system uses - the kernel heap, both usermode test payloads, and the
 * user stack the loader maps. See the address-map table in CLAUDE.md.
 */

ENTRY(_start)

PHDRS
{
    program PT_LOAD FLAGS(7); /* PF_R | PF_W | PF_X */
}

SECTIONS
{
    . = 0x400000;

    .text : {
        *(.text.start)
        *(.text .text.*)
    } :program

    .rodata : {
        *(.rodata .rodata.*)
    } :program

    .data : {
        *(.data .data.*)
    } :program

    /* Note, verified rather than assumed: this does NOT end up
     * exercising loader.rs's `p_memsz > p_filesz` zero-fill path, even
     * though .bss is a NOBITS section. When sections are explicitly
     * assigned to a PHDR in a linker script, lld extends p_filesz to
     * cover the trailing NOBITS section anyway, so the segment arrives
     * with p_filesz == p_memsz and the zeroes come from the file rather
     * than from the loader. Neither `(NOLOAD)` nor page-aligning .bss
     * changed that. It's harmless - the program sees a zeroed buffer
     * either way - but it means the hand-encoded ELF in runner/build.rs
     * remains the only thing that actually covers the zero-fill branch,
     * which is a reason to keep it rather than retire it.
     */
    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    } :program

    /* Metadata that would otherwise land in its own non-PT_LOAD segments
     * or bloat the image. None of it means anything without a dynamic
     * loader or an unwinder, neither of which exists here.
     */
    /DISCARD/ : {
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.comment)
        *(.note .note.*)
    }
}
