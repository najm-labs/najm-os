/* Linker script for Najm OS userland programs.
 *
 * Three things here are load-bearing, and all three exist because of what
 * kernel/src/loader.rs does:
 *
 * 1. A FIXED LOAD ADDRESS, and therefore a non-PIE ET_EXEC binary. The
 *    loader supports neither PIE nor relocations nor dynamic linking - it
 *    reads p_vaddr and maps the segment exactly there. Setting `.` to an
 *    absolute address below is what makes that assumption true rather
 *    than merely hoped for.
 *
 * 2. THREE PT_LOAD SEGMENTS, SPLIT BY PERMISSION. This used to be a
 *    single RWX segment, for a reason that was honest at the time: the
 *    loader mapped every user page writable *and* executable regardless
 *    of what the segment asked for, so splitting them bought nothing and
 *    risked two segments sharing a page (which the loader could not
 *    handle). Both halves of that reasoning are now obsolete - the loader
 *    derives page flags from p_flags and refuses any segment that asks
 *    for write and execute together. A single RWX segment would now be
 *    rejected at load time, which is the correct outcome: it described a
 *    program whose code was writable and whose data was executable.
 *
 * 3. PAGE ALIGNMENT BETWEEN SEGMENTS. Permissions are a property of a
 *    page, not of a byte range, so two segments sharing a page cannot
 *    have different permissions - one would silently inherit the other's.
 *    The `. = ALIGN(4096)` lines below are what stop that, and the loader
 *    asserts on any overlap rather than trusting this file to be right.
 *    The cost is up to 4 KiB of padding per boundary, which is the
 *    correct thing to spend to make W^X real.
 *
 * The address itself (0x400000) is the conventional x86_64 ET_EXEC load
 * address, and is deliberately distinct from every other fixed range this
 * system uses. See abi/src/layout.rs for the whole map.
 */

ENTRY(_start)

PHDRS
{
    text   PT_LOAD FLAGS(5); /* PF_R | PF_X - code, never writable */
    rodata PT_LOAD FLAGS(4); /* PF_R        - constants, neither writable nor executable */
    data   PT_LOAD FLAGS(6); /* PF_R | PF_W - mutable state, never executable */
}

SECTIONS
{
    . = 0x400000;

    .text : {
        *(.text.start)
        *(.text .text.*)
    } :text

    . = ALIGN(4096);

    .rodata : {
        *(.rodata .rodata.*)
    } :rodata

    . = ALIGN(4096);

    .data : {
        *(.data .data.*)
    } :data

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
    } :data

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
