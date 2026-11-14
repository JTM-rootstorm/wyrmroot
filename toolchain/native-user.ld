OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

PHDRS
{
    text PT_LOAD FILEHDR PHDRS FLAGS(5);
    data PT_LOAD FLAGS(6);
    note PT_NOTE FLAGS(4);
    stack PT_GNU_STACK FLAGS(6);
}

SECTIONS
{
    . = 0x00400000 + SIZEOF_HEADERS;

    .text : ALIGN(16)
    {
        KEEP(*(.text._start))
        *(.text .text.*)
    } :text

    .rodata : ALIGN(16)
    {
        *(.rodata .rodata.*)
    } :text

    /* The Deepwyrm ABI note (root OS_STACK_ARCHITECTURE_PLAN.md V1): loaders
       refuse an image without it. */
    .note.deepwyrm.abi : ALIGN(4)
    {
        KEEP(*(.note.deepwyrm.abi))
    } :text :note

    . = ALIGN(4096);
    .data : ALIGN(16)
    {
        *(.data .data.*)
    } :data

    .bss (NOLOAD) : ALIGN(16)
    {
        *(.bss .bss.*)
        *(COMMON)
    } :data

    /DISCARD/ :
    {
        *(.comment)
        *(.eh_frame .eh_frame_hdr)
        *(.note .note.*)
    }
}
