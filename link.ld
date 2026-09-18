OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

/* Explicit PHDRS suppresses ld's automatic GNU_STACK header, so
   SIZEOF_HEADERS is exactly 64 + 56, matching mkelf.py's prefix. */
PHDRS
{
    image PT_LOAD FLAGS(7);
}

SECTIONS
{
    . = 0x400000 + SIZEOF_HEADERS;
    /* x86 instructions and byte strings need no inter-object alignment. */
    .text . : SUBALIGN(1) { *(.text .text.*) } :image
    .rodata : SUBALIGN(1) { *(.rodata .rodata.*) } :image
    .data ALIGN(8) : { *(.data .data.*) } :image
    .bss ALIGN(8) (NOLOAD) : { *(.bss .bss.*) *(COMMON) } :image
    /DISCARD/ : { *(*) }
}
