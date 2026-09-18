#!/usr/bin/env python3
"""Keep one load segment, its BSS extent, and the ELF headers needed to run it."""

import struct
import sys
from pathlib import Path


EHDR = struct.Struct("<16sHHIQQQIHHHHHH")
PHDR = struct.Struct("<IIQQQQQQ")
PAGE_SIZE = 0x1000


def require(condition, message):
    if not condition:
        raise SystemExit(f"mkelf.py: {message}")


def main():
    require(len(sys.argv) == 3, "usage: mkelf.py <linked-elf> <output>")
    image = Path(sys.argv[1]).read_bytes()
    require(len(image) >= EHDR.size, "truncated ELF header")
    header = EHDR.unpack_from(image)
    ident, kind, machine, version, entry, phoff = header[:6]
    require(ident[:7] == b"\x7fELF\x02\x01\x01", "expected little-endian ELF64")
    require((kind, machine, version) == (2, 62, 1), "expected x86-64 ET_EXEC")
    require(header[8:10] == (EHDR.size, PHDR.size), "unexpected ELF header sizes")
    phnum = header[10]
    require(phoff >= EHDR.size and phoff + phnum * PHDR.size <= len(image),
            "program header table is outside the input file")
    loads = []
    for index in range(phnum):
        phdr = PHDR.unpack_from(image, phoff + index * PHDR.size)
        if phdr[0] == 1:  # PT_LOAD
            loads.append(phdr)
    require(len(loads) == 1, "expected exactly one PT_LOAD segment")
    _, _, offset, vaddr, _, filesz, memsz, _ = loads[0]
    require(0 < filesz <= memsz, "invalid PT_LOAD file/memory sizes")
    require(offset + filesz <= len(image), "PT_LOAD extends beyond the input file")
    require(vaddr <= entry < vaddr + filesz, "entry point is outside PT_LOAD data")

    # link.ld's explicit, single PHDR makes SIZEOF_HEADERS 120. It also
    # starts .text there without alignment padding, so no pad-shift is needed.
    content_offset = EHDR.size + PHDR.size
    require(vaddr % PAGE_SIZE == content_offset % PAGE_SIZE,
            f"PT_LOAD address {vaddr:#x} is not congruent to output offset "
            f"{content_offset:#x} modulo {PAGE_SIZE:#x}; link with link.ld")
    with Path(sys.argv[2]).open("wb") as output:
        output.write(EHDR.pack(ident, 2, 62, 1, entry, EHDR.size, 0, 0,
                               EHDR.size, PHDR.size, 1, 0, 0, 0))
        output.write(PHDR.pack(1, 7, content_offset, vaddr, vaddr,
                               filesz, memsz, PAGE_SIZE))
        output.write(memoryview(image)[offset:offset + filesz])


if __name__ == "__main__":
    main()
