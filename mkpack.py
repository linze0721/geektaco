#!/usr/bin/env python3
"""Package the forum's linked PT_LOAD as a self-extracting x86-64 ELF."""

import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile


EHDR = struct.Struct("<16sHHIQQQIHHHHHH")
PHDR = struct.Struct("<IIQQQQQQ")
PAGE = 4096
PACK_BASE = 0x2000000
MAX_OFFSET = 32640  # forward ZX0 v2
HEADER_SIZE = EHDR.size + PHDR.size


def require(ok, why):
    if not ok:
        raise ValueError(why)


def branch_filter(data, inverse=False):
    """Bijective E8/E9 rel32-to-absolute transform, including opcode-like data."""
    result = bytearray(data)
    pos = 0
    while pos + 5 <= len(result):
        if result[pos] in (0xe8, 0xe9):
            value = int.from_bytes(result[pos + 1:pos + 5], "little")
            value = (value - (pos + 5) if inverse else value + pos + 5) & 0xffffffff
            result[pos + 1:pos + 5] = value.to_bytes(4, "little")
            pos += 5
        else:
            pos += 1
    return bytes(result)


class Block:
    """One ZX0 optimal-parse block; chain links to the preceding block."""

    __slots__ = ("bits", "index", "offset", "chain")

    def __init__(self, bits, index, offset, chain):
        self.bits = bits
        self.index = index
        self.offset = offset
        self.chain = chain


class BitWriter:
    def __init__(self):
        self.data = bytearray()
        self.mask = 0
        self.index = 0
        self.backtrack = True  # ZX0's initial literal indicator is implicit.

    def bit(self, value):
        if self.backtrack:
            if value:
                self.data[-1] |= 1
            self.backtrack = False
        else:
            if not self.mask:
                self.mask = 128
                self.index = len(self.data)
                self.data.append(0)
            if value:
                self.data[self.index] |= self.mask
            self.mask >>= 1

    def gamma(self, value, inverted=False):
        for shift in range(value.bit_length() - 2, -1, -1):
            self.bit(0)
            self.bit(((value >> shift) & 1) ^ inverted)
        self.bit(1)


def zx0_compress(data):
    """Optimal ZX0 v2 parse (forward mode), in Python without build tools.

    At each position, retain cheapest literal/last-offset/new-offset path for
    every possible distance; the shared best_length table prices all match
    lengths. This is the same dynamic-programming format as upstream ZX0.
    """
    size = len(data)
    limit = min(size - 1, MAX_OFFSET)
    last_literal = [None] * (limit + 1)
    last_match = [None] * (limit + 1)
    optimal = [None] * size
    matched = [0] * (limit + 1)
    best_length = [0] * size
    if size > 2:
        best_length[2] = 2
    last_match[1] = Block(-1, -1, 1, None)
    gamma_bits = [0] + [2 * value.bit_length() - 1 for value in range(1, size + 1)]
    offset_bits = [0] + [8 + gamma_bits[(offset - 1) // 128 + 1]
                         for offset in range(1, limit + 1)]

    for index in range(size):
        best_size = 2
        for offset in range(1, min(index, limit) + 1):
            if data[index] == data[index - offset]:
                previous = last_literal[offset]
                if previous is not None:
                    length = index - previous.index
                    block = Block(previous.bits + 1 + gamma_bits[length],
                                  index, offset, previous)
                    last_match[offset] = block
                    if optimal[index] is None or block.bits < optimal[index].bits:
                        optimal[index] = block
                matched[offset] += 1
                if matched[offset] > 1:
                    if best_size < matched[offset]:
                        length = best_length[best_size]
                        bits = optimal[index - length].bits + gamma_bits[length - 1]
                        while best_size < matched[offset]:
                            best_size += 1
                            candidate = optimal[index - best_size].bits + gamma_bits[best_size - 1]
                            if candidate <= bits:
                                best_length[best_size] = best_size
                                bits = candidate
                            else:
                                best_length[best_size] = best_length[best_size - 1]
                    length = best_length[matched[offset]]
                    bits = (optimal[index - length].bits + offset_bits[offset]
                            + gamma_bits[length - 1])
                    previous = last_match[offset]
                    if previous is None or previous.index != index or previous.bits > bits:
                        block = Block(bits, index, offset, optimal[index - length])
                        last_match[offset] = block
                        if optimal[index] is None or block.bits < optimal[index].bits:
                            optimal[index] = block
            else:
                matched[offset] = 0
                previous = last_match[offset]
                if previous is not None:
                    length = index - previous.index
                    block = Block(previous.bits + 1 + gamma_bits[length] + length * 8,
                                  index, 0, previous)
                    last_literal[offset] = block
                    if optimal[index] is None or block.bits < optimal[index].bits:
                        optimal[index] = block

    chain = []
    block = optimal[-1]
    while block is not None:
        chain.append(block)
        block = block.chain
    chain.reverse()
    writer = BitWriter()
    last_offset = 1
    cursor = 0
    previous_index = -1
    for block in chain[1:]:
        length = block.index - previous_index
        if block.offset == 0:
            writer.bit(0)
            writer.gamma(length)
            writer.data.extend(data[cursor:cursor + length])
        elif block.offset == last_offset:
            writer.bit(0)
            writer.gamma(length)
        else:
            writer.bit(1)
            writer.gamma((block.offset - 1) // 128 + 1, inverted=True)
            writer.data.append((127 - (block.offset - 1) % 128) << 1)
            writer.backtrack = True  # first length bit goes in offset byte
            writer.gamma(length - 1)
            last_offset = block.offset
        cursor += length
        previous_index = block.index
    require(cursor == size, "ZX0 optimal parse did not cover the image")
    writer.bit(1)
    writer.gamma(256, inverted=True)  # end marker, never a real distance
    return bytes(writer.data)


class ZX0Reader:
    """Byte/bit order models unpack.asm, including new-offset backtracking."""

    def __init__(self, data):
        self.data = data
        self.cursor = 0
        self.last_byte = 0
        self.mask = 0
        self.bit_value = 0
        self.backtrack = False

    def byte(self):
        require(self.cursor < len(self.data), "truncated ZX0 payload")
        self.last_byte = self.data[self.cursor]
        self.cursor += 1
        return self.last_byte

    def bit(self):
        if self.backtrack:
            self.backtrack = False
            return self.last_byte & 1
        self.mask >>= 1
        if not self.mask:
            self.mask = 128
            self.bit_value = self.byte()
        return bool(self.bit_value & self.mask)

    def gamma(self, inverted=False):
        value = 1
        while not self.bit():
            value = value * 2 + (self.bit() ^ inverted)
        return value


def decode_model(data, size):
    reader = ZX0Reader(data)
    output = bytearray()
    offset = 1

    def copy(length):
        require(0 < offset <= len(output) and len(output) + length <= size,
                "ZX0 distance or output length is invalid")
        for _ in range(length):
            output.append(output[-offset])

    while True:
        length = reader.gamma()
        require(len(output) + length <= size, "ZX0 literal run overflows image")
        output.extend(reader.byte() for _ in range(length))
        if not reader.bit():
            copy(reader.gamma())
            if not reader.bit():
                continue
        while True:
            high = reader.gamma(inverted=True)
            if high == 256:
                require(len(output) == size and reader.cursor == len(data),
                        "ZX0 stream ended before/after the original image")
                return bytes(output)
            low = reader.byte()
            offset = high * 128 - (low >> 1)
            reader.backtrack = True
            copy(reader.gamma() + 1)
            if not reader.bit():
                break


def image_segment(path):
    image = path.read_bytes()
    require(len(image) >= EHDR.size, "truncated ELF")
    header = EHDR.unpack_from(image)
    ident, kind, machine, version, entry, phoff = header[:6]
    require(ident[:7] == b"\x7fELF\x02\x01\x01" and (kind, machine, version) == (2, 62, 1),
            "expected static ELF64 x86-64 executable")
    require(header[8:10] == (EHDR.size, PHDR.size), "unexpected ELF/program header size")
    require(phoff + header[10] * PHDR.size <= len(image), "truncated program headers")
    loads = [PHDR.unpack_from(image, phoff + i * PHDR.size)
             for i in range(header[10])]
    loads = [ph for ph in loads if ph[0] == 1]
    require(len(loads) == 1, "expected exactly one PT_LOAD")
    _, flags, offset, vaddr, _, filesz, memsz, _ = loads[0]
    require(flags & 7 == 7 and 5 <= filesz <= memsz and offset + filesz <= len(image),
            "invalid RWX image segment")
    require(vaddr <= entry < vaddr + filesz, "entry outside image")
    require(vaddr < 1 << 31 and memsz < 1 << 31 and (vaddr & (PAGE - 1)) == (offset & (PAGE - 1)),
            "image cannot be mapped at its linked address")
    require(vaddr + memsz < PACK_BASE, "packed segment overlaps unpacked destination")
    return ident, entry, vaddr, memsz, image[offset:offset + filesz]


def pack(image_path, stub_path, output_path):
    ident, entry, address, memsz, image = image_segment(image_path)
    filtered = branch_filter(image)
    encoded = zx0_compress(filtered)
    require(decode_model(encoded, len(image)) == filtered and
            branch_filter(filtered, inverse=True) == image,
            "ZX0/branch-filter round-trip failed")
    with tempfile.TemporaryDirectory(prefix="geektaco-pack-") as work:
        code_path = Path(work) / "unpack.bin"
        subprocess.run(["nasm", "-f", "bin", f"-DPACK_BASE={PACK_BASE}",
                        f"-DIMG_ADDR={address}", f"-DIMG_SIZE={len(image)}",
                        f"-DIMG_MEMSZ={memsz}", f"-DIMG_ENTRY={entry}",
                        str(stub_path), "-o", str(code_path)], check=True)
        code = code_path.read_bytes()
    size = HEADER_SIZE + len(code) + len(encoded)
    require(PACK_BASE + size < (1 << 31), "packed mapping exceeds supported address space")
    header = EHDR.pack(ident, 2, 62, 1, PACK_BASE + HEADER_SIZE, EHDR.size, 0, 0,
                       EHDR.size, PHDR.size, 1, 0, 0, 0)
    segment = PHDR.pack(1, 7, 0, PACK_BASE, PACK_BASE, size, size, PAGE)
    content = header + segment + code + encoded
    require(len(content) == size, "packed ELF size mismatch")

    # Check the actual container's compressed bytes before replacing output.
    # Atomic rename leaves the previous working binary intact on failure.
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=output_path.parent, prefix=f".{output_path.name}.",
                                         delete=False) as output:
            temporary = Path(output.name)
            output.write(content)
        result = temporary.read_bytes()
        require(result[:HEADER_SIZE] == header + segment and
                branch_filter(decode_model(result[HEADER_SIZE + len(code):], len(image)), True) == image,
                "packed ELF failed byte-for-byte image verification")
        os.chmod(temporary, 0o755)
        os.replace(temporary, output_path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    print(f"{output_path}: {size} bytes (header {HEADER_SIZE}, stub {len(code)}, "
          f"ZX0 payload {len(encoded)}; original image {len(image)}, memsz {memsz})")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("usage: mkpack.py geektaco.elf unpack.asm geektaco")
    try:
        pack(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))
    except ValueError as exc:
        raise SystemExit(f"mkpack.py: {exc}") from exc
