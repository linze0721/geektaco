#!/usr/bin/env python3
"""Build-time string compressor for geektaco.

The rendered pages are enormously redundant: `<form method=post action=/`,
`<input type=submit value="[`, `<a href="/` and friends recur up to ten times
across the string table. Measured: 3355 bytes of literals, gzip 1474.

This replaces the plain table with a token dictionary. Bytes 0x01..0x1f that
do not occur in the corpus become token IDs; a greedy pass repeatedly folds
the substring with the highest `count*(len-1) - (len+1)` into a new token.
Tokens may nest, so the expander in render.asm recurses.

`make` regenerates strtab.inc whenever strings.txt or this file changes.
Values must not contain NUL: str_ids and str_dict are NUL-separated and the
renderer finds string N by counting NULs, so an embedded 0 would shift every
later ID.

    ./mkstr.py strings.txt strtab.inc
"""
import sys, collections, re

ESC = {'\\r': 13, '\\n': 10, '\\t': 9, '\\\\': 92}


def unescape(s: str) -> bytes:
    out = bytearray()
    i = 0
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s):
            two = s[i:i+2]
            if two in ESC:
                out.append(ESC[two]); i += 2; continue
        out.extend(s[i].encode('utf-8')); i += 1
    return bytes(out)


def load(path):
    strings = []
    for line in open(path, encoding='utf-8'):
        line = line.rstrip('\n')
        if not line or line.startswith('#'):
            continue
        name, _, value = line.partition('\t')
        v = unescape(value)
        if 0 in v:
            sys.exit(f'mkstr.py: {name} contains NUL, which would shift every later string ID')
        strings.append((name, v))
    return strings


def compress(strings):
    blob = b''.join(v for _, v in strings)
    used = set(blob)
    # The expander finds token `id` by skipping `id - TOK_LO` NULs in the
    # dictionary, so the IDs must be CONTIGUOUS. Take the longest run of control bytes absent from
    # the corpus rather than every absent byte: 10 and 13 occur (CRLF in the
    # HTTP headers) and a gap there would make every later token index wrong.
    best_run = []
    run = []
    for b in range(1, 32):
        if b in used:
            run = []
        else:
            run.append(b)
            if len(run) > len(best_run):
                best_run = list(run)
    free = best_run
    if not free:
        sys.exit('no contiguous run of free control bytes')

    # Work on the concatenation so tokens may span the whole corpus, but keep
    # per-string boundaries so we can slice the result back out afterwards.
    parts = [v for _, v in strings]
    entries = []
    for tok in free:
        joined = b'\x00'.join(parts)
        cnt = collections.Counter()
        for n in range(3, 40):
            for i in range(len(joined) - n):
                sub = joined[i:i+n]
                if 0 in sub:
                    continue
                cnt[sub] += 1
        best = None
        for sub, c in cnt.items():
            if c < 2:
                continue
            gain = c * (len(sub) - 1) - (len(sub) + 1)
            if best is None or gain > best[0]:
                best = (gain, sub)
        if not best or best[0] <= 0:
            break
        entries.append(best[1])
        parts = [p.replace(best[1], bytes([tok])) for p in parts]

    return free, entries, parts


def expand(data, free, entries):
    out = bytearray()
    for ch in data:
        if ch in free[:len(entries)]:
            out += expand(entries[free.index(ch)], free, entries)
        else:
            out.append(ch)
    return bytes(out)


TIERS = (16, 255)   # string-table length tiers, shortest walked first


def sid_name(key):
    """String ID symbol for a key: s_head -> sid_head."""
    return 'sid_' + (key[2:] if key.startswith('s_') else key)


def nasm_bytes(data):
    """Emit as a NASM db line, printable runs quoted, others numeric."""
    out, run = [], []
    for b in data:
        if 32 <= b < 127 and b not in (0x27, 0x5c):
            run.append(chr(b))
        else:
            if run:
                out.append("'" + ''.join(run) + "'"); run = []
            out.append(str(b))
    if run:
        out.append("'" + ''.join(run) + "'")
    return ', '.join(out) if out else '0'


def main():
    src, dst = sys.argv[1], sys.argv[2]
    strings = load(src)
    free, entries, parts = compress(strings)

    # Round-trip or refuse to emit. A silently wrong table would corrupt every
    # page in a way that looks like a rendering bug.
    for (name, orig), got in zip(strings, parts):
        if expand(got, free, entries) != orig:
            sys.exit(f'round-trip FAILED for {name}')

    raw = sum(len(v) for _, v in strings)
    comp = sum(len(p) for p in parts)
    dic = sum(len(e) + 1 for e in entries)

    # Every string gets an ID: its position in the table below. render.asm
    # emits by ID (`call emit` followed by inline ID bytes, bit 7 flagging the
    # last one of a run), so IDs must stay below 0x80. Lookup walks NULs from
    # str_ids, so no offset table exists; instead the short tags that page
    # loops emit per row go first and the stylesheet head goes last, keeping
    # that walk short. The sort is stable, so the s_l_* stats labels (walked
    # by pointer in emit_stats) stay consecutive.
    order = sorted(range(len(parts)), key=lambda i: sum(len(parts[i]) > t for t in TIERS))
    # Identical non-empty strings share one copy and one ID; the first in
    # `order` owns it and later keys become aliases. Empty strings stay
    # distinct: s_l_end is a positional terminator, not content.
    first = {}
    alias = {}
    for i in order:
        if parts[i] and parts[i] in first:
            alias[i] = first[parts[i]]
        else:
            first.setdefault(parts[i], i)
    order = [i for i in order if i not in alias]
    if len(order) > 0x80:
        sys.exit(f'{len(order)} strings: IDs must fit in 7 bits')

    out = [
        '; Generated by mkstr.py from strings.txt -- do not edit.',
        f'; {raw} bytes of literals -> {comp} compressed + {dic} dictionary.',
        '; Token IDs are control bytes absent from the corpus. Tokens nest, so',
        '; the expander in render.asm recurses. Expansion happens ONLY in',
        '; ob_puts (build-time literals); user data never passes through it.',
        '; Dictionary entry k and string ID k are both found by skipping k NULs',
        '; from str_dict / str_ids.',
        '',
        # TOK_HI must bound the entries that actually exist, not the free
        # list: a gap here makes the expander index past the table.
        'TOK_LO equ %d' % free[0],
        'TOK_HI equ %d' % free[len(entries) - 1],
        '; %d entries, IDs %s' % (len(entries), ','.join(str(f) for f in free[:len(entries)])),
        '',
    ]
    for sid, i in enumerate(order):
        out.append(f'{sid_name(strings[i][0])} equ {sid}')
    for i, j in alias.items():
        out.append(f'{sid_name(strings[i][0])} equ {sid_name(strings[j][0])}')
    out.append(f'SID_COUNT equ {len(order)}   ; emit opcodes take IDs SID_COUNT..127')
    out.append('')
    out.append('str_dict:')
    for e in entries:
        out.append(f'    db {nasm_bytes(e)}, 0')
    out.append('')
    out.append('str_ids:')
    for i in order:
        for j in (j for j, k in alias.items() if k == i):
            out.append(f'{strings[j][0]}:')
        # An empty string is a lone NUL: a second one would shift every ID.
        body = f'{nasm_bytes(parts[i])}, 0' if parts[i] else '0'
        out.append(f'{strings[i][0]}: db {body}')
    out.append('')

    open(dst, 'w', encoding='utf-8').write('\n'.join(out))
    print(f'{len(entries)} tokens (IDs {free[0]}..{free[len(entries)-1]})')
    print(f'literals {raw} -> text {comp} + dict {dic} = {comp + dic}')
    print(f'saving {raw - comp - dic} bytes; round-trip OK')


if __name__ == '__main__':
    main()
