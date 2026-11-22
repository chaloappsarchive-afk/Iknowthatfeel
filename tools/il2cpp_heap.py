#!/usr/bin/env python3
"""
il2cpp_heap.py -- pull the *name heap* out of an obfuscated global-metadata.dat.

Chicken Gun's metadata is XOR-obfuscated with a sawtooth keystream
    cipher[i] = plain[i] ^ ((i + C) & 0xFF)
applied per region with a region-specific phase C, while other regions are left
in the clear.  tools/il2cpp_decrypt.py recovers a phase per 256-byte block; this
tool then locates the string heap (the biggest run of NUL-terminated C#
identifiers), which holds every type / method / field / property name in the
game, and lets you query it.

    python3 tools/il2cpp_heap.py dump    apk/global-metadata.dat -o work/names.txt
    python3 tools/il2cpp_heap.py find    apk/global-metadata.dat --regex 'bot'
    python3 tools/il2cpp_heap.py context apk/global-metadata.dat --name BotController --after 60
    python3 tools/il2cpp_heap.py stats   apk/global-metadata.dat
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from typing import List, Tuple

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from il2cpp_decrypt import best_phases, apply_phases, ident_count  # noqa: E402

IDENT_RUN = re.compile(rb"[\x20-\x7e]{1,}\x00")
IDENTISH = re.compile(r"^[A-Za-z_<>$][A-Za-z0-9_<>.`$\[\]]*$")


def decrypt(path: str, cache: str | None = None) -> bytes:
    """De-obfuscate, using a cache file when present (the pass costs ~20 s)."""
    if cache and os.path.exists(cache) and os.path.getsize(cache) == os.path.getsize(path):
        return open(cache, "rb").read()
    data = np.fromfile(path, dtype=np.uint8)
    dec = apply_phases(data, best_phases(data))
    out = dec.astype(np.uint8).tobytes()
    if cache:
        os.makedirs(os.path.dirname(cache) or ".", exist_ok=True)
        open(cache, "wb").write(out)
    return out


def strings(b: bytes, lo: int = 0, hi: int | None = None) -> List[Tuple[int, str]]:
    hi = len(b) if hi is None else hi
    return [(m.start(), m.group()[:-1].decode("utf-8", "replace"))
            for m in IDENT_RUN.finditer(b, lo, hi)]


def locate_heap(b: bytes, window: int = 4096, thresh: float = 0.55) -> Tuple[int, int]:
    """Biggest contiguous run of windows dominated by identifier-like strings."""
    scores = []
    for s in range(0, len(b) - window, window):
        chunk = b[s:s + window]
        ids = IDENT_RUN.findall(chunk)
        good = sum(1 for x in ids if IDENTISH.match(x[:-1].decode("latin1")))
        cov = sum(len(x) for x in ids) / window
        scores.append(1.0 if (good >= 20 and cov > thresh) else 0.0)
    best = (0, 0, 0)
    i = 0
    while i < len(scores):
        if scores[i]:
            j = i
            while j < len(scores) and scores[j]:
                j += 1
            if j - i > best[1] - best[0]:
                best = (i, j, j - i)
            i = j
        else:
            i += 1
    return best[0] * window, best[1] * window


def heap_names(b: bytes, lo: int, hi: int) -> List[str]:
    out = []
    for m in IDENT_RUN.finditer(b, lo, hi):
        s = m.group()[:-1].decode("utf-8", "replace")
        if IDENTISH.match(s):
            out.append(s)
    return out


def cmd_stats(a: argparse.Namespace) -> int:
    b = decrypt(a.meta, a.cache)
    lo, hi = locate_heap(b)
    names = heap_names(b, lo, hi)
    print(f"file              : {a.meta} ({len(b)/1e6:.2f} MB)")
    print(f"identifiers total : {ident_count(b)}")
    print(f"heap region       : 0x{lo:X} .. 0x{hi:X} ({(hi-lo)/1e6:.2f} MB)")
    print(f"heap names        : {len(names)} (unique {len(set(names))})")
    kinds = {"types(PascalCase)": sum(1 for n in set(names) if n[:1].isupper() and "_" not in n),
             "fields(m_/lower)": sum(1 for n in set(names) if n[:1].islower() or n.startswith("m_")),
             "properties(get_)": sum(1 for n in set(names) if n.startswith("get_")),
             "coroutines(<>d__)": sum(1 for n in set(names) if ">d__" in n),
             "lambdas(<>b__)": sum(1 for n in set(names) if ">b__" in n),
             "ctor": sum(1 for n in set(names) if n in (".ctor", ".cctor"))}
    for k, v in kinds.items():
        print(f"    {k:<22} {v}")
    return 0


def cmd_dump(a: argparse.Namespace) -> int:
    b = decrypt(a.meta, a.cache)
    lo, hi = locate_heap(b)
    names = heap_names(b, lo, hi)
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    with open(a.out, "w") as fh:
        fh.write("\n".join(names))
    print(f"# {len(names)} names from heap 0x{lo:X}..0x{hi:X} -> {a.out}", file=sys.stderr)
    return 0


def cmd_find(a: argparse.Namespace) -> int:
    b = decrypt(a.meta, a.cache)
    lo, hi = locate_heap(b)
    names = heap_names(b, lo, hi)
    rx = re.compile(a.regex, re.I if a.ignore_case else 0)
    hits = sorted({n for n in names if rx.search(n)})
    for n in hits:
        print(n)
    print(f"# {len(hits)} unique name(s) matched {a.regex!r} out of {len(names)}",
          file=sys.stderr)
    if a.out:
        open(a.out, "w").write("\n".join(hits))
        print(f"# written to {a.out}", file=sys.stderr)
    return 0


def cmd_context(a: argparse.Namespace) -> int:
    """Names are emitted per type, so neighbours == members of the same class."""
    b = decrypt(a.meta, a.cache)
    lo, hi = locate_heap(b)
    names = heap_names(b, lo, hi)
    rx = re.compile(a.name, 0 if a.exact else re.I)
    idxs = [i for i, n in enumerate(names) if (n == a.name if a.exact else rx.search(n))]
    if not idxs:
        print(f"# no heap name matches {a.name!r}", file=sys.stderr)
        return 1
    for i in idxs[:a.max_matches]:
        print(f"\n=== {names[i]!r} at heap position {i} "
              f"(members of the same type are adjacent) ===")
        for j in range(max(0, i - a.before), min(len(names), i + a.after + 1)):
            print(("  >> " if j == i else "     ") + names[j])
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("meta")
    common.add_argument("--cache", default="work/global-metadata.dec.dat",
                        help="cache of the de-obfuscated file")

    for name, fn, hlp in (("stats", cmd_stats, "heap region + name statistics"),
                          ("dump", cmd_dump, "write every heap name to a file"),
                          ("find", cmd_find, "list names matching a regex"),
                          ("context", cmd_context, "show a name and its neighbours")):
        p = sub.add_parser(name, help=hlp, parents=[common])
        if name == "dump":
            p.add_argument("-o", "--out", default="work/names.txt")
        if name == "find":
            p.add_argument("--regex", required=True)
            p.add_argument("-i", "--ignore-case", action="store_true")
            p.add_argument("-o", "--out")
        if name == "context":
            p.add_argument("--name", required=True)
            p.add_argument("--exact", action="store_true")
            p.add_argument("--before", type=int, default=25)
            p.add_argument("--after", type=int, default=45)
            p.add_argument("--max-matches", type=int, default=3)
        p.set_defaults(func=fn)

    a = ap.parse_args()
    return a.func(a)


if __name__ == "__main__":
    raise SystemExit(main())
