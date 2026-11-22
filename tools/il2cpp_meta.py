#!/usr/bin/env python3
"""
il2cpp_meta.py -- parse Unity IL2CPP global-metadata.dat WITHOUT Il2CppDumper.

    python3 tools/il2cpp_meta.py info    global-metadata.dat
    python3 tools/il2cpp_meta.py find    global-metadata.dat --name clearbots
    python3 tools/il2cpp_meta.py types   global-metadata.dat --name bot
    python3 tools/il2cpp_meta.py literals global-metadata.dat --find bot

The header layout drifts between metadata versions (24.x -> 27 -> 29 -> 31), so
the section offsets are read from the stable leading part of the header and the
record sizes are *self-calibrated*: candidate struct sizes are scored by how
many of their name indices resolve to real NUL-terminated strings.  That makes
the tool work on versions it was never explicitly taught.

If Il2CppDumper output (DummyDll/*.dll + Script.json / Il2Cpp.h) is available,
feed the DummyDll to tools/dnscan.py and Script.json to tools/il2cpp_native.py.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import struct
import sys
from typing import Dict, List, Optional, Tuple

SANITY = 0xFAB11BAF

# leading header sections, in order, valid for metadata v24.x .. v31
LEADING = [
    "stringLiteral", "stringLiteralData", "string", "events", "properties",
    "methods", "parameterDefaultValues", "fieldDefaultValues",
    "fieldAndParameterDefaultValueData", "fieldMarshaledSizes", "parameters",
    "fields", "genericParameters", "genericParameterConstraints",
    "genericContainers", "nestedTypes", "interfaces", "vtableMethods",
    "interfaceOffsets", "typeDefinitions", "images", "assemblies",
]


class Meta:
    def __init__(self, data: bytes) -> None:
        self.data = data
        sanity, version = struct.unpack_from("<Ii", data, 0)
        if sanity != SANITY:
            raise SystemExit(f"[!] bad sanity 0x{sanity:08X} -- not global-metadata.dat")
        self.version = version
        self.sections: Dict[str, Tuple[int, int]] = {}
        for i, name in enumerate(LEADING):
            base = 8 + i * 8
            if base + 8 > len(data):
                break
            off, size = struct.unpack_from("<ii", data, base)
            if 0 <= off <= len(data) and size >= 0:
                self.sections[name] = (off, size)
        self.method_size = 0
        self.typedef_size = 0
        self.image_size = 0
        self._calibrate()

    # -- low level ----------------------------------------------------------
    def sect(self, name: str) -> Tuple[int, int]:
        return self.sections.get(name, (0, 0))

    def cstr(self, index: int) -> Optional[str]:
        off, size = self.sect("string")
        if index < 0 or index >= size:
            return None
        p = off + index
        end = self.data.find(b"\x00", p, off + size + 1)
        if end < 0:
            return None
        try:
            return self.data[p:end].decode("utf-8")
        except UnicodeDecodeError:
            return None

    def valid_index(self, index: int) -> bool:
        s = self.cstr(index)
        return s is not None and s != "" and s.isprintable()

    # -- calibration --------------------------------------------------------
    def _candidates(self, name: str, sizes: List[int],
                    token_tag: int = 0) -> Tuple[int, int]:
        """Score candidate record sizes: name index must resolve to a real
        string and (when known) the token must carry the right table tag."""
        off, size = self.sect(name)
        best = (0.0, 0)
        for sz in sizes:
            if sz <= 0 or size % sz:
                continue
            n = size // sz
            probe = min(n, 4000)
            ok = 0
            for i in range(probe):
                base = off + i * sz
                if not self.valid_index(struct.unpack_from("<i", self.data, base)[0]):
                    continue
                if token_tag:
                    tok_off = 20 if sz >= 32 else 16
                    tok = struct.unpack_from("<I", self.data, base + tok_off)[0]
                    if (tok >> 24) != token_tag or (tok & 0xFFFFFF) != i + 1:
                        continue
                ok += 1
            score = ok / probe if probe else 0.0
            if score > best[0]:
                best = (score, sz)
        return best

    def _calibrate(self) -> None:
        # method records: nameIndex(4) declaringType(4) [returnType(4)] parameterStart(4)
        #               genericContainerIndex(4) token(4) flags(2) iflags(2) slot(2) paramCount(2)
        score, sz = self._candidates("methods", [32, 28, 36, 24, 40, 20], token_tag=0x06)
        self.method_size = sz
        self.method_score = score
        score, sz = self._candidates("typeDefinitions", [76, 88, 92, 84, 80, 64, 96])
        self.typedef_size = sz
        self.typedef_score = score
        score, sz = self._candidates("images", [40, 36, 32, 44, 20])
        self.image_size = sz
        self.image_score = score

    # -- tables -------------------------------------------------------------
    @property
    def method_count(self) -> int:
        _, size = self.sect("methods")
        return size // self.method_size if self.method_size else 0

    @property
    def typedef_count(self) -> int:
        _, size = self.sect("typeDefinitions")
        return size // self.typedef_size if self.typedef_size else 0

    def method(self, i: int) -> dict:
        off, _ = self.sect("methods")
        base = off + i * self.method_size
        vals = struct.unpack_from("<iiiiiiHHHH", self.data, base) if self.method_size >= 32 \
            else struct.unpack_from("<iiiiiHHHH", self.data, base)
        if self.method_size >= 32:
            name_i, decl, _ret, pstart, _gc, token, flags, iflags, slot, pcount = vals
        else:
            name_i, decl, pstart, _gc, token, flags, iflags, slot, pcount = vals
        return {"index": i, "nameIndex": name_i, "name": self.cstr(name_i),
                "declaringType": decl, "token": token & 0xFFFFFFFF,
                "parameterStart": pstart, "parameterCount": pcount,
                "flags": flags, "slot": slot}

    def typedef(self, i: int) -> dict:
        off, _ = self.sect("typeDefinitions")
        base = off + i * self.typedef_size
        name_i, ns_i = struct.unpack_from("<ii", self.data, base)
        # last record fields are: u32 token, u16 customAttributeStart, u16 count
        token = struct.unpack_from("<I", self.data, base + self.typedef_size - 8)[0] \
            if self.typedef_size >= 12 else 0
        method_start = struct.unpack_from("<i", self.data, base + 40)[0] \
            if self.typedef_size >= 44 else -1
        return {"index": i, "name": self.cstr(name_i), "namespace": self.cstr(ns_i),
                "token": token, "methodStart": method_start}

    def full_type_name(self, i: int) -> str:
        td = self.typedef(i)
        nm = td.get("name") or f"<type#{i}>"
        ns = td.get("namespace")
        return f"{ns}.{nm}" if ns else nm

    def image(self, i: int) -> dict:
        off, _ = self.sect("images")
        if not self.image_size:
            return {}
        base = off + i * self.image_size
        name_i = struct.unpack_from("<i", self.data, base)[0]
        vals = struct.unpack_from("<iiiii", self.data, base)
        return {"index": i, "name": self.cstr(name_i), "typeStart": vals[2],
                "typeCount": vals[3], "raw": vals}

    def image_count(self) -> int:
        _, size = self.sect("images")
        return size // self.image_size if self.image_size else 0

    def literals(self) -> List[Tuple[int, str]]:
        off, size = self.sect("stringLiteral")
        doff, dsize = self.sect("stringLiteralData")
        out = []
        for i in range(size // 8):
            ln, di = struct.unpack_from("<Ii", self.data, off + i * 8)
            if di < 0 or di + ln > dsize or ln > 4096:
                continue
            try:
                out.append((i, self.data[doff + di: doff + di + ln].decode("utf-8", "replace")))
            except Exception:
                continue
        return out


# ---------------------------------------------------------------------------
def load(path: str) -> Meta:
    with open(path, "rb") as fh:
        return Meta(fh.read())


def cmd_info(args: argparse.Namespace) -> int:
    m = load(args.meta)
    print(f"file            : {args.meta}  ({len(m.data)/1e6:.2f} MB)")
    print(f"metadata version: {m.version}")
    print(f"methods         : {m.method_count} (record size {m.method_size}, "
          f"calibration {m.method_score:.0%})")
    print(f"typeDefinitions : {m.typedef_count} (record size {m.typedef_size}, "
          f"calibration {m.typedef_score:.0%})")
    print(f"images          : {m.image_count()} (record size {m.image_size})")
    if m.method_score < 0.5 or m.typedef_score < 0.5:
        print("[!] calibration is weak -> this metadata version may need a new "
              "candidate record size; results below can be noisy.", file=sys.stderr)
    print("\nsections (offset, size):")
    for k, (o, s) in m.sections.items():
        print(f"    {k:<38} 0x{o:<10X} {s}")
    print("\nimages:")
    for i in range(min(m.image_count(), 60)):
        im = m.image(i)
        print(f"    [{i:>2}] {im.get('name')}  types {im.get('typeStart')}..+"
              f"{im.get('typeCount')}")
    return 0


def cmd_find(args: argparse.Namespace) -> int:
    m = load(args.meta)
    pat = re.compile(args.name, re.I)
    hits = 0
    for i in range(m.method_count):
        d = m.method(i)
        nm = d["name"]
        if not nm or not pat.search(nm):
            continue
        decl = d["declaringType"]
        tname = m.full_type_name(decl) if 0 <= decl < m.typedef_count else f"<type#{decl}>"
        print(f"[{i:>7}] 0x{d['token']:08X}  {tname}::{nm}  "
              f"params={d['parameterCount']} flags=0x{d['flags']:02X} slot={d['slot']}")
        hits += 1
        if hits >= args.max:
            print("... truncated (--max)")
            break
    print(f"# {hits} method(s) matched {args.name!r}", file=sys.stderr)
    return 0


def cmd_types(args: argparse.Namespace) -> int:
    m = load(args.meta)
    pat = re.compile(args.name, re.I)
    hits = 0
    for i in range(m.typedef_count):
        td = m.typedef(i)
        full = m.full_type_name(i)
        if not pat.search(full):
            continue
        print(f"[{i:>6}] 0x{td['token']:08X} {full}  methodStart={td['methodStart']}")
        if args.methods and td["methodStart"] >= 0:
            j = td["methodStart"]
            while j < m.method_count:
                d = m.method(j)
                if d["declaringType"] != i:
                    break
                print(f"          - {d['name']}({d['parameterCount']})")
                j += 1
                if args.methods_max and j - td["methodStart"] > args.methods_max:
                    print("          ...")
                    break
        hits += 1
        if hits >= args.max:
            break
    print(f"# {hits} type(s) matched {args.name!r}", file=sys.stderr)
    return 0


def cmd_literals(args: argparse.Namespace) -> int:
    m = load(args.meta)
    pat = re.compile(args.find, re.I)
    lits = m.literals()
    print(f"# {len(lits)} string literals in table", file=sys.stderr)
    hits = 0
    for i, s in lits:
        if pat.search(s):
            print(f"[{i:>6}] {s!r}")
            hits += 1
            if hits >= args.max:
                break
    print(f"# {hits} literal(s) matched", file=sys.stderr)
    if args.json:
        with open(args.json, "w") as fh:
            json.dump([{"index": i, "text": s} for i, s in lits], fh, indent=1)
        print(f"# wrote {args.json}", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("info", help="header/version/section summary")
    p.add_argument("meta"); p.set_defaults(func=cmd_info)

    p = sub.add_parser("find", help="find methods by name regex")
    p.add_argument("meta"); p.add_argument("--name", required=True)
    p.add_argument("--max", type=int, default=200); p.set_defaults(func=cmd_find)

    p = sub.add_parser("types", help="find types by name regex")
    p.add_argument("meta"); p.add_argument("--name", required=True)
    p.add_argument("--methods", action="store_true", help="also list their methods")
    p.add_argument("--methods-max", type=int, default=60)
    p.add_argument("--max", type=int, default=120); p.set_defaults(func=cmd_types)

    p = sub.add_parser("literals", help="search the string-literal table")
    p.add_argument("meta"); p.add_argument("--find", required=True)
    p.add_argument("--max", type=int, default=200)
    p.add_argument("--json", help="also dump all literals to this json")
    p.set_defaults(func=cmd_literals)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
