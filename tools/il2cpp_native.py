#!/usr/bin/env python3
"""
il2cpp_native.py -- ARM64/ARM disassembly of libil2cpp.so (capstone + pyelftools).

    python3 tools/il2cpp_native.py info    libil2cpp.so
    python3 tools/il2cpp_native.py disasm  libil2cpp.so --vaddr 0x1234 --count 60
    python3 tools/il2cpp_native.py script  libil2cpp.so --json Script.json --name clearbots
    python3 tools/il2cpp_native.py grep    libil2cpp.so --find clearbots

`script` consumes Il2CppDumper's Script.json (produced on a PC, or from any
dump you already have) and disassembles just the methods whose name matches.
Addresses are auto-detected as file offset / virtual address / base-relative.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import List, Optional, Tuple

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import capstone as cs

ARCH_BY_MACHINE = {
    "EM_AARCH64": ("arm64", ["CS_ARCH_ARM64", "CS_ARCH_AARCH64"], cs.CS_MODE_LITTLE_ENDIAN),
    "EM_ARM": ("arm32", ["CS_ARCH_ARM"], cs.CS_MODE_ARM),
    "EM_X86_64": ("x86_64", ["CS_ARCH_X86"], cs.CS_MODE_64),
    "EM_386": ("x86", ["CS_ARCH_X86"], cs.CS_MODE_32),
}
DEFAULT_ARCH = ARCH_BY_MACHINE["EM_AARCH64"]


def pick_arch(names: List[str]) -> int:
    for n in names:
        v = getattr(cs, n, None)
        if v is not None:
            return v
    raise SystemExit(f"[!] this capstone build lacks {names}")


class Lib:
    def __init__(self, path: str) -> None:
        self.path = path
        self.data = open(path, "rb").read()
        self.elf = ELFFile(open(path, "rb"))
        self.machine = self.elf.header.e_machine
        self.bits = self.elf.elfclass
        name, arch_names, mode = ARCH_BY_MACHINE.get(self.machine, DEFAULT_ARCH)
        self.arch_name = name
        self.md = cs.Cs(pick_arch(arch_names), mode)
        self.md.detail = False
        self.segments = [(s.header.p_vaddr, s.header.p_offset, s.header.p_filesz,
                          s.header.p_flags) for s in self.elf.iter_segments()
                         if s.header.p_type == "PT_LOAD"]
        base = min((v for v, o, f, fl in self.segments), default=0)
        self.image_base = base

    # -- address translation ------------------------------------------------
    def vaddr_to_off(self, vaddr: int) -> Optional[int]:
        for v, o, f, _ in self.segments:
            if v <= vaddr < v + f:
                return o + (vaddr - v)
        return None

    def off_to_vaddr(self, off: int) -> Optional[int]:
        for v, o, f, _ in self.segments:
            if o <= off < o + f:
                return v + (off - o)
        return None

    def resolve(self, value: int) -> Tuple[int, int, str]:
        """Return (vaddr, file_offset, how) for a loosely-specified address."""
        cands = [
            ("as-vaddr", value),
            ("as-vaddr+base", value + self.image_base),
            ("as-offset", self.off_to_vaddr(value) if value else None),
        ]
        for how, v in cands:
            if v is None:
                continue
            off = self.vaddr_to_off(v)
            if off is not None:
                return v, off, how
        return value, value, "as-raw-offset"

    def exec_range(self, off: int) -> int:
        for v, o, f, fl in self.segments:
            if o <= off < o + f and (fl & 1):        # PF_X
                return o + f - off
        return 4096

    def symbols(self, pat: Optional[str] = None) -> List[tuple]:
        out = []
        rx = re.compile(pat, re.I) if pat else None
        for sec in self.elf.iter_sections():
            if not isinstance(sec, SymbolTableSection):
                continue
            for sym in sec.iter_symbols():
                if sym.name and (rx is None or rx.search(sym.name)):
                    out.append((sym.name, sym.entry.st_value, sym.entry.st_size,
                                sym.entry.st_info.type))
        return out


def disasm_at(lib: Lib, vaddr: int, off: int, count: int, label: str = "") -> None:
    n = lib.exec_range(off)
    code = lib.data[off:off + min(n, count * 4 + 64)]
    print(f"--- {label} vaddr 0x{vaddr:X} file 0x{off:X} ({lib.arch_name}) ---")
    for ins in lib.md.disasm(code, vaddr):
        print(f"  0x{ins.address:08X}: {ins.bytes.hex():<10} {ins.mnemonic:<10} {ins.op_str}")
        count -= 1
        if count <= 0:
            break
        if ins.mnemonic in ("ret",) and count < 0:
            break


def cmd_info(a: argparse.Namespace) -> int:
    lib = Lib(a.so)
    print(f"file        : {a.so} ({len(lib.data)/1e6:.1f} MB)")
    print(f"machine     : {lib.machine}  class: ELF{lib.bits}")
    print(f"arch picked : {lib.arch_name}")
    print(f"image base  : 0x{lib.image_base:X}")
    print("PT_LOAD segments:")
    for v, o, f, fl in lib.segments:
        flags = "".join(c for c, b in (("R", 4), ("W", 2), ("X", 1)) if fl & b)
        print(f"    vaddr 0x{v:<12X} off 0x{o:<12X} size 0x{f:<10X} {flags}")
    syms = lib.symbols()
    print(f"symbols     : {len(syms)}")
    il2cpp = [s for s in syms if "il2cpp" in s[0].lower()]
    for name, val, size, t in il2cpp[:25]:
        print(f"    0x{val:X} {name}")
    if len(il2cpp) > 25:
        print(f"    ... {len(il2cpp)-25} more il2cpp_* exports")
    return 0


def cmd_disasm(a: argparse.Namespace) -> int:
    lib = Lib(a.so)
    v, off, how = lib.resolve(a.vaddr)
    print(f"# interpreted {hex(a.vaddr)} {how}", file=sys.stderr)
    disasm_at(lib, v, off, a.count, a.label or "")
    return 0


def cmd_script(a: argparse.Namespace) -> int:
    lib = Lib(a.so)
    doc = json.load(open(a.json))
    methods = doc.get("ScriptMethod") or doc.get("Methods") or []
    pat = re.compile(a.name, re.I)
    hits = 0
    for m in methods:
        name = m.get("Name") or m.get("Signature") or ""
        if not pat.search(str(name)):
            continue
        addr = int(m.get("Address", 0))
        if not addr:
            continue
        v, off, how = lib.resolve(addr)
        print(f"\n### {name}   [{how} 0x{addr:X}]")
        disasm_at(lib, v, off, a.count, name)
        hits += 1
        if hits >= a.max:
            break
    print(f"# {hits} method(s) matched {a.name!r} out of {len(methods)}", file=sys.stderr)
    return 0


def cmd_grep(a: argparse.Namespace) -> int:
    lib = Lib(a.so)
    rx = re.compile(re.escape(a.find).encode(), re.I)
    hits = 0
    for m in rx.finditer(lib.data):
        s = max(0, m.start() - 32)
        ctx = re.sub(rb"[^\x20-\x7e]", b".", lib.data[s:m.end() + 32]).decode()
        va = lib.off_to_vaddr(m.start())
        print(f"@file 0x{m.start():X}" + (f" vaddr 0x{va:X}" if va else "") + f"  ...{ctx}...")
        hits += 1
        if hits >= a.max:
            break
    for name, val, size, t in lib.symbols(a.find):
        print(f"[sym] 0x{val:X} {name} size={size} type={t}")
        hits += 1
    print(f"# {hits} hit(s)", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("info", help="ELF/arch/segment/export summary"); p.add_argument("so")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("disasm", help="disassemble at an address")
    p.add_argument("so"); p.add_argument("--vaddr", type=lambda x: int(x, 0), required=True)
    p.add_argument("--count", type=int, default=60); p.add_argument("--label")
    p.set_defaults(func=cmd_disasm)

    p = sub.add_parser("script", help="disassemble methods from Il2CppDumper Script.json")
    p.add_argument("so"); p.add_argument("--json", required=True)
    p.add_argument("--name", required=True); p.add_argument("--count", type=int, default=80)
    p.add_argument("--max", type=int, default=10)
    p.set_defaults(func=cmd_script)

    p = sub.add_parser("grep", help="search bytes + symbols")
    p.add_argument("so"); p.add_argument("--find", required=True)
    p.add_argument("--max", type=int, default=40)
    p.set_defaults(func=cmd_grep)

    a = ap.parse_args()
    return a.func(a)


if __name__ == "__main__":
    raise SystemExit(main())
