"""
Pure-python CIL (ECMA-335) disassembler + metadata token resolver.

No Java / no .NET runtime needed: builds on top of `dnfile` (pip), which parses
the PE + CLI metadata tables.  Used for Mono-Unity APKs where the game code
lives in assets/bin/Data/Managed/Assembly-CSharp.dll.
"""
from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# opcode tables:  op -> (mnemonic, operand_kind)
# operand_kind: None | 'i1' | 'u1' | 'i2' | 'u2' | 'i4' | 'i8' | 'r4' | 'r8'
#               | 'br1' | 'br4' | 'token' | 'switch' | 'u1x4' (unaligned.)
# ---------------------------------------------------------------------------

OP1: Dict[int, Tuple[str, Optional[str]]] = {
    0x00: ("nop", None), 0x01: ("break", None),
    0x02: ("ldarg.0", None), 0x03: ("ldarg.1", None),
    0x04: ("ldarg.2", None), 0x05: ("ldarg.3", None),
    0x06: ("ldloc.0", None), 0x07: ("ldloc.1", None),
    0x08: ("ldloc.2", None), 0x09: ("ldloc.3", None),
    0x0A: ("stloc.0", None), 0x0B: ("stloc.1", None),
    0x0C: ("stloc.2", None), 0x0D: ("stloc.3", None),
    0x0E: ("ldarg.s", "u1"), 0x0F: ("ldarga.s", "u1"), 0x10: ("starg.s", "u1"),
    0x11: ("ldloc.s", "u1"), 0x12: ("ldloca.s", "u1"), 0x13: ("stloc.s", "u1"),
    0x14: ("ldnull", None), 0x15: ("ldc.i4.m1", None),
    0x16: ("ldc.i4.0", None), 0x17: ("ldc.i4.1", None), 0x18: ("ldc.i4.2", None),
    0x19: ("ldc.i4.3", None), 0x1A: ("ldc.i4.4", None), 0x1B: ("ldc.i4.5", None),
    0x1C: ("ldc.i4.6", None), 0x1D: ("ldc.i4.7", None), 0x1E: ("ldc.i4.8", None),
    0x1F: ("ldc.i4.s", "i1"), 0x20: ("ldc.i4", "i4"), 0x21: ("ldc.i8", "i8"),
    0x22: ("ldc.r4", "r4"), 0x23: ("ldc.r8", "r8"),
    0x25: ("dup", None), 0x26: ("pop", None),
    0x27: ("jmp", "token"), 0x28: ("call", "token"), 0x29: ("calli", "token"),
    0x2A: ("ret", None),
    0x2B: ("br.s", "br1"), 0x2C: ("brfalse.s", "br1"), 0x2D: ("brtrue.s", "br1"),
    0x2E: ("beq.s", "br1"), 0x2F: ("bge.s", "br1"), 0x30: ("bgt.s", "br1"),
    0x31: ("ble.s", "br1"), 0x32: ("blt.s", "br1"), 0x33: ("bne.un.s", "br1"),
    0x34: ("bge.un.s", "br1"), 0x35: ("bgt.un.s", "br1"), 0x36: ("ble.un.s", "br1"),
    0x37: ("blt.un.s", "br1"),
    0x38: ("br", "br4"), 0x39: ("brfalse", "br4"), 0x3A: ("brtrue", "br4"),
    0x3B: ("beq", "br4"), 0x3C: ("bge", "br4"), 0x3D: ("bgt", "br4"),
    0x3E: ("ble", "br4"), 0x3F: ("blt", "br4"), 0x40: ("bne.un", "br4"),
    0x41: ("bge.un", "br4"), 0x42: ("bgt.un", "br4"), 0x43: ("ble.un", "br4"),
    0x44: ("blt.un", "br4"), 0x45: ("switch", "switch"),
    0x46: ("ldind.i1", None), 0x47: ("ldind.u1", None), 0x48: ("ldind.i2", None),
    0x49: ("ldind.u2", None), 0x4A: ("ldind.i4", None), 0x4B: ("ldind.u4", None),
    0x4C: ("ldind.i8", None), 0x4D: ("ldind.i", None), 0x4E: ("ldind.r4", None),
    0x4F: ("ldind.r8", None), 0x50: ("ldind.ref", None),
    0x51: ("stind.ref", None), 0x52: ("stind.i1", None), 0x53: ("stind.i2", None),
    0x54: ("stind.i4", None), 0x55: ("stind.i8", None), 0x56: ("stind.r4", None),
    0x57: ("stind.r8", None),
    0x58: ("add", None), 0x59: ("sub", None), 0x5A: ("mul", None),
    0x5B: ("div", None), 0x5C: ("div.un", None), 0x5D: ("rem", None),
    0x5E: ("rem.un", None), 0x5F: ("and", None), 0x60: ("or", None),
    0x61: ("xor", None), 0x62: ("shl", None), 0x63: ("shr", None),
    0x64: ("shr.un", None), 0x65: ("neg", None), 0x66: ("not", None),
    0x67: ("conv.i1", None), 0x68: ("conv.i2", None), 0x69: ("conv.i4", None),
    0x6A: ("conv.i8", None), 0x6B: ("conv.r4", None), 0x6C: ("conv.r8", None),
    0x6D: ("conv.u4", None), 0x6E: ("conv.u8", None),
    0x6F: ("callvirt", "token"), 0x70: ("cpobj", "token"), 0x71: ("ldobj", "token"),
    0x72: ("ldstr", "token"), 0x73: ("newobj", "token"), 0x74: ("castclass", "token"),
    0x75: ("isinst", "token"), 0x76: ("conv.r.un", None),
    0x79: ("unbox", "token"), 0x7A: ("throw", None),
    0x7B: ("ldfld", "token"), 0x7C: ("ldflda", "token"), 0x7D: ("stfld", "token"),
    0x7E: ("ldsfld", "token"), 0x7F: ("ldsflda", "token"), 0x80: ("stsfld", "token"),
    0x81: ("stobj", "token"),
    0x82: ("conv.ovf.i1.un", None), 0x83: ("conv.ovf.u1.un", None),
    0x84: ("conv.ovf.i2.un", None), 0x85: ("conv.ovf.u2.un", None),
    0x86: ("conv.ovf.i4.un", None), 0x87: ("conv.ovf.u4.un", None),
    0x88: ("conv.ovf.i8.un", None), 0x89: ("conv.ovf.u8.un", None),
    0x8D: ("newarr", "token"), 0x8E: ("ldlen", None), 0x8F: ("ldelema", "token"),
    0x90: ("ldelem.i1", None), 0x91: ("ldelem.u1", None), 0x92: ("ldelem.i2", None),
    0x93: ("ldelem.u2", None), 0x94: ("ldelem.i4", None), 0x95: ("ldelem.u4", None),
    0x96: ("ldelem.i8", None), 0x97: ("ldelem.i", None), 0x98: ("ldelem.r4", None),
    0x99: ("ldelem.r8", None), 0x9A: ("ldelem.ref", None),
    0x9B: ("stelem.i", None), 0x9C: ("stelem.i1", None), 0x9D: ("stelem.i2", None),
    0x9E: ("stelem.i4", None), 0x9F: ("stelem.i8", None), 0xA0: ("stelem.r4", None),
    0xA1: ("stelem.r8", None), 0xA2: ("stelem.ref", None),
    0xA3: ("ldelem", "token"), 0xA4: ("stelem", "token"), 0xA5: ("unbox.any", "token"),
    0xB3: ("conv.ovf.i1", None), 0xB4: ("conv.ovf.u1", None),
    0xB5: ("conv.ovf.i2", None), 0xB6: ("conv.ovf.u2", None),
    0xB7: ("conv.ovf.i4", None), 0xB8: ("conv.ovf.u4", None),
    0xB9: ("conv.ovf.i8", None), 0xBA: ("conv.ovf.u8", None),
    0xC2: ("refanyval", "token"), 0xC3: ("ckfinite", None),
    0xC6: ("mkrefany", "token"), 0xD0: ("ldtoken", "token"),
    0xD1: ("conv.ovf.i1", None), 0xD2: ("conv.ovf.u1", None),
    0xD3: ("conv.ovf.i2", None), 0xD4: ("conv.ovf.u2", None),
    0xD5: ("conv.ovf.i4", None), 0xD6: ("conv.ovf.u4", None),
    0xD7: ("conv.ovf.i8", None), 0xD8: ("conv.ovf.u8", None),
    0xE0: ("add.ovf", None), 0xE1: ("add.ovf.un", None),
    0xE2: ("mul.ovf", None), 0xE3: ("mul.ovf.un", None),
    0xE4: ("sub.ovf", None), 0xE5: ("sub.ovf.un", None),
}

OP2: Dict[int, Tuple[str, Optional[str]]] = {
    0x00: ("arglist", None), 0x01: ("ceq", None), 0x02: ("cgt", None),
    0x03: ("cgt.un", None), 0x04: ("clt", None), 0x05: ("clt.un", None),
    0x06: ("ldftn", "token"), 0x07: ("ldvirtftn", "token"),
    0x09: ("ldarg", "u2"), 0x0A: ("ldarga", "u2"), 0x0B: ("starg", "u2"),
    0x0C: ("ldloc", "u2"), 0x0D: ("ldloca", "u2"), 0x0E: ("stloc", "u2"),
    0x0F: ("localloc", None), 0x11: ("endfilter", None),
    0x12: ("unaligned.", "u1"), 0x13: ("volatile.", None), 0x14: ("tail.", None),
    0x15: ("initobj", "token"), 0x16: ("constrained.", "token"),
    0x17: ("cpblk", None), 0x18: ("initblk", None), 0x19: ("no.", "u1"),
    0x1A: ("rethrow", None), 0x1C: ("sizeof", "token"),
    0x1D: ("refanytype", None), 0x1E: ("readonly.", None),
}

TOKEN_TABLES = {
    0x01: "TypeRef", 0x02: "TypeDef", 0x04: "Field", 0x06: "MethodDef",
    0x0A: "MemberRef", 0x11: "StandAloneSig", 0x1B: "TypeSpec",
    0x2C: "MethodSpec", 0x2B: "AssemblyRef",
}


class MethodBody:
    __slots__ = ("code", "max_stack", "init_locals", "has_exceptions",
                 "local_sig", "eh_clauses")

    def __init__(self) -> None:
        self.code = b""
        self.max_stack = 8
        self.init_locals = True
        self.has_exceptions = False
        self.local_sig: Optional[int] = None
        self.eh_clauses: List[dict] = []


def parse_method_body(raw: bytes) -> MethodBody:
    """Parse a CIL method body (fat or tiny header) incl. EH clauses."""
    mb = MethodBody()
    if not raw:
        return mb
    flags = raw[0]
    if (flags & 0x03) == 0x02:                      # tiny header
        size = (flags >> 2) & 0x3F
        mb.code = raw[1:1 + size]
        return mb
    # fat header: 12 bytes
    if len(raw) < 12:
        return mb
    # fat header layout: u2 flags|size, u2 MaxStack, u4 CodeSize, u4 LocalVarSigTok
    flags_size, max_stack, code_size = struct.unpack_from("<HHI", raw, 0)
    local_sig_tok = struct.unpack_from("<I", raw, 8)[0]
    mb.max_stack = max_stack
    mb.init_locals = bool(flags_size & 0x10)
    mb.has_exceptions = bool(flags_size & 0x08)
    hdr_size = (flags_size >> 12) * 4
    mb.code = raw[hdr_size:hdr_size + code_size]
    if local_sig_tok:
        mb.local_sig = local_sig_tok & 0x00FFFFFF
    if mb.has_exceptions:
        off = hdr_size + code_size
        off = (off + 3) & ~3                          # align 4
        mb.eh_clauses = _parse_eh(raw, off)
    return mb


EH_KIND = {0: "catch", 1: "filter", 2: "finally", 4: "fault", 8: "dup"}


def _parse_eh(raw: bytes, off: int) -> List[dict]:
    clauses: List[dict] = []
    while off + 4 <= len(raw):
        kind, data_size = struct.unpack_from("<BH", raw, off)
        fat = bool(kind & 0x40)
        more = bool(kind & 0x80)
        if fat:
            data_size = struct.unpack_from("<I", raw, off + 1)[0]
            off += 4
        else:
            off += 4
        entry_sz = 24 if fat else 12
        n = max(0, (data_size - (4 if fat else 4))) // entry_sz if data_size else 0
        for i in range(n):
            base = off + i * entry_sz
            if base + entry_sz > len(raw):
                break
            if fat:
                flags, toff, tlen, hoff, hlen, ctok = struct.unpack_from("<IIIIII", raw, base)
            else:
                flags, toff, tlen, hoff, hlen, ctok = struct.unpack_from("<HBBBBi".replace("i", "I"), raw, base)
            clauses.append({
                "kind": EH_KIND.get(flags & 0x0F, hex(flags)),
                "try_off": toff, "try_len": tlen,
                "handler_off": hoff, "handler_len": hlen,
                "class_token": ctok if flags & 0x0F == 0 else 0,
                "filter_off": ctok if flags & 0x0F == 1 else 0,
            })
        off += data_size - 4
        if not more:
            break
        off = (off + 3) & ~3
    return clauses


class Instruction:
    __slots__ = ("offset", "op", "mnemonic", "kind", "value", "size")

    def __init__(self, offset: int, op: int, mnemonic: str, kind: Optional[str],
                 value: Any, size: int) -> None:
        self.offset = offset
        self.op = op
        self.mnemonic = mnemonic
        self.kind = kind
        self.value = value
        self.size = size

    def __repr__(self) -> str:
        return f"IL_{self.offset:04x}: {self.mnemonic} {self.value!r}"


def decode_il(code: bytes) -> List[Instruction]:
    out: List[Instruction] = []
    i = 0
    n = len(code)
    while i < n:
        start = i
        b = code[i]
        i += 1
        if b == 0xFE:
            if i >= n:
                break
            b2 = code[i]
            i += 1
            entry = OP2.get(b2)
            op = (0xFE << 8) | b2
        else:
            entry = OP1.get(b)
            op = b
        if entry is None:
            out.append(Instruction(start, op, f"?? 0x{op:x}", None, None, i - start))
            continue
        mn, kind = entry
        val: Any = None
        try:
            if kind is None:
                pass
            elif kind == "u1":
                val = code[i]; i += 1
            elif kind == "i1":
                val = struct.unpack_from("<b", code, i)[0]; i += 1
            elif kind == "u2":
                val = struct.unpack_from("<H", code, i)[0]; i += 2
            elif kind == "i4":
                val = struct.unpack_from("<i", code, i)[0]; i += 4
            elif kind == "i8":
                val = struct.unpack_from("<q", code, i)[0]; i += 8
            elif kind == "r4":
                val = struct.unpack_from("<f", code, i)[0]; i += 4
            elif kind == "r8":
                val = struct.unpack_from("<d", code, i)[0]; i += 8
            elif kind == "token":
                val = struct.unpack_from("<I", code, i)[0]; i += 4
            elif kind == "br1":
                d = struct.unpack_from("<b", code, i)[0]; i += 1
                val = i + d
            elif kind == "br4":
                d = struct.unpack_from("<i", code, i)[0]; i += 4
                val = i + d
            elif kind == "switch":
                cnt = struct.unpack_from("<I", code, i)[0]; i += 4
                base = i + cnt * 4
                targets = []
                for _ in range(cnt):
                    if i + 4 > n:
                        break
                    d = struct.unpack_from("<i", code, i)[0]; i += 4
                    targets.append(base + d)
                val = targets
            else:
                raise AssertionError(kind)
        except struct.error:
            out.append(Instruction(start, op, mn + " <truncated>", kind, None, n - start))
            break
        out.append(Instruction(start, op, mn, kind, val, i - start))
    return out
