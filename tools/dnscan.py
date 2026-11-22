#!/usr/bin/env python3
"""
dnscan.py -- find & disassemble methods inside .NET assemblies (no Java/.NET needed).

Typical use for a Mono-Unity APK:

    python3 tools/dnscan.py scan Assembly-CSharp.dll --name clearbots
    python3 tools/dnscan.py scan Assembly-CSharp.dll --name 'bot' --il
    python3 tools/dnscan.py strings Assembly-CSharp.dll --find clearbots
    python3 tools/dnscan.py scan folder_or_apk --name clearbots --il

Works on: a single .dll/.exe, a directory (recursive) or an .apk/.zip (the
relevant managed DLLs are pulled out of assets/bin/Data/Managed/ on the fly).
"""
from __future__ import annotations

import argparse
import os
import tempfile
import re
import sys
import zipfile
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import il_disasm as IL  # noqa: E402

try:
    import dnfile
except ImportError:
    sys.exit("dnfile is missing:  pip install dnfile")

ELEM = {
    0x00: "end", 0x01: "void", 0x02: "bool", 0x03: "char", 0x04: "i1", 0x05: "u1",
    0x06: "i2", 0x07: "u2", 0x08: "i4", 0x09: "u4", 0x0A: "i8", 0x0B: "u8",
    0x0C: "r4", 0x0D: "r8", 0x0E: "string", 0x0F: "ptr", 0x10: "byref",
    0x11: "valuetype", 0x12: "class", 0x13: "var", 0x14: "array", 0x15: "genericinst",
    0x16: "typedbyref", 0x18: "i", 0x19: "u", 0x1C: "object", 0x1D: "szarray",
    0x1E: "mvar", 0x1F: "cmod_reqd", 0x20: "cmod_opt", 0x41: "modifier",
    0x45: "pinned",
}


# ---------------------------------------------------------------------------
class Asm:
    """Thin wrapper over dnfile with the caches we need for pretty printing."""

    def __init__(self, data: bytes, origin: str = "<memory>") -> None:
        self.origin = origin
        self.data = data
        # dnfile 0.18 wants a real filesystem path -> spill to a temp file
        fd, tmp = tempfile.mkstemp(suffix=".netbin")
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        self._tmp = tmp
        self.dn = dnfile.dnPE(tmp, fast_load=False)
        md = self.dn.net.mdtables
        self.md = md
        self._typedef_of_method: Dict[int, int] = {}
        self._build_method_owner()

    def __del__(self) -> None:
        try:
            if getattr(self, "_tmp", None) and os.path.exists(self._tmp):
                os.unlink(self._tmp)
        except Exception:
            pass

    # -- metadata helpers ---------------------------------------------------
    def _rows(self, table: str) -> List[Any]:
        t = getattr(self.md, table, None)
        if t is None:
            return []
        rows = getattr(t, "rows", None)
        return list(rows) if rows else []

    def _build_method_owner(self) -> None:
        # dnfile resolves TypeDef.MethodList into a list of the MethodDef row
        # objects that belong to that type -> map them back by identity.
        ident = {id(r): i for i, r in enumerate(self._rows("MethodDef"), start=1)}
        for ti, td in enumerate(self._rows("TypeDef"), start=1):
            for row in (getattr(td, "MethodList", None) or []):
                mi = ident.get(id(row)) or ident.get(id(getattr(row, "row", None)))
                if mi:
                    self._typedef_of_method[mi] = ti
        if len(self._typedef_of_method) < len(ident):
            self._fallback_owner_map()

    def _fallback_owner_map(self) -> None:
        tdefs = self._rows("TypeDef")
        nmeth = len(self._rows("MethodDef"))
        starts: List[int] = []
        for td in tdefs:
            s = None
            ml = getattr(td, "MethodList", None)
            for attr in ("row_index", "row_indexes", "value", "row"):
                v = getattr(ml, attr, None) if ml is not None else None
                if isinstance(v, (list, tuple)) and v:
                    s = v[0]
                    break
                if isinstance(v, int):
                    s = v
                    break
                r = getattr(v, "row_index", None) if v is not None else None
                if isinstance(r, int):
                    s = r
                    break
            starts.append(s if isinstance(s, int) and s > 0 else None)
        known = [(i + 1, s) for i, s in enumerate(starts) if s]
        for mi in range(1, nmeth + 1):
            owner = None
            for ti, s in known:
                if s <= mi:
                    owner = ti
            if owner:
                self._typedef_of_method[mi] = owner

    def type_name(self, row_index: int) -> str:
        rows = self._rows("TypeDef")
        if 1 <= row_index <= len(rows):
            td = rows[row_index - 1]
            ns = getattr(td, "TypeNamespace", "") or ""
            nm = getattr(td, "TypeName", "") or ""
            return f"{ns}.{nm}" if ns else str(nm)
        return f"<TypeDef#{row_index}>"

    def owner_of_method(self, method_index: int) -> str:
        ti = self._typedef_of_method.get(method_index)
        return self.type_name(ti) if ti else "<unknown type>"

    def resolve_token(self, token: int) -> str:
        table = (token >> 24) & 0xFF
        rid = token & 0x00FFFFFF
        name = IL.TOKEN_TABLES.get(table, f"table 0x{table:02x}")
        if table == 0x70:                                   # user string
            return self.user_string(rid)
        try:
            rows = self._rows(name)
            if not (1 <= rid <= len(rows)):
                return f"{name}[{rid}]"
            row = rows[rid - 1]
        except Exception:
            return f"{name}[{rid}]"
        if name in ("TypeDef",):
            return self.type_name(rid)
        if name == "TypeRef":
            ns = getattr(row, "TypeRefNamespace", "") or ""
            nm = getattr(row, "TypeRefName", "") or ""
            return f"{ns}.{nm}" if ns else str(nm)
        if name == "MethodDef":
            return f"{self.owner_of_method(rid)}::{getattr(row, 'Name', '?')}"
        if name == "MemberRef":
            cls = getattr(row, "Class", None)
            cname = "?"
            inner = getattr(cls, "row", None) if cls is not None else None
            if inner is not None:
                for a in ("TypeName", "TypeRefName", "Name", "TypeNamespace"):
                    v = getattr(inner, a, None)
                    if v:
                        cname = str(v)
                        break
            return f"{cname}::{getattr(row, 'Name', '?')}"
        if name == "MethodSpec":
            m = getattr(row, "Method", None)
            inner = getattr(m, "row", None) if m is not None else None
            nm = getattr(inner, "Name", None) if inner is not None else None
            return f"{nm or '?'}<...>"
        if name == "Field":
            return f"field {getattr(row, 'Name', '?')}"
        if name == "TypeSpec":
            return "typespec"
        if name == "StandAloneSig":
            return "signature"
        return f"{name}[{rid}]"

    def user_string(self, rid: int) -> str:
        try:
            us = self.dn.net.user_strings
            if us is not None:
                s = us.get(rid) or us.get_us(rid)
                if s is None and hasattr(us, "get_all"):
                    for item in us.get_all():
                        if getattr(item, "rva", None) == rid or getattr(item, "index", None) == rid:
                            s = getattr(item, "value", None)
                if s is not None:
                    return f'"{s}"'
        except Exception:
            pass
        return f"#US[{rid}]"

    # -- signatures ---------------------------------------------------------
    def method_signature(self, blob: Any) -> str:
        raw = getattr(blob, "value", None) or getattr(blob, "raw_data", None) or blob
        if not isinstance(raw, (bytes, bytearray)) or not raw:
            return "(?)"
        try:
            return "(" + ", ".join(self._sig_params(bytes(raw))) + ")"
        except Exception:
            return "(?)"

    def _sig_params(self, b: bytes) -> List[str]:
        i = [0]

        def byte() -> int:
            v = b[i[0]]; i[0] += 1; return v

        def compressed() -> int:
            v = byte()
            if v < 0x80:
                return v
            if v < 0xC0:
                return ((v & 0x3F) << 8) | byte()
            return ((v & 0x1F) << 24) | (byte() << 16) | (byte() << 8) | byte()

        def etype() -> str:
            t = byte()
            base = ELEM.get(t, f"0x{t:02x}")
            if t in (0x11, 0x12, 0x1C - 0x0B, 0x15):
                pass
            if t in (0x11, 0x12):
                tok = compressed()
                return f"{base}({tok})"
            if t == 0x15:
                g = etype()
                argc = compressed()
                args = [etype() for _ in range(argc)]
                return f"{g}<{', '.join(args)}>"
            if t == 0x1D:
                return etype() + "[]"
            if t in (0x0F, 0x10):
                return etype() + ("*" if t == 0x0F else "&")
            if t in (0x13, 0x1E):
                n = compressed()
                return f"{base}!{n}"
            return base

        cc = byte()
        if cc & 0x10:                                   # generic
            compressed()
        pcount = compressed()
        etype()                                          # return type
        return [etype() for _ in range(pcount)]


# ---------------------------------------------------------------------------
def load_assemblies(path: str) -> List[Asm]:
    out: List[Asm] = []
    if os.path.isdir(path):
        for root, _dirs, files in os.walk(path):
            for f in sorted(files):
                if f.lower().endswith((".dll", ".exe")):
                    p = os.path.join(root, f)
                    try:
                        out.append(Asm(open(p, "rb").read(), p))
                    except Exception as e:
                        print(f"[!] skip {p}: {e}", file=sys.stderr)
    elif zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for n in z.namelist():
                low = n.lower()
                if low.endswith((".dll", ".exe")) and (
                    "managed" in low or low.endswith("assembly-csharp.dll")
                    or "/plugins/" in low
                ):
                    try:
                        out.append(Asm(z.read(n), f"{path}!{n}"))
                    except Exception as e:
                        print(f"[!] skip {n}: {e}", file=sys.stderr)
    else:
        try:
            out.append(Asm(open(path, "rb").read(), path))
        except Exception as e:
            print(f"[!] cannot open {path}: {e}", file=sys.stderr)
    return out


def iter_methods(asm: Asm):
    for idx, row in enumerate(asm._rows("MethodDef"), start=1):
        yield idx, row


def dump_method(asm: Asm, idx: int, row: Any, show_il: bool, out) -> None:
    name = str(getattr(row, "Name", "?"))
    owner = asm.owner_of_method(idx)
    rva = getattr(row, "Rva", 0) or 0
    sig = asm.method_signature(getattr(row, "Signature", None))
    tok = 0x06000000 | idx
    print(f"\n=== [{asm.origin}] 0x{tok:08X}  {owner}::{name}{sig}", file=out)
    print(f"    RVA: 0x{rva:X}" if rva else "    (abstract/extern, no body)", file=out)
    if not rva:
        return
    try:
        off = asm.dn.get_offset_from_rva(rva)
        raw = asm.data[off:off + 65536]
    except Exception as e:
        print(f"    [!] body read failed: {e}", file=out)
        return
    mb = IL.parse_method_body(raw)
    ins = IL.decode_il(mb.code)
    print(f"    maxstack={mb.max_stack} initLocals={mb.init_locals} "
          f"codeSize={len(mb.code)} instrs={len(ins)}", file=out)
    if not show_il:
        # one-line summary of interesting calls
        calls = [asm.resolve_token(i.value) for i in ins
                 if i.kind == "token" and i.mnemonic in
                 ("call", "callvirt", "newobj", "ldsfld", "stsfld", "ldfld", "stfld")]
        for c in calls[:12]:
            print(f"      -> {c}", file=out)
        return
    labels = set()
    for i in ins:
        if i.kind in ("br1", "br4"):
            labels.add(i.value)
        elif i.kind == "switch":
            labels.update(i.value or [])
    for i in ins:
        mark = "  <<<<" if i.offset in labels else ""
        if i.kind == "token":
            arg = asm.resolve_token(i.value) + f"  /* 0x{i.value:08X} */"
        elif i.kind in ("br1", "br4"):
            arg = f"IL_{i.value:04x}"
        elif i.kind == "switch":
            arg = "(" + ", ".join(f"IL_{t:04x}" for t in (i.value or [])) + ")"
        elif isinstance(i.value, float):
            arg = repr(i.value)
        elif i.value is None:
            arg = ""
        else:
            arg = str(i.value)
        print(f"    IL_{i.offset:04x}: {i.mnemonic:<14} {arg}{mark}", file=out)
    for c in mb.eh_clauses:
        cls = asm.resolve_token(c["class_token"]) if c.get("class_token") else ""
        print(f"    EH {c['kind']:<8} try IL_{c['try_off']:04x}+{c['try_len']:<5} "
              f"handler IL_{c['handler_off']:04x}+{c['handler_len']:<5} {cls}", file=out)


def load_all(targets) -> List[Asm]:
    out: List[Asm] = []
    for t in targets:
        out.extend(load_assemblies(t))
    return out


def cmd_scan(args: argparse.Namespace) -> int:
    pat = re.compile(args.name, re.IGNORECASE)
    total = 0
    for asm in load_all(args.target):
        for idx, row in iter_methods(asm):
            nm = str(getattr(row, "Name", ""))
            if not pat.search(nm):
                continue
            if args.owner and not re.search(args.owner, asm.owner_of_method(idx), re.I):
                continue
            total += 1
            dump_method(asm, idx, row, args.il, sys.stdout)
    print(f"\n# matched {total} method(s)", file=sys.stderr)
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    for asm in load_all(args.target):
        print(f"### {asm.origin}: {len(asm._rows('MethodDef'))} methods, "
              f"{len(asm._rows('TypeDef'))} types")
        if args.types:
            pat = re.compile(args.types, re.I)
            for ti, td in enumerate(asm._rows("TypeDef"), start=1):
                if pat.search(asm.type_name(ti)):
                    print("   ", asm.type_name(ti))
    return 0


def iter_user_strings(asm: Asm):
    """Walk the #US heap by hand: <compressed length><utf-16le text><terminal byte>."""
    us = getattr(asm.dn.net, "user_strings", None)
    if us is None:
        return
    off = getattr(us, "file_offset", None)
    size = getattr(us, "_data_size", None)
    if size is None:
        st = getattr(us, "struct", None)
        size = getattr(st, "Size", None)
    if not off or not size:
        return
    blob = asm.data[off:off + size]
    i = 1                                    # heap[0] is the empty string terminator
    while i < len(blob):
        b0 = blob[i]
        if b0 < 0x80:
            ln, hdr = b0, 1
        elif b0 < 0xC0:
            if i + 2 > len(blob):
                break
            ln, hdr = ((b0 & 0x3F) << 8) | blob[i + 1], 2
        else:
            if i + 4 > len(blob):
                break
            ln = ((b0 & 0x3F) << 24) | (blob[i + 1] << 16) | (blob[i + 2] << 8) | blob[i + 3]
            hdr = 4
        if ln <= 0 or i + hdr + ln > len(blob):
            break
        body = blob[i + hdr:i + hdr + ln]
        try:
            text = body[:-1].decode("utf-16-le")
        except Exception:
            text = body.decode("utf-8", "replace")
        yield i, text
        i += hdr + ln


def cmd_strings(args: argparse.Namespace) -> int:
    pat = re.compile(args.find, re.I)
    for asm in load_all(args.target):
        found = 0
        for idx, text in iter_user_strings(asm):
            if pat.search(text):
                print(f"[#US 0x{idx:X}] {text!r}")
                found += 1
                if found > args.max:
                    break
        # raw pass: ASCII and UTF-16LE runs (catches obfuscated/embedded payloads)
        for m in re.finditer(rb"[ -~]{4,}", asm.data):
            s = m.group().decode("ascii", "replace")
            if pat.search(s):
                print(f"[RAW  @0x{m.start():X}] {s!r}")
                found += 1
        for m in re.finditer((u"(?:[ -~]\x00){4,}").encode("latin-1"), asm.data):
            s = m.group().decode("utf-16-le", "replace")
            if pat.search(s):
                print(f"[UTF16@0x{m.start():X}] {s!r}")
                found += 1
        if found > args.max:
            print(f"# {asm.origin}: truncated at {args.max} (--max)")
        else:
            print(f"# {asm.origin}: {found} hit(s)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="find + disassemble methods by name regex")
    s.add_argument("target", nargs="+", help=".dll/.exe, directory or .apk (several allowed)")
    s.add_argument("--name", required=True, help="regex matched against method names")
    s.add_argument("--owner", help="also filter by declaring type regex")
    s.add_argument("--il", action="store_true", help="print full IL (default: call summary)")
    s.set_defaults(func=cmd_scan)

    l = sub.add_parser("list", help="summarise assemblies / list type names")
    l.add_argument("target", nargs="+")
    l.add_argument("--types", help="regex filter for type names")
    l.set_defaults(func=cmd_list)

    st = sub.add_parser("strings", help="search #US heap + raw ASCII strings")
    st.add_argument("target", nargs="+")
    st.add_argument("--find", required=True)
    st.add_argument("--max", type=int, default=200)
    st.set_defaults(func=cmd_strings)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
