#!/usr/bin/env python3
"""
apk_recon.py -- first pass over an APK: classify it, find the code containers,
and grep every one of them for a name (e.g. "clearbots").

    python3 tools/apk_recon.py info    game.apk
    python3 tools/apk_recon.py grep    game.apk --find clearbots
    python3 tools/apk_recon.py extract game.apk --out work/
    python3 tools/apk_recon.py manifest game.apk

Pure python: zipfile + androguard (binary AndroidManifest.xml, dex).
Mono-Unity  -> assets/bin/Data/Managed/Assembly-CSharp.dll   (use dnscan.py)
IL2CPP     -> lib/*/libil2cpp.so + assets/.../global-metadata.dat (use il2cpp_meta.py)
Mod menu   -> classes*.dex                                   (androguard disasm)
"""
from __future__ import annotations

import argparse
import logging
import os
import re
import sys
import zipfile
from typing import Dict, List, Tuple

CODE_PAT = re.compile(
    r"(assets/bin/data/managed/.*\.(dll|exe)$"
    r"|assets/bin/data/managed/metadata/global-metadata\.dat$"
    r"|lib/[^/]+/libil2cpp\.so$"
    r"|lib/[^/]+/libunity\.so$"
    r"|lib/[^/]+/.*\.so$"
    r"|classes[0-9]*\.dex$)", re.I)


def quiet() -> None:
    """androguard 4.x logs through loguru; keep our own output readable."""
    logging.disable(logging.WARNING)
    try:
        from loguru import logger
        logger.remove()
        logger.add(sys.stderr, level="ERROR")
    except Exception:
        pass


def open_apk(path: str) -> zipfile.ZipFile:
    if not zipfile.is_zipfile(path):
        sys.exit(f"[!] not a zip/apk: {path}")
    return zipfile.ZipFile(path)


def classify(z: zipfile.ZipFile) -> Dict[str, object]:
    names = z.namelist()
    low = [n.lower() for n in names]
    managed = [n for n in names if re.search(r"assets/bin/data/managed/.*\.dll$", n, re.I)]
    il2cpp = [n for n in names if re.search(r"lib/[^/]+/libil2cpp\.so$", n, re.I)]
    meta = [n for n in names if n.lower().endswith("global-metadata.dat")]
    dex = [n for n in names if re.match(r"classes\d*\.dex$", n, re.I)]
    unity = any("lib/unity" in n.lower() or "assets/bin/data" in n.lower() for n in low)
    if il2cpp and meta:
        engine = "Unity IL2CPP"
    elif managed:
        engine = "Unity Mono"
    elif unity:
        engine = "Unity (unknown scripting backend)"
    else:
        engine = "not a Unity app (or repacked)"
    return {
        "entries": len(names),
        "engine": engine,
        "managed_dlls": managed,
        "libil2cpp": il2cpp,
        "metadata": meta,
        "dex": dex,
        "native_libs": sorted({n for n in names if re.search(r"^lib/[^/]+/.*\.so$", n)}),
        "total_size": sum(i.file_size for i in z.infolist()),
    }


def cmd_info(args: argparse.Namespace) -> int:
    with open_apk(args.apk) as z:
        info = classify(z)
        print(f"APK            : {args.apk}")
        print(f"entries        : {info['entries']}   uncompressed: {info['total_size']/1e6:.1f} MB")
        print(f"engine         : {info['engine']}")
        print(f"classes*.dex   : {info['dex']}")
        print(f"managed dlls   : {len(info['managed_dlls'])}")
        for n in info["managed_dlls"][:40]:
            print(f"    {n}  ({z.getinfo(n).file_size/1024:.0f} KB)")
        print(f"libil2cpp.so   : {info['libil2cpp']}")
        print(f"metadata       : {info['metadata']}")
        print(f"native libs    : {len(info['native_libs'])}")
        for n in info["native_libs"][:30]:
            print(f"    {n}  ({z.getinfo(n).file_size/1024:.0f} KB)")
    return 0


def cmd_manifest(args: argparse.Namespace) -> int:
    quiet()
    with open_apk(args.apk) as z:
        try:
            from androguard.core.apk import APK
        except Exception:
            try:
                from androguard.core.bytecodes.apk import APK  # older androguard
            except Exception as e:
                sys.exit(f"[!] androguard unavailable: {e}")
        apk = APK(args.apk)
        print("package        :", apk.get_package())
        print("versionName    :", apk.get_androidversion_name())
        print("versionCode    :", apk.get_androidversion_code())
        print("minSdk/target  :", apk.get_min_sdk_version(), "/", apk.get_target_sdk_version())
        print("permissions    :", len(apk.get_permissions()))
        for p in apk.get_permissions()[:40]:
            print("    ", p)
        print("activities     :", len(apk.get_activities()))
        print("services       :", apk.get_services())
        print("receivers      :", apk.get_receivers())
        print("main activity  :", apk.get_main_activity())
        sig = None
        try:
            sig = apk.get_signature_names()
        except Exception:
            pass
        print("signatures     :", sig)
        libs = apk.get_libraries()
        print("uses-libraries :", libs)
    return 0


def _iter_interesting(z: zipfile.ZipFile) -> List[Tuple[str, bytes]]:
    out = []
    for n in z.namelist():
        if CODE_PAT.search(n) or n.lower().endswith((".json", ".xml", ".txt", ".cfg")):
            try:
                data = z.read(n)
            except Exception:
                continue
            if len(data) < 400 * 1024 * 1024:
                out.append((n, data))
    return out


def cmd_grep(args: argparse.Namespace) -> int:
    pat = re.compile(args.find.encode() if isinstance(args.find, str) else args.find, re.I)
    ascii_pat = re.compile(re.escape(args.find).encode(), re.I)
    with open_apk(args.apk) as z:
        targets = _iter_interesting(z)
        print(f"# scanning {len(targets)} entries for {args.find!r}", file=sys.stderr)
        for name, data in targets:
            hits = 0
            for m in ascii_pat.finditer(data):
                s = max(0, m.start() - 40)
                ctx = data[s:m.end() + 40]
                printable = re.sub(rb"[^\x20-\x7e]", b".", ctx).decode()
                print(f"[{name} @0x{m.start():X}] ...{printable}...")
                hits += 1
                if hits >= args.max_per_file:
                    print(f"[{name}] ... truncated (--max-per-file)")
                    break
            # UTF-16LE variant (common in .NET #US heap and in dex strings)
            for m in re.finditer(re.escape(args.find.encode("utf-16-le")), data, re.I):
                print(f"[{name} @0x{m.start():X}] (utf16) {args.find}")
                hits += 1
            if hits:
                print(f"# {name}: {hits} hit(s)", file=sys.stderr)
    return 0


def cmd_extract(args: argparse.Namespace) -> int:
    os.makedirs(args.out, exist_ok=True)
    wanted = ("managed", "libil2cpp", "global-metadata", "classes", ".so", ".dll")
    n = 0
    with open_apk(args.apk) as z:
        for name in z.namelist():
            low = name.lower()
            if args.only and not re.search(args.only, name, re.I):
                continue
            if not args.only and not any(w in low for w in wanted):
                continue
            dest = os.path.join(args.out, name)
            os.makedirs(os.path.dirname(dest) or args.out, exist_ok=True)
            with z.open(name) as src, open(dest, "wb") as fh:
                fh.write(src.read())
            print("extracted", dest)
            n += 1
    print(f"# {n} file(s) -> {args.out}", file=sys.stderr)
    return 0


def cmd_dex(args: argparse.Namespace) -> int:
    """Search dex method/class names (mod menus often live here)."""
    quiet()
    pat = re.compile(args.name, re.I)
    try:
        from androguard.misc import AnalyzeAPK
    except Exception as e:
        sys.exit(f"[!] androguard import failed: {e}")
    print("# loading APK with androguard (can take a minute)...", file=sys.stderr)
    _a, _d, dx = AnalyzeAPK(args.apk)
    found = 0
    for cls in dx.get_classes():
        cname = cls.get_vm_class().get_name()
        for m in cls.get_methods():
            mname = m.get_method().get_name()
            if pat.search(mname) or (args.owner and pat.search(cname)):
                meth = m.get_method()
                print(f"\n=== {cname}->{mname}{meth.get_descriptor()}")
                if args.xrefs:
                    try:
                        for off, caller, _ in m.get_xref_from():
                            cm = caller.get_method() if hasattr(caller, "get_method") else caller
                            cn = caller.get_class_name() if hasattr(caller, "get_class_name") else "?"
                            print(f"    <- called from {cn}->{getattr(cm, 'get_name', lambda: '?')()}"
                                  f"{getattr(cm, 'get_descriptor', lambda: '')()} @0x{off:X}")
                    except Exception as e:
                        print("    [xref failed]", e)
                try:
                    for ins in meth.get_instructions():
                        print(f"    {ins.get_name():<22} {ins.get_output()}")
                except Exception as e:
                    print("    [disasm failed]", e)
                found += 1
                if found >= args.max:
                    break
        if found >= args.max:
            break
    print(f"# {found} dex method(s) matched", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    for name, fn, hlp in (("info", cmd_info, "classify the APK, list code containers"),
                          ("manifest", cmd_manifest, "AndroidManifest summary via androguard"),
                          ("grep", cmd_grep, "grep every code/config entry for a string"),
                          ("extract", cmd_extract, "pull managed dlls / libs / dex out"),
                          ("dex", cmd_dex, "find + disassemble dex methods by name")):
        p = sub.add_parser(name, help=hlp)
        p.add_argument("apk")
        if name == "grep":
            p.add_argument("--find", required=True)
            p.add_argument("--max-per-file", type=int, default=12)
        if name == "extract":
            p.add_argument("--out", default="work")
            p.add_argument("--only", help="extra regex filter on entry names")
        if name == "dex":
            p.add_argument("--name", required=True)
            p.add_argument("--owner", action="store_true")
            p.add_argument("--xrefs", action="store_true", help="also print callers")
            p.add_argument("--max", type=int, default=25)
        p.set_defaults(func=fn)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
