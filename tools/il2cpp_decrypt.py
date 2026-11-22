#!/usr/bin/env python3
"""
il2cpp_decrypt.py -- break the "sawtooth XOR" obfuscation found on
Chicken Gun's global-metadata.dat and rebuild a clean, parseable file.

Observed scheme (see RE_NOTES.md):
    cipher[i] = plain[i] ^ ((i + C) & 0xFF)
applied only to *some* regions of the file, each region with its own phase C
(0x0F over the name heap, others elsewhere), leaving the rest in clear text.
Because (i & 0xFF) is the column inside a 256-byte block, the key for a given
phase is the SAME 256-byte vector for every block -> all 256 candidate phases
can be scored for every block in one vectorised pass.

    python3 tools/il2cpp_decrypt.py probe   global-metadata.dat
    python3 tools/il2cpp_decrypt.py decrypt global-metadata.dat -o work/global-metadata.dec.dat
    python3 tools/il2cpp_decrypt.py decrypt global-metadata.dat --phase 0x0F --only-encrypted

`decrypt` picks the best phase per 256-byte block (score = fraction of bytes
that are 0x00 / 0xFF / printable ASCII, i.e. what real metadata looks like) and
never scores worse than leaving the bytes untouched, so plaintext regions stay
plaintext automatically.
"""
from __future__ import annotations

import argparse
import collections
import os
import re
import sys

import numpy as np

SANITY = bytes([0xAF, 0x1B, 0xB1, 0xFA])
IDENT = re.compile(rb"[A-Za-z_<>$][A-Za-z0-9_<>.`$]{2,}\x00")


def load(path: str) -> np.ndarray:
    return np.fromfile(path, dtype=np.uint8)


def key_matrix() -> np.ndarray:
    """K[C][k] = (k + C) & 0xFF -- 256 phases x 256 columns."""
    k = np.arange(256, dtype=np.uint8)
    return ((k[None, :].astype(np.uint16) + k[:, None].astype(np.uint16)) & 0xFF).astype(np.uint8)


def score_blocks(data: np.ndarray) -> np.ndarray:
    """Return (nblocks, 256) scores: how metadata-like each block looks per phase."""
    n = (len(data) // 256) * 256
    M = data[:n].reshape(-1, 256)
    K = key_matrix()
    out = np.empty((M.shape[0], 256), dtype=np.float32)
    good = np.zeros(256, dtype=bool)
    good[0x00] = True
    good[0xFF] = True
    good[0x20:0x7F] = True
    for C in range(256):
        P = M ^ K[C][None, :]
        out[:, C] = good[P].mean(axis=1)
    return out


def best_phases(data: np.ndarray) -> np.ndarray:
    sc = score_blocks(data)
    # never "decrypt" into something worse than the bytes as they are (phase 0
    # is not the identity, so score the untouched block too and keep the max)
    n = (len(data) // 256) * 256
    M = data[:n].reshape(-1, 256)
    base = np.zeros(256, dtype=bool)
    base[0x00] = base[0xFF] = True
    base[0x20:0x7F] = True
    raw = base[M].mean(axis=1)
    ph = sc.argmax(axis=1).astype(np.uint8)
    ph[sc.max(axis=1) < raw] = 0xFF                     # 0xFF = leave untouched
    return ph


def apply_phases(data: np.ndarray, ph: np.ndarray) -> np.ndarray:
    out = data.copy()
    n = (len(data) // 256) * 256
    K = key_matrix()
    M = out[:n].reshape(-1, 256)
    todo = ph != 0xFF
    if todo.any():
        M[todo] = M[todo] ^ K[ph[todo]]
    return out


def decrypt_global(data: np.ndarray, C: int) -> np.ndarray:
    k = ((np.arange(len(data)) & 0xFF) + C).astype(np.uint8)
    return data ^ k


def ident_count(buf: bytes) -> int:
    return len(IDENT.findall(buf))


def cmd_probe(a: argparse.Namespace) -> int:
    data = load(a.meta)
    N = len(data)
    print(f"file            : {a.meta} ({N/1e6:.2f} MB)")
    print(f"sanity in raw   : {'YES at 0x%X' % data.tobytes().find(SANITY) if SANITY in data.tobytes() else 'no'}")
    for C in range(256):
        b = decrypt_global(data, C).tobytes()
        pos = b.find(SANITY)
        ids = ident_count(b)
        if pos >= 0 or ids > 20000:
            print(f"  global phase C=0x{C:02X}: sanity@{'0x%X' % pos if pos >= 0 else '-'}"
                  f"  identifiers={ids}")
    ph = best_phases(data)
    dec = apply_phases(data, ph)
    b = dec.tobytes()
    print(f"\nper-block phases: {len(ph)} blocks, "
          f"{int((ph == 0xFF).sum())} left untouched")
    print("  phase histogram (top 10):",
          [("0x%02X" % c if c != 0xFF else "raw", n) for c, n in
           collections.Counter(ph.tolist()).most_common(10)])
    print(f"  identifiers after decrypt : {ident_count(b)}")
    print(f"  raw identifier count      : {ident_count(data.tobytes())}")
    pos = b.find(SANITY)
    print(f"  sanity after decrypt      : {'0x%X' % pos if pos >= 0 else 'still absent'}")
    for pat in (b".ctor\x00", b"BotController", b"ClearBots", b"PhotonNetwork"):
        print(f"  {pat!r:<22} -> {b.find(pat.decode('latin1').encode('latin1'))}")
    # per-region phase map, coalesced
    print("\nphase map (runs of >=16 blocks):")
    runs = []
    cur = [0, ph[0], 1]
    for i in range(1, len(ph)):
        if ph[i] == cur[1]:
            cur[2] += 1
        else:
            runs.append(tuple(cur))
            cur = [i, ph[i], 1]
    runs.append(tuple(cur))
    for start, c, ln in runs:
        if ln >= 16:
            print(f"  0x{start*256:08X} len {ln*256:>9} phase "
                  f"{'raw' if c == 0xFF else '0x%02X' % c}")
    return 0


def cmd_decrypt(a: argparse.Namespace) -> int:
    data = load(a.meta)
    if a.phase is not None:
        dec = decrypt_global(data, a.phase)
        how = f"global phase 0x{a.phase:02X}"
    else:
        ph = best_phases(data)
        dec = apply_phases(data, ph)
        how = f"{int((ph != 0xFF).sum())} blocks re-phased, " \
              f"{int((ph == 0xFF).sum())} kept as-is"
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    dec.astype(np.uint8).tofile(a.out)
    b = dec.tobytes()
    print(f"# {how}", file=sys.stderr)
    print(f"# identifiers: {ident_count(data.tobytes())} -> {ident_count(b)}", file=sys.stderr)
    print(f"# wrote {a.out} ({len(b)} bytes)", file=sys.stderr)
    if a.fix_header and SANITY not in b[:16]:
        print("# header still lacks the sanity magic -- tables must be located "
              "blindly (il2cpp_meta.py will report a weak calibration)", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("probe", help="find the phase(s) and report what decrypts")
    p.add_argument("meta")
    p.set_defaults(func=cmd_probe)

    p = sub.add_parser("decrypt", help="write a de-obfuscated copy")
    p.add_argument("meta")
    p.add_argument("-o", "--out", default="work/global-metadata.dec.dat")
    p.add_argument("--phase", type=lambda x: int(x, 0),
                   help="single global phase (e.g. 0x0F); default = per-block auto")
    p.add_argument("--only-encrypted", action="store_true",
                   help="alias for the per-block auto mode (default)")
    p.add_argument("--fix-header", action="store_true")
    p.set_defaults(func=cmd_decrypt)

    a = ap.parse_args()
    return a.func(a)


if __name__ == "__main__":
    raise SystemExit(main())
