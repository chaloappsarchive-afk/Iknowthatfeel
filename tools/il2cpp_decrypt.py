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


# ----------------------------------------------------------------------------
# Точная (не эвристическая) добор фаз по «крибам» — известным plaintext-байтам.
#
# `best_phases()` угадывает фазу по тому, насколько блок похож на метаданные, и
# на части блоков ошибается: в кэше Chicken Gun таких оказалось 677 (все в
# таблицах MethodDefinition, всем нужна фаза 111). Ошибка дорого стоит — запись
# метода читается как мусор (nameIndex 539446771 вместо имени).
#
# Здесь фаза решается точно: у записи MethodDefinition на base + (rid-1)*stride
# токен на +12 обязан равняться 0x06000000|rid. Четыре известных байта дают C
# однозначно (C = (cipher[i] ^ plain[i] - i) & 0xFF, и все четыре байта обязаны
# сойтись), а остальные записи блока работают как проверка. Вероятность
# случайного совпадения ~256^-3 на анкер, то есть решение достоверно.
# ----------------------------------------------------------------------------
def phases_from(raw: np.ndarray, dec: np.ndarray) -> np.ndarray:
    """Восстановить массив фаз по паре (шифртекст, текущий кэш).

    Нужно, чтобы лечить уже существующий кэш: сами фазы в нём не хранятся.
    Блок, который не трогали (в `best_phases` это 0xFF), возвращается как 0xFF —
    в нём dec совпадает с raw побайтово.
    """
    nb = min(len(raw), len(dec)) // 256
    ph = np.full(nb, 0xFF, dtype=np.uint8)
    d = (raw[:nb * 256].astype(np.uint16) ^ dec[:nb * 256].astype(np.uint16)).astype(np.uint8)
    M = d.reshape(nb, 256)
    idx = np.arange(256, dtype=np.uint16)
    touched = M.any(axis=1)
    cand = ((M[:, 0].astype(np.uint16) - idx[0]) & 0xFF).astype(np.uint8)
    # фаза обязана быть одной на весь блок; иначе блок считаем нетронутым
    ok = np.all(M == ((idx[None, :] + cand[:, None].astype(np.uint16)) & 0xFF).astype(np.uint8),
                axis=1)
    ph[touched & ok] = cand[touched & ok]
    return ph


def _crib_phase(raw, pos, want):
    """Фаза C из одного 4-байтного криба, либо None, если байты не согласованы."""
    C = ((int(raw[pos]) ^ want[0]) - pos) & 0xFF
    for i in (1, 2, 3):
        j = pos + i
        if (raw[j] ^ ((j + C) & 0xFF)) != want[i]:
            return None
    return C


def _crib_ok(raw, pos, want, C):
    C = int(C)          # numpy uint8 в арифметике переполняется (NEP 50)
    for i in range(4):
        j = pos + i
        if (raw[j] ^ ((j + C) & 0xFF)) != want[i]:
            return False
    return True


def heal_by_tokens(raw, phases, chunks, stride=30, tok_off=12, tag=0x06,
                   max_records=1 << 20):
    """Дорешить фазы блоков по токенам таблиц, лежащих на ровной решётке.

    `chunks` — {base: {rid: позиция_записи}} (то, что дал `Meta.chunks()` по
    текущему кэшу). Для чанка, где rids идут подряд (`rec == base+(rid-1)*stride`),
    анкеры берутся с решётки и обход продолжается за последнюю найденную запись —
    именно там лежат блоки, которые кэш расшифровал неверно и потому потерял.
    Для перемешанного чанка анкеры берутся только из найденных записей.

    Обход чанка останавливается, когда криб перестаёт сходиться: значит решётка
    ушла за конец таблицы. Это же делает функцию безопасной — чужие данные она
    не трогает.

    Возвращает (phases, changes, covered): `changes` — список
    (позиция_блока, старая_фаза, новая), `covered` — сколько записей подтверждено.
    """
    raw = bytes(raw)
    n = len(raw)
    phases = phases.copy()
    changes, covered = [], 0
    nblk = len(phases)

    def take_block(anchors):
        """Решить фазу блока по анкерам; None, если криб не сошёлся."""
        (p0, rid0) = anchors[0]
        want = ((tag << 24) | rid0).to_bytes(4, 'little')
        cur = int(phases[p0 >> 8]) if (p0 >> 8) < nblk else 0xFF
        if cur != 0xFF and _crib_ok(raw, p0, want, cur) and \
                all(_crib_ok(raw, p, ((tag << 24) | r).to_bytes(4, 'little'), cur)
                    for p, r in anchors[1:]):
            return cur, False
        C = _crib_phase(raw, p0, want)
        if C is None:
            return None, False
        for p, r in anchors[1:]:
            if not _crib_ok(raw, p, ((tag << 24) | r).to_bytes(4, 'little'), C):
                return None, False
        return C, True

    for base, recs in sorted(chunks.items()):
        if not recs:
            continue
        inorder = all(rec == base + (rid - 1) * stride for rid, rec in recs.items())
        anchors = [(base + (rid - 1) * stride + tok_off, rid) for rid in sorted(recs)] \
            if not inorder else None
        if anchors is not None:                       # перемешанный чанк: только найденное
            byblk = collections.OrderedDict()
            for p, r in anchors:
                byblk.setdefault(p & ~0xFF, []).append((p, r))
            for _, group in byblk.items():
                C, solved = take_block(group)
                if C is None:
                    continue
                covered += len(group)
                b = group[0][0] >> 8
                if b < nblk and phases[b] != C:
                    changes.append((b << 8, int(phases[b]), C))
                    phases[b] = C
            continue
        k = 0                                         # ровный чанк: идём по решётке
        while k < max_records:
            p = base + k * stride + tok_off
            if p + 4 > n:
                break
            bs = p & ~0xFF
            group, kk = [], k
            while kk < max_records:
                q = base + kk * stride + tok_off
                if (q & ~0xFF) != bs or q + 4 > n:
                    break
                group.append((q, kk + 1))
                kk += 1
            C, _ = take_block(group)
            if C is None:
                break
            covered += len(group)
            b = bs >> 8
            if b < nblk and phases[b] != C:
                changes.append((bs, int(phases[b]), C))
                phases[b] = C
            k = kk
    return phases, changes, covered


def heal_cache(raw_path, blob: bytes, verbose: bool = True, raw_bytes=None):
    """Полный проход лечения кэша: вернуть (новый_blob, список_изменённых_блоков).

    `raw_path` — путь к исходным (зашифрованным) метаданным; если вызывающий уже
    держит их в памяти, он может передать `raw_bytes` и повторного чтения не будет.
    Импорт `il2cpp_tables` отложенный: тот модуль импортирует этот, и обратная
    зависимость на уровне модулей дала бы цикл.
    """
    from il2cpp_tables import Meta, calibrate_heap, TAG_METHOD, METH_STRIDE, METH_TOK

    if raw_bytes is None:
        raw_bytes = open(raw_path, 'rb').read()
    raw = np.frombuffer(raw_bytes, dtype=np.uint8)
    dec = np.frombuffer(blob, dtype=np.uint8)
    if len(raw) != len(dec):
        return blob, []
    phases = phases_from(raw, dec)
    m = Meta(blob, 0)
    m.B = calibrate_heap(m, blob)
    chunks = m.methods()
    phases, changes, covered = heal_by_tokens(raw, phases, chunks,
                                              stride=METH_STRIDE, tok_off=METH_TOK,
                                              tag=TAG_METHOD)
    if verbose:
        sys.stderr.write('[il2cpp_decrypt] крибы токенов: подтверждено %d записей '
                         'MethodDef в %d чанках, фаз исправлено %d\n'
                         % (covered, len(chunks), len(changes)))
    if not changes:
        return blob, []
    out = apply_phases(raw, phases)
    return out.tobytes(), changes


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


def cmd_heal(a: argparse.Namespace) -> int:
    """Долечить кэш дешифровки по крибам токенов MethodDefinition."""
    raw = open(a.meta, 'rb').read()
    if a.cache and os.path.exists(a.cache) and os.path.getsize(a.cache) == len(raw):
        blob = open(a.cache, 'rb').read()
        print('кэш: %s (%d байт)' % (a.cache, len(blob)))
    else:
        arr = np.frombuffer(raw, dtype=np.uint8)
        blob = apply_phases(arr, best_phases(arr)).tobytes()
        print('кэша нет — дешифровано заново (%d байт)' % len(blob))
    out, changes = heal_cache(a.meta, blob, raw_bytes=raw)
    if not changes:
        print('все фазы уже верны, править нечего')
        return 0
    hist = collections.Counter((old, new) for _, old, new in changes)
    print('исправлено блоков: %d' % len(changes))
    for (old, new), c in hist.most_common():
        print('   фаза %s -> %d: блоков %d' % ('0xFF(нет)' if old == 0xFF else old, new, c))
    for bs, old, new in changes[:10]:
        print('   блок 0x%X: %s -> %d' % (bs, '0xFF' if old == 0xFF else old, new))
    if len(changes) > 10:
        print('   ... и ещё %d' % (len(changes) - 10))
    if a.dry_run:
        print('--dry-run: кэш не переписан')
        return 0
    dst = a.out or a.cache
    if not dst:
        print('некуда писать: укажите --out или --cache')
        return 2
    d = os.path.dirname(dst)
    if d and not os.path.isdir(d):
        os.makedirs(d)
    open(dst, 'wb').write(out)
    print('записано: %s (%d байт)' % (dst, len(out)))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("probe", help="find the phase(s) and report what decrypts")
    p.add_argument("meta")
    p.set_defaults(func=cmd_probe)

    p = sub.add_parser("heal", help="re-solve block phases from MethodDef token cribs")
    p.add_argument("meta")
    p.add_argument("--cache", default="work/global-metadata.dec.dat")
    p.add_argument("-o", "--out")
    p.add_argument("--dry-run", action="store_true",
                   help="только показать, какие блоки неверны")
    p.set_defaults(func=cmd_heal)

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
