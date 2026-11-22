#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
il2cpp_tables.py — разбор таблиц глобальных метаданных IL2CPP *после* дешифровки,
для упаковок, где таблицы перемешаны/уплотнены обфускатором.

Зачем это нужно
---------------
Обычные дамперы (Il2CppDumper / Il2CppInspector) читают заголовок global-metadata.dat
и берут смещения таблиц из него. В `com.chaloapps.roosterrudy` (Chicken Gun 6.5.3)
заголовок испорчен намеренно (sanity 0xAF1BB1FA отсутствует в файле и во всех 256
глобальных фазах XOR), поэтому смещения таблиц приходится искать структурно.

Что умеет этот модуль (всё — без заголовка):
  1. Дешифрует файл поблочно (`il2cpp_decrypt.best_phases`) и кэширует результат.
  2. Калибрует базу кучи имён по таблице свойств (единственная таблица, чья
     раскладка совпадает со стандартной).
  3. Находит таблицы по «линейной зависимости» позиция <-> RID токена, работая
     по *всем* байтовым смещениям (записи здесь невыровненные!).
  4. Разбивает каждую таблицу на «чанки» — по одному на сборку; токены внутри
     чанка нумеруются с 1.
  5. Восстанавливает классы: метод -> declaringType -> тип, и печатает состав.

Раскладка, установленная для этой сборки (см. analysis/bot-lifecycle.md)
------------------------------------------------------------------
  MethodDefinition, 30 байт, шаг 30, записи НЕ выровнены:
      +0  u32  индекс типа (returnType; таблица Il2CppType живёт в libil2cpp.so)
      +4  u16  0x0800 (константа, назначение не установлено)
      +6  u16  parameterStart          (0xFFFF, если параметров нет)
      +8  u32  0xFFFFFFFF / 0xFFFF0000 (маркер наличия параметров)
      +12 u32  token = 0x06000000 | (индекс + 1)
      +16 u32  MethodAttributes (биты SpecialName/RTSpecialName переставлены)
      +20 u16  slot                   (0xFFFF = не виртуальный)
      +22 u16  parameterCount
      +24 u32  nameIndex
      +28 u16  declaringType          (ГЛОБАЛЬНЫЙ индекс типа)
    Доказательства: parameterStart[i]+parameterCount[i]==parameterStart[i+1]
    выполняется для 2932 из 2948 соседних пар; slot равен 0xFFFF у 6838 методов
    и <100 у 2168, промежуточных значений нет; у MoveNext flags=0x1E1
    (Private|Final|Virtual|HideBySig|NewSlot) — ровно то, что выдаёт Roslyn.

  TypeDefinition, 76 байт, шаг 76:
      +0  u32  namespaceIndex
      +68 u32  token = 0x02000000 | (индекс + 1)
      +72 u32  nameIndex          <-- имя перенесено в конец записи
    (methodStart/method_count в этой упаковке не локализованы — не нужны:
     принадлежность методу определяется полем declaringType.)

  PropertyDefinition, 20 байт — стандартная:
      +0 nameIndex, +4 get, +8 set, +12 attrs, +16 token = 0x17000000 | rid

Использование
-------------
  python tools/il2cpp_tables.py layout  <meta>
  python tools/il2cpp_tables.py chunks  <meta> [--min 300]
  python tools/il2cpp_tables.py class   <meta> --name BotController [--methods] [--fields]
  python tools/il2cpp_tables.py method  <meta> --name CheckIsSpawnedBot
  python tools/il2cpp_tables.py grep    <meta> --regex 'Bot' [--assembly N]
  python tools/il2cpp_tables.py dump    <meta> -o analysis/classes.txt

Все команды принимают --cache (по умолчанию work/global-metadata.dec.dat):
если кэш существует и совпадает по размеру с исходником, дешифровка пропускается.
"""

import argparse
import collections
import os
import re
import struct
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from il2cpp_decrypt import best_phases, apply_phases  # noqa: E402

IDENT = re.compile(rb'^[A-Za-z_<>.`$@][A-Za-z0-9_<>.`$@]*$')

# ---- раскладки этой упаковки -------------------------------------------------
METH_STRIDE, METH_TOK, METH_NAME, METH_DECL = 30, 12, 24, 28
TYPE_STRIDE, TYPE_TOK, TYPE_NAME, TYPE_NS = 76, 68, 72, 0
PROP_STRIDE, PROP_TOK, PROP_NAME = 20, 16, 0
TAG_METHOD, TAG_TYPE, TAG_PROP, TAG_FIELD = 0x06, 0x02, 0x17, 0x04


# ----------------------------------------------------------------------------
class Meta(object):
    """Расшифрованные метаданные + найденные таблицы."""

    def __init__(self, blob, heap_base):
        self._nc = {}
        self.b = blob
        self.n = len(blob)
        self.B = heap_base
        a = np.frombuffer(blob, dtype=np.uint8).astype(np.uint32)
        n = self.n
        # u32 на КАЖДОМ байтовом смещении: записи здесь невыровненные
        self.U = a[0:n - 3] | (a[1:n - 2] << 8) | (a[2:n - 1] << 16) | (a[3:n] << 24)

    # -- куча имён ----------------------------------------------------------
    def name(self, idx):
        """Имя по индексу кучи; None, если индекс не указывает на начало строки."""
        if idx is None or idx < 0 or idx >= 3000000:
            return None
        if idx in self._nc:
            return self._nc[idx]
        q = self.B + idx
        if q < 1 or q >= self.n or self.b[q - 1:q] != b'\x00':
            return None
        e = self.b.find(b'\x00', q, min(q + 200, self.n))
        if e < 0:
            return None
        t = self.b[q:e]
        res = t.decode('utf8', 'replace') if IDENT.match(t) else None
        self._nc[idx] = res
        return res

    def name_index(self, s):
        """Индекс кучи для строки s (первое вхождение), либо None."""
        p = self.b.find(s.encode() + b'\x00')
        return p - self.B if p >= 0 else None

    def u32(self, p, off=0):
        return struct.unpack_from('<I', self.b, p + off)[0]

    def u16(self, p, off=0):
        return struct.unpack_from('<H', self.b, p + off)[0]

    # -- поиск чанков -------------------------------------------------------
    def chunks(self, tag, stride, tok_off, name_off, max_rid, tol_blocks=64):
        """
        Возвращает список чанков: (base, {rid: record_pos}).

        Таблицы в этой упаковке разорваны на фрагменты (по одному на сборку),
        а внутри фрагмента запись с rid=k всегда лежит на base + (k-1)*stride.
        Поэтому base = позиция_токена - tok_off - (rid-1)*stride одинаков для
        всех записей чанка, и чанки находятся простой кластеризацией base.

        Требование «rid+1 стоит ровно через stride» здесь НЕ используется:
        оно рвёт чанк на куски в первом же месте, где одна запись не
        дешифровалась/не распозналась. Вместо этого сначала отбираются записи
        с читаемым именем — это отсекает случайные совпадения байтов.
        """
        m = (self.U & np.uint32(0xFF000000)) == np.uint32(tag << 24)
        pos = np.nonzero(m)[0]
        rid = (self.U[pos] & np.uint32(0x00FFFFFF)).astype(np.int64)
        keep = (rid >= 1) & (rid <= max_rid)
        pos, rid = pos[keep].tolist(), rid[keep].tolist()

        by_base = collections.defaultdict(dict)
        for p, r in zip(pos, rid):
            rec = p - tok_off
            if rec < 0 or rec + stride > self.n:
                continue
            nm = self.name(self.u32(rec, name_off))
            if not nm:
                continue
            base = rec - (r - 1) * stride
            by_base[base].setdefault(r, rec)

        # кластеризуем близкие base: разрыв в несколько записей — это дырки
        # в распознавании, а не граница чанка
        keys = sorted(by_base)
        groups, cur = [], []
        for k in keys:
            if cur and k - cur[-1] <= stride * tol_blocks:
                cur.append(k)
            else:
                if cur:
                    groups.append(cur)
                cur = [k]
        if cur:
            groups.append(cur)

        out = []
        for g in groups:
            merged = {}
            for k in g:
                for r, rec in by_base[k].items():
                    merged.setdefault(r, rec)
            # база чанка = медианная (устойчива к дыркам)
            base = sorted(g, key=lambda k: -len(by_base[k]))[0]
            out.append((base, merged))
        out.sort(key=lambda t: t[1] and min(t[1].values()))
        return out

    # -- высокоуровневые выборки -------------------------------------------
    def methods(self):
        """{global_chunk_base: {rid: record}} — все методы всех сборок."""
        # chunks() уже вернул позиции НАЧАЛА записи (rec = pos_токена - tok_off)
        return dict(self.chunks(TAG_METHOD, METH_STRIDE, METH_TOK,
                                METH_NAME, 0x80000))

    def types(self):
        return dict(self.chunks(TAG_TYPE, TYPE_STRIDE, TYPE_TOK,
                                TYPE_NAME, 0x20000))

    def properties(self):
        return dict(self.chunks(TAG_PROP, PROP_STRIDE, PROP_TOK,
                                PROP_NAME, 0x40000))


# ----------------------------------------------------------------------------
def load(path, cache):
    """Дешифрует (или берёт кэш) и калибрует базу кучи по таблице свойств."""
    raw = open(path, 'rb').read()
    if cache and os.path.exists(cache) and os.path.getsize(cache) == len(raw):
        blob = open(cache, 'rb').read()
        src = '%s (кэш)' % cache
    else:
        phases = best_phases(raw)
        blob = apply_phases(raw, phases)
        src = 'дешифровано (%d блоков)' % len(raw)
        if cache:
            d = os.path.dirname(cache)
            if d and not os.path.isdir(d):
                os.makedirs(d)
            open(cache, 'wb').write(blob)
            src += ' -> %s' % cache
    m = Meta(blob, 0)
    base = calibrate_heap(m, blob)
    m.B = base
    sys.stderr.write('[il2cpp_tables] %s; база кучи = 0x%X\n' % (src, base))
    return m


def calibrate_heap(m, blob):
    """
    База кучи = B такое, что B + nameIndex указывает на начало строки.
    Калибруем по таблице свойств: её раскладка стандартная, а токены 0x17xxxxxx
    ищутся перебором. Берём первое длинное совпадение.
    """
    a = m.U
    hits = np.nonzero((a & np.uint32(0xFF000000)) == np.uint32(TAG_PROP << 24))[0]
    cands = hits[:4000].tolist()
    best = (0, 0)
    for B in range(0xA0000, 0xE0000, 2):
        score = 0
        for p in cands[:300]:
            rec = p - PROP_TOK
            if rec < 0:
                continue
            idx = struct.unpack_from('<I', blob, rec)[0]
            q = B + idx
            if 0 < q < len(blob) - 2 and blob[q - 1:q] == b'\x00':
                e = blob.find(b'\x00', q, min(q + 160, len(blob)))
                if e > q and IDENT.match(blob[q:e]):
                    score += 1
        if score > best[0]:
            best = (score, B)
        if score >= 300:
            break
    if best[0] < 30:
        raise SystemExit('не удалось откалибровать базу кучи (лучший счёт %d)' % best[0])
    return best[1]


# ----------------------------------------------------------------------------
SM_RE = re.compile(r'^<.*>d__\d+$')          # state machine корутины
DC_RE = re.compile(r'^<>c')                  # <>c / <>c__DisplayClass...


def group_methods(m, meth_chunk):
    """{declaringType: [(rid, record), ...]} для чанка методов."""
    by_dt = collections.defaultdict(list)
    for rid, rec in sorted(meth_chunk.items()):
        by_dt[m.u16(rec, METH_DECL)].append((rid, rec))
    return by_dt


def guess_offset(by_dt, trids, sample=200):
    """
    Грубая оценка OFF (globalTypeIndex = OFF + rid) по гистограмме разностей.

    Для истинной пары (чанк методов, чанк типов) разность dt - trid одинакова
    у большинства совпадений, поэтому мода гистограммы и есть OFF.
    Обе стороны прореживаются — оценка от этого не страдает.
    """
    dts = sorted(by_dt)
    if not dts or not trids:
        return None
    s1 = max(1, len(dts) // sample)
    s2 = max(1, len(trids) // sample)
    c = collections.Counter()
    for dt in dts[::s1]:
        for trid in trids[::s2]:
            c[dt - trid] += 1
    return c.most_common(1)[0][0] if c else None


def score_offset(m, by_dt, type_chunk, off):
    """
    Точность сопоставления при данном OFF (0..1) по compiler-generated типам:
      * у '<X>d__N' обязан быть MoveNext;
      * у '<>c...' — только '.ctor'/'.cctor' и '<...>b__...'.
    Возвращает (доля, число проверенных типов).
    """
    good = tot = 0
    for trid, trec in type_chunk.items():
        name = m.name(m.u32(trec, TYPE_NAME))
        if not name:
            continue
        is_sm = bool(SM_RE.match(name))
        if not is_sm and not DC_RE.match(name):
            continue
        ms = by_dt.get(off + trid)
        if ms is None:
            continue
        names = {m.name(m.u32(r, METH_NAME)) for _, r in ms}
        if not names:
            continue
        tot += 1
        if is_sm:
            good += 'MoveNext' in names
        else:
            good += all(x in ('.ctor', '.cctor') or x.startswith('<')
                        for x in names if x)
    return (good / float(tot) if tot else 0.0), tot


def pair_assembly(m, meth_chunk, type_chunk, window=24, by_dt=None):
    """
    Связывает чанк методов с чанком типов одной сборки.

    declaringType у метода — ГЛОБАЛЬНЫЙ индекс типа, а rid типа — локальный
    внутри чанка, поэтому  globalIndex = OFF + rid.  OFF сначала угадывается
    по моде гистограммы разностей (guess_offset), затем уточняется перебором
    ±window по достоверности compiler-generated имён (score_offset).
    """
    if by_dt is None:
        by_dt = group_methods(m, meth_chunk)
    if not by_dt or not type_chunk:
        return None, 0.0, by_dt
    trids = sorted(type_chunk)
    dts = sorted(by_dt)
    # Дешёвые фильтры до гистограммы:
    #  * разброс declaringType примерно равен разбросу rid типов своей сборки
    #    (в обеих нумерациях типы идут подряд, просто со сдвигом OFF);
    #  * различных declaringType не может быть больше, чем типов в сборке.
    span_t = trids[-1] - trids[0]
    span_d = dts[-1] - dts[0]
    if abs(span_d - span_t) > max(64, span_t // 6):
        return None, 0.0, by_dt
    if len(by_dt) > len(type_chunk) * 1.25:
        return None, 0.0, by_dt
    off0 = guess_offset(by_dt, trids)
    if off0 is None:
        return None, 0.0, by_dt
    best, best_off = -1.0, None
    for off in range(off0 - window, off0 + window + 1):
        sc, tot = score_offset(m, by_dt, type_chunk, off)
        if tot >= 8 and sc > best:
            best, best_off = sc, off
    if best_off is None:
        sc, tot = score_offset(m, by_dt, type_chunk, off0)
        if tot >= 3 and sc >= 0.5:
            best, best_off = sc, off0
    return best_off, best, by_dt


def class_name(m, trec):
    ns = m.name(m.u32(trec, TYPE_NS)) or ''
    nm = m.name(m.u32(trec, TYPE_NAME)) or '?'
    return (ns + '.' + nm) if ns else nm


def find_type(m, tchunks, wanted):
    """Все типы с таким именем: [(chunk_base, rid, record, full_name)]."""
    out = []
    for cb, chunk in tchunks.items():
        for rid, rec in sorted(chunk.items()):
            if m.name(m.u32(rec, TYPE_NAME)) == wanted:
                out.append((cb, rid, rec, class_name(m, rec)))
    return out


def fmt_method(m, rid, rec):
    ps = m.u16(rec, 6)
    return ('rid=%-6d %-46s type=%-6d params=%-2d slot=%-5d flags=0x%-6X typeIdx=%d'
            % (rid, (m.name(m.u32(rec, METH_NAME)) or '?')[:46],
               m.u16(rec, METH_DECL), m.u16(rec, 22),
               m.u16(rec, 20), m.u32(rec, 16), m.u32(rec, 0)))


# ----------------------------------------------------------------------------
def cmd_layout(m, args):
    print('Раскладка записей, установленная для этой упаковки:')
    print('  MethodDefinition  шаг %2d  token@+%-2d nameIndex@+%-2d declaringType@+%d(u16)'
          % (METH_STRIDE, METH_TOK, METH_NAME, METH_DECL))
    print('                      parameterStart@+6(u16) parameterCount@+22(u16) slot@+20(u16)')
    print('  TypeDefinition    шаг %2d  token@+%-2d nameIndex@+%-2d namespaceIndex@+%d'
          % (TYPE_STRIDE, TYPE_TOK, TYPE_NAME, TYPE_NS))
    print('  PropertyDefinition шаг %2d token@+%-2d nameIndex@+%-2d'
          % (PROP_STRIDE, PROP_TOK, PROP_NAME))
    print('  база кучи имён: 0x%X' % m.B)
    for label, fn, cap in (('методов', m.methods, 0x80000),
                           ('типов', m.types, 0x20000),
                           ('свойств', m.properties, 0x40000)):
        ch = fn()
        total = sum(len(v) for v in ch.values())
        print('  таблиц %-10s: %3d чанков, %7d записей' % (label, len(ch), total))


def cmd_chunks(m, args):
    for label, ch, kind in (('МЕТОДЫ', m.methods(), 'm'),
                            ('ТИПЫ', m.types(), 't')):
        print('\n=== чанки: %s ===' % label)
        rows = sorted(ch.items(), key=lambda kv: -len(kv[1]))
        for base, items in rows:
            if len(items) < args.min:
                continue
            rids = sorted(items)
            first = items[rids[0]]
            if kind == 't':
                label2 = class_name(m, first)
            else:
                label2 = m.name(m.u32(first, METH_NAME)) or '?'
            print('  base=0x%08X записей=%-6d rid %d..%-7d 0x%08X..0x%08X  первый: %s'
                  % (base, len(items), rids[0], rids[-1],
                     items[rids[0]], items[rids[-1]], label2[:48]))


def method_index(m, mch):
    """Предвычисление: для каждого чанка методов — диапазон declaringType и
    группировка {declaringType: [(rid, rec), ...]}."""
    idx = []
    for mb, chunk in sorted(mch.items()):
        by_dt = group_methods(m, chunk)
        dts = sorted(by_dt)
        idx.append({'base': mb, 'chunk': chunk, 'by_dt': by_dt,
                    'lo': dts[0], 'hi': dts[-1], 'n': len(chunk)})
    idx.sort(key=lambda d: -d['n'])
    return idx


def cmd_class(m, args):
    tch = m.types()
    mch = m.methods()
    hits = find_type(m, tch, args.name)
    if not hits:
        print('тип %r не найден' % args.name)
        return 1
    mi_all = method_index(m, mch)
    for cb, rid, rec, full in hits:
        print('\n=== %s   (чанк типов 0x%X, rid=%d, запись 0x%X, token=0x%08X)'
              % (full, cb, rid, rec, m.u32(rec, TYPE_TOK)))
        types = tch[cb]
        best = None
        for mi in mi_all:
            off, score, _ = pair_assembly(m, mi['chunk'], types, by_dt=mi['by_dt'])
            if off is None:
                continue
            # приоритет: чанк, где у типа реально есть методы, затем — счёт
            key = ((rid + off) in mi['by_dt'], score)
            if best is None or key > best[0]:
                best = (key, mi, off, score)
        if not best:
            print('   чанк методов не сопоставлен')
            continue
        _, mi, off, score = best
        ms = mi['by_dt'].get(rid + off, [])
        print('   чанк методов 0x%X; globalTypeIndex = OFF(%d) + rid(%d) = %d'
              ' (достоверность %.2f); методов: %d'
              % (mi['base'], off, rid, rid + off, score, len(ms)))
        if args.methods:
            for r, rec2 in ms:
                print('     ' + fmt_method(m, r, rec2))


def cmd_method(m, args):
    mch = m.methods()
    idx = m.name_index(args.name)
    print('индекс кучи для %r: %s' % (args.name, idx))
    found = 0
    for base, chunk in sorted(mch.items()):
        for rid, rec in sorted(chunk.items()):
            if m.name(m.u32(rec, METH_NAME)) == args.name:
                print('  чанк 0x%08X  %s' % (base, fmt_method(m, rid, rec)))
                found += 1
    if not found:
        print('  не найдено ни одной записи')
    return 0 if found else 1


def cmd_grep(m, args):
    rx = re.compile(args.regex, re.I if args.i else 0)
    n = 0
    for base, chunk in sorted(m.methods().items()):
        for rid, rec in sorted(chunk.items()):
            nm = m.name(m.u32(rec, METH_NAME))
            if nm and rx.search(nm):
                print('  0x%08X %s' % (base, fmt_method(m, rid, rec)))
                n += 1
                if args.limit and n >= args.limit:
                    return 0
    print('всего: %d' % n)
    return 0


def cmd_dump(m, args):
    """
    Полный дамп: все типы и все методы, сгруппированные по чанкам (= по сборкам).
    Для каждого чанка типов подбирается соответствующий чанк методов и печатается
    OFF, так что globalTypeIndex = OFF + rid, и метод принадлежит типу, если
    его declaringType == globalTypeIndex.
    """
    tch, mch = m.types(), m.methods()
    mi_all = method_index(m, mch)
    pairs = []
    for i, (cb, types) in enumerate(sorted(tch.items(), key=lambda kv: -len(kv[1]))):
        best = None
        for mi in mi_all:
            off, score, _ = pair_assembly(m, mi['chunk'], types, by_dt=mi['by_dt'])
            if off is not None and (best is None or score > best[2]):
                best = (mi, off, score)
        pairs.append((cb, types, best))
        sys.stderr.write('\rчанки типов: %d/%d' % (i + 1, len(tch)))
    sys.stderr.write('\n')

    n_t = n_m = 0
    with open(args.o, 'w') as f:
        f.write('# globalTypeIndex = OFF + rid;  метод принадлежит типу, если '
                'declaringType == globalTypeIndex\n')
        for cb, types, best in pairs:
            mi, off, score = best if best else ({'base': 0, 'by_dt': {}}, 0, 0.0)
            f.write('\n### ЧАНК ТИПОВ 0x%08X (%d записей) <-> чанк методов 0x%08X, '
                    'OFF=%s, достоверность %.2f\n'
                    % (cb, len(types), mi['base'], off, score))
            by_dt = mi['by_dt']
            for rid, rec in sorted(types.items()):
                gi = (off + rid) if off is not None else -1
                f.write('TYPE rid=%-6d 0x%08X globalIdx=%-6d %s\n'
                        % (rid, rec, gi, class_name(m, rec)))
                n_t += 1
                for rid2, rec2 in by_dt.get(gi, []):
                    f.write('    ' + fmt_method(m, rid2, rec2) + '\n')
                    n_m += 1
    print('записано %s: %d типов, %d методов' % (args.o, n_t, n_m))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('metadata')
    ap.add_argument('--cache', default='work/global-metadata.dec.dat')
    sub = ap.add_subparsers(dest='cmd', required=True)

    sub.add_parser('layout')
    p = sub.add_parser('chunks')
    p.add_argument('--min', type=int, default=300)
    p = sub.add_parser('class')
    p.add_argument('--name', required=True)
    p.add_argument('--methods', action='store_true')
    p = sub.add_parser('method')
    p.add_argument('--name', required=True)
    p = sub.add_parser('grep')
    p.add_argument('--regex', required=True)
    p.add_argument('-i', action='store_true')
    p.add_argument('--limit', type=int, default=0)
    p = sub.add_parser('dump')
    p.add_argument('-o', required=True)

    args = ap.parse_args()
    m = load(args.metadata, args.cache)
    fn = {'layout': cmd_layout, 'chunks': cmd_chunks, 'class': cmd_class,
          'method': cmd_method, 'grep': cmd_grep, 'dump': cmd_dump}[args.cmd]
    return fn(m, args) or 0


if __name__ == '__main__':
    sys.exit(main())
