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
from il2cpp_decrypt import best_phases, apply_phases, heal_cache  # noqa: E402

IDENT = re.compile(rb'^[A-Za-z_<>.`$@][A-Za-z0-9_<>.`$@]*$')

# ---- раскладки этой упаковки -------------------------------------------------
METH_STRIDE, METH_TOK, METH_NAME, METH_DECL = 30, 12, 24, 28
TYPE_STRIDE, TYPE_TOK, TYPE_NAME, TYPE_NS = 76, 68, 72, 0
PROP_STRIDE, PROP_TOK, PROP_NAME = 20, 16, 0
PROP_GET, PROP_SET, PROP_ATTRS = 4, 8, 12
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

    def raw_name(self, idx):
        """Имя по индексу кучи БЕЗ проверки на идентификатор.

        `name()` отбраковывает строки, не похожие на идентификатор C#, и из-за этого
        теряются легальные имена с `=` и цифрами — например сгенерированные Roslyn
        типы `__StaticArrayInitTypeSize=20/24/72` (хвост таблицы TypeDefinition
        игровой сборки). Здесь принимается любая NUL-терминированная печатная
        ASCII-строка длиной >= 2.
        """
        if idx is None or idx < 0 or idx >= 3000000:
            return None
        q = self.B + idx
        if q < 1 or q >= self.n or self.b[q - 1:q] != b'\x00':
            return None
        e = self.b.find(b'\x00', q, min(q + 200, self.n))
        # минимум один символ: в обфусцированном коде легальны однобуквенные имена
        # типов (rid 1392 игровой сборки — это тип `F`, рядом `G` и `H`), а от мусора
        # защищают проверка на NUL-границу и требование печатного ASCII
        if e < 0 or e - q < 1:
            return None
        t = self.b[q:e]
        if not all(32 <= c < 127 for c in t):
            return None
        return t.decode('ascii')

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
    """Дешифрует (или берёт кэш), долечивает фазы по крибам и калибрует базу кучи.

    Лечение (`il2cpp_decrypt.heal_cache`) прогоняется всегда, в том числе на
    готовом кэше: он переписывается, только если нашлись блоки с неверной фазой.
    """
    raw = open(path, 'rb').read()
    if cache and os.path.exists(cache) and os.path.getsize(cache) == len(raw):
        blob = open(cache, 'rb').read()
        src = '%s (кэш)' % cache
    else:
        # best_phases/apply_phases работают с ndarray: на bytes у них .reshape нет
        arr = np.frombuffer(raw, dtype=np.uint8)
        blob = apply_phases(arr, best_phases(arr)).tobytes()
        src = 'дешифровано (%d блоков)' % len(raw)
    blob, healed = heal_cache(path, blob, raw_bytes=raw)
    if healed:
        src += ', долечено блоков: %d' % len(healed)
    if cache and (healed or not os.path.exists(cache)
                  or os.path.getsize(cache) != len(raw)):
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


def extend_type_chunk(m, chunk, base, stride=TYPE_STRIDE, tok_off=TYPE_TOK,
                      max_rid=4000, tag=TAG_TYPE):
    """Дочитать с решётки записи TypeDef, которые `chunks()` отбраковал по имени.

    `chunks()` принимает запись, только если `name()` вернул идентификатор C#.
    Из-за этого в хвосте игровой сборки теряются легальные типы, чьи имена содержат
    `=` и цифры: `__StaticArrayInitTypeSize=20/24/72` (rid 1493/1496/1497).
    Функция идёт по решётке `base + (i-1)*stride`, берёт записи с тегом токена 0x02
    и читает имя через `raw_name()`; результат сливается с `chunk` (по token rid).

    Возвращает (новый_chunk, список_найденных_rid).
    """
    out = dict(chunk)
    added = []
    for i in range(1, max_rid + 1):
        rec = base + (i - 1) * stride
        tok = m.u32(rec, tok_off)
        if tok >> 24 != tag:
            continue
        rid = tok & 0xFFFFFF
        if rid in out or not (1 <= rid <= max_rid):
            continue
        if m.raw_name(m.u32(rec, TYPE_NAME)):
            out[rid] = rec
            added.append(rid)
    return out, sorted(added)


def lattice_types(m, base, stride=TYPE_STRIDE, tok_off=TYPE_TOK, max_rid=4000,
                  tag=TAG_TYPE):
    """Восстановить чанк TypeDefinition обходом решётки от `base`.

    `chunks()` выводит базу каждой записи как `rec - (rid-1)*stride` и группирует по
    ней. На перемешанных чанках (а они перемешаны: в игровом `0xADF964` = rid 1494,
    следующая `0xADF9B0` = rid 1493; в чанке Photon rid идёт 1..17, затем 16..22,
    19..26, 24..48) такой вывод даёт разные базы для соседних записей и дробит один
    чанк на десятки «чанков». Обход решётки этого не делает: он идёт подряд с шагом
    `stride` и читает rid из токена.

    Граница чанка определяется без имён: обрыв, когда тег токена не тот, rid вне
    диапазона, либо rid уже встречался (значит начался следующий чанк — там
    нумерация restart-ует с 1). Записи с нечитаемым именем в результат входят
    (например rid 62 чанка Photon и rid 1495 игрового: у обоих `nameIndex = 42`,
    то есть индекс до начала кучи строк, — маркер затёртого имени).

    Возвращает {rid: позиция_записи}.
    """
    out = {}
    pos = base
    while pos + stride <= m.n:
        tok = m.u32(pos, tok_off)
        if tok >> 24 != tag:
            break
        rid = tok & 0xFFFFFF
        if not 1 <= rid <= max_rid or rid in out:
            break
        out[rid] = pos
        pos += stride
    return out


def lattice_methods(m, base, stride=METH_STRIDE, tok_off=METH_TOK, max_rid=200000,
                    tag=TAG_METHOD):
    """Восстановить чанк MethodDefinition обходом решётки от `base`.

    То же, что `lattice_types()`, но для методов: rids внутри чанка MethodDef идут
    подряд (в чанке игровой сборки rid 1 на базе, в чанке Photon — тоже), поэтому
    граница определяется повтором rid либо невалидным токеном. Возвращает
    {rid: позиция_записи}.
    """
    out = {}
    pos = base
    while pos + stride <= m.n:
        tok = m.u32(pos, tok_off)
        if tok >> 24 != tag:
            break
        rid = tok & 0xFFFFFF
        if not 1 <= rid <= max_rid or rid in out:
            break
        out[rid] = pos
        pos += stride
    return out


def type_positions(chunk):
    """Перенумеровать чанк TypeDef ПО ПОРЯДКУ ХРАНЕНИЯ записей.

    Это главное открытие по связкам: `MethodDefinition.declaringType` — ГЛОБАЛЬНЫЙ
    ИНДЕКС типа, а индекс в IL2CPP — это порядковый номер записи в таблице, а не
    rid из её токена. В этом файле записи TypeDefinition переставлены: у 713 из
    1498 записей игровой сборки rid в токене не равен порядковому номеру
    (смещения от −2 до +27, локальные циклы вроде rid 2→позиция 4→rid 3→позиция 2).
    Перестановка локальная, поэтому база чанка определена верно, а вот полю token
    доверять нельзя.

    Проверено механически на 410 машинно-проверяемых типах (итераторы `<X>d__N`,
    `<>c__DisplayClass*`, `<>c`): связка «индекс = позиция хранения, OFF = 3401»
    даёт 410/410 согласованных назначений, а «индекс = rid токена, OFF = 3400» —
    только 276/410. Для сборки Photon: позиция+15832 даёт 8/8, токен+15831 — 7/8.
    Пример: `BombMonster` владеет DieR/Explode/DamageInRadius, `BotAnimEvents` —
    AttackEvent/AttackEnd/PlayDieSound/ShootProjectile, `BotBodyPartDmgReceiver` —
    Damage; при индексации по токену все три сдвигаются на соседние типы.

    Возвращает (by_pos, tokens): `by_pos` {k: rec} с k от 1 в порядке хранения,
    `tokens` {k: rid_из_токена}.
    """
    order = sorted(chunk.items(), key=lambda kv: kv[1])
    by_pos, tokens = {}, {}
    for k, (rid, rec) in enumerate(order, 1):
        by_pos[k] = rec
        tokens[k] = rid
    return by_pos, tokens


_ITER_CORE = {'MoveNext', '.ctor', 'SetStateMachine', 'System.IDisposable.Dispose',
              'System.Collections.Generic.IEnumerator<System.Object>.get_Current',
              'System.Collections.IEnumerator.Reset',
              'System.Collections.IEnumerator.get_Current'}


def _iter_like(names):
    """Похож ли набор имён на компиляторный итератор `<X>d__N`."""
    if not names or 'MoveNext' not in names:
        return False
    for n in names:
        if n in _ITER_CORE or n.startswith('<>m__Finally') \
                or n.startswith('System.Collections.IEnumerable') \
                or n.startswith('System.Collections.Generic.IEnumerable'):
            continue
        return False
    return True


def _lambda_like(names):
    """Похож ли набор на `<>c` / `<>c__DisplayClass*`: только конструкторы и лямбды."""
    return bool(names) and all(n in ('.ctor', '.cctor') or 'b__' in n for n in names)


def solve_type_off(m, types_idx, methods, offs, name_off=TYPE_NAME,
                   decl_off=METH_DECL, name_off_m=METH_NAME):
    """Подобрать OFF связки `declaringType = OFF + индекс_типа` без ручного угадывания.

    Индексом может быть и rid из токена, и порядковый номер записи — вызывающий
    сам решает, какой словарь передать в `types_idx`. Оценка чисто механическая:
    берутся типы, чьё имя обязывает набор методов (итераторы `<X>d__N` и
    лямбда-классы `<>c`/`<>c__DisplayClass*`), и проверяется, совпал ли набор.
    Возвращает (лучший_OFF, {OFF: (совпало, всего)}).
    """
    groups = collections.defaultdict(set)
    for rec in methods.values():
        nm = m.raw_name(m.u32(rec, name_off_m))
        if nm:
            groups[m.u16(rec, decl_off)].add(nm)
    scored = {}
    for off in offs:
        ok = tot = 0
        for idx, trec in types_idx.items():
            nm = m.raw_name(m.u32(trec, name_off))
            if not nm:
                continue
            ms = groups.get(off + idx)
            if ITER_NAME.match(nm):
                tot += 1
                ok += 1 if _iter_like(ms) else 0
            elif LAMBDA_NAME.match(nm):
                tot += 1
                ok += 1 if _lambda_like(ms) else 0
        scored[off] = (ok, tot)
    best = max(scored, key=lambda o: (scored[o][0], -abs(o)))
    return best, scored


ITER_NAME = re.compile(r'^<.*>d__\d+$')
LAMBDA_NAME = re.compile(r'^<>c(__DisplayClass\d+_\d+)?(__\d+)?$')


def infer_base_classes(m, types_by_pos, methods, off, min_links=2,
                       flags_off=16, slot_off=20, decl_off=METH_DECL,
                       name_off=METH_NAME):
    """Частично восстановить иерархию: кто кого переопределяет.

    `parentIndex`/`nestedTypes`/`interfaces` в этом файле не читаются, но vtable
    остаётся: у виртуального метода есть колонка `slot`, и переопределение несёт тот
    же slot, что и объявление виртуала у предка, при том же имени. Объявление
    отличается флагом NewSlot (0x100), переопределение — его отсутствием.

    Совпадение по одному (имя, slot) ненадёжно: слоты коллизят на коротких именах
    (`Damage`, `Heal`, `Update`) у несвязанных типов — на игровой сборке это даёт 500
    пар, среди которых `AdsCanvas : <MoveObjectsContinuously>d__10`. Требование
    `min_links = 2` совпавших виртуалов оставляет 23 пары, и у каждого потомка
    кандидат ровно один. Все 23 выглядят правдоподобно (`JSONLazyCreator : JSONNode`
    — 13 виртуалов, `CarController : Vehicle` — 9, `HoverMotor : Motor` — 2), но это
    эвристика: печатать её надо как предположение, а не как факт, и в пересобранную
    метадату (`parentIndex`) она не пишется.

    Возвращает {индекс_потомка: (индекс_предка, [(имя, slot), ...])}.
    """
    decl, over = collections.defaultdict(list), collections.defaultdict(list)
    for rec in methods.values():
        nm = m.raw_name(m.u32(rec, name_off))
        if not nm:
            continue
        flags = m.u32(rec, flags_off)
        slot = m.u16(rec, slot_off)
        if slot == 0xFFFF or not (flags & 0x40):        # 0x40 = Virtual
            continue
        k = m.u16(rec, decl_off) - off
        if k not in types_by_pos:
            continue
        (decl if (flags & 0x100) else over)[(nm, slot)].append(k)   # 0x100 = NewSlot
    pairs = collections.Counter()
    which = collections.defaultdict(list)
    for key, descs in over.items():
        if key not in decl:
            continue
        for d in descs:
            for b in decl[key]:
                if d != b:
                    pairs[(d, b)] += 1
                    which[(d, b)].append(key)
    out = {}
    for (d, b), c in pairs.items():
        if c < min_links or d in out:
            continue
        out[d] = (b, sorted(which[(d, b)]))
    return out


def accessor_names(pname):
    """Возможные имена get/set-аксессоров для свойства pname.

    Обычное свойство `Foo` даёт `get_Foo`/`set_Foo`. Явная реализация интерфейса
    в метаданных хранится под полным именем — свойство
    `System.Collections.IEnumerator.Current` обслуживается методом
    `System.Collections.IEnumerator.get_Current` (в игровой сборке таких 375).
    """
    g = {'get_' + pname}
    s = {'set_' + pname}
    if '.' in pname:
        iface, short = pname.rsplit('.', 1)
        g.add(iface + '.get_' + short)
        s.add(iface + '.set_' + short)
    return g, s


def resolve_property_owners(m, methods, props):
    """Привязать записи PropertyDef к типам-владельцам.

    В PropertyDef нет поля «владелец»: в оригинале принадлежность типу задаётся
    диапазоном TypeDef.propertyStart/property_count, а эти поля в данном файле не
    читаются. Зато у свойства есть get/set — смещения аксессоров ОТНОСИТЕЛЬНО
    первого метода владельца. Отсюда правила.

    Проход 1 — точное смещение: у типа dt есть метод с именем `get_<имя>` (или
    явной реализацией интерфейса `<интерфейс>.get_X`) ровно по адресу
    first_method[dt] + get. Кандидатов часто несколько (`get_Current`, `get_Item`
    есть у десятков типов), поэтому выбор делается ПОРЯДКОМ rid свойств: они идут
    сплошными диапазонами по типам (94 из 98 проверенных владельцев — непрерывный
    диапазон, 4 нарушения монотонности на 248). Проход по возрастанию rid требует
    неубывающей позиции владельца и предпочитает предыдущего владельца.

    Проход 2 — мягкое правило, для свойств, у которых смещение «съехало» (так
    ведёт себя, например, SimpleJSON). Кандидат принимается, только если:
      * метод с именем аксессора у этого типа существует;
      * get < числа методов типа (смещение влезает в его блок);
      * тип лежит в окне между ближайшими привязанными соседями по rid;
      * найденный аксессор ещё не занят другим свойством этого типа — иначе
        получилось бы два одноимённых свойства у одного класса, чего C# не
        допускает (кроме индексаторов `Item`, у которых аксессоры разные).
    Принимается единственный кандидат; иначе свойство остаётся непривязанным.

    Возвращает (owners, unresolved, stats):
      owners     {prop_rid: {'dt': globalTypeIdx, 'get': method_rid|None,
                             'set': method_rid|None, 'how': 'смещение'|'имя'}}
      unresolved [prop_rid, ...]  — без владельца
      stats      Counter со счётчиками способов и отказов
    """
    import collections as _c
    mname = {r: m.name(m.u32(rec, METH_NAME)) for r, rec in methods.items()}
    decl = {r: m.u16(rec, METH_DECL) for r, rec in methods.items()}
    first, count = {}, _c.Counter()
    for r in sorted(methods):
        first.setdefault(decl[r], r)
        count[decl[r]] += 1
    byname = _c.defaultdict(list)
    for r, n in mname.items():
        if n:
            byname[n].append(r)
    order = sorted(first, key=lambda d: first[d])
    pos = {dt: i for i, dt in enumerate(order)}

    # кандидаты: точные (по смещению) и все совпадения по имени аксессора
    exact = {}
    gacc, sacc = _c.defaultdict(dict), _c.defaultdict(dict)
    for prid, prec in sorted(props.items()):
        pname = m.name(m.u32(prec, PROP_NAME))
        if not pname:
            continue
        g, s = m.u32(prec, PROP_GET), m.u32(prec, PROP_SET)
        gn, sn = accessor_names(pname)
        ex = set()
        for off, names, store in ((g, gn, gacc), (s, sn, sacc)):
            for want in names:
                for r in byname.get(want, ()):
                    dt = decl[r]
                    store[prid].setdefault(dt, []).append(r)
                    if off != 0xFFFFFFFF and r - first[dt] == off:
                        ex.add(dt)
        exact[prid] = sorted(ex, key=lambda d: pos[d])

    owners, used, reasons = {}, set(), {}

    def choose(prid, store, dt, off):
        """rid аксессора: сначала точное смещение, затем незанятый, затем любой."""
        lst = sorted(set(store[prid].get(dt, ())))
        if not lst:
            return None
        if off != 0xFFFFFFFF and (first[dt] + off) in lst:
            return first[dt] + off
        for r in lst:
            if r not in used:
                return r
        return lst[0]

    def exact_rid(prid, store, dt, off):
        """rid аксессора, давший точное совпадение смещения (или None)."""
        if off == 0xFFFFFFFF:
            return None
        r = first[dt] + off
        return r if r in store[prid].get(dt, ()) else None

    last = -1
    for prid in sorted(props):
        if prid not in exact:
            reasons[prid] = 'нет имени'
            continue
        g, s = m.u32(props[prid], PROP_GET), m.u32(props[prid], PROP_SET)
        # Два свойства одного типа не могут делить один метод-аксессор: так
        # отсеиваются дубли, которые иначе липнут к одному владельцу (пара
        # `System.Collections.IEnumerator.Current` у каждого итератора).
        free = []
        for dt in exact[prid]:
            clash = False
            for off, store in ((g, gacc), (s, sacc)):
                r = exact_rid(prid, store, dt, off)
                if r is not None and r in used:
                    clash = True
            if not clash:
                free.append(dt)
        cs = [dt for dt in free if pos[dt] >= last] or free
        if not cs:
            reasons[prid] = 'аксессор занят другим свойством'
            continue
        dt = order[last] if (last >= 0 and order[last] in cs) else cs[0]
        gr, sr = choose(prid, gacc, dt, g), choose(prid, sacc, dt, s)
        owners[prid] = {'dt': dt, 'get': gr, 'set': sr, 'how': 'смещение'}
        used.update(r for r in (gr, sr) if r is not None)
        last = pos[dt]
        reasons[prid] = 'смещение'

    anchors = sorted(owners)
    for prid in sorted(props):
        if prid in owners or prid not in exact:
            continue
        g, s = m.u32(props[prid], PROP_GET), m.u32(props[prid], PROP_SET)
        before = [a for a in anchors if a < prid]
        after = [a for a in anchors if a > prid]
        lo = pos[owners[before[-1]]['dt']] if before else -1
        hi = pos[owners[after[0]]['dt']] if after else len(order)
        cands = []
        for dt in sorted(set(list(gacc[prid]) + list(sacc[prid])), key=lambda d: pos[d]):
            if g != 0xFFFFFFFF and g >= count[dt]:
                continue                        # смещение не влезает в блок методов
            if not lo <= pos[dt] <= hi:
                continue                        # вне окна между соседними якорями
            gr = choose(prid, gacc, dt, g)
            if g != 0xFFFFFFFF and (gr is None or gr in used):
                continue                        # аксессор уже занят другим свойством
            cands.append(dt)
        if len(cands) == 1:
            dt = cands[0]
            gr, sr = choose(prid, gacc, dt, g), choose(prid, sacc, dt, s)
            owners[prid] = {'dt': dt, 'get': gr, 'set': sr, 'how': 'имя'}
            used.update(r for r in (gr, sr) if r is not None)
            reasons[prid] = 'имя'
        else:
            reasons[prid] = 'неоднозначно' if cands else 'аксессор не найден'

    unresolved = [prid for prid in sorted(props) if prid not in owners]
    # одна причина на свойство: сумма счётчиков равна числу записей PropertyDef
    stats = _c.Counter(reasons.get(prid, 'нет имени') for prid in props)
    return owners, unresolved, stats



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


# Сборки, чанки которых разобраны вручную: эвристика chunks() эти регионы
# фрагментирует, поэтому обход делается решёткой от известного адреса.
# off — НЕ данность: его перепроверяет solve_type_off (см. analysis/metadata-repair.md §1.6).
KNOWN_ASSEMBLIES = collections.OrderedDict((
    ('game',   {'types': 0xAC3E74, 'methods': 0x411540, 'max_rid': 20000, 'off': 3401}),
    ('photon', {'types': 0xBAA8E8, 'methods': 0x66A0F8, 'max_rid': 9999,  'off': 15832}),
    ('trilib', {'types': 0xBABB50, 'methods': 0x66D884, 'max_rid': 9999,  'off': 15894}),
))


def assembly_index(m, name, off=None, offs=None):
    """Индекс одной сборки: типы по ПОРЯДКУ ЗАПИСИ и методы по declaringType.

    Возвращает (by_pos, toks, groups, methods, off, solved, scored, tail), где
    `by_pos[k]` — адрес k-й записи TypeDef (k = 1-based порядковый номер в чанке),
    `toks[k]` — её токен, `groups[dt]` — [(rid, rec), ...] методов, `methods` —
    плоский словарь {rid: rec} БЕЗ хвостовой записи, `off` — связка `dt = off + k`,
    `solved`/`scored` — результат solve_type_off, `tail` — записи в конце региона
    методов, принадлежащие следующей сборке (см. split_tail).

    ВАЖНО: индекс типа — это порядковый номер записи, а не rid её токена: записи
    внутри чанка переставлены (в игровой сборке расходятся 713 из 1498).
    """
    spec = KNOWN_ASSEMBLIES[name]
    lat = lattice_types(m, spec['types'])
    by_pos, toks = type_positions(lat)
    methods = lattice_methods(m, spec['methods'], max_rid=spec['max_rid'])
    methods, tail = split_tail(m, methods, spec['off'], len(by_pos))
    groups = collections.defaultdict(list)
    for r, rec in methods.items():
        groups[m.u16(rec, METH_DECL)].append((r, rec))
    for k in groups:
        groups[k].sort()
    if offs is None:
        # диапазон — вокруг уже известного OFF сборки (у game 3401, у photon 15832),
        # иначе подбор ищет не там
        offs = range(spec['off'] - 12, spec['off'] + 13)
    solved, scored = solve_type_off(m, by_pos, methods, offs)
    if off is None:
        off = solved if scored[solved][0] else spec['off']
    return by_pos, toks, groups, methods, off, solved, scored, tail


def split_tail(m, methods, off, ntypes, decl_off=METH_DECL, name_off=METH_NAME):
    """Отделить «хвост» региона методов — записи, принадлежащие СЛЕДУЮЩЕЙ сборке.

    Регион чанка методов заканчивается записью, чей declaringType указывает за
    пределы чанка типов своей сборки. На всех трёх разобранных сборках хвост ровно
    один, и записей с dt ниже своего диапазона нет:

        game       rid 9184  dt 4904   ReleaseGssBuffer  -> System.dll!NetSecurityNative
        PUN        rid  474  dt 15896  CreateWebRequest  -> TriLibCore!AssetDownloader
        TriLibCore rid  674  dt 15981  get_debug         -> следующая сборка

    Принадлежность доказана порядком кучи имён: `ReleaseGssBuffer` (heap 637766)
    стоит сразу за `System.dll` -> `NetSecurityNative` -> `bufferPtr`, а
    `CreateWebRequest` (heap 2048894) — за `TriLibCore.dll` -> `AssetDownloader` ->
    `httpRequestMethod`; оба dt точно попадают на тип следующей сборки
    (у TriLibCore OFF = 15894 подтверждён 52/52, `AssetDownloader` = k=2 -> dt 15896).

    Возвращает (own, tail): `own` = {rid: rec} с dt в [off+1, off+ntypes],
    `tail` = [(rid, dt, имя)] — то, что своей сборке не принадлежит.
    """
    lo, hi = off + 1, off + ntypes
    own, tail = {}, []
    for rid, rec in methods.items():
        dt = m.u16(rec, decl_off)
        if lo <= dt <= hi:
            own[rid] = rec
        else:
            tail.append((rid, dt, m.raw_name(m.u32(rec, name_off)) or '?'))
    return own, sorted(tail)


def pair_assembly(m, meth_chunk, type_chunk, window=24, by_dt=None):
    """УСТАРЕЛО: связка по rid токена. Оставлена только для cmd_chunks.

    Связывает чанк методов с чанком типов одной сборки.

    declaringType у метода — ГЛОБАЛЬНЫЙ индекс типа, и он равен OFF + порядковый
    номер записи типа, а не OFF + rid (см. assembly_index).  OFF сначала угадывается
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
    """УСТАРЕЛО: ищет по фрагментам chunks(), где rid — локальный номер фрагмента.

    Все типы с таким именем: [(chunk_base, rid, record, full_name)]."""
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
    """Тип и его методы — по ПОРЯДКУ ЗАПИСИ в чанке (dt = OFF + k), не по rid токена."""
    names = (list(KNOWN_ASSEMBLIES) if args.assembly == 'all'
             else [a.strip() for a in args.assembly.split(',')])
    found = 0
    for name in names:
        by_pos, toks, groups, methods, off, solved, scored, tail = \
            assembly_index(m, name, args.off)
        print('\n### сборка %r: чанк типов 0x%X, чанк методов 0x%X; '
              'dt = OFF(%d) + номер записи' % (name, KNOWN_ASSEMBLIES[name]['types'],
                                               KNOWN_ASSEMBLIES[name]['methods'], off))
        print('    подбор OFF по compiler-generated типам: лучший %d -> %d/%d'
              ' (известный %d, взят %d)%s'
              % (solved, scored[solved][0], scored[solved][1],
                 KNOWN_ASSEMBLIES[name]['off'], off,
                 '' if solved == off else '  <-- РАСХОЖДЕНИЕ'))
        if tail:
            print('    хвост региона (принадлежит СЛЕДУЮЩЕЙ сборке, исключён): %s'
                  % ', '.join('rid %d dt %d %s' % t for t in tail))
        for k in sorted(by_pos):
            rec = by_pos[k]
            nm = m.raw_name(m.u32(rec, TYPE_NAME)) or ''
            hit = (nm == args.name) if not args.substr else (args.name.lower() in nm.lower())
            if not hit:
                continue
            found += 1
            ms = groups.get(off + k, [])
            print('\n=== %s' % class_name(m, rec))
            print('    номер записи k=%-6d token rid=%-6d dt=%-6d запись 0x%X; методов %d'
                  % (k, toks[k] & 0xFFFFFF, off + k, rec, len(ms)))
            if k != (toks[k] & 0xFFFFFF):
                print('    (rid токена расходится с номером записи — записи переставлены)')
            if args.methods:
                for r, rec2 in ms:
                    print('     ' + fmt_method(m, r, rec2))
    if not found:
        print('\nтип %r не найден в сборках %s' % (args.name, ', '.join(names)))
        print('если он в другой сборке: найди её чанк по уникальному имени '
              '(lattice_types от адреса-кандидата) и добавь в KNOWN_ASSEMBLIES')
        return 1
    return 0


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
    """Полный дамп разобранных сборок: dt = OFF + ПОРЯДКОВЫЙ НОМЕР записи типа.

    Прежняя версия печатала `globalTypeIndex = OFF + rid` — это неверно: записи
    TypeDef внутри чанка переставлены, и declaringType ссылается на порядковый
    номер записи. Полный человекочитаемый дамп игровой сборки делает
    tools/il2cpp_dump.py; эта команда — быстрая проверка связки по всем сборкам.
    """
    names = (list(KNOWN_ASSEMBLIES) if args.assembly == 'all'
             else [a.strip() for a in args.assembly.split(',')])
    n_t = n_m = 0
    with open(args.o, 'w') as f:
        f.write('# globalTypeIndex = OFF + порядковый номер записи типа (НЕ rid токена);\n'
                '# метод принадлежит типу, если его declaringType == globalTypeIndex\n')
        for name in names:
            by_pos, toks, groups, methods, off, solved, scored, tail = \
                assembly_index(m, name, args.off)
            f.write('\n### СБОРКА %s: чанк типов 0x%08X (%d записей) <-> чанк методов '
                    '0x%08X (%d записей), OFF=%d (подбор: лучший %d -> %d/%d)\n'
                    % (name, KNOWN_ASSEMBLIES[name]['types'], len(by_pos),
                       KNOWN_ASSEMBLIES[name]['methods'], len(methods), off,
                       solved, scored[solved][0], scored[solved][1]))
            if tail:
                f.write('# хвост региона методов (следующая сборка, исключён): %s\n'
                        % ', '.join('rid %d dt %d %s' % t for t in tail))
            for k in sorted(by_pos):
                rec = by_pos[k]
                ms = groups.get(off + k, [])
                f.write('TYPE k=%-6d tokenRid=%-6d 0x%08X globalIdx=%-6d %s%s\n'
                        % (k, toks[k] & 0xFFFFFF, rec, off + k, class_name(m, rec),
                           '' if k == (toks[k] & 0xFFFFFF) else '   [переставлено]'))
                n_t += 1
                for r, rec2 in ms:
                    f.write('    ' + fmt_method(m, r, rec2) + '\n')
                    n_m += 1
    print('записано %s: %d типов, %d методов (%s)' % (args.o, n_t, n_m, ', '.join(names)))
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
    p.add_argument('--substr', action='store_true',
                   help='искать подстроку в имени типа, а не точное совпадение')
    p.add_argument('--assembly', default='all',
                   help='game|photon|all или список через запятую (по умолчанию all)')
    p.add_argument('--off', type=int, default=None,
                   help='не подбирать OFF, а взять указанный')
    p = sub.add_parser('method')
    p.add_argument('--name', required=True)
    p = sub.add_parser('grep')
    p.add_argument('--regex', required=True)
    p.add_argument('-i', action='store_true')
    p.add_argument('--limit', type=int, default=0)
    p = sub.add_parser('dump')
    p.add_argument('-o', required=True)
    p.add_argument('--assembly', default='all')
    p.add_argument('--off', type=int, default=None)

    args = ap.parse_args()
    m = load(args.metadata, args.cache)
    fn = {'layout': cmd_layout, 'chunks': cmd_chunks, 'class': cmd_class,
          'method': cmd_method, 'grep': cmd_grep, 'dump': cmd_dump}[args.cmd]
    return fn(m, args) or 0


if __name__ == '__main__':
    sys.exit(main())
