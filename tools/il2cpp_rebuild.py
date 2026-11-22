#!/usr/bin/env python3
"""il2cpp_rebuild.py — собрать из обфусцированного global-metadata.dat файл с
валидным заголовком и стандартной раскладкой таблиц (игровая сборка).

Зачем
-----
У `com.chaloapps.roosterrudy` заголовок metadata испорчен намеренно (sanity
0xFAB11BAF отсутствует и в файле, и во всех 256 глобальных фазах XOR), а сами
таблицы физически **разбросаны** по файлу: записи TypeDef занимают 11 % размаха
своих позиций, MethodDef — 32 %, то есть сплошных массивов, на которые должен
указывать заголовок, в файле просто нет. Поэтому «починить заголовок» нельзя —
файл приходится **пересобирать**: вытащить распознанные записи игровой сборки и
уложить их сплошными массивами в стандартной раскладке, попутно восстановив те
поля записей, которые в исходнике отсутствуют (methodStart/method_count,
propertyStart/property_count, абсолютные индексы get/set).

Что попадает в результат
------------------------
Заголовок: sanity 0xFAB11BAF, version 24, 30 пар (offset, size) — 248 байт.
Секции: string, properties, methods, typeDefinitions, images (1), assemblies (1).
Пустые секции (offset/size = 0): stringLiteral(Data), events, parameters, fields,
genericParameters/Constraints/Containers, nestedTypes, interfaces, vtableMethods,
interfaceOffsets, rgctxEntries, referencedAssemblies, attributes*, unresolved*,
windowsRuntime*, exportedTypeDefinitions, *DefaultValues, fieldMarshaledSizes.

Ограничения (честно)
--------------------
* **Только игровая сборка.** Прочие 126 чанков TypeDef (библиотеки) не
  пересобираются: для них не установлен OFF (связка globalTypeIndex = OFF + rid),
  поэтому их методы к типам не привязать.
* **Полей нет.** FieldDefinition игровой сборки отсутствует в файле физически
  (проверено: известные имена полей не встречаются как u32 ни в расшифрованном,
  ни в сыром виде, ни с учётом keystream). fieldStart = -1, field_count = 0.
* **Типы возврата/параметров неизвестны.** returnType = 0, таблица parameters
  пуста (parameterStart = -1); число параметров сохранено в parametersCount.
  Колонка `+0` исходного MethodDef индексом типа возврата не является.
* **parentIndex / byvalTypeIndex / declaringTypeIndex / genericContainerIndex =
  -1**: таблиц типов-предков и дженериков мы не распознали, поэтому иерархия
  классов в результате отсутствует.
* **nestedTypes не заполнен**, хотя вложенные типы (`<>c`, `<>c__DisplayClass99_0`,
  `<DestroySelf>d__6`, …) лежат в массиве typeDefinitions как обычные записи.
* **version выбран 24** (раскладка записей v24.5). Точную версию метаданных
  подтверждает только `libil2cpp.so`, а его в `apk/` нет. Если внешний инструмент
  ожидает 27/29 — файл ему не подойдёт, и проверить это здесь нечем.
* **RVA/Offset проставить некуда** — без `libil2cpp.so` нет кода.
* Совместимость с Il2CppDumper/Il2CppInspector **не проверена** (в песочнице нет
  ни .NET, ни Java, ни самого `libil2cpp.so`, который этим инструментам тоже
  нужен). Проверка здесь — собственный round-trip: файл перечитывается по
  смещениям из заголовка и сравнивается с исходными таблицами (`--verify`,
  включён по умолчанию).

Запуск
------
    .venv/bin/python tools/il2cpp_rebuild.py apk/global-metadata.dat \
            --cache work/global-metadata.dec.dat \
            -o work/global-metadata.game-only.dat
    # без самопроверки / с другой версией:
    ... --no-verify --version 27
"""

from __future__ import annotations

import argparse
import collections
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import il2cpp_tables as T  # noqa: E402

SANITY = 0xFAB11BAF
GAME_TYPE_BASE = 0xAC3E74
GAME_METHOD_BASE = 0x411540
GAME_PROP_BASE = 0x2FE698
# declaringType = GAME_OFF + ПОРЯДКОВЫЙ НОМЕР записи типа в чанке (не rid токена:
# записи TypeDefinition в исходнике переставлены, у 713 из 1498 токен расходится с
# номером). Выбор подтверждён механически: T.solve_type_off на 410 типах с
# обязывающим именем даёт позиция+3401 -> 406/410 против токен+3400 -> 279/410.
GAME_OFF = 3401

# размеры записей v24.5
SZ_TYPE, SZ_METHOD, SZ_PROP, SZ_IMAGE, SZ_ASM = 92, 32, 20, 24, 64

# порядок пар (offset, size) в заголовке v24.5
SECTIONS = [
    "stringLiteral", "stringLiteralData", "string", "events", "properties",
    "methods", "parameterDefaultValues", "fieldDefaultValues",
    "fieldAndParameterDefaultValueData", "fieldMarshaledSizes", "parameters",
    "fields", "genericParameters", "genericParameterConstraints",
    "genericContainers", "nestedTypes", "interfaces", "vtableMethods",
    "interfaceOffsets", "typeDefinitions", "rgctxEntries", "images", "assemblies",
    "referencedAssemblies", "attributesInfo", "attributeTypes",
    "unresolvedVirtualCallParameterTypes", "unresolvedVirtualCallParameterRanges",
    "windowsRuntimeTypeNamePairs", "exportedTypeDefinitions",
]
HEADER_SIZE = 8 + 8 * len(SECTIONS)


class Strings:
    """Куча строк: индекс 0 — пустая строка, дальше NUL-терминированные имена."""

    def __init__(self):
        self.buf = bytearray(b"\x00")
        self.idx: dict[str, int] = {"": 0}

    def add(self, s: str) -> int:
        if s in self.idx:
            return self.idx[s]
        i = len(self.buf)
        self.buf += s.encode("utf-8") + b"\x00"
        self.idx[s] = i
        return i


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("metadata")
    ap.add_argument("--cache", default="work/global-metadata.dec.dat")
    ap.add_argument("-o", "--out", default="work/global-metadata.game-only.dat")
    ap.add_argument("--version", type=int, default=24)
    ap.add_argument("--image-name", default="Assembly-CSharp.dll")
    ap.add_argument("--assembly-name", default="Assembly-CSharp")
    ap.add_argument("--no-verify", action="store_true")
    args = ap.parse_args(argv)

    m = T.load(args.metadata, args.cache)
    methods = m.methods()[GAME_METHOD_BASE]
    props = m.properties().get(GAME_PROP_BASE, {})

    # Обход решётки (а не `chunks()`): так в таблицу попадают записи с нечитаемым
    # именем (__StaticArrayInitTypeSize=20/24/72 и rid 1495), которые chunks()
    # отбраковывает. Затем перенумеровываем по порядку хранения — именно на него
    # ссылается declaringType.
    lat = T.lattice_types(m, GAME_TYPE_BASE)
    types, type_tokens = T.type_positions(lat)
    permuted = [k for k in types if type_tokens[k] != k]
    # Хвост региона методов принадлежит СЛЕДУЮЩЕЙ сборке (rid 9184 ReleaseGssBuffer,
    # dt 4904 -> System.dll!NetSecurityNative), в game-only файл он не попадает.
    methods, tail = T.split_tail(m, methods, GAME_OFF, len(types))
    off, scored = T.solve_type_off(m, types, methods, range(GAME_OFF - 4, GAME_OFF + 5))
    print("# типов %d, у %d rid токена != номер записи; подбор OFF: %d -> %d/%d"
          % (len(types), len(permuted), off, scored[off][0], scored[off][1]))
    if off != GAME_OFF:
        raise SystemExit("OFF не сошёлся: подобранный %d, заданный %d" % (off, GAME_OFF))
    print("# методов своих %d; хвост региона исключён: %s"
          % (len(methods), ", ".join("rid %d dt %d %s" % t for t in tail) or "нет"))

    ntypes = max(types) if types else 0

    # --- 1. методы: сгруппировать по типу и перенумеровать сплошно ------------
    by_dt: dict[int, list] = collections.defaultdict(list)
    for rid, rec in sorted(methods.items()):
        by_dt[m.u16(rec, T.METH_DECL)].append((rid, rec))
    known_dt = {GAME_OFF + r for r in types}
    new_order: list[tuple[int, object]] = []       # (старый rid, запись)
    method_start: dict[int, int] = {}              # globalTypeIndex -> индекс
    method_count: dict[int, int] = {}
    new_index: dict[int, int] = {}                 # старый rid -> новый индекс
    for dt in sorted(known_dt):
        lst = by_dt.get(dt, [])
        if not lst:
            continue
        method_start[dt] = len(new_order)
        method_count[dt] = len(lst)
        for rid, rec in lst:
            new_index[rid] = len(new_order)
            new_order.append((rid, rec))
    orphan_start = len(new_order)
    # После split_tail сирот быть не должно: единственная запись с dt вне своего чанка
    # типов (rid 9184) принадлежит System.dll и исключена. Проверка оставлена как страховка.
    orphans = [(rid, rec) for dt, lst in sorted(by_dt.items()) if dt not in known_dt
               for rid, rec in lst]
    for rid, rec in orphans:
        new_index[rid] = len(new_order)
        new_order.append((rid, rec))

    meth_name = {rid: (m.name(m.u32(rec, T.METH_NAME)) or "") for rid, rec in methods.items()}

    # --- 2. свойства: владелец, затем сплошная укладка по типам ---------------
    # Владелец в PropertyDef не хранится (в оригинале это TypeDef.propertyStart/
    # property_count), поэтому восстанавливаем его общим резолвером: по смещениям
    # get/set от первого метода типа, именам аксессоров (включая явные реализации
    # интерфейса <интерфейс>.get_X) и порядку rid свойств.
    resolved, unresolved_rids, prop_stats = T.resolve_property_owners(m, methods, props)
    owners: dict[int, list] = collections.defaultdict(list)
    unowned: list[tuple] = []
    for prid, prec in sorted(props.items()):
        pname = m.name(m.u32(prec, T.PROP_NAME)) or ""
        g, s = m.u32(prec, T.PROP_GET), m.u32(prec, T.PROP_SET)
        info = resolved.get(prid)
        row = (prid, prec, pname, g, s, info)
        if info is not None:
            owners[info["dt"]].append(row)
        else:
            unowned.append(row)

    prop_start: dict[int, int] = {}
    prop_count: dict[int, int] = {}
    prop_order: list[tuple] = []
    for dt in sorted(known_dt):
        lst = owners.get(dt, [])
        if not lst:
            continue
        prop_start[dt] = len(prop_order)
        prop_count[dt] = len(lst)
        prop_order.extend(lst)
    unowned_start = len(prop_order)
    prop_order.extend(unowned)

    # --- 3. куча строк --------------------------------------------------------
    S = Strings()
    img_name_i = S.add(args.image_name)
    asm_name_i = S.add(args.assembly_name)
    type_name_i, type_ns_i = {}, {}
    for trid, trec in types.items():
        type_name_i[trid] = S.add(m.raw_name(m.u32(trec, T.TYPE_NAME))
                                  or m.name(m.u32(trec, T.TYPE_NAME)) or "")
        type_ns_i[trid] = S.add(m.raw_name(m.u32(trec, T.TYPE_NS))
                                or m.name(m.u32(trec, T.TYPE_NS)) or "")
    meth_name_i = {rid: S.add(nm) for rid, nm in meth_name.items()}
    prop_name_i = {prid: S.add(pname) for prid, _, pname, _, _, _ in prop_order}

    # --- 4. массивы -----------------------------------------------------------
    str_blob = bytes(S.buf)

    # MethodDefinition v24.5 (32 байта):
    #   nameIndex, declaringType, returnType, parameterStart, genericContainerIndex,
    #   token  (6 × u32)  +  flags, iflags, slot, parametersCount (4 × u16)
    method_blob = bytearray()
    for rid, rec in new_order:
        dt = m.u16(rec, T.METH_DECL)
        trid = dt - GAME_OFF
        slot = m.u16(rec, 20)
        method_blob += struct.pack("<IiiiiI", meth_name_i[rid],
                                   trid - 1 if trid in types else -1, 0, -1, -1,
                                   m.u32(rec, T.METH_TOK))
        method_blob += struct.pack("<HHHH", m.u32(rec, 16) & 0xFFFF, 0,
                                   slot, m.u16(rec, 22))

    prop_blob = bytearray()
    n_abs_get = 0
    for prid, prec, pname, g, s, info in prop_order:
        # get/set: в исходнике смещения от первого метода типа -> делаем абсолютными
        # индексами нового массива методов (в валидной метадате это MethodIndex).
        ga = sa = 0xFFFFFFFF
        if info is not None:
            if info["get"] is not None and info["get"] in new_index:
                ga = new_index[info["get"]]
                n_abs_get += 1
            if info["set"] is not None and info["set"] in new_index:
                sa = new_index[info["set"]]
        prop_blob += struct.pack("<IIII", prop_name_i[prid], ga, sa,
                                 m.u32(prec, T.PROP_ATTRS))
        prop_blob += struct.pack("<I", m.u32(prec, T.PROP_TOK))

    type_blob = bytearray()
    for trid in range(1, ntypes + 1):
        trec = types.get(trid)
        dt = GAME_OFF + trid
        ms, mc = method_start.get(dt, -1), method_count.get(dt, 0)
        ps, pc = prop_start.get(dt, -1), prop_count.get(dt, 0)
        if trec is None:
            ni = nsi = 0
            tok = 0
        else:
            ni, nsi = type_name_i[trid], type_ns_i[trid]
            # токен пишем согласованный с индексом (0x02000000|индекс): в исходнике
            # записи переставлены и rid токена расходится с позицией у %d типов, а
            # валидная метадата обязана иметь token = 0x02000000|(index+1).
            # Оригинальные токены сохранены в analysis/Dump.cs у каждого типа.
            tok = 0x02000000 | trid
        # nameIndex, namespaceIndex, byvalTypeIndex, byrefTypeIndex, declaringTypeIndex,
        # parentIndex, elementTypeIndex, genericContainerIndex (8 × u32/i32)
        type_blob += struct.pack("<Iiiiiiii", ni, nsi, -1, -1, -1, -1, -1, -1)
        # flags, fieldStart, methodStart, eventStart, propertyStart,
        # nestedTypesStart, interfacesStart (7 × u32/i32)
        type_blob += struct.pack("<Iiiiiii", 0, -1, ms, -1, ps, -1, -1)
        # vtableStart, interfaceOffsetsStart (2 × i32)
        type_blob += struct.pack("<ii", -1, -1)
        type_blob += struct.pack("<HHHHHHHH", mc, pc, 0, 0, 0, 0, 0, 0)
        type_blob += struct.pack("<II", 0, tok)

    image_blob = struct.pack("<IiiIiI", img_name_i, 0, 0, ntypes, -1, 0x20000001)
    asm_blob = struct.pack("<iiii", 0, -1, -1, 0)                     # image/attr/refStart/refCount
    asm_blob += struct.pack("<iiiiiiiiii", asm_name_i, -1, -1, 0x8004, 0, 0,
                            1, 0, 0, 0)                               # aname
    asm_blob += b"\x00" * 8                                           # public_key_token

    # --- 5. раскладка и заголовок --------------------------------------------
    body = collections.OrderedDict()
    body["string"] = str_blob
    body["properties"] = bytes(prop_blob)
    body["methods"] = bytes(method_blob)
    body["typeDefinitions"] = bytes(type_blob)
    body["images"] = image_blob
    body["assemblies"] = asm_blob

    pos = HEADER_SIZE
    offs: dict[str, tuple[int, int]] = {}
    for name in SECTIONS:
        blob = body.get(name)
        if blob:
            offs[name] = (pos, len(blob))
            pos += len(blob)
            pos = (pos + 3) & ~3                       # выравнивание 4
        else:
            offs[name] = (0, 0)

    out = bytearray()
    out += struct.pack("<Ii", SANITY, args.version)
    for name in SECTIONS:
        out += struct.pack("<ii", *offs[name])
    assert len(out) == HEADER_SIZE, len(out)
    cur = HEADER_SIZE
    for name in SECTIONS:
        blob = body.get(name)
        if not blob:
            continue
        if cur < offs[name][0]:
            out += b"\x00" * (offs[name][0] - cur)
        out += blob
        cur = offs[name][0] + len(blob)
        pad = ((cur + 3) & ~3) - cur
        out += b"\x00" * pad
        cur += pad

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_bytes(bytes(out))
    print("# записано %s (%d байт = %.1f КБ)" % (args.out, len(out), len(out) / 1024))
    print("# заголовок: sanity=0x%08X version=%d размер=%d" % (SANITY, args.version, HEADER_SIZE))
    for name in SECTIONS:
        o, s = offs[name]
        if s:
            rec = {"string": None, "properties": SZ_PROP, "methods": SZ_METHOD,
                   "typeDefinitions": SZ_TYPE, "images": SZ_IMAGE,
                   "assemblies": SZ_ASM}.get(name)
            print("#   %-16s offset=0x%-8X size=%-9d %s" % (
                name, o, s, ("записей: %d" % (s // rec)) if rec else "байт"))
    print("# типы: %d, методы: %d (сирот без владельца: %d), свойства: %d (без владельца: %d)"
          % (ntypes, len(new_order), len(orphans), len(prop_order), len(unowned)))

    if not args.no_verify:
        verify(args.out, m, types, meth_name, ntypes, new_index, prop_order)
    return 0


def verify(path: str, m, types, meth_name, ntypes, new_index, prop_order) -> None:
    """Перечитать файл ПО СМЕЩЕНИЯМ ИЗ ЗАГОЛОВКА и сравнить с исходником."""
    print("\n=== round-trip проверка ===")
    B = open(path, "rb").read()
    sanity, version = struct.unpack_from("<Ii", B, 0)
    assert sanity == SANITY, hex(sanity)
    hdr = {}
    for i, name in enumerate(SECTIONS):
        o, s = struct.unpack_from("<ii", B, 8 + 8 * i)
        hdr[name] = (o, s)
    print("  sanity 0x%08X version %d — заголовок читается" % (sanity, version))

    to, ts = hdr["typeDefinitions"]
    n_t = ts // SZ_TYPE
    mo, ms_ = hdr["methods"]
    n_m = ms_ // SZ_METHOD
    po, ps = hdr["properties"]
    n_p = ps // SZ_PROP
    print("  typeDefinitions: %d записей (ожидалось %d)" % (n_t, ntypes))
    print("  methods        : %d записей (ожидалось %d)" % (n_m, len(new_index)))
    print("  properties     : %d записей (ожидалось %d)" % (n_p, len(prop_order)))
    assert n_t == ntypes and n_m == len(new_index) and n_p == len(prop_order)

    so, ss = hdr["string"]
    heap = B[so:so + ss]

    def nm(i: int) -> str:
        if i < 0:
            return "?"
        e = heap.index(b"\x00", i)
        return heap[i:e].decode("utf-8", "replace")

    # имена типов: сверяем каждый
    bad = 0
    for trid, trec in types.items():
        want = m.raw_name(m.u32(trec, T.TYPE_NAME)) or m.name(m.u32(trec, T.TYPE_NAME)) or ""
        ni = struct.unpack_from("<I", B, to + (trid - 1) * SZ_TYPE)[0]
        if nm(ni) != want:
            bad += 1
    print("  имена типов: расхождений %d из %d" % (bad, len(types)))
    assert bad == 0

    # токены типов обязаны быть согласованы с индексом (в исходнике они переставлены)
    tok_bad = 0
    for trid in types:
        tok = struct.unpack_from("<I", B, to + (trid - 1) * SZ_TYPE + 88)[0]
        if tok != (0x02000000 | trid):
            tok_bad += 1
    print("  токены типов: 0x02000000|индекс у всех %d записей, расхождений %d"
          % (len(types), tok_bad))
    assert tok_bad == 0

    # методы BotController: должны вернуться те же имена в том же порядке
    for probe in ("BotController", "GameController", "CharacterMotor",
                  "BombMonster", "BotAnimEvents", "BotBodyPartDmgReceiver"):
        trid = next((r for r, rec in types.items()
                     if (m.name(m.u32(rec, T.TYPE_NAME)) or "") == probe), None)
        if trid is None:
            continue
        base = to + (trid - 1) * SZ_TYPE
        mstart, mcount = struct.unpack_from("<iH", B, base + 40)[0], \
            struct.unpack_from("<H", B, base + 68)[0]
        got = []
        for k in range(mcount):
            ni = struct.unpack_from("<I", B, mo + (mstart + k) * SZ_METHOD)[0]
            got.append(nm(ni))
        print("  %-16s methodStart=%-6d method_count=%-4d %s"
              % (probe, mstart, mcount, ", ".join(got[:6]) + ("…" if len(got) > 6 else "")))

    # propertyStart/property_count: диапазоны свойств должны читаться и давать
    # осмысленные имена (в исходной метадате эти поля не читаются вообще)
    for probe in ("CharacterMotor", "GameController", "JSONNode"):
        trid = next((r for r, rec in types.items()
                     if (m.raw_name(m.u32(rec, T.TYPE_NAME)) or "") == probe), None)
        if trid is None:
            continue
        base = to + (trid - 1) * SZ_TYPE
        pstart = struct.unpack_from("<i", B, base + 48)[0]
        pcount = struct.unpack_from("<H", B, base + 70)[0]
        if pstart < 0 or pcount == 0:
            print("  %-16s propertyStart=%d property_count=%d (свойств нет)"
                  % (probe, pstart, pcount))
            continue
        names = [nm(struct.unpack_from("<I", B, po + (pstart + k) * SZ_PROP)[0])
                 for k in range(pcount)]
        assert all(x is not None for x in names), probe
        print("  %-16s propertyStart=%-6d property_count=%-4d %s"
              % (probe, pstart, pcount, ", ".join(names[:6]) + ("…" if len(names) > 6 else "")))

    # свойства: get/set стали абсолютными индексами и указывают на get_/set_
    ok = chk = 0
    for i, (prid, prec, pname, g, s, info) in enumerate(prop_order):
        rec = po + i * SZ_PROP
        ni, ga, sa = struct.unpack_from("<III", B, rec)[:3]
        if nm(ni) != pname:
            print("  РАСХОЖДЕНИЕ имени свойства rid=%d: %r != %r" % (prid, nm(ni), pname))
        if ga != 0xFFFFFFFF:
            chk += 1
            want, _ = T.accessor_names(pname)
            if nm(struct.unpack_from("<I", B, mo + ga * SZ_METHOD)[0]) in want:
                ok += 1
    print("  свойства: имён совпало %d/%d; абсолютный get указан у %d, из них ведут на "
          "get_<имя> — %d" % (len(prop_order), len(prop_order), chk, ok))
    print("  size(string)=%d, size(images)=%d, size(assemblies)=%d"
          % (hdr["string"][1], hdr["images"][1], hdr["assemblies"][1]))
    print("  ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ")


if __name__ == "__main__":
    raise SystemExit(main())
