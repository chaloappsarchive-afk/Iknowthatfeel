#!/usr/bin/env python3
"""il2cpp_dump.py — Dump.cs для обфусцированного global-metadata.dat без libil2cpp.so.

Зачем свой дампер
-----------------
Il2CppDumper / Il2CppInspector этот файл не берут по двум причинам:
  1. заголовок испорчен намеренно (sanity 0xFAB11BAF отсутствует и в файле, и во всех
     256 глобальных фазах XOR), смещения таблиц приходится искать структурно;
  2. `libil2cpp.so` в `apk/` нет, а без него нечем подтвердить раскладку записей и
     некуда мапить адреса (RVA/Offset).
`tools/il2cpp_tables.py` находит таблицы структурно; этот скрипт печатает из них
`Dump.cs` в формате, близком к Il2CppDumper.

Что здесь ПРАВДА, а что ЗАГЛУШКА
--------------------------------
Правда (прочитано из таблиц):
  * имена и количество типов, их токены и позиции записей, namespace;
  * имена методов, число параметров, принадлежность типу, флаги, значение колонки
    «slot», токены;
  * имена свойств и их get/set; владелец свойства восстановлен проверкой
    «метод `firstMethodRid + get` называется `get_<имя свойства>`».

Заглушки (в этом файле не восстанавливаются):
  * **типы возврата и типы параметров.** Колонка `+0` MethodDef индексом типа возврата
    НЕ является (опровергнуто на `CharacterMotor`: `set_titer` = 19708,
    `get_HP`/`get_isInAir`/`get_MyBodyguard` = 36310). Поэтому все возвраты напечатаны
    как `void`, все параметры — как `object p0, p1, …`. Это НЕ факт о сигнатуре.
  * **поля.** Таблица FieldDefinition игровой сборки отсутствует в файле физически:
    известные имена полей (`destroyingDuration`, `dieSound`, `agent`, `mySpawnedBots`,
    `MaxBotsCount`, `isBot`, `renderSet`, …) не встречаются как u32 ни в расшифрованном,
    ни в сыром файле, ни с учётом keystream `(p+i+C)&0xFF` (проверено решёткой шага 12 —
    совпадения единичные, цепочек нет). Вместо полей печатаются строки кучи имён из окна
    вокруг имени типа, не занятые именами методов/типов/свойств: туда попадают поля,
    имена параметров и локальных переменных. Блок помечен `// [эвристика по куче]`.
    Куча дедуплицирована, поэтому часть имён класса лежит далеко от своего окна.
  * **базовые классы, интерфейсы, вложенные типы, дженерики, RVA/Offset** — таблиц
    nestedTypes/interfaces/vtableMethods/genericContainers в распознанном виде нет,
    адресов нет без `libil2cpp.so`.
  * **class/struct/enum/interface/delegate не различаются** — всё печатается как
    `class`; типы с единственным `.ctor` помечены комментарием (там бывают enum,
    делегаты и компоненты-маркеры вроде `ChickenZombieBot`).
  * значение колонки «slot» приведено как наблюдение: у `BotController..ctor` оно равно
    24 при установленном бите Virtual, чего у конструктора быть не может, поэтому
    модификаторы `virtual`/`override` печатаются только у методов с флагом Virtual
    и помечены как приблизительные.

Запуск
------
    .venv/bin/python tools/il2cpp_dump.py apk/global-metadata.dat \
            --cache work/global-metadata.dec.dat -o analysis/Dump.cs

    # все найденные чанки типов (не только игровая сборка):
    ...  --assembly all
    # без эвристики по полям:
    ...  --no-heap-fields
"""

from __future__ import annotations

import argparse
import collections
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import il2cpp_tables as T  # noqa: E402

GAME_TYPE_BASE = 0xAC3E74
GAME_METHOD_BASE = 0x411540
GAME_PROP_BASE = 0x2FE698
# declaringType — ГЛОБАЛЬНЫЙ ИНДЕКС типа, а индекс в IL2CPP это порядковый номер
# записи в таблице, НЕ rid из её токена: записи TypeDefinition в этом файле
# переставлены (у 713 из 1498 записей игровой сборки rid токена != номер позиции).
# Проверено механически на 410 типах с обязывающим именем (итераторы <X>d__N и
# лямбда-классы <>c/<>c__DisplayClass*): индекс=позиция, OFF=3401 -> 406/410
# согласованных назначений; индекс=rid токена, OFF=3400 -> только 279/410.
GAME_OFF = 3401          # globalTypeIndex = GAME_OFF + порядковый номер записи типа
HEAP_WINDOW = 520        # байт в каждую сторону от имени типа для эвристики полей
MAX_HEAP_FIELDS = 40

ACCESS = {0: "/*CompilerControlled*/ ", 1: "private ", 2: "private protected ",
          3: "internal ", 4: "protected ", 5: "protected internal ", 6: "public "}


def flag_bits(flags: int) -> str:
    out = []
    for bit, nm in ((0x0010, "static"), (0x0020, "final"), (0x0040, "virtual"),
                    (0x0080, "hidebysig"), (0x0100, "newslot"), (0x0400, "abstract"),
                    (0x0800, "specialname"), (0x1000, "rtspecialname"),
                    (0x2000, "pinvokeimpl")):
        if flags & bit:
            out.append(nm)
    return "|".join(out) or "-"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("metadata")
    ap.add_argument("--cache", default="work/global-metadata.dec.dat")
    ap.add_argument("-o", "--out", default="analysis/Dump.cs")
    ap.add_argument("--assembly", choices=("game", "all"), default="game")
    ap.add_argument("--rvas", default="",
                    help="JSON от `il2cpp_so.py dump-rvas`: тогда у каждого метода "
                         "печатаются RVA и Offset из libil2cpp.so")
    ap.add_argument("--no-heap-fields", action="store_true",
                    help="не печатать эвристику полей из кучи имён")
    args = ap.parse_args(argv)

    B = open(args.cache, "rb").read()
    m = T.load(args.metadata, args.cache)

    # --- таблица RVA из libil2cpp.so (необязательно) ------------------------
    # JSON делает `tools/il2cpp_so.py dump-rvas`: там rid метода -> vaddr из
    # массива Il2CppCodeGenModule.methodPointers и сегменты PT_LOAD, по которым
    # vaddr переводится в файловый offset.
    rva_tab: dict[int, int] = {}
    rva_meta: dict = {}
    if args.rvas:
        import json as _json
        rva_meta = _json.loads(Path(args.rvas).read_text())
        rva_tab = {int(k): v for k, v in rva_meta.get("rva", {}).items() if v}
        _loads = rva_meta.get("loads", [])

        def vaddr_to_off(va: int):
            for v, o, sz, _f in _loads:
                if v <= va < v + sz:
                    return o + (va - v)
            return None
        print("# RVA: загружено %d ненулевых указателей из %s (methodCount=%s, %s)"
              % (len(rva_tab), args.rvas, rva_meta.get("method_count"),
                 rva_meta.get("arch")))
    else:
        def vaddr_to_off(va: int):
            return None
    HB = m.B
    tchunks, mchunks, pchunks = m.types(), m.methods(), m.properties()

    methods = mchunks[GAME_METHOD_BASE]
    props = pchunks.get(GAME_PROP_BASE, {})

    # Чанк типов берём обходом решётки, а не из `chunks()`: тот отбраковывает записи
    # с нечитаемым именем и теряет хвост таблицы (__StaticArrayInitTypeSize=20/24/72
    # и rid 1495, у которого имя затёрто). Затем перенумеровываем ПО ПОРЯДКУ
    # ХРАНЕНИЯ — именно на него ссылается declaringType (см. GAME_OFF).
    lat = T.lattice_types(m, GAME_TYPE_BASE)
    types, type_tokens = T.type_positions(lat)
    permuted = [k for k in types if type_tokens[k] != k]

    # Хвост региона методов: ПОСЛЕДНЯЯ запись принадлежит следующей сборке, а не игре
    # (rid 9184 ReleaseGssBuffer, dt 4904 -> System.dll!NetSecurityNative — порядок кучи
    # имён: 637727 System.dll, 637738 NetSecurityNative, 637756 bufferPtr, 637766
    # ReleaseGssBuffer). Правило проверено на трёх сборках, см. T.split_tail.
    methods, tail = T.split_tail(m, methods, GAME_OFF, len(types))
    best_off, scored = T.solve_type_off(m, types, methods, range(GAME_OFF - 4, GAME_OFF + 5))
    tok_off_best, tok_scored = T.solve_type_off(m, lat, methods, range(GAME_OFF - 5, GAME_OFF + 4))
    print("# типов %d (обход решётки от 0x%X), у %d из них rid токена != номер записи"
          % (len(types), GAME_TYPE_BASE, len(permuted)))
    bases = T.infer_base_classes(m, types, methods, GAME_OFF)
    print("# подбор OFF: по позиции лучший %d -> %d/%d; по rid токена лучший %d -> %d/%d"
          % (best_off, scored[best_off][0], scored[best_off][1],
             tok_off_best, tok_scored[tok_off_best][0], tok_scored[tok_off_best][1]))
    if best_off != GAME_OFF:
        raise SystemExit("OFF не сошёлся: подобранный %d, заданный %d" % (best_off, GAME_OFF))
    print("# методов %d (своих); хвост региона исключён: %s"
          % (len(methods), ", ".join("rid %d dt %d %s" % t for t in tail) or "нет"))

    # --- методы по declaringType --------------------------------------------
    by_dt: dict[int, list] = collections.defaultdict(list)
    for rid, rec in sorted(methods.items()):
        by_dt[m.u16(rec, T.METH_DECL)].append((rid, rec, m.name(m.u32(rec, T.METH_NAME)) or "?"))
    meth_name = {rid: nm for lst in by_dt.values() for rid, _, nm in lst}
    first_method = {dt: lst[0][0] for dt, lst in by_dt.items()}

    # --- свойства и их владельцы ---------------------------------------------
    # У PropertyDef нет поля «владелец»: принадлежность типу в оригинале задаётся
    # диапазоном TypeDef.propertyStart/property_count, а он в этом файле не
    # читается. Восстанавливаем по get/set (смещения от первого метода типа),
    # именам аксессоров и порядку rid свойств — см. resolve_property_owners().
    prop_owner, unresolved_rids, prop_stats = T.resolve_property_owners(m, methods, props)
    props_by_owner: dict[int, list] = collections.defaultdict(list)
    for prid, info in sorted(prop_owner.items()):
        prec = props[prid]
        props_by_owner[info["dt"]].append(
            (prid, m.name(m.u32(prec, T.PROP_NAME)) or "", m.u32(prec, T.PROP_GET),
             m.u32(prec, T.PROP_SET), m.u32(prec, T.PROP_TOK), info))
    unresolved_props = [(prid, m.name(m.u32(props[prid], T.PROP_NAME)) or "",
                         m.u32(props[prid], T.PROP_GET), m.u32(props[prid], T.PROP_SET))
                        for prid in unresolved_rids]

    # --- индексы имён, уже занятые таблицами (для эвристики полей) ------------
    claimed: set[int] = set()
    for _, rec in types.items():
        claimed.add(m.u32(rec, T.TYPE_NAME))
    for _, rec in methods.items():
        claimed.add(m.u32(rec, T.METH_NAME))
    for _, rec in props.items():
        claimed.add(m.u32(rec, T.PROP_NAME))

    out: list[str] = []
    w = out.append
    n_types = n_methods = n_props = 0

    w("// ============================================================================")
    w("// Dump.cs — объявления, восстановленные из apk/global-metadata.dat")
    w("// com.chaloapps.roosterrudy (Chicken Gun 6.5.3), IL2CPP, обфусцированные метаданные")
    w("//")
    w("// Сгенерировано tools/il2cpp_dump.py. Il2CppDumper этот файл не берёт:")
    if rva_tab:
        w("// заголовок исходных метаданных испорчен намеренно, поэтому таблицы")
        w("// восстановлены вручную, а адреса взяты из libil2cpp.so (--rvas).")
    else:
        w("// заголовок исходных метаданных испорчен намеренно, а libil2cpp.so")
        w("// отсутствует — RVA/Offset взять неоткуда. Как появится, перегенерируй с")
        w("// --rvas work/method_rvas.json (таблицу делает tools/il2cpp_so.py).")
    w("//")
    if rva_tab:
        w("// RVA/Offset: из libil2cpp.so, массив Il2CppCodeGenModule.methodPointers")
        w("// (%s, methodCount=%s, ненулевых указателей %d). Отсутствие строки RVA у"
          % (rva_meta.get("arch"), rva_meta.get("method_count"), len(rva_tab)))
        w("// метода значит, что указатель нулевой (abstract/pinvoke) либо rid вне")
        w("// таблицы бинарника.")
        w("//")
    w("// ЗАГЛУШКИ (подробно — в docstring инструмента):")
    w("//   * все возвраты напечатаны как void, все параметры как object pN: колонка +0")
    w("//     MethodDef индексом типа возврата не является;")
    w("//   * полей нет: FieldDefinition игровой сборки в файле отсутствует физически.")
    w("//     Вместо них — эвристика по куче имён, помечена `// [эвристика по куче]`;")
    w("//   * базовые классы неизвестны (parentIndex не читается); для %d типов напечатана"
      % len(bases))
    w("//     эвристика по vtable: совпадение (имя виртуала, slot) у переопределения и")
    w("//     объявления — помечена как [эвристика по vtable], фактом не является;")
    w("//   * интерфейсы, вложенные типы, дженерики — неизвестны;")
    w("//   * всё напечатано как class: enum/struct/interface/delegate не различимы.")
    w("//")
    w("// ФАКТЫ: имена типов и методов, namespace, число параметров, принадлежность типу,")
    w("// флаги, колонка slot, токены, свойства с get/set и их владельцы.")
    w("//")
    w("// Игровая сборка: чанк типов 0x%X (%d записей, шаг %d), чанк методов 0x%X"
      % (GAME_TYPE_BASE, len(types), T.TYPE_STRIDE, GAME_METHOD_BASE))
    w("// (%d записей, шаг %d), чанк свойств 0x%X (%d записей, шаг %d)."
      % (len(methods), T.METH_STRIDE, GAME_PROP_BASE, len(props), T.PROP_STRIDE))
    w("// Связка: globalTypeIndex = %d + ПОРЯДКОВЫЙ НОМЕР записи типа в чанке." % GAME_OFF)
    w("// Записи TypeDefinition в этом файле переставлены, поэтому rid из токена")
    w("// (0x02xxxxxx) НЕ равен индексу: у %d записей из %d они расходятся."
      % (len(permuted), len(types)))
    w("// declaringType ссылается на индекс (позицию), а не на токен — привязка")
    w("// методов ниже сделана по индексу; токен записи напечатан рядом как факт.")
    w("// ============================================================================")
    w("")

    by_ns: dict[str, list] = collections.defaultdict(list)
    for trid, trec in sorted(types.items()):
        by_ns[(m.raw_name(m.u32(trec, T.TYPE_NS))
               or m.name(m.u32(trec, T.TYPE_NS)) or "")].append((trid, trec))

    for ns in sorted(by_ns):
        if ns:
            w("namespace %s" % ns)
            w("{")
        ind = "\t" if ns else ""
        for trid, trec in by_ns[ns]:
            tname = (m.raw_name(m.u32(trec, T.TYPE_NAME))
                     or m.name(m.u32(trec, T.TYPE_NAME)) or "<без имени>")
            dt = GAME_OFF + trid
            ms = by_dt.get(dt, [])
            prs = props_by_owner.get(dt, [])
            cls = tname.split("`")[0]
            w("%s// --------------------------------------------------------------" % ind)
            w("%s// TypeDefIndex: %d   token: 0x%08X (rid %d%s)   запись: 0x%X"
              % (ind, trid, m.u32(trec, T.TYPE_TOK), type_tokens[trid],
                 "" if type_tokens[trid] == trid else "  <-- расходится с индексом", trec))
            w("%s// globalTypeIndex: %d = OFF(%d) + индекс(%d)" % (ind, dt, GAME_OFF, trid))
            if trid in bases:
                bidx, links = bases[trid]
                bname = (m.raw_name(m.u32(types[bidx], T.TYPE_NAME))
                         or m.name(m.u32(types[bidx], T.TYPE_NAME)) or "?")
                w("%s// [эвристика по vtable] вероятный базовый класс: %s (индекс %d) —"
                  % (ind, bname, bidx))
                w("%s//   совпало %d виртуалов по (имя, slot): %s"
                  % (ind, len(links), ", ".join("%s/%d" % (n, sl) for n, sl in links[:6])
                     + ("…" if len(links) > 6 else "")))
            w("%s// методов: %d%s   свойств: %d" % (
                ind, len(ms),
                "  (rid %d..%d)" % (ms[0][0], ms[-1][0]) if ms else "", len(prs)))
            if len(ms) == 1 and ms[0][2] == ".ctor":
                w("%s// только .ctor: enum, делегат или компонент-маркер — по метаданным не различить" % ind)
            w("%s// --------------------------------------------------------------" % ind)
            w("%spublic class %s" % (ind, tname))
            w("%s{" % ind)

            if prs:
                w("%s\t// ---- Свойства (PropertyDefinition) ----" % ind)
                for prid, pname, g, s, ptok, info in prs:
                    g_rid, s_rid = info["get"], info["set"]
                    acc = ("get; " if g_rid else "") + ("set; " if s_rid else "")
                    g_txt = "+%d" % g if g != 0xFFFFFFFF else "—"
                    s_txt = "+%d" % s if s != 0xFFFFFFFF else "—"
                    w("%s\t// Property rid=%d token=0x%08X  get=%s  set=%s (от первого метода типа)"
                      % (ind, prid, ptok, g_txt, s_txt))
                    w("%s\t// владелец найден по правилу «%s»; аксессоры: get rid=%s, set rid=%s"
                      % (ind, info["how"], g_rid or "—", s_rid or "—"))
                    w("%s\tpublic object %s { %s}" % (ind, pname, acc or "/*аксессоров нет*/"))
                    w("")
                n_props += len(prs)

            if ms:
                w("%s\t// ---- Методы (MethodDefinition) ----" % ind)
                for rid, rec, nm in ms:
                    pc = m.u16(rec, 22)
                    slot = m.u16(rec, 20)
                    flags = m.u32(rec, 16)
                    bits = flag_bits(flags)
                    w("%s\t// rid=%d  пар=%d  slot=%s  flags=0x%X (%s)  колонка+0=%d  token=0x%08X"
                      % (ind, rid, pc, "—" if slot == 0xFFFF else slot, flags, bits,
                         m.u32(rec, 0), m.u32(rec, T.METH_TOK)))
                    if rid in rva_tab:
                        va = rva_tab[rid]
                        fo = vaddr_to_off(va)
                        w("%s\t// RVA: 0x%X  Offset: %s   [из methodPointers libil2cpp.so]"
                          % (ind, va, "0x%X" % fo if fo is not None else "—"))
                    ps = ", ".join("object p%d" % i for i in range(pc))
                    if nm == ".ctor":
                        w("%s\t%s%s(%s) { }" % (ind, ACCESS.get(flags & 7, ""), cls, ps))
                    elif nm == ".cctor":
                        w("%s\tstatic %s() { }   // флаги/slot в этой записи недостоверны" % (ind, cls))
                    else:
                        mods = ""
                        if "static" in bits:
                            mods += "static "
                        if "abstract" in bits:
                            mods += "abstract "
                        elif "virtual" in bits:
                            mods += "override " if "newslot" not in bits else "virtual "
                        body = ";" if "abstract" in bits else " { }"
                        w("%s\t%s%svoid %s(%s)%s" % (ind, ACCESS.get(flags & 7, ""), mods, nm, ps, body))
                w("")
                n_methods += len(ms)

            if not args.no_heap_fields:
                ni = HB + m.u32(trec, T.TYPE_NAME)      # абсолютная позиция в файле
                lo, hi = max(1, ni - HEAP_WINDOW), min(len(B) - 2, ni + HEAP_WINDOW)
                found, i = [], lo
                while i < hi:
                    if 32 <= B[i] < 127 and B[i - 1] == 0:
                        j = i
                        while j < len(B) and 32 <= B[j] < 127:
                            j += 1
                        if j < len(B) and B[j] == 0 and j - i > 1 and (i - HB) not in claimed:
                            s = B[i:j].decode("ascii", "replace")
                            if s != tname:
                                found.append("%s(%d)" % (s, i - HB))
                        i = j + 1
                        continue
                    i += 1
                if found:
                    w("%s\t// ---- [эвристика по куче] НЕ из FieldDefinition (её в файле нет)." % ind)
                    w("%s\t//      Строки имён из окна ±%d байт вокруг имени типа, не занятые" % (ind, HEAP_WINDOW))
                    w("%s\t//      именами методов/типов/свойств: поля, параметры, локальные переменные." % ind)
                    for k in range(0, min(len(found), MAX_HEAP_FIELDS), 4):
                        w("%s\t//   " % ind + ", ".join(found[k:k + 4]))
                    if len(found) > MAX_HEAP_FIELDS:
                        w("%s\t//   … ещё %d" % (ind, len(found) - MAX_HEAP_FIELDS))
                    w("")
            w("%s}" % ind)
            w("")
            n_types += 1
        if ns:
            w("}")
            w("")

    # --- методы без владельца -------------------------------------------------
    known = {GAME_OFF + r for r in types}
    orphans = {dt: lst for dt, lst in by_dt.items() if dt not in known}
    if orphans:
        w("// ============================================================================")
        w("// Методы, чей declaringType не соответствует ни одной записи типа игровой сборки")
        w("// (групп: %d, методов: %d). Имена и число параметров достоверны, владелец не установлен:"
          % (len(orphans), sum(len(v) for v in orphans.values())))
        w("// либо это типы из другой сборки, либо записи типов не распознались.")
        w("// ============================================================================")
        for dt, lst in sorted(orphans.items()):
            w("// declaringType = %d (индекс типа %d), методов %d" % (dt, dt - GAME_OFF, len(lst)))
            for rid, rec, nm in lst:
                w("//   rid=%d  пар=%d  slot=%s  flags=0x%X  %s"
                  % (rid, m.u16(rec, 22),
                     "—" if m.u16(rec, 20) == 0xFFFF else m.u16(rec, 20),
                     m.u32(rec, 16), nm))
            w("")
            n_methods += len(lst)

    # --- свойства без владельца ----------------------------------------------
    if unresolved_props:
        w("// ============================================================================")
        w("// Свойства, владелец которых не восстановлен (%d из %d)."
          % (len(unresolved_props), len(props)))
        w("// Проверены оба правила: (1) у типа есть метод по адресу first_method+get с")
        w("// именем get_<свойство> — включая явные реализации интерфейса вида")
        w("// <интерфейс>.get_X; (2) у типа есть метод с таким именем и get < числа его")
        w("// методов. Здесь не сработало ни то ни другое: аксессора с таким именем в")
        w("// игровом чанке MethodDef нет вовсе — он в другой сборке или вырезан.")
        w("// ============================================================================")
        for prid, pname, g, s in unresolved_props:
            w("// Property rid=%d  %s   get=%s set=%s"
              % (prid, pname,
                 "+%d" % g if g != 0xFFFFFFFF else "—",
                 "+%d" % s if s != 0xFFFFFFFF else "—"))
        w("")

    # --- прочие чанки типов (не игровая сборка) --------------------------------
    if args.assembly == "all":
        w("// ============================================================================")
        w("// Прочие чанки TypeDefinition (другие сборки). Для сборки Photon/PUN OFF")
        w("// установлен (позиция+15832, см. analysis/photon-assembly.md), для остальных —")
        w("// нет, поэтому методы к этим типам не привязаны: только имена и токены.")
        w("// ============================================================================")
        for base, ch in sorted(tchunks.items(), key=lambda kv: -len(kv[1])):
            if base == GAME_TYPE_BASE:
                continue
            w("// чанк 0x%X: %d записей" % (base, len(ch)))
            for rid, rec in sorted(ch.items()):
                nm = m.name(m.u32(rec, T.TYPE_NAME))
                nsi = m.name(m.u32(rec, T.TYPE_NS)) or ""
                w("//   rid=%-6d token=0x%08X  %s%s" % (rid, m.u32(rec, T.TYPE_TOK),
                                                        (nsi + ".") if nsi else "", nm))
            w("")
            n_types += len(ch)

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text("\n".join(out) + "\n", encoding="utf-8")
    print("# типов: %d   методов: %d   свойств: %d (без владельца: %d)"
          % (n_types, n_methods, n_props, len(unresolved_props)))
    print("# групп методов без типа-владельца: %d (хвост региона исключён заранее)"
          % len(orphans))
    print("# записано: %s  (%.1f КБ, %d строк)"
          % (args.out, Path(args.out).stat().st_size / 1024, len(out)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
