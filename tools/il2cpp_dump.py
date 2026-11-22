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
GAME_OFF = 3400          # globalTypeIndex (MethodDef.declaringType) = GAME_OFF + rid
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
    ap.add_argument("--no-heap-fields", action="store_true",
                    help="не печатать эвристику полей из кучи имён")
    args = ap.parse_args(argv)

    B = open(args.cache, "rb").read()
    m = T.load(args.metadata, args.cache)
    HB = m.B
    tchunks, mchunks, pchunks = m.types(), m.methods(), m.properties()

    types = tchunks[GAME_TYPE_BASE]
    methods = mchunks[GAME_METHOD_BASE]
    props = pchunks.get(GAME_PROP_BASE, {})

    # --- методы по declaringType --------------------------------------------
    by_dt: dict[int, list] = collections.defaultdict(list)
    for rid, rec in sorted(methods.items()):
        by_dt[m.u16(rec, T.METH_DECL)].append((rid, rec, m.name(m.u32(rec, T.METH_NAME)) or "?"))
    meth_name = {rid: nm for lst in by_dt.values() for rid, _, nm in lst}
    first_method = {dt: lst[0][0] for dt, lst in by_dt.items()}

    # --- свойства и их владельцы ---------------------------------------------
    props_by_owner: dict[int, list] = collections.defaultdict(list)
    unresolved_props = []
    for prid, prec in sorted(props.items()):
        pname = m.name(m.u32(prec, T.PROP_NAME))
        if not pname:
            continue
        g, s = m.u32(prec, 4), m.u32(prec, 8)
        want = "get_" + pname
        owners = [dt for dt, F in first_method.items()
                  if 0 < g < 0xFFFF and meth_name.get(F + g) == want]
        if not owners and 0 < g < 0xFFFF:
            # без get-метода ищем по set-методу
            owners = [dt for dt, F in first_method.items()
                      if 0 < s < 0xFFFF and meth_name.get(F + s) == "set_" + pname]
        if owners:
            for dt in owners:
                props_by_owner[dt].append((prid, pname, g, s, m.u32(prec, T.PROP_TOK), len(owners)))
        else:
            unresolved_props.append((prid, pname, g, s))

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
    w("// Сгенерировано tools/il2cpp_dump.py. Il2CppDumper этот файл не берёт: заголовок")
    w("// испорчен намеренно, а libil2cpp.so отсутствует (RVA/Offset взять неоткуда).")
    w("//")
    w("// ЗАГЛУШКИ (подробно — в docstring инструмента):")
    w("//   * все возвраты напечатаны как void, все параметры как object pN: колонка +0")
    w("//     MethodDef индексом типа возврата не является;")
    w("//   * полей нет: FieldDefinition игровой сборки в файле отсутствует физически.")
    w("//     Вместо них — эвристика по куче имён, помечена `// [эвристика по куче]`;")
    w("//   * базовые классы, интерфейсы, вложенные типы, дженерики — неизвестны;")
    w("//   * всё напечатано как class: enum/struct/interface/delegate не различимы.")
    w("//")
    w("// ФАКТЫ: имена типов и методов, namespace, число параметров, принадлежность типу,")
    w("// флаги, колонка slot, токены, свойства с get/set и их владельцы.")
    w("//")
    w("// Игровая сборка: чанк типов 0x%X (%d записей, шаг %d), чанк методов 0x%X"
      % (GAME_TYPE_BASE, len(types), T.TYPE_STRIDE, GAME_METHOD_BASE))
    w("// (%d записей, шаг %d), чанк свойств 0x%X (%d записей, шаг %d)."
      % (len(methods), T.METH_STRIDE, GAME_PROP_BASE, len(props), T.PROP_STRIDE))
    w("// Связка: globalTypeIndex = %d + rid типа." % GAME_OFF)
    w("// ============================================================================")
    w("")

    by_ns: dict[str, list] = collections.defaultdict(list)
    for trid, trec in sorted(types.items()):
        by_ns[m.name(m.u32(trec, T.TYPE_NS)) or ""].append((trid, trec))

    for ns in sorted(by_ns):
        if ns:
            w("namespace %s" % ns)
            w("{")
        ind = "\t" if ns else ""
        for trid, trec in by_ns[ns]:
            tname = m.name(m.u32(trec, T.TYPE_NAME)) or "<без имени>"
            dt = GAME_OFF + trid
            ms = by_dt.get(dt, [])
            prs = props_by_owner.get(dt, [])
            cls = tname.split("`")[0]
            w("%s// --------------------------------------------------------------" % ind)
            w("%s// TypeDefIndex: %d   token: 0x%08X   запись: 0x%X" % (ind, trid, m.u32(trec, T.TYPE_TOK), trec))
            w("%s// globalTypeIndex: %d = OFF(%d) + rid(%d)" % (ind, dt, GAME_OFF, trid))
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
                for prid, pname, g, s, ptok, nown in prs:
                    acc = ("get; " if 0 < g < 0xFFFF else "") + ("set; " if 0 < s < 0xFFFF else "")
                    w("%s\t// Property rid=%d token=0x%08X  get=+%s  set=+%s (от первого метода типа)%s"
                      % (ind, prid, ptok,
                         g if 0 < g < 0xFFFF else "—", s if 0 < s < 0xFFFF else "—",
                         "  ВЛАДЕЛЕЦ НЕ ОДНОЗНАЧЕН (%d кандидатов)" % nown if nown > 1 else ""))
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
            w("// declaringType = %d (rid %d), методов %d" % (dt, dt - GAME_OFF, len(lst)))
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
        w("// Свойства, владелец которых не восстановлен (%d из %d): get/set в"
          % (len(unresolved_props), len(props)))
        w("// PropertyDefinition — смещения от первого метода типа-владельца, и ни один тип")
        w("// не дал метода с именем get_<свойство>. Причины: аксессор в другой сборке,")
        w("// свойство без get-аксессора, либо сдвиг базы у владельца.")
        w("// ============================================================================")
        for prid, pname, g, s in unresolved_props:
            w("// Property rid=%d  %s   get=+%s set=+%s"
              % (prid, pname, g if 0 < g < 0xFFFF else "—", s if 0 < s < 0xFFFF else "—"))
        w("")

    # --- прочие чанки типов (не игровая сборка) --------------------------------
    if args.assembly == "all":
        w("// ============================================================================")
        w("// Прочие чанки TypeDefinition (другие сборки). OFF для них не установлен,")
        w("// поэтому методы к этим типам не привязаны — только имена и токены.")
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
    print("# групп методов без типа-владельца: %d" % len(orphans))
    print("# записано: %s  (%.1f КБ, %d строк)"
          % (args.out, Path(args.out).stat().st_size / 1024, len(out)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
