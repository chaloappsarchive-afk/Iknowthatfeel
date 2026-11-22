#!/usr/bin/env python3
"""
il2cpp_so.py -- что можно вытащить из libil2cpp.so, когда он есть в apk/.

Без `libil2cpp.so` вся работа с метаданными упирается в потолок: нет RVA/Offset,
нет порядка вызовов внутри метода, нет версии метаданных (в пересобранном файле
`version = 24` стоит по умолчанию). Этот скрипт закрывает три вещи.

1. `module` / `rva` / `dump-rvas` — таблица указателей на код игровой сборки.
   В современном IL2CPP на каждый image есть структура `Il2CppCodeGenModule`,
   первое поле которой `const char* assemblyName` указывает на строку
   `"Assembly-CSharp.dll"` в .rodata. Найдя указатель на эту строку, получаем
   саму структуру, а в ней `methodCount` и `methodPointers` — массив указателей
   на функции, индексированный **rid токена метода минус 1**. Отсюда RVA каждого
   из 9 006 распознанных методов, и `methodCount` независимо подтверждает (или
   опровергает) размер нашего чанка MethodDef (max rid 9184).

2. `loader` — функция, открывающая `global-metadata.dat`. В обфусцированной
   сборке именно там живёт расшифровка метаданных, а рядом — проверка
   `header->version`: immediates инструкций `cmp` в диапазоне 20..31 показывают,
   какие версии метаданных поддерживает этот бинарник.

3. `disasm` — дизассемблер (capstone) по rid метода: порядок вызовов внутри
   `BotController.DestroySelf` или `DieR` перестаёт быть реконструкцией.

Подкоманды:

    python3 tools/il2cpp_so.py info      apk/libil2cpp.so
    python3 tools/il2cpp_so.py module    apk/libil2cpp.so [--image Assembly-CSharp.dll]
    python3 tools/il2cpp_so.py rva       apk/libil2cpp.so --rid 5700
    python3 tools/il2cpp_so.py dump-rvas apk/libil2cpp.so -o work/method_rvas.json
    python3 tools/il2cpp_so.py loader    apk/libil2cpp.so [--count 200]
    python3 tools/il2cpp_so.py version   apk/libil2cpp.so
    python3 tools/il2cpp_so.py disasm    apk/libil2cpp.so --rid 5700 [--count 80]

Адреса печатаются в двух видах: `vaddr` (как в ELF, база загрузки 0) и `offset`
(позиция в файле). Il2CppDumper в Dump.cs печатает RVA относительно базы образа,
то есть наш `vaddr` для позиционно-независимой библиотеки и есть RVA.

Файл `.so` в git НЕ коммитится (см. /.gitignore) — он лежит локально в `apk/`.
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from pathlib import Path

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
except ImportError:                                  # pragma: no cover
    print("нужен pyelftools:  .venv/bin/pip install pyelftools", file=sys.stderr)
    raise

try:
    import capstone as cs
except ImportError:                                  # pragma: no cover
    cs = None

META_NAME = b"global-metadata.dat"
GAME_IMAGE = "Assembly-CSharp.dll"

# Диапазон версий метаданных, который имеет смысл искать в `cmp`-immediates.
VERSION_RANGE = range(16, 32)


class So:
    """ELF-обёртка: сегменты, перевод vaddr<->offset, поиск строк и указателей."""

    def __init__(self, path: str):
        self.path = path
        self.data = Path(path).read_bytes()
        self.elf = ELFFile(open(path, "rb"))
        self.machine = self.elf.header["e_machine"]
        self.bits = self.elf.elfclass
        self.loads = []
        for seg in self.elf.iter_segments():
            if seg.header["p_type"] == "PT_LOAD":
                h = seg.header
                self.loads.append((h["p_vaddr"], h["p_offset"], h["p_filesz"],
                                   h["p_flags"]))
        self.exec_ranges = [(v, o, s) for v, o, s, f in self.loads if f & 1]

    # --- переводы адресов ---------------------------------------------------
    def off_to_vaddr(self, off: int):
        for v, o, s, _ in self.loads:
            if o <= off < o + s:
                return v + (off - o)
        return None

    def vaddr_to_off(self, va: int):
        for v, o, s, _ in self.loads:
            if v <= va < v + s:
                return o + (va - v)
        return None

    def writable_off(self, off: int) -> bool:
        """Попадает ли offset в PT_LOAD с флагом записи (.data/.data.rel.ro)."""
        return any(o <= off < o + s for _, o, s, f in self.loads if f & 2)

    def is_exec(self, va: int) -> bool:
        """Попадает ли vaddr в исполняемый PT_LOAD."""
        return any(v <= va < v + s for v, _, s, f in self.loads if f & 1)

    # --- поиск --------------------------------------------------------------
    def find_str(self, needle: bytes):
        """Все позиции строки в файле как (offset, vaddr)."""
        out, i = [], 0
        while True:
            i = self.data.find(needle, i)
            if i < 0:
                return out
            out.append((i, self.off_to_vaddr(i)))
            i += 1

    def find_ptrs(self, va: int, width: int = 8):
        """Все места в файле, где лежит указатель на `va`."""
        fmt = "<Q" if width == 8 else "<I"
        needle = struct.pack(fmt, va)
        out, i = [], 0
        while True:
            i = self.data.find(needle, i)
            if i < 0:
                return out
            out.append((i, self.off_to_vaddr(i)))
            i += 1

    def u32(self, off: int) -> int:
        return struct.unpack_from("<I", self.data, off)[0]

    def u64(self, off: int) -> int:
        return struct.unpack_from("<Q", self.data, off)[0]

    # --- символы ------------------------------------------------------------
    def exports(self):
        names = []
        for sec in self.elf.iter_sections():
            if isinstance(sec, SymbolTableSection):
                for sym in sec.iter_symbols():
                    if sym.name and sym["st_value"]:
                        names.append((sym.name, sym["st_value"], sym["st_size"]))
        return names

    # --- дизассемблер -------------------------------------------------------
    def disasm(self, va: int, count: int):
        if cs is None:
            raise SystemExit("capstone не установлен: .venv/bin/pip install capstone")
        arch, mode = self._cs_arch()
        md = cs.Cs(arch, mode)
        md.detail = False
        off = self.vaddr_to_off(va)
        if off is None:
            raise SystemExit("vaddr 0x%X не попадает ни в один PT_LOAD" % va)
        code = self.data[off:off + count * 4]
        return list(md.disasm(code, va))

    def _cs_arch(self):
        if self.machine == "EM_AARCH64":
            arch = getattr(cs, "CS_ARCH_ARM64", None) or getattr(cs, "CS_ARCH_AARCH64")
            return arch, cs.CS_MODE_LITTLE_ENDIAN
        if self.machine == "EM_ARM":
            return cs.CS_ARCH_ARM, cs.CS_MODE_ARM | cs.CS_MODE_LITTLE_ENDIAN
        if self.machine == "EM_X86_64":
            return cs.CS_ARCH_X86, cs.CS_MODE_64
        raise SystemExit("неподдерживаемая архитектура: %s" % self.machine)


# --- Il2CppCodeGenModule ------------------------------------------------------

def find_codegen_modules(so: So, image: str = GAME_IMAGE):
    """Найти структуру Il2CppCodeGenModule по указателю на имя образа.

    `assemblyName` — первое поле структуры почти во всех версиях, но на всякий
    случай перебираем небольшие отрицательные смещения. Структуру подтверждаем
    по двум признакам: рядом лежит правдоподобное `methodCount` (тысячи, а не
    миллионы), а указанный `methodPointers` даёт массив, у которого >= 90 %
    значений попадают в исполняемый сегмент.
    """
    hits = so.find_str(image.encode() + b"\x00")
    if not hits:
        raise SystemExit("строка %r в файле не найдена" % image)
    found = []
    for stroff, strva in hits:
        if strva is None:
            continue
        for ptr_off, ptr_va in so.find_ptrs(strva):
            if not so.writable_off(ptr_off):
                # указатель лежит вне .data/.data.rel.ro — например, в program
                # headers, где p_vaddr сегмента случайно равен адресу строки.
                # Il2CppCodeGenModule там находиться не может.
                continue
            for delta in (0, 8, 16, 24):
                base_off = ptr_off - delta
                if base_off < 0 or base_off + 64 > len(so.data):
                    continue
                cand = _try_module(so, base_off, strva)
                if cand:
                    cand["name_vaddr"] = strva
                    cand["name_ptr_at"] = ptr_va
                    cand["struct_delta"] = delta
                    found.append(cand)
    return found


def _try_module(so: So, base_off: int, name_va: int):
    """Проверить кандидата: (methodCount, methodPointers) в первых 64 байтах."""
    best = None
    # Окно намеренно широкое: в разных версиях Unity между `assemblyName` и
    # `methodPointers` встаёт то adjustorThunk-таблица, то tokenRanges, поэтому
    # поле methodCount ищем в первых 56 байтах, а указатель -- в 120.
    for coff in range(0, 56, 4):
        if base_off + coff + 4 > len(so.data):
            break
        cnt = so.u32(base_off + coff)
        if not (100 <= cnt <= 400000):
            continue
        # Указатели в структуре 8-байтно выровнены, поэтому начинать надо не от
        # `coff + 4`, а от ближайшей выровненной позиции: иначе поле
        # methodPointers (например +0x20 при methodCount на +0x08) попадает
        # между шагами скана и структура не находится.
        for poff in range(((coff + 4) + 7) & ~7, 128, 8):
            if poff <= coff or base_off + poff + 8 > len(so.data):
                continue
            ptr = so.u64(base_off + poff)
            moff = so.vaddr_to_off(ptr)
            if moff is None or moff + cnt * 8 > len(so.data):
                continue
            # Нулевой указатель законен (abstract/pinvoke), но «годным» не
            # считается: иначе массив, почти целиком состоящий из нулей, проходит
            # проверку. В настоящей таблице кода подавляющее большинство
            # элементов ненулевые и ведут в исполняемый сегмент.
            nz = ok = 0
            for k in range(0, min(cnt, 400)):
                fn = so.u64(moff + k * 8)
                if fn == 0:
                    continue
                nz += 1
                if so.vaddr_to_off(fn) is not None and so.is_exec(fn):
                    ok += 1
            if nz >= max(5, min(50, cnt // 10)) and ok / nz >= 0.9:
                score = ok
                if best is None or score > best["_score"]:
                    best = {"count_off": coff, "ptr_off": poff,
                            "method_count": cnt, "method_pointers_vaddr": ptr,
                            "method_pointers_offset": moff, "_score": score,
                            "struct_offset": base_off,
                            "struct_vaddr": so.off_to_vaddr(base_off)}
    return best


def pick_module(mods, image: str):
    if not mods:
        raise SystemExit(
            "Il2CppCodeGenModule для %r не найден: указатель на строку есть, но\n"
            "правдоподобной пары (methodCount, methodPointers) рядом нет. Возможно,\n"
            "в этой версии Unity поле assemblyName не первое — попробуйте --delta."
            % image)
    # при равном качестве массива предпочитаем delta=0: почти во всех версиях
    # Unity `assemblyName` — первое поле Il2CppCodeGenModule
    mods.sort(key=lambda d: (-d["_score"], -d["method_count"], d["struct_delta"]))
    return mods[0]


def read_rvas(so: So, mod: dict, limit: int | None = None):
    """rid метода (с 1) -> vaddr функции (0 = заглушка/abstract)."""
    out = {}
    moff = mod["method_pointers_offset"]
    n = mod["method_count"] if limit is None else min(limit, mod["method_count"])
    for k in range(n):
        out[k + 1] = so.u64(moff + k * 8)
    return out


# --- подкоманды ---------------------------------------------------------------

def cmd_info(a):
    so = So(a.so)
    print("файл            : %s (%d байт = %.1f МБ)" % (a.so, len(so.data), len(so.data) / 1048576))
    print("архитектура     : %s, %d бит" % (so.machine, so.bits))
    print("PT_LOAD сегменты:")
    for v, o, s, f in so.loads:
        print("  vaddr=0x%-10X offset=0x%-10X size=0x%-10X flags=%s%s"
              % (v, o, s, f, "  (исполняемый)" if f & 1 else ""))
    ex = so.exports()
    print("символов с адресом: %d" % len(ex))
    for pat in ("il2cpp_init", "il2cpp_thread_attach", "il2cpp_domain_get",
                "MetadataCache", "CodeRegistration"):
        hit = [n for n, _, _ in ex if pat.lower() in n.lower()]
        if hit:
            print("  %-18s %s" % (pat, ", ".join(hit[:4])))
    for needle, label in ((META_NAME, "global-metadata.dat"),
                          (GAME_IMAGE.encode(), GAME_IMAGE)):
        hits = so.find_str(needle)
        print("строка %-22s : %d совпадений%s"
              % (label, len(hits),
                 "  первая offset=0x%X vaddr=0x%X" % hits[0] if hits and hits[0][1] else ""))
    return 0


def cmd_module(a):
    so = So(a.so)
    mods = find_codegen_modules(so, a.image)
    print("кандидатов Il2CppCodeGenModule для %r: %d" % (a.image, len(mods)))
    for d in mods[:6]:
        print("  структура offset=0x%X vaddr=%s  methodCount=%d (поле +%d)  "
              "methodPointers vaddr=0x%X offset=0x%X (поле +%d)  delta=%d  годных %d"
              % (d["struct_offset"],
                 "0x%X" % d["struct_vaddr"] if d["struct_vaddr"] else "—",
                 d["method_count"],
                 d["count_off"], d["method_pointers_vaddr"],
                 d["method_pointers_offset"], d["ptr_off"], d["struct_delta"],
                 d["_score"]))
    if not mods:
        return 1
    mod = pick_module(mods, a.image)
    rvas = read_rvas(so, mod)
    nz = sum(1 for v in rvas.values() if v)
    print("\nвыбран: methodCount=%d, ненулевых указателей %d (%.1f %%)"
          % (mod["method_count"], nz, 100 * nz / len(rvas)))
    print("сравнение с метаданными: наш чанк MethodDef игровой сборки — 9 006 "
          "распознанных записей, максимальный rid 9 184.")
    first = [(k, v) for k, v in sorted(rvas.items()) if v][:5]
    for k, v in first:
        o = so.vaddr_to_off(v)
        print("  rid %-6d -> vaddr 0x%X  (offset %s)"
              % (k, v, "0x%X" % o if o is not None else "—"))
    return 0


def cmd_images(a):
    """Перечислить образы (сборки), для которых в .so есть таблица кода.

    Полезно не только справочно: зная methodCount каждой сборки, можно сопоставить
    её с распознанными чанками MethodDef из метаданных (их 240) и тем самым
    подобрать OFF для библиотечных сборок — сейчас он установлен только для
    игровой, поэтому методы Photon/UnityEngine к своим типам не привязаны.
    """
    so = So(a.so)
    names = set()
    for off, _va in so.find_str(b".dll\x00"):
        # find_str возвращает позицию самого ".dll\0", а assemblyName в структуре
        # указывает на НАЧАЛО имени образа — поэтому сначала отходим назад до
        # границы строки, и уже её начало переводим в vaddr.
        start = off
        while start > 0 and 32 <= so.data[start - 1] < 127:
            start -= 1
        nm = so.data[start:off + 4].decode("ascii", "replace")
        va = so.off_to_vaddr(start)
        if len(nm) > 4 and va:
            names.add((nm, va))
    print("строк-кандидатов на имя образа: %d" % len(names))
    rows = []
    for nm, va in sorted(names):
        mods = []
        for ptr_off, _ptr_va in so.find_ptrs(va):
            if not so.writable_off(ptr_off):
                continue
            cand = _try_module(so, ptr_off, va)
            if cand:
                cand["name"] = nm
                # базу берём ровно в позиции указателя, то есть assemblyName —
                # первое поле структуры (delta = 0)
                cand["struct_delta"] = 0
                mods.append(cand)
        if mods:
            mods.sort(key=lambda d: (-d["_score"], -d["method_count"], d["struct_delta"]))
            rows.append(mods[0])
    rows.sort(key=lambda d: -d["method_count"])
    if not rows:
        print("ни одной таблицы кода не найдено")
        return 1
    print("\n%-42s %-10s %s" % ("образ", "методов", "структура / methodPointers"))
    for d in rows:
        print("%-42s %-10d 0x%X -> 0x%X  (count +%d, ptrs +%d)"
              % (d["name"], d["method_count"], d["struct_offset"],
                 d["method_pointers_vaddr"], d["count_off"], d["ptr_off"]))
    print("\nвсего образов с таблицей кода: %d, суммарно методов: %d"
          % (len(rows), sum(d["method_count"] for d in rows)))
    return 0


def cmd_rva(a):
    so = So(a.so)
    mod = pick_module(find_codegen_modules(so, a.image), a.image)
    rvas = read_rvas(so, mod)
    for rid in a.rid:
        va = rvas.get(rid)
        if va is None:
            print("rid %-6d: вне таблицы (methodCount=%d)" % (rid, mod["method_count"]))
        elif va == 0:
            print("rid %-6d: указатель нулевой (abstract / pinvoke / вырезан)" % rid)
        else:
            off = so.vaddr_to_off(va)
            print("rid %-6d: RVA 0x%X   Offset 0x%X" % (rid, va, off if off is not None else -1))
    return 0


def cmd_dump_rvas(a):
    so = So(a.so)
    mod = pick_module(find_codegen_modules(so, a.image), a.image)
    rvas = read_rvas(so, mod)
    # PT_LOAD кладём сюда же: по нему потребитель (tools/il2cpp_dump.py --rvas)
    # переводит vaddr в файловый offset, не перечитывая .so
    out = {"image": a.image, "method_count": mod["method_count"],
           "arch": so.machine, "bits": so.bits,
           "struct_vaddr": mod["struct_vaddr"],
           "method_pointers_vaddr": mod["method_pointers_vaddr"],
           "loads": [list(x) for x in so.loads],
           "rva": {str(k): v for k, v in sorted(rvas.items())}}
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(out))
    nz = sum(1 for v in rvas.values() if v)
    print("# записано %s: methodCount=%d, ненулевых %d" % (a.out, mod["method_count"], nz))
    return 0


def cmd_loader(a):
    so = So(a.so)
    hits = so.find_str(META_NAME)
    if not hits:
        raise SystemExit("строка 'global-metadata.dat' не найдена — загрузчик "
                         "либо не здесь, либо имя склеено иначе")
    print("строка 'global-metadata.dat' в %d местах:" % len(hits))
    for off, va in hits[:6]:
        print("  offset=0x%X vaddr=%s" % (off, "0x%X" % va if va else "—"))
    refs = []
    for _, va in hits:
        if va:
            refs += so.find_ptrs(va)
    print("\nуказателей на строку: %d" % len(refs))
    for off, va in refs[:8]:
        print("  лежит по offset=0x%X vaddr=%s" % (off, "0x%X" % va if va else "—"))
    if not refs:
        print("\nПрямого указателя нет: на ARM64 строку обычно грузят парой "
              "ADRP+ADD, а не указателем в .data. Тогда ищем по-другому — см. "
              "`version` (он сканирует весь исполняемый сегмент на ADRP, "
              "нацеленный на страницу строки).")
    return 0


def _adrp_targets(so: So, va_page: int):
    """Найти ADRP, нацеленные на страницу `va_page`, в исполняемых сегментах."""
    out = []
    for ins in _all_exec_insns(so):
        if ins.mnemonic == "adrp":
            m = re.search(r"#(0x[0-9a-fA-F]+)", ins.op_str)
            if m and int(m.group(1), 16) == va_page:
                out.append(ins)
    return out


def _all_exec_insns(so: So, step_limit: int = 4_000_000):
    """Линейная развёртка исполняемых сегментов (для поиска ADRP/CMP)."""
    if cs is None:
        raise SystemExit("capstone не установлен")
    arch, mode = so._cs_arch()
    md = cs.Cs(arch, mode)
    for v, o, s, f in so.loads:
        if not f & 1:
            continue
        code = so.data[o:o + s]
        n = 0
        for ins in md.disasm(code, v):
            yield ins
            n += 1
            if n > step_limit:
                return


def cmd_version(a):
    so = So(a.so)
    print("Ищем признаки версии метаданных по коду вокруг 'global-metadata.dat'.")
    hits = [va for _, va in so.find_str(META_NAME) if va]
    if not hits:
        print("строка не найдена — версия по этому признаку не определяется")
        return 1
    page = hits[0] & ~0xFFF
    print("страница строки: 0x%X" % page)
    adrp = _adrp_targets(so, page)
    print("ADRP на эту страницу: %d" % len(adrp))
    imm_hits = {}
    for ins in adrp[: a.sites or len(adrp)]:
        window = so.disasm(ins.address - 0x100, 200)
        for w in window:
            if w.mnemonic in ("cmp", "subs", "mov") and w.op_str.startswith(("w", "x")):
                m = re.search(r"#(0x[0-9a-fA-F]+|\d+)$", w.op_str)
                if not m:
                    continue
                val = int(m.group(1), 0)
                if val in VERSION_RANGE:
                    imm_hits.setdefault(val, []).append((ins.address, w.address,
                                                         "%s %s" % (w.mnemonic, w.op_str)))
    if not imm_hits:
        print("сравнений с версиями 16..31 рядом не найдено (окно ±0x100 байт)")
        return 1
    print("\nнайденные immediates (версия метаданных обычно среди них):")
    for val in sorted(imm_hits):
        sites = imm_hits[val]
        print("  %-4d  %d раз   первый: ADRP@0x%X  %s @0x%X"
              % (val, len(sites), sites[0][0], sites[0][2], sites[0][1]))
    print("\nТрактовка: максимумы этой таблицы — версии, которые бинарник умеет "
          "читать. Если 24 и 24.5 в одной строке не различимы (в коде это одно "
          "число 24), окончательный ответ даёт раскладка записей, а она у нас "
          "уже подтверждена эмпирически (TypeDef 76/MethodDef 30 в исходнике).")
    return 0


def cmd_disasm(a):
    so = So(a.so)
    mod = pick_module(find_codegen_modules(so, a.image), a.image)
    rvas = read_rvas(so, mod)
    va = rvas.get(a.rid)
    if not va:
        raise SystemExit("rid %d: указатель нулевой или вне таблицы (methodCount=%d)"
                         % (a.rid, mod["method_count"]))
    print("rid %d  RVA 0x%X  Offset 0x%X" % (a.rid, va, so.vaddr_to_off(va)))
    label = a.label
    print("// %s" % label if label else "// (имя метода подставь из Dump.cs)")
    for ins in so.disasm(va, a.count):
        mark = ""
        if ins.mnemonic in ("bl", "b", "blr"):
            mark = "   ; <-- вызов/переход"
        print("0x%-10X %-10s %-38s%s" % (ins.address, ins.mnemonic, ins.op_str, mark))
        if ins.mnemonic == "ret":
            break
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp, image=True):
        sp.add_argument("so", help="путь к libil2cpp.so (обычно apk/libil2cpp.so)")
        if image:
            sp.add_argument("--image", default=GAME_IMAGE,
                            help="имя образа (по умолчанию %s)" % GAME_IMAGE)

    sp = sub.add_parser("info", help="ELF: сегменты, экспорты, ключевые строки")
    common(sp, image=False); sp.set_defaults(fn=cmd_info)

    sp = sub.add_parser("module", help="найти Il2CppCodeGenModule и methodPointers")
    common(sp); sp.set_defaults(fn=cmd_module)

    sp = sub.add_parser("images", help="все образы (сборки) и их methodCount")
    common(sp, image=False); sp.set_defaults(fn=cmd_images)

    sp = sub.add_parser("rva", help="RVA/Offset метода по rid")
    common(sp); sp.add_argument("--rid", type=int, action="append", required=True,
                                help="rid метода (можно несколько раз)")
    sp.set_defaults(fn=cmd_rva)

    sp = sub.add_parser("dump-rvas", help="выгрузить таблицу rid->RVA в JSON")
    common(sp); sp.add_argument("-o", "--out", default="work/method_rvas.json")
    sp.set_defaults(fn=cmd_dump_rvas)

    sp = sub.add_parser("loader", help="где открывается global-metadata.dat")
    common(sp, image=False); sp.set_defaults(fn=cmd_loader)

    sp = sub.add_parser("version", help="признаки версии метаданных в коде")
    common(sp, image=False)
    sp.add_argument("--sites", type=int, default=0, help="сколько ADRP-сайтов смотреть (0 = все)")
    sp.set_defaults(fn=cmd_version)

    sp = sub.add_parser("disasm", help="дизассемблер метода по rid")
    common(sp); sp.add_argument("--rid", type=int, required=True)
    sp.add_argument("--count", type=int, default=80, help="сколько инструкций")
    sp.add_argument("--label", default="", help="подпись (имя метода) для печати")
    sp.set_defaults(fn=cmd_disasm)

    a = p.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
