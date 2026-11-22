#!/usr/bin/env python3
"""Синтетический ARM64 libil2cpp.so для смоук-теста tools/il2cpp_so.py.

    python3 tools/tests/make_fake_so.py work/fake-libil2cpp.so

Строит минимальный ELF (ET_DYN, EM_AARCH64, без section headers) с тремя
PT_LOAD-сегментами и раскладывает в них то, что ищет il2cpp_so.py:

  .rodata   строки "Assembly-CSharp.dll" и "global-metadata.dat";
  .text     несколько функций (nop/ret/bl) плюс пара ADRP+ADD, грузящая адрес
            "global-metadata.dat", и `cmp w0, #24` рядом с ней — это имитация
            проверки версии метаданных в загрузчике;
  .data     структура Il2CppCodeGenModule (assemblyName, methodCount,
            methodPointers) и сам массив указателей на код, где один элемент
            нулевой (abstract-метод).

Ничего общего с реальным бинарником игры: файл нужен только чтобы проверить,
что поиск структуры, перевод vaddr<->offset и дизассемблер работают, ДО того как
в apk/ появится настоящий libil2cpp.so на десятки мегабайт.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

# --- адреса сегментов ---------------------------------------------------------
TEXT_VA, TEXT_OFF = 0x1000, 0x1000
RO_VA, RO_OFF = 0x10000, 0x10000
DATA_VA, DATA_OFF = 0x20000, 0x20000

NOP = 0xD503201F
RET = 0xD65F03C0


def bl(delta_bytes: int) -> int:
    """BL на смещение delta_bytes (знаковое, кратно 4)."""
    return 0x94000000 | ((delta_bytes >> 2) & 0x03FFFFFF)


def subs_imm32(rn: int, imm: int) -> int:
    """CMP Wn, #imm (это SUBS WZR, Wn, #imm)."""
    return 0x71000000 | ((imm & 0xFFF) << 10) | (rn << 5) | 31


def adrp(rd: int, here: int, target_page: int) -> int:
    """ADRP Xrd, #страница — imm считается от страницы текущей инструкции."""
    imm = (target_page - (here & ~0xFFF)) >> 12
    return 0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | rd


def add_imm64(rd: int, rn: int, imm: int) -> int:
    """ADD Xrd, Xrn, #imm (12 бит, без сдвига)."""
    return 0x91000000 | ((imm & 0xFFF) << 10) | (rn << 5) | rd


def movz(rd: int, imm: int) -> int:
    return 0xD2800000 | ((imm & 0xFFFF) << 5) | rd


def build() -> bytes:
    # --- .rodata -------------------------------------------------------------
    ro = bytearray()
    name_va = RO_VA + len(ro)
    ro += b"Assembly-CSharp.dll\x00"
    while len(ro) % 8:
        ro += b"\x00"
    meta_va = RO_VA + len(ro)
    ro += b"global-metadata.dat\x00"

    # --- .text ---------------------------------------------------------------
    # Функции методов. Индексы = rid-1 в таблице methodPointers.
    # Методов должно быть >= 100: столько требует фильтр ложных срабатываний в
    # il2cpp_so._try_module (у настоящей игровой сборки их ~9 тысяч).
    N_METHODS = 120
    funcs: dict[int, int] = {}          # rid -> vaddr (0 = null)
    text = bytearray()

    def emit(words: list[int]) -> int:
        va = TEXT_VA + len(text)
        # именно extend, а не `text += ...`: дополняющее присваивание сделало бы
        # `text` локальной переменной этой вложенной функции. extend принимает
        # bytes как последовательность целых, поэтому слова склеиваем заранее.
        text.extend(b"".join(struct.pack("<I", w) for w in words))
        return va

    for rid in range(1, N_METHODS + 1):
        if rid == 1:
            funcs[rid] = emit([NOP, NOP, RET])
        elif rid == 2:
            # вызов другой функции и возврат — на нём проверяется disasm
            funcs[rid] = TEXT_VA + len(text)
            text.extend(struct.pack("<II", bl(0x40), RET))
        elif rid == 3:
            funcs[rid] = 0                  # abstract/pinvoke: нулевой указатель
        elif rid == 4:
            funcs[rid] = emit([movz(0, 7), RET])
        elif rid == 7:
            funcs[rid] = emit([NOP, NOP, NOP, RET])
        else:
            funcs[rid] = emit([RET])

    # «Загрузчик метаданных»: ADRP+ADD на строку global-metadata.dat и проверка
    # версии cmp w0, #24 — именно такую последовательность ищет `version`.
    here = TEXT_VA + len(text)
    text += struct.pack("<I", adrp(0, here, meta_va & ~0xFFF))
    text += struct.pack("<I", add_imm64(0, 0, meta_va & 0xFFF))
    text += struct.pack("<I", subs_imm32(0, 24))
    text += struct.pack("<I", NOP)
    text += struct.pack("<I", RET)

    # --- .data.rel.ro --------------------------------------------------------
    data = bytearray()
    mod_va = DATA_VA + len(data)
    ptrs_va = mod_va + 0x100              # массив указателей чуть дальше
    data += struct.pack("<Q", name_va)    # +0x00 assemblyName
    data += struct.pack("<II", len(funcs), 0)   # +0x08 methodCount, adjustorThunkCount
    data += struct.pack("<Q", 0)          # +0x10 adjustorThunks
    data += struct.pack("<Q", 0)          # +0x18 tokenRanges
    data += struct.pack("<Q", ptrs_va)    # +0x20 methodPointers
    while len(data) < 0x100:
        data += b"\x00"
    assert DATA_VA + len(data) == ptrs_va, (len(data), ptrs_va)
    for rid in sorted(funcs):
        data += struct.pack("<Q", funcs[rid])

    # --- ELF -----------------------------------------------------------------
    segs = [
        (TEXT_VA, TEXT_OFF, len(text), 5),     # R+X
        (RO_VA, RO_OFF, len(ro), 4),           # R
        (DATA_VA, DATA_OFF, len(data), 6),     # R+W
    ]
    ehsize, phentsize = 64, 56
    ehdr = struct.pack(
        "<4sBBBBB7sHHIQQQIHHHHHH",
        b"\x7fELF", 2, 1, 1, 0, 0, b"\x00" * 7,
        3,                 # e_type = ET_DYN
        183,               # e_machine = EM_AARCH64
        1,                 # e_version
        TEXT_VA,           # e_entry
        ehsize,            # e_phoff
        0,                 # e_shoff (section headers отсутствуют)
        0,                 # e_flags
        ehsize, phentsize, len(segs), 64, 0, 0,
    )
    assert len(ehdr) == ehsize, len(ehdr)

    out = bytearray(ehdr)
    for va, off, sz, flags in segs:
        out += struct.pack("<IIQQQQQQ", 1, flags, off, va, va, sz, sz, 0x1000)
    assert len(out) == ehsize + phentsize * len(segs)

    for va, off, sz, _flags in segs:
        blob = {TEXT_VA: text, RO_VA: ro, DATA_VA: data}[va]
        assert len(blob) == sz
        out += b"\x00" * (off - len(out))
        out += blob
    return bytes(out), {"name_va": name_va, "meta_va": meta_va, "mod_va": mod_va,
                        "ptrs_va": ptrs_va, "funcs": funcs}


def main() -> int:
    dst = sys.argv[1] if len(sys.argv) > 1 else "work/fake-libil2cpp.so"
    blob, info = build()
    Path(dst).parent.mkdir(parents=True, exist_ok=True)
    Path(dst).write_bytes(blob)
    print("# записано %s (%d байт)" % (dst, len(blob)))
    for k in ("name_va", "meta_va", "mod_va", "ptrs_va"):
        print("#   %-9s 0x%X" % (k, info[k]))
    print("#   methodCount=%d, нулевой указатель у rid=%s"
          % (len(info["funcs"]),
             [r for r, v in info["funcs"].items() if not v]))
    print("# проверка:  .venv/bin/python tools/il2cpp_so.py module %s" % dst)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
