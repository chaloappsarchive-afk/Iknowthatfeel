#!/usr/bin/env python3
"""Синтетический `global-metadata.dat` в упаковке Chicken Gun — для регрессий связки.

`make_fake_metadata.py` строит **валидный** файл v24.5 с заголовком: он проверяет
`il2cpp_meta.py`. Этот генератор строит файл в той упаковке, в которой лежит реальный
`apk/global-metadata.dat`: без заголовка, с таблицами, разбросанными по файлу
«решётками» невыровненных записей. На нём проверяются правила, которые были
установлены на реальном файле и которые легко сломать по неосторожности:

1. **индекс типа — порядковый номер записи, а не rid её токена.** Записи TypeDef
   внутри чанка переставлены, поэтому `declaringType = OFF + k`, где `k` — позиция
   записи. Фикстура переставляет токены так, что связка по rid даёт заведомо худший
   счёт `solve_type_off`, чем связка по позиции;
2. **хвост региона методов принадлежит следующей сборке.** Последняя запись региона
   ссылается на тип соседней сборки (`dt` вне своего диапазона) — `split_tail()`
   обязан отсечь ровно её;
3. **родство по vtable восстанавливается парой (имя виртуала, slot)**, а не одним
   slot: `infer_base_classes()` должен найти посаженную пару `CarController : Vehicle`
   и не должен находить связь по случайному совпадению slot у разных имён;
4. **решётка останавливается на границе чанка** (повтор rid / чужой тег), а не
   расползается на соседнюю сборку.

Использование:

    python3 tools/tests/make_scattered_metadata.py [out.dat]   # записать файл
    python3 tools/tests/test_scattered.py                      # прогнать проверки

Файл намеренно НЕ зашифрован: поблочный XOR проверяется на реальном
`global-metadata.dat` (`il2cpp_decrypt.py heal`), а правила связки от шифрования
не зависят.
"""
import struct
import sys

# ---------------------------------------------------------------------------
# раскладки записей — те же константы, что в tools/il2cpp_tables.py
TYPE_STRIDE, TYPE_TOK, TYPE_NAME, TYPE_NS = 76, 68, 72, 0
METH_STRIDE, METH_TOK, METH_NAME, METH_DECL = 30, 12, 24, 28
METH_PSTART, METH_FLAGS, METH_SLOT, METH_PCOUNT = 6, 16, 20, 22
TAG_TYPE, TAG_METHOD = 0x02, 0x06

# флаги MethodDef (ECMA-335, младшие 3 бита — MemberAccess)
F_PRIVATE, F_PUBLIC = 0x01, 0x06
F_VIRTUAL, F_HIDEBYSIG, F_NEWSLOT, F_ABSTRACT = 0x40, 0x80, 0x100, 0x400

HEAP_BASE = 0x1000          # база кучи имён (m.B): строка с индексом i лежит на B+i
# Базы намеренно НЕ кратны 4: в реальном файле записи невыровненные, и инструмент,
# который молча предполагает выравнивание, должен на этой фикстуре упасть.
TA, TB = 0x4002, 0x4202     # чанки TypeDef: сборка A, затем сборка B
MA = 0x2006                 # чанк MethodDef сборки A
MB = 0x3002                 # чанк MethodDef сборки B
OFF_A, OFF_B = 100, 106     # dt = OFF + номер записи; диапазоны смежные, как в файле

# Сборка A. Порядок в списке = ПОРЯДОК ХРАНЕНИЯ (k = 1..N), token rid переставлен.
# Имена подобраны так, чтобы solve_type_off имел обязывающие типы:
#   <MoveObject>d__13  — итератор: обязан иметь MoveNext
#   <>c                — лямбда-класс: только .ctor и <…>b__…
TYPES_A = [
    ('GameController',      'ChickenGun', 3),
    ('<MoveObject>d__13',   '',           1),
    ('<>c',                 '',           6),
    ('Vehicle',             'ChickenGun', 2),
    ('CarController',       'ChickenGun', 5),
    ('BotController',       'ChickenGun.AI', 4),
]
# (k типа, имя метода, число параметров, flags, slot)
METHODS_A = [
    (1, 'Awake',                        0, F_PUBLIC | F_HIDEBYSIG, None),
    (1, 'Start',                        0, F_PUBLIC | F_HIDEBYSIG, None),
    (1, 'CleanTiters',                  0, F_PUBLIC | F_HIDEBYSIG, None),
    (2, '.ctor',                        1, F_PRIVATE | F_HIDEBYSIG, None),
    (2, 'MoveNext',                     0, F_PUBLIC | F_VIRTUAL | F_HIDEBYSIG, 5),
    (2, 'System.IDisposable.Dispose',   1, F_PRIVATE | F_VIRTUAL | F_HIDEBYSIG, None),
    (3, '.ctor',                        0, F_PUBLIC | F_HIDEBYSIG, None),
    (3, '<CleanTiters>b__88_0',         1, F_PUBLIC | F_HIDEBYSIG, None),
    # Vehicle ОБЪЯВЛЯЕТ виртуалы (NewSlot), CarController ПЕРЕОПРЕДЕЛЯЕТ (без NewSlot):
    # две совпавшие пары (имя, slot) — порог infer_base_classes(min_links=2)
    (4, 'Explode',                      0, F_PUBLIC | F_VIRTUAL | F_HIDEBYSIG | F_NEWSLOT, 7),
    (4, 'Move',                         1, F_PUBLIC | F_VIRTUAL | F_HIDEBYSIG | F_NEWSLOT, 8),
    (5, 'Explode',                      0, F_PUBLIC | F_VIRTUAL | F_HIDEBYSIG, 7),
    (5, 'Move',                         1, F_PUBLIC | F_VIRTUAL | F_HIDEBYSIG, 8),
    # ловушка: тот же slot 7, но другое имя и другой тип — связью быть не должно
    (6, 'DestroySelf',                  0, F_PUBLIC | F_VIRTUAL | F_HIDEBYSIG | F_NEWSLOT, 7),
    (6, 'DieR',                         1, F_PUBLIC | F_HIDEBYSIG, None),
]
# хвост региона A: rid продолжается, а dt указывает на тип сборки B
TAIL_A = ('CreateWebRequest', 3, F_PUBLIC | F_HIDEBYSIG, None, OFF_B + 1)

TYPES_B = [
    ('AssetDownloader',      'TriLibCore', 1),
    ('HttpRequestMethod',    '',          2),
    ('<DownloadAsset>d__3',  '',          3),
    ('<>c',                  'TriLibCore', 4),
]
METHODS_B = [
    (1, 'LoadModelFromUri',             4, F_PUBLIC | F_HIDEBYSIG, None),
    (1, '.ctor',                        0, F_PUBLIC | F_HIDEBYSIG, None),
    (3, '.ctor',                        1, F_PRIVATE | F_HIDEBYSIG, None),
    (3, 'MoveNext',                     0, F_PUBLIC | F_VIRTUAL | F_HIDEBYSIG, 5),
    (4, '.ctor',                        0, F_PUBLIC | F_HIDEBYSIG, None),
    (4, '<DownloadAsset>b__0',          1, F_PUBLIC | F_HIDEBYSIG, None),
]


class Heap(object):
    """Куча имён: строка с индексом i начинается на B+i (как в реальном файле).

    Индекс 0 — пустая строка: на B лежит один NUL, он же служит границей для
    строки с индексом 1 (`raw_name()` требует, чтобы байт перед строкой был нулём).
    """

    def __init__(self, base):
        self.base = base
        self.buf = bytearray(b'\x00')      # B+0: пустая строка и граница для B+1
        self.idx = {}

    def add(self, s):
        if s in self.idx:
            return self.idx[s]
        off = len(self.buf)
        self.buf.extend(s.encode('ascii') + b'\x00')
        self.idx[s] = off
        return off


def _type_rec(heap, name, ns, token_rid):
    rec = bytearray(TYPE_STRIDE)
    struct.pack_into('<i', rec, TYPE_NS, heap.add(ns) if ns else -1)
    struct.pack_into('<I', rec, TYPE_TOK, (TAG_TYPE << 24) | token_rid)
    struct.pack_into('<I', rec, TYPE_NAME, heap.add(name))
    return rec


def _meth_rec(heap, token_rid, name, nparams, flags, slot, dt):
    rec = bytearray(METH_STRIDE)
    struct.pack_into('<H', rec, METH_PSTART, 0xFFFF)
    struct.pack_into('<I', rec, METH_TOK, (TAG_METHOD << 24) | token_rid)
    struct.pack_into('<I', rec, METH_FLAGS, flags)
    struct.pack_into('<H', rec, METH_SLOT, 0xFFFF if slot is None else slot)
    struct.pack_into('<H', rec, METH_PCOUNT, nparams)
    struct.pack_into('<I', rec, METH_NAME, heap.add(name))
    struct.pack_into('<H', rec, METH_DECL, dt)
    return rec


def build(off_a=OFF_A, off_b=OFF_B):
    """Собрать blob. Возвращает (blob, info) — info нужен тесту для ожиданий."""
    heap = Heap(HEAP_BASE)
    size = 0x6000
    blob = bytearray(size)

    # --- чанки TypeDef: записи кладутся ПО ПОРЯДКУ ХРАНЕНИЯ, токены переставлены
    def put_rec(pos, rec):
        blob[pos:pos + len(rec)] = rec        # срез bytearray — копия, [:] = не работает

    for k, (nm, ns, tok) in enumerate(TYPES_A, start=1):
        put_rec(TA + (k - 1) * TYPE_STRIDE, _type_rec(heap, nm, ns, tok))
    for k, (nm, ns, tok) in enumerate(TYPES_B, start=1):
        put_rec(TB + (k - 1) * TYPE_STRIDE, _type_rec(heap, nm, ns, tok))

    # --- чанки MethodDef: rid идёт подряд, dt = OFF + ПОЗИЦИЯ типа
    def put(base, off, rows, start_rid=1):
        rid = start_rid
        for k, nm, np_, fl, slot in rows:
            put_rec(base + (rid - 1) * METH_STRIDE,
                    _meth_rec(heap, rid, nm, np_, fl, slot, off + k))
            rid += 1
        return rid

    tail_rid = put(MA, off_a, METHODS_A)
    put_rec(MA + (tail_rid - 1) * METH_STRIDE,
            _meth_rec(heap, tail_rid, TAIL_A[0], TAIL_A[1], TAIL_A[2], TAIL_A[3], TAIL_A[4]))
    put(MB, off_b, METHODS_B)

    # куча заполняется в конце: строки добавлялись по мере записи таблиц
    assert HEAP_BASE + len(heap.buf) < MA, 'куча наехала на таблицы'
    blob[HEAP_BASE:HEAP_BASE + len(heap.buf)] = heap.buf

    info = {
        'heap_base': HEAP_BASE, 'TA': TA, 'TB': TB, 'MA': MA, 'MB': MB,
        'off_a': off_a, 'off_b': off_b,
        'types_a': len(TYPES_A), 'types_b': len(TYPES_B),
        'methods_a_own': len(METHODS_A), 'tail_rid': tail_rid,
        'tail_name': TAIL_A[0], 'tail_dt': TAIL_A[4],
        'methods_b': len(METHODS_B),
        # k-позиции, у которых token rid расходится с номером записи
        'permuted_a': sum(1 for k, (_, _, tok) in enumerate(TYPES_A, 1) if tok != k),
        'base_pair': ('CarController', 'Vehicle', 2),
        'trap': ('BotController', 7),   # slot 7 совпал, имя — нет: связью быть не должно
    }
    return bytes(blob), info


def main(argv):
    out = argv[1] if len(argv) > 1 else 'work/fake-scattered.dat'
    blob, info = build()
    with open(out, 'wb') as f:
        f.write(blob)
    print('записано %s (%d байт)' % (out, len(blob)))
    for k in ('TA', 'TB', 'MA', 'MB', 'off_a', 'off_b', 'types_a', 'types_b',
              'methods_a_own', 'tail_rid', 'tail_name', 'tail_dt', 'methods_b',
              'permuted_a'):
        print('  %-14s %s' % (k, info[k]))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
