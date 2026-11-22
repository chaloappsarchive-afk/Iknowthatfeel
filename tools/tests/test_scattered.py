#!/usr/bin/env python3
"""Регрессии связки «метод → тип» на синтетическом файле (`make_scattered_metadata.py`).

Прогон:

    .venv/bin/python tools/tests/test_scattered.py

Проверяются правила, установленные на реальном `apk/global-metadata.dat`
(доказательства — `analysis/metadata-repair.md` §1.6 и `analysis/photon-assembly.md`):

1. индекс типа = ПОРЯДОК записи в чанке, а не rid её токена (`solve_type_off`);
2. хвост региона методов принадлежит следующей сборке (`split_tail`);
3. решётка не расползается на соседний чанк (`lattice_types`/`lattice_methods`);
4. родство по vtable — пара (имя виртуала, slot), а не один slot
   (`infer_base_classes`), и совпадение slot при разных именах связью не считается.

pytest не требуется: скрипт печатает результаты и возвращает код 1 при провале.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))

import il2cpp_tables as T                      # noqa: E402
from make_scattered_metadata import build      # noqa: E402

FAILED = []
PASSED = [0]


def check(what, got, want):
    if got == want:
        PASSED[0] += 1
        print('  ok   %-58s %s' % (what, got if not isinstance(got, (list, dict)) else
                                   '%d элем.' % len(got)))
    else:
        FAILED.append(what)
        print('  FAIL %-58s получили %r, ждали %r' % (what, got, want))


def main():
    blob, info = build()
    m = T.Meta(blob, info['heap_base'])
    off_a, off_b = info['off_a'], info['off_b']

    # -- 1. чанки типов: решётка, перестановка, граница -----------------------
    print('\n[1] чанк TypeDef сборки A')
    lat_a = T.lattice_types(m, info['TA'])
    check('записей в чанке A (решётка не ушла в чанк B)', len(lat_a), info['types_a'])
    by_pos, toks = T.type_positions(lat_a)
    check('номера записей A', sorted(by_pos), list(range(1, info['types_a'] + 1)))
    check('переставленных токенов (rid != номер записи)',
          sum(1 for k in by_pos if (toks[k] & 0xFFFFFF) != k), info['permuted_a'])
    check('имя k=1 (namespace + имя)', T.class_name(m, by_pos[1]), 'ChickenGun.GameController')
    check('имя k=2', T.class_name(m, by_pos[2]), '<MoveObject>d__13')
    check('имя k=3', T.class_name(m, by_pos[3]), '<>c')

    print('\n[2] чанк TypeDef сборки B')
    lat_b = T.lattice_types(m, info['TB'])
    check('записей в чанке B', len(lat_b), info['types_b'])
    by_pos_b, toks_b = T.type_positions(lat_b)
    check('имя B k=1', T.class_name(m, by_pos_b[1]), 'TriLibCore.AssetDownloader')
    check('имя B k=3', T.class_name(m, by_pos_b[3]), '<DownloadAsset>d__3')

    # -- 2. чанки методов ----------------------------------------------------
    print('\n[3] чанк MethodDef')
    meth_a = T.lattice_methods(m, info['MA'])
    check('записей в регионе A (свои + хвост)', len(meth_a),
          info['methods_a_own'] + 1)
    meth_b = T.lattice_methods(m, info['MB'])
    check('записей в регионе B (решётка не смешала чанки)', len(meth_b), info['methods_b'])
    check('rid хвоста', max(meth_a), info['tail_rid'])
    check('имя хвоста', m.raw_name(m.u32(meth_a[info['tail_rid']], T.METH_NAME)),
          info['tail_name'])
    check('dt хвоста (указывает на сборку B)',
          m.u16(meth_a[info['tail_rid']], T.METH_DECL), info['tail_dt'])
    check('dt хвоста = OFF_B + 1, то есть тип B k=1', info['tail_dt'], off_b + 1)

    # -- 3. связка: позиция против токена ------------------------------------
    print('\n[4] связка declaringType = OFF + ПОРЯДОК записи')
    offs = range(off_a - 4, off_a + 5)
    pos_off, pos_scored = T.solve_type_off(m, by_pos, meth_a, offs)
    tok_off, tok_scored = T.solve_type_off(m, lat_a, meth_a, offs)
    check('OFF по позиции записи', pos_off, off_a)
    check('OFF по rid токена (должен отличаться)', tok_off != off_a, True)
    check('счёт по позиции лучше счёта по токену',
          pos_scored[pos_off][0] > tok_scored[tok_off][0], True)
    check('по позиции согласовано все обязывающие типы',
          pos_scored[pos_off], (pos_scored[pos_off][1], pos_scored[pos_off][1]))
    off_b_solved, sc_b = T.solve_type_off(m, by_pos_b, meth_b, range(off_b - 4, off_b + 5))
    check('OFF сборки B', off_b_solved, off_b)
    check('счёт по B', sc_b[off_b_solved], (sc_b[off_b_solved][1], sc_b[off_b_solved][1]))

    # владельцы при правильной связке
    def owner_name(rec):
        if rec is None:
            return None
        k = m.u16(rec, T.METH_DECL) - off_a
        return T.class_name(m, by_pos[k]) if k in by_pos else None

    def rid_of(name):
        for r, rec in meth_a.items():
            if m.raw_name(m.u32(rec, T.METH_NAME)) == name:
                return r, rec
        return None, None

    for meth, want in (('CleanTiters', 'ChickenGun.GameController'),
                       ('MoveNext', '<MoveObject>d__13'),
                       ('<CleanTiters>b__88_0', '<>c'),
                       ('DieR', 'ChickenGun.AI.BotController')):
        _, rec = rid_of(meth)
        check('владелец %s' % meth, owner_name(rec), want)

    # -- 4. хвост ------------------------------------------------------------
    print('\n[5] split_tail: хвост региона принадлежит следующей сборке')
    own_a, tail_a = T.split_tail(m, meth_a, off_a, len(by_pos))
    check('своих методов A', len(own_a), info['methods_a_own'])
    check('хвостов A', [(r, dt, nm) for r, dt, nm in tail_a],
          [(info['tail_rid'], info['tail_dt'], info['tail_name'])])
    own_b, tail_b = T.split_tail(m, meth_b, off_b, len(by_pos_b))
    check('своих методов B', len(own_b), info['methods_b'])
    check('хвостов у B нет', tail_b, [])
    check('после split_tail чужих dt в A не осталось',
          sorted({m.u16(rec, T.METH_DECL) for rec in own_a.values()}
                 - set(range(off_a + 1, off_a + len(by_pos) + 1))), [])

    # -- 5. родство по vtable -------------------------------------------------
    print('\n[6] infer_base_classes: пара (имя виртуала, slot)')
    bases = T.infer_base_classes(m, by_pos, own_a, off_a)
    k_car = next(k for k in by_pos if T.class_name(m, by_pos[k]) == 'ChickenGun.CarController')
    k_veh = next(k for k in by_pos if T.class_name(m, by_pos[k]) == 'ChickenGun.Vehicle')
    k_bot = next(k for k in by_pos if T.class_name(m, by_pos[k]) == 'ChickenGun.AI.BotController')
    check('найдена ровно одна связь', len(bases), 1)
    check('потомок — CarController', sorted(bases), [k_car])
    check('предок — Vehicle', bases[k_car][0], k_veh)
    check('совпавшие виртуалы', bases[k_car][1], [('Explode', 7), ('Move', 8)])
    check('BotController предком не обзавёлся (slot 7 при другом имени — не связь)',
          k_bot in bases, False)
    check('порог min_links=1 добавил бы ложную пару? (проверка на 2)',
          len(T.infer_base_classes(m, by_pos, own_a, off_a, min_links=2)), 1)

    # -- 6. свойства решётки: невыровненность ---------------------------------
    print('\n[7] решётка')
    check('база чанка A не кратна 4 (записи невыровненные)', info['TA'] % 4, 2)
    check('база региона методов A не кратна 4', info['MA'] % 4, 2)
    check('адрес k=3 = база + 2*76', by_pos[3], info['TA'] + 2 * T.TYPE_STRIDE)
    check('адрес rid 2 метода A = база + 30', meth_a[2], info['MA'] + T.METH_STRIDE)

    print('\n%s' % ('=' * 70))
    if FAILED:
        print('ПРОВАЛЕНО: %d из %d (%s)' % (len(FAILED), len(FAILED) + PASSED[0],
                                            '; '.join(FAILED)))
        return 1
    print('ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ: %d' % PASSED[0])
    return 0


if __name__ == '__main__':
    sys.exit(main())
