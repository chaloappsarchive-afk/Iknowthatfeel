# `GameController.CleanTiters` — что это и что оно чистит

Задача: понять, относится ли `CleanTiters` к удалению ботов.
**Ответ: нет.** Это зачистка в конце матча (Battle Royale), и работает она по
**игрокам** (`CharacterMotor`), а не по ботам. Ниже — всё, что удаётся доказать
по метаданным, и то, что остаётся гипотезой.

---

## 1. Факты о методе

```
класс      GameController        (тип rid=486, globalTypeIndex 3886)
запись     0x424C80              (чанк методов 0x411540)
rid        2657
имя        CleanTiters           nameIndex = 528811
параметров 1                     parameterStart != 0xFFFF, parameterCount = 1
slot       0xFFFF                невиртуальный
flags      0x81                  Private | HideBySig  -> private void
+0         36310                 (см. §6 — колонка ненадёжна)
```

Место в классе (порядковый номер метода = порядок объявления):

```
2652  StartBattleRoyaleGame          0 пар.
2653  StartBattleRoyaleR             0 пар.   (RPC)
2654  CheckBattleRoyaleAlives        0 пар.   -> 4 лямбды b__81_0..3
2655  BattleRoyalePvPFinishedR       0 пар.   (RPC)
2656  BattleRoyaleTeamsFinishedR     1 пар.   (RPC)
2657  CleanTiters                    1 пар.   <-- private
2658  SyncSavedLightningParams       0 пар.
2659  ReadAndApplyCustomPropsLightningParams  1 пар.
```

То есть метод стоит в хвосте battle-royale-ветки класса, сразу за
`BattleRoyaleTeamsFinishedR` — на пути «матч закончился → объявили победителя →
что-то почистили».

## 2. Как он скомпилирован: одна лямбда + кэшированный делегат

```
<>c.<CleanTiters>b__88_0     тип GameController+<>c (rid 476, dt 3876)
                             rid 2681, 1 параметр, flags 0x83 (internal, final)
кэш делегата                 поле <>9__88_0 в куче (индекс 529948+)
имя параметра лямбды         'it' (индекс 529886, вплотную к имени лямбды)
```

Блок кучи (индексы 529733–529947) — все лямбды `GameController+<>c` подряд:

```
529733  <CheckBattleRoyaleAlives>b__81_0
529766  <CheckBattleRoyaleAlives>b__81_1
529799  <CheckBattleRoyaleAlives>b__81_2
529832  <CheckBattleRoyaleAlives>b__81_3
529865  <CleanTiters>b__88_0
529886  it                                    <-- параметр лямбды
529889  <IsVehiclesLimitReached>b__97_0
529921  <CheckIsSpawnedBot>b__99_0
529948  <>9__81_0  <>9__81_1  <>9__81_2  <>9__81_3  <>9__88_0  <>9__97_0  <>9__99_0
```

`<>9__NN_M` — стандартное поле кэша делегата Roslyn для статической
(незахватывающей) лямбды `<метод>b__NN_M`. Значит предикат передаётся
**делегатом**, то есть `CleanTiters` — это перебор коллекции в LINQ-стиле:

```csharp
private void CleanTiters(??? x)                     // реконструкция
{
    // коллекция игроков/моторов, фильтр предикатом it => ..., кэш <>9__88_0
    foreach (var it in players.Where(it => <условие>))
        it.titer = <null/0/false>;                  // или Object.Destroy(it.titer)
}
```

Display-класса (`<>c__DisplayClass88_0`) у метода **нет** — значит лямбда
ничего не захватывает, кроме, возможно, `this`.

## 3. Соседство в куче: `winnerId`

```
528778  CheckBattleRoyaleAlives   метод rid 2654 (0 пар.)
528802  winnerId                  непокрытая строка (поле или параметр)
528811  CleanTiters               метод rid 2657 (1 пар.)
528823  lightningParams           непокрытая строка (поле: SyncSavedLightningParams 0 пар.)
```

`winnerId` стоит вплотную перед `CleanTiters`, у которого ровно один параметр →
наиболее вероятная сигнатура **`CleanTiters(int winnerId)`**.
Строго доказать нельзя: правило «имена параметров печатаются перед именем
метода» подтверждается лишь частично (см. `analysis/bot-lifecycle.md` §7),
а `lightningParams` в той же позиции — явно поле, а не параметр.

Другие «победительные» имена в куче: `winner` (520607), `winnerNameText`
(520652), `WinnerTeam` (521660), `winnerTeam` (521813), `GetWinnerTeam`
(595258), поле `BattleRoyaleFinishedR` (527828).

## 4. Единственный `titer` в игре — свойство `CharacterMotor`

Поиск по всей куче (121 886 строк) даёт ровно 4 имени с `titer`, и все они —
в блоке класса `CharacterMotor` (тип rid 966, globalTypeIndex 4366,
120 методов — это класс игрока/персонажа):

```
методы    rid 5958  get_titer      0 пар.
          rid 5959  set_titer      0 пар.
свойство  PropertyDefinition rid 437 'titer', get=111, set=112
          (get/set — номер метода от первого метода типа:
           111 -> rid 5958 get_titer, 112 -> rid 5959 set_titer)
поле      _titer   (индекс кучи 587954) — backing-поле автосвойства
имя       titer    (индекс кучи 588069)
```

Соседи по таблице свойств и по блоку полей:

```
свойства CharacterMotor: playerTauntsManager, FPSCameraPosition, isInAir,
    MyBodyguard, ViewID, LastKiller, MyPassengerIndex, titer, damageReciver
поля рядом с _titer: ... lastCloneGroundedTime, viewPos, grenagePivot, grenades,
    bufGrenadeType, _titer, _damageReciver
методы рядом: get_MyPassengerIndex(5957), get_titer(5958), set_titer(5959),
    Cheater(5960), get_damageReciver(5961), OnPortalScale(5962), OnPortalScaleR(5963)
```

`titer` и `damageReciver` — два последних добавленных автосвойства класса
(самые большие rid среди геттеров), то есть поздняя фича. `titer` —
единственное место во всей игре, где встречается это слово; ни типа `Titer`,
ни префиксов/суффиксов с ним нет.

## 5. Что это может значить (гипотезы, по убыванию правдоподобия)

Слово почти наверняка **опечатка разработчика**: кодовая база ими полна —
`GetTemRelColor` (Team), `MatchFinidhed` (Finished), `SynsProps` (Sync),
`damageReciver` (Receiver), `AllPlayersNotDublicated` (Duplicated),
`BotteBullet` (Bottle), `MosterSpine` (Monster), `RaundFinished` (Round),
`HipPointsWidget`, `grenagePivot` (granade), `_plaayerTauntsManager`.

1. **«титр» = надголовочная подпись/маркер игрока.** У `CharacterMotor` уже
   есть `HPBarPrefab` и `hudCollider` — надголовочный UI в игре существует
   (`HPBar`: `SetTeamName`, `teamName`, `teamIcon`, `HPLine`; `HipPointsWidget`:
   `armor`, `UpdateArmor`). Тогда `CleanTiters(winnerId)` в конце BR-матча
   снимает/гасит маркеры у всех игроков, кроме победителя. Лучше всего
   согласуется с соседством `winnerId` и с местом метода в BR-ветке.
2. **`timer` (опечатка m→t).** `CleanTimers(...)` = снять отложенные вызовы у
   всех игроков в конце матча. Согласуется с предикатом и с «чисткой», но хуже
   объясняет параметр `winnerId`.
3. **`title`/«титул».** Победитель получает титул, у остальных он снимается.
4. **`trigger`/`turret`.** В игре есть `Turret`, `Tower`, `TriggerBlock`,
   `TriggerActivator`, но ни один из них не связан с `CharacterMotor.titer`
   по именам — слабая гипотеза.

Во всех вариантах механика одна: **перебор игроков, фильтр предикатом
`it => ...`, сброс/уничтожение `titer` у каждого**.

## 6. Важная поправка: колонка `+0` — не надёжный индекс типа возврата

Раньше считалось, что `+0 u32` у `MethodDefinition` — `returnType`.
Проверка на `CharacterMotor` это опровергает:

```
get_isInAir      +0 = 36310   (ожидался bool)
get_HP           +0 = 36310   (ожидался float/int)
get_MyBodyguard  +0 = 36310   (ожидалась ссылка на объект)
set_titer        +0 = 19708   (сеттер обязан возвращать void)
GetTemRelColor   +0 = 19708   (ожидался Color)
```

При этом `36310` — самое частое значение (177 из ~250 геттеров, все `.ctor`,
все 188 `MoveNext`), а `19708` общее для всех предикатов и bool-проверок
(`IsGrounded`, `get_IsAlive`, `IsMyLimitReached`, `IsInvObjLimitReached`,
`IsVehiclesLimitReached`, `FindCarTarget`, `<CleanTiters>b__88_0`,
`<IsVehiclesLimitReached>b__97_0`, `<CheckIsSpawnedBot>b__99_0`).

Вывод: `36310` ≈ void/«нет типа», `19708` ≈ bool — но переносить это на
конкретный метод можно только как **вероятное** значение. Сигнатура
`CheckIsSpawnedBot -> bool` остаётся правдоподобной (три соседних предиката
дают то же значение), однако строго из метаданных не следует.

## 7. К ботам это не относится

* У бот-классов (`BotController`, `OtchimBot`, `HuggyWuggyBot`,
  `ChickenZombieBot`, `BotAnimEvents`, `BotBodyPartDmgReceiver`,
  `BotRenderingSets`, `BotteBullet`) нет ни одного упоминания `titer`.
* У спавнеров (`GeneralZombieSpawnTrigger`, `ESHudItem`, `ESZombieManager`,
  `ESZombieSpawnTrigger`, `ESZombieSpawnEmitter`, `SpawnZType`) тоже.
* Единственный «удаляющий» метод у `BotController` — `DestroySelf`
  (rid 5700, виртуальный, slot 14, 0 параметров); рядом поле
  `destroyingDuration` и RPC-смерть `DieR` (rid 5699, 1 параметр).

Удаление ботов разобрано в `analysis/bot-lifecycle.md` §6.

## 8. Что сняло бы все вопросы

Тело метода: нужен `libil2cpp.so` этой сборки (в репозитории его нет — только
`global-metadata.dat`) и сопоставление `MethodSpec`/адресов. Тогда
`CleanTiters` читается как обычный ARM64-код: какой список перебирается, что
делается с `it.titer`, и откуда берётся параметр.

## 9. Воспроизведение

```bash
.venv/bin/python tools/il2cpp_tables.py apk/global-metadata.dat class  --name GameController --methods
.venv/bin/python tools/il2cpp_tables.py apk/global-metadata.dat method --name CleanTiters
.venv/bin/python tools/il2cpp_heap.py find    apk/global-metadata.dat --regex titer -i
.venv/bin/python tools/il2cpp_heap.py context apk/global-metadata.dat --name CleanTiters --before 4 --after 4
```
