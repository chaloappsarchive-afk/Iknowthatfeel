# «Валидная метадата»: что удалось пересобрать и чего в ней нет

Задача была — получить из обфусцированного `apk/global-metadata.dat` файл с нормальным
заголовком, который читают стандартные инструменты. Коротко: **починить заголовок нельзя,
файл можно только пересобрать**, и пересобран он частично. Результат:

```
analysis/global-metadata.game-only.dat    527 980 байт (515,6 КБ), sanity 0xFAB11BAF, version 24
tools/il2cpp_rebuild.py                   генератор + round-trip проверка (--verify по умолчанию)
analysis/Dump.cs                          объявления игровой сборки (3,6 МБ, 55 091 строка)
tools/il2cpp_dump.py                      генератор Dump.cs
```

---

## 1. Почему нельзя просто дописать заголовок

Две независимые причины.

**(a) Заголовок уничтожен, а не зашифрован.** Санити-слово `0xFAB11BAF` (байты
`AF 1B B1 FA`) отсутствует и в исходном файле, и во всех 256 глобальных фазах XOR.
Поблочная дешифровка (`plain[i] = cipher[i] ^ ((i+C)&0xFF)`, своя фаза `C` на каждый
256-байтовый блок) восстанавливает **имена** — 4 727 → 128 301 читаемых идентификаторов, —
но не заголовок: там нечего восстанавливать, смещения таблиц в нём не зашифрованы, а стёрты.

**(b) Таблицы физически разбросаны.** В валидном `global-metadata.dat` каждая таблица —
сплошной массив, на который указывает пара `(offset, size)` из заголовка. Здесь записи
одной и той же таблицы лежат кусками по всему файлу:

| таблица | шаг записи | найдено чанков | найдено записей | размах позиций | заполнение размаха |
|---|---|---|---|---|---|
| TypeDefinition | 76 | 127 | 16 182 | 0x2E040F … 0xD51BCC (10,44 МБ) | **11,2 %** |
| MethodDefinition | 30 | 240 | 112 040 | 0x3571FE … 0xD52BDC (9,98 МБ) | **32,1 %** |
| PropertyDefinition | 20 | 84 | 17 924 | 0x2E5404 … 0xB821A5 (8,61 МБ) | **4,0 %** |

Самая длинная непрерывная цепочка TypeDef — 1 226 записей (0xB3B3A8), MethodDef —
5 919 (0x5357FA). То есть обфускатор переставил записи по сборкам, и ни один
`(offset, size)` не опишет таблицу целиком. Отсюда единственно возможный путь: вытащить
записи нужной сборки и **уложить их заново сплошными массивами**.

---

## 2. Что лежит в `global-metadata.game-only.dat`

Заголовок 248 байт = `sanity(4) + version(4) + 30 пар (offset, size)`. Секции:

| секция | offset | size | записей | шаг |
|---|---|---|---|---|
| `string` | 0xF8 | 88 176 | — | — |
| `properties` | 0x15968 | 13 460 | 673 | 20 |
| `methods` | 0x18DFC | 288 192 | 9 006 | 32 |
| `typeDefinitions` | 0x5F3BC | 137 816 | 1 498 | 92 |
| `images` | 0x80E14 | 24 | 1 | 24 |
| `assemblies` | 0x80E2C | 64 | 1 | 64 |

Все прочие секции — `offset = 0, size = 0`: `stringLiteral(Data)`, `events`, `parameters`,
`fields`, `genericParameters`, `genericParameterConstraints`, `genericContainers`,
`nestedTypes`, `interfaces`, `vtableMethods`, `interfaceOffsets`, `rgctxEntries`,
`referencedAssemblies`, `attributesInfo`, `attributeTypes`, `unresolvedVirtualCall*`,
`windowsRuntimeTypeNamePairs`, `exportedTypeDefinitions`, `parameterDefaultValues`,
`fieldDefaultValues`, `fieldAndParameterDefaultValueData`, `fieldMarshaledSizes`.

Раскладка записей взята из v24.5: `TypeDefinition` 92 байта, `MethodDefinition` 32,
`PropertyDefinition` 20, `Il2CppImageDefinition` 24, `Il2CppAssemblyDefinition` 64.

**Что пришлось достраивать**, потому что в исходнике этих колонок нет в usable-виде:

* `TypeDefinition.methodStart` / `method_count` — восстановлены по группировке
  `MethodDefinition.declaringType` (в исходнике поиск колонок `methodStart`/`method_count`
  дал лучший результат 5,8 %, то есть их там нет). Методы при этом **перенумерованы**:
  уложены сплошь по возрастанию типа-владельца, иначе `methodStart`/`method_count`
  не имели бы смысла.
* `TypeDefinition.propertyStart` / `property_count` — так же, по владельцу свойства.
* `PropertyDefinition.get` / `set` — в исходнике это **смещения от первого метода типа**
  (проверено на 252 из 673), а стандарт требует абсолютных индексов массива методов.
  Пересчитаны в абсолютные.
* `MethodDefinition.declaringType` — из глобального индекса `3400 + rid` переведён
  в индекс массива типов (`rid - 1`).
* Куча строк собрана заново (дедуплицирована, индекс 0 = пустая строка), все `nameIndex`
  пересчитаны.

---

## 3. Round-trip проверка (прошла)

Файл перечитывается **по смещениям из собственного заголовка** и сверяется с исходными
таблицами:

```
sanity 0xFAB11BAF version 24 — заголовок читается
typeDefinitions: 1498 записей (ожидалось 1498)
methods        : 9006 записей (ожидалось 9006)
properties     : 673 записей  (ожидалось 673)
имена типов: расхождений 0 из 1494
BotController    methodStart=5646  method_count=27   Awake, Start, PlaySpawnFX, CheckAttack, Damage, Heal…
GameController   methodStart=2645  method_count=62   get_GameStartTime, Awake, Start, SendMyEvent, OnEvent, CheckIsMapValid…
CharacterMotor   methodStart=5831  method_count=120  get_playerClothingManager, get_playerTauntsManager, get_FPSCameraPosition, Awake, Start, TakePhoto…
свойства: имён совпало 673/673; абсолютный get указан у 217, из них ведут на get_<имя> — 217
ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ
```

Запустить самому:

```bash
.venv/bin/python tools/il2cpp_rebuild.py apk/global-metadata.dat \
        --cache work/global-metadata.dec.dat -o analysis/global-metadata.game-only.dat
```

---

## 4. Чего в этом файле НЕТ (и почему)

* **Только игровая сборка.** Прочие 126 чанков TypeDef (mscorlib, UnityEngine, Photon,
  DOTween, …) не пересобраны: для них не установлен `OFF` (связка
  `globalTypeIndex = OFF + rid` подобрана только для игровой сборки, `OFF = 3400`),
  поэтому их методы к типам не привязать. В файле один `image` (`Assembly-CSharp.dll`)
  и одна `assembly`.
* **1 498 записей типов при 1 494 распознанных.** В чанке есть rid до 1498, но четыре
  записи не распознаны — на их месте лежат нулевые заглушки (`nameIndex = 0`, `token = 0`).
  Это честная дырка, а не данные.
* **Полей нет вообще.** `FieldDefinition` игровой сборки отсутствует в файле физически.
  Проверено тремя способами: (1) по тегу `0x04` находятся только 6 301 запись и все —
  библиотечные; (2) известные имена полей (`destroyingDuration` 583143, `dieSound` 583175,
  `agent` 583106, `mySpawnedBots` 533608, `MaxBotsCount` 533622, `isBot` 537686,
  `renderSet` 583191, `winnerId` 528802) **не встречаются как u32** ни в расшифрованном,
  ни в сыром файле; (3) поиск по сырому файлу с учётом keystream — u32 на позиции `p`
  равен `V`, если `(raw[p+i] ^ V[i])` образует арифметическую прогрессию с шагом −1
  по модулю 256, — даёт единичные совпадения без решётки шага 12. Значит `fieldStart = -1`,
  `field_count = 0`, и **смещения полей неизвестны**.
* **Типы возврата и типы параметров неизвестны.** `returnType = 0`, таблица `parameters`
  пуста (`parameterStart = -1`); сохранено только `parametersCount`. Причина: колонка `+0`
  исходного `MethodDefinition` индексом типа возврата **не является** — опровергнуто на
  `CharacterMotor` (`set_titer` = 19708, `get_HP`/`get_isInAir`/`get_MyBodyguard` = 36310),
  подробности в [`CleanTiters.md`](CleanTiters.md) §6.
* **Иерархии классов нет**: `parentIndex`, `byvalTypeIndex`, `byrefTypeIndex`,
  `declaringTypeIndex`, `elementTypeIndex`, `genericContainerIndex` = −1. Таблицы
  `nestedTypes`, `interfaces`, `vtableMethods`, `interfaceOffsets`, `genericContainers`
  пусты, хотя вложенные типы (`<>c`, `<>c__DisplayClass99_0`, `<DestroySelf>d__6`, …)
  лежат в `typeDefinitions` как обычные записи.
* **RVA/Offset проставить некуда** — `libil2cpp.so` в `apk/` отсутствует, кода нет.
* **version = 24 выбран по умолчанию.** Точную версию метаданных подтверждает только
  `libil2cpp.so`; если внешний инструмент ожидает 27/29, раскладка не совпадёт
  (переключается флагом `--version`, но раскладка записей в скрипте — v24.5).
* **Совместимость с Il2CppDumper / Il2CppInspector не проверена**: в песочнице нет ни
  .NET, ни Java, ни самого `libil2cpp.so`, который этим инструментам в любом случае нужен
  вторым входом. Проверено только одно: файл самосогласован и читается по собственному
  заголовку (§3).

---

## 5. `Dump.cs`

`analysis/Dump.cs` — объявления игровой сборки в формате, близком к Il2CppDumper:
1 494 типа, 9 006 методов, 238 свойств с установленным владельцем
(456 свойств без владельца вынесены в отдельный хвост, 2 группы методов без
типа-владельца — тоже).

Факты в нём: имена типов и методов, namespace, число параметров, принадлежность типу,
флаги, значение колонки «slot», токены, свойства с get/set.

Заглушки (помечены и в шапке файла, и в docstring `tools/il2cpp_dump.py`):
все возвраты напечатаны как `void`, все параметры как `object p0, p1, …`; всё
напечатано как `class` (enum/struct/interface/delegate не различимы); базовых классов
и RVA нет.

Вместо полей для каждого типа печатается блок `// [эвристика по куче]` — строки имён из
окна ±520 байт вокруг имени типа, не занятые именами методов/типов/свойств. Туда попадают
поля, имена параметров и локальных переменных; из-за дедупликации кучи часть имён класса
лежит далеко от своего окна, а в окно попадают имена **соседних** классов. Пример для
`BotController` (TypeDefIndex 933):

```
//   damageMultiplier(582454), bodyPart(582471), newHP(582541), frommWhomViewId(582547)
//   attackIndex(582604), myEnemy(582682), myOwner(582690), damagePerAttack(582698)
//   attackDist(582714), isAttacking(582725), hitAudio(582737), minDistToOwner(582746)
//   myBot(582889), animation2(583035), spawnFXPrefab(583046), projectilePivot(583060)
//   agent(583106), targetPoint(583112), UpdateTargetPeriod(583124), destroyingDuration(583143)
//   myVoiceAudio(583162), dieSound(583175), attack(583184), renderSet(583191)
```

Первые строки — это поля соседей (`Bodyguard`, `SantaGirlBodyguard`,
`BotBodyPartDmgReceiver`), а начиная с `animation2` — уже сам `BotController`.
Заодно видно `frommWhomViewId` — поле, хранящее viewId источника урона; оно косвенно
подтверждает разбор в [`bot-destroy-pun.md`](bot-destroy-pun.md): урон и смерть
ходят по сети идентификаторами PhotonView.

Сгенерировать заново:

```bash
.venv/bin/python tools/il2cpp_dump.py apk/global-metadata.dat \
        --cache work/global-metadata.dec.dat -o analysis/Dump.cs
# все чанки типов, не только игровая сборка:  --assembly all
# без эвристики по полям:                     --no-heap-fields
```
