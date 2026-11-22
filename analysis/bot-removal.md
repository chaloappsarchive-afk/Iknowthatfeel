# Как в Chicken Gun 6.5.3 удаляются боты

Разбор по `apk/global-metadata.dat` (`com.chaloapps.roosterrudy`, IL2CPP, обфускация снята:
`plain[i] = cipher[i] ^ ((i+C)&0xFF)`, по фазе `C` на каждый 256-байтовый блок; регион кучи имён
`0xB7D00–0x2DF300` использует `C=0x0F`). Все позиции — в расшифрованной копии
`work/global-metadata.dec.dat`, база кучи имён `B = 0xB7CA4`.

Игровая сборка: TypeDef-чанк `0xAC3E74` (1 498 записей), MethodDef-чанк `0x411540` (9 184 записи),
связка `globalTypeIdx = 3401 + порядковый номер записи типа` (записи переставлены,
rid токена им не равен — см. [`metadata-repair.md`](metadata-repair.md) §1.6).

> **Поправка (важно).** Записи `TypeDefinition` в этом файле переставлены, и
> `declaringType` ссылается на **порядковый номер записи**, а не на rid из её токена;
> связка `globalTypeIndex = 3401 + номер записи` (было написано `3400 + rid`).
> Доказательство и метод — [`metadata-repair.md`](metadata-repair.md) §1.6. Часть
> Часть привязок «тип → методы» в этом документе была из-за этого сдвинута на соседа и
> исправлена по тексту. Сводка поправок:
>
> | было | стало | почему |
> |---|---|---|
> | `BotAnimEvents.DieR/Explode/DamageInRadius` (5674/5675/5676) | **`BombMonster`** (индекс 927) | у `BotAnimEvents` (индекс 928) другие методы |
> | `BotBodyPartDmgReceiver`: `Start/AttackEvent/AttackEnd/PlayDieSound/ShootProjectile` | **`BotAnimEvents`** (индекс 928) | `BotBodyPartDmgReceiver` (929) владеет только `Damage` и `.ctor` |
> | `SantaGirlBodyguard.DestroySelf` (5668) | **`Bodyguard`** (индекс 925, 21 метод) | `SantaGirlBodyguard` (926) — только `Start/Update/.ctor` |
> | `TauntAnimationsEventsHandler.RPC_SecureDestroyPlayer` (6291) | **`SecurePlayerController`** (индекс 1012) | у того же типа `RequestPlayerDestruction` и `OnLeftRoom` |
> | `InventoryMotoObject.CallPhotonNetworkDestroy` (4464) | **`InventoryItem`** (индекс 748, 16 методов) | `InventoryMotoObject` (749) владеет только `.ctor` |
> | `FirepitInvObj.CallPhotonNetworkDestroy` (4240) | **`FNAFLaptopVideoCamera`** (индекс 714) | `FirepitInvObj` (715) — только `Start/Update/.ctor` |
> | `CameraDistanceWidget.DestroyCurrentBodyguard` (3372) | **`BodyguardsWidget`** (индекс 577) | — |
>
> Методы `BotController` (индекс 932, rid 5686..5712), `CharacterMotor` (965) и
> `GameController` (485) не изменились: у этих записей номер отличается от rid токена
> ровно на 1, что компенсируется новым OFF.



Это продолжение [`bot-lifecycle.md`](bot-lifecycle.md): там — как бот **создаётся** и помечается
(`SetAsBot`, `isBot`, `CheckIsSpawnedBot`). Здесь — как он **исчезает**.

**Почему** он исчезает именно так, а не сетевой командой Photon, разобрано отдельно —
[`bot-destroy-pun.md`](bot-destroy-pun.md) (протокол PUN2 против метаданных).

---

## 0. Коротко

1. **Единой «функции удаления ботов» в игре нет.** Ни `ClearBots`, ни `RemoveAllBots`, ни
   `DespawnBots`, ни `DestroyAllMobs` — 0 совпадений в куче имён (см. [`ClearBots.md`](ClearBots.md)).
2. Бот удаляется **поштучно, сам про себя**: `BotController.DestroySelf` (rid **5700**, 0 параметров).
   Это единственный метод с таким именем у ботов.
3. Смерть инициируется по сети RPC-методом **`DieR`** («R» = RPC; в игре так помечены все
   сетевые вызовы: `DamageRPC`, `RespawnRPC`, `StartAttackR`, `DieR`).
4. Между смертью и удалением есть задержка: у `BotController` есть поле **`destroyingDuration`**
   (heap 583143) — типичный `yield return new WaitForSeconds(destroyingDuration)` перед `Destroy`.
5. **Боты не пулятся.** Пул (`ObjectPool`) в игре есть, но `OnSpawn`/`OnRecycle` реализованы только
   у снарядов: `BaseBulletScript`, `Missile`, `MolotovBullet`, `BaseGrenade`, `GroundMine`, `Arrow`,
   `TankFood`, `ChickenCoinTrigger`. Ни у одного бот-класса этих методов нет ⇒ бот уничтожается
   настоящим `Object.Destroy`, а не возвращается в пул.
6. **Игровая сборка не объявляет собственных методов сетевого удаления.** Имена
   `PhotonNetwork` (heap 2038651), `RemoveInstantiatedGO` (2040806), `DestroyPlayerObjects`
   (2040162), `Despawn`/`DespawnAll`/`DespawnActiveTweens`/`DespawnObjects` (1894805–2121680)
   в куче есть, но лежат **далеко за пределами области игровых имён** (~470000–650000) —
   это библиотека Photon PUN и DOTween. В игровой области из «пуловых» имён только
   `OnLifeTimeEnded` (559465), `RecycleAfter` (602145), `RecycleAfterItem` (602028),
   `RecycleAfterList` (602754) — снаряды/предметы. Единственный игровой символ сетевого
   уничтожения — `SecurePlayerController.RPC_SecureDestroyPlayer` (rid 6291); у этого же
   типа (индекс 1012) `RequestPlayerDestruction` и `OnLeftRoom`, то есть он про
   игроков-читеров и выход из комнаты.
   **Оговорка:** вызывает ли игра библиотечный `PhotonNetwork.Destroy` из тел методов — по
   метаданным не определить (тел нет, `libil2cpp.so` отсутствует). Доказуемо только
   отсутствие собственных объявлений и то, что `BotController.DestroySelf` нуль-параметрический,
   тогда как сетевое удаление обязано нести viewId. Разбор этого вопроса по протоколу PUN2:
   [`bot-destroy-pun.md`](bot-destroy-pun.md).
7. **Спавнеры ничего не удаляют.** У `GeneralZombieSpawnTrigger` и `ESHudItem` весь API —
   `get_SpawnPoints, OnTriggerEnter, SpawnZombies, SpawnMob, OnDrawGizmos`. Поля — только
   `mySpawnedBots` и `MaxBotsCount`. Метода очистки списка нет ⇒ список либо чистится обратным
   вызовом из `DestroySelf`, либо фильтруется по «живости» (в игре есть готовый образец такого
   паттерна: `CrashArenaBaseGun.RemoveNullTargets`, rid 7269).
8. **Гоночные боты не удаляются, а прячутся**: `FollowAI.HideCar` (rid 8193, 3 параметра) +
   корутина `<HideCar>d__58`.
9. Корутина `<DestroySelf>d__6` (тип rid 273), которую раньше не удавалось привязать к классу, —
   это **`ItemControl.DestroySelf`**, к ботам отношения не имеет (доказательство в §6).

---

## 1. Основной сценарий: обычный бот (`BotController`)

`BotController` — тип rid **933** (dt 4333), 27 методов, rid 5686–5712. Имя в куче: heap **582918**.

Полный список методов (имя, число параметров, значение колонки `+20`):

```
Awake, Start(s8), PlaySpawnFX(s9), CheckAttack, Damage(s10), Heal(2,s11),
ApplyDamage(1,s12), FlashDamageFX(2,s4), get_IsTopShaderDevic(s13), InitColor,
FlashDamageFXCrt, DamageRPC, UpdateHP(1), DieR(1), DestroySelf(s14), ApplyHeal(s15),
UpdateTarget(1,s5), StartAttack(s16), StartAttackR(s17), StopAttack(s18),
StopAttackR(s19), DamageTarget(s20), AttackEndEvent(s21), PlayDieSound(s22),
ShootProjectile(s23), .ctor(s24), .cctor
```

Поля класса (строки кучи, не занятые именами методов/типов/свойств, в окне 582918–583257):

```
animation2, spawnFXPrefab, projectilePivot, spawnFXPivot, attackAnimsCount,
agent, targetPoint, UpdateTargetPeriod, destroyingDuration, myVoiceAudio,
dieSound, attack, renderSet, initColor, dmgFXCrt, bufMat
```

Что отсюда следует про удаление:

| Символ | rid | Роль в удалении |
|---|---|---|
| `DieR` | 5699 (1 параметр, flags `0x86` = Public\|HideBySig, невиртуальный) | RPC-смерть: приходит от того, кто нанёс смертельный урон. 1 параметр — почти наверняка «кто убил» / «чем убил» |
| `PlayDieSound` | 5709 (s22, flags `0x1C6`) | звук смерти; поля `myVoiceAudio`, `dieSound` |
| `DestroySelf` | **5700** (s14, 0 параметров, flags `0x1C4` = Virtual\|NewSlot\|HideBySig\|Family) | собственно удаление. `protected virtual`, 0 параметров ⇒ всю информацию берёт из полей объекта; объявлен как точка переопределения для потомков |
| `destroyingDuration` | поле, heap 583143 | задержка между анимацией смерти и `Destroy` |
| `agent` | поле | NavMeshAgent: перед удалением его надо снять/погасить |
| `spawnFXPrefab`, `spawnFXPivot` | поля | эффект появления (`PlaySpawnFX`); симметричного «deathFX» поля нет ⇒ эффекты смерти идут через `BotAnimEvents` |

Порядок вызовов внутри `DieR`/`DestroySelf` **не восстанавливается**: тел методов в
`global-metadata.dat` нет, а `libil2cpp.so` в `apk/` отсутствует. Реконструкция по составу полей
и по тому, как это обычно делается в Unity+PUN:

```
Damage / DamageRPC / ApplyDamage  →  UpdateHP  →  HP <= 0
        ↓
DieR(killer)                      ← RPC, рассылается всем
        ↓
PlayDieSound(); анимация смерти (Animator)
        ↓  (анимационное событие)
BotAnimEvents.PlayDieSound        ← см. §2 (взрывных колбэков у бота нет)
        ↓  yield WaitForSeconds(destroyingDuration)
DestroySelf()                     → Object.Destroy(gameObject)
        ↓
список mySpawnedBots у спавнера теряет элемент (см. §5)
```

---

## 2. Анимационные события: `BotAnimEvents` (и почему `BombMonster` — не он)

`BotAnimEvents` — индекс **928** (dt 4329), 6 методов:

```
Start (rid 5678)             AttackEvent (rid 5679)   AttackEnd (rid 5680)
PlayDieSound (rid 5681)      ShootProjectile (rid 5682)   .ctor (rid 5683)
```

То есть приёмник animation events бота отвечает за **атаку и звук смерти**, а не за
взрыв. Методы `DieR` (5674), `Explode` (5675) и `DamageInRadius` (5676) принадлежат
соседнему типу `BombMonster` — индекс **927**, dt 4328, 4 метода; это отдельный
моб-взрывчатка, у которого `Explode` идёт как `virtual` без NewSlot (slot 14), то есть
переопределение виртуала предка. Раньше эти три метода приписывались `BotAnimEvents` —
это следствие индексации типов по rid токена вместо номера записи (см. поправку выше).

Ниже по тексту сохранены рассуждения про animation events: они верны по сути
(нуль-параметрические методы на кадрах клипа), но относятся к `BotAnimEvents`
как к приёмнику событий атаки/звука.

Назначение подтверждается порядком кучи имён (позиция 33290): `SantaGirlBodyguard` →
`BombMonster` → `DieR` → `BotAnimEvents` → `AttackEvent`/`AttackEnd`/`PlayDieSound`/
`ShootProjectile` → `myBot` → `BotBodyPartDmgReceiver`. Куча пишется тип-за-типом и от
перестановки записей TypeDef не зависит, так что это независимая проверка
(детали — [`metadata-repair.md`](metadata-repair.md) §1.6).

Это класс-приёмник **animation events**: такие методы вешаются прямо на кадры анимационного клипа
и вызываются движком без параметров — ровно та сигнатура, которая здесь у всех трёх. То есть
момент «бот реально удаляется» привязан к кадру анимации смерти/взрыва, а не к логике урона.

Рядом, в том же окне кучи (582838–582895), лежит блок **`BotBodyPartDmgReceiver`**
(тип rid 929, dt 4329; методы `Start, AttackEvent, AttackEnd, PlayDieSound, ShootProjectile`):

```
AttackEvent, AttackEnd, PlayDieSound, ShootProjectile, myBot
```

Поле **`myBot`** — обратная ссылка на своего бота: коллайдеры отдельных частей тела
(голова/рука/нога) пробрасывают урон и события в `BotController`. Удалением этот класс не
занимается — он только ретранслирует события.

---

## 3. Другие боты: у всех смерть есть, удаления нет

| Класс | rid / dt | Методы | Про удаление |
|---|---|---|---|
| `OtchimBot` | 945 / 4345 | `Start, EnableNavMeshAgent, DieR, DamageTarget, AttackEndEvent, OnChildTrigger, AttackPlayer(2), .ctor(1)` | `DieR` rid **5754**, своего `DestroySelf` нет |
| `HuggyWuggyBot` | 942 / 4342 | те же 8 методов, та же форма | `DieR` rid **5733** |
| «третий бот» (см. §7) | 943 / — | `Awake, Update, MoveToTarget, DamageTarget, AttackEndEvent, DieR, .ctor` | `DieR` rid **5750**; поля `useNavMesh, attackFX, lookRotation, moveDelta` |
| `ChickenZombieBot` | 935 / 4335 | только `.ctor` | маркер-компонент, смерти нет |
| `CheaterHunterBot` | 426 / 3826 | только `.ctor` | маркер-компонент |
| `DragonFireAttackEvents` | 936 / 4336 | `DieR, .ctor` | `DieR` rid **5721** |
| `BombMonster` | 927 / 4327 | `Start, Update, .ctor` | смерти нет — «монстр-бомба» |
| `Egglet` | 937 / 4337 | `StartFire, StopFire, .ctor` | поле **`myObjToSpawnAfterDeath`** (heap 583473) — «что заспавнить после смерти» |
| `BotRenderingSets` | 930 / 4330 | `Damage, .ctor(2)` | только визуал: `damageColor, topDeviceMaterial, emissionFlashColor` |
| `BotteBullet` | 1108 / 4508 | `Start, Throw, Explode(2,s18), DestroyInRadius(s16), .ctor` | снаряд бота: `DestroyInRadius` rid **6789** |

**`OtchimBot` и `HuggyWuggyBot` не имеют `DestroySelf`** — значит у них удаление делает либо
базовый класс, либо `DieR` напрямую. У обоих
есть `EnableNavMeshAgent` (как и у `BotController` поле `agent`) — перед удалением агент
отключается, иначе NavMesh оставляет «дырку».

`Egglet.myObjToSpawnAfterDeath` — единственное в игре поле, явно описывающее «что появится
после смерти»: у бота может быть посмертный спавн (цыплёнок-яйцо), и тогда удаление родителя
сопровождается созданием нового объекта.

---

## 4. Боты-телохранители и гоночные боты — две отдельные схемы

### 4.1 `Bodyguard` (индекс 925 / dt 4326, 21 метод)

```
Awake, Start, LateUpdate, ApplyHeal(s6), KeepDistToOwner(1,s5), SyncAnimRun,
SyncAnimIdle, ApplyDamage, DamageRPC(2,s4), UpdateHP(2), OnMyOwnerDamaged(1),
CheckAttack(2), StartAttack(s7), StartAttackR(s8), StopAttack(1,s9),
StopAttackR(s10), DamageTarget(s11), SetOwner(s12), DestroySelf(1), UpdateCloneState(s13), .ctor
```

**`DestroySelf` rid 5668, 1 параметр, НЕ виртуальный.** Вызывается снаружи:
у `CharacterMotor` есть **`DestroyCurrentBodyguard` (rid 5939, 1 параметр)** и геттер
`get_MyBodyguard`. То есть телохранителя удаляет владелец (игрок), а не он сам:
`CharacterMotor.DestroyCurrentBodyguard(...)` → `Bodyguard.DestroySelf(...)`.
(Раньше этот 21-методный тип читался как `SantaGirlBodyguard`; настоящий
`SantaGirlBodyguard` — соседняя запись, индекс 926, и у неё только `Start`/`Update`/
`.ctor`, то есть это надстройка над общим `Bodyguard`.) Параметр у `DestroySelf` один — скорее всего «уничтожать ли по сети / немедленно ли».

Есть также `BodyguardsWidget.DestroyCurrentBodyguard` (rid 3372, 0 пар., индекс 577) —
UI-виджет умеет сбросить текущего телохранителя.

### 4.2 Гоночные боты: `RaceCarController` + `FollowAI`

`RaceCarController` (rid 520 / dt 3920): `get_carID, Awake, Start, OnDestroy (rid 3048),
SetAsBot (rid 3050, 0 пар., public), SetParticipantInfo, GetDamage, GetCrashed(1), Explode,
get_Alive, FindCarTarget`; поля `isBot, followAI, explosionPivot`.

`FollowAI` (rid 1353 / dt 4753, 21 метод) — ИИ, ведущий машину-бота по waypoint'ам:
**`HideCar` (rid 8193, 3 параметра)** + корутина `<HideCar>d__58` (тип rid 1349),
`OnCarCrashed(1)`, `ReverseReset` + `<ReverseReset>d__62`, `ResetRotation` + `<ResetRotation>d__63`.

**Гоночный бот не уничтожается — он прячется.** `HideCar` с тремя параметрами и корутиной —
это «убрать машину с трассы, подождав N секунд» (финиш, вылет, краш). Удаление объекта
происходит только через штатный `RaceCarController.OnDestroy`/`Explode`.

---

## 5. Кто убирает бота из списка `mySpawnedBots`

Спавнеры мобов в игре (все — только спавн, ни одного метода удаления):

| Класс | rid / dt | Методы |
|---|---|---|
| `GeneralZombieSpawnTrigger` | 494 / 3894 | `get_SpawnPoints(s7), OnTriggerEnter, SpawnZombies(1), SpawnMob, OnDrawGizmos(1), .ctor` |
| `ESHudItem` | 241 / 3641 | те же 6 методов, та же форма |
| `ESZombieManager` | 238 / 3638 | `get_CurMaxZCount, Awake, CreateMonster, CreateBossMonster(2), .ctor(2)` |
| `ESZombieSpawnEmitter` | 237 / 3637 | `.cctor, .ctor, <CreateBossMonster>b__6_0` |
| `SpawnZType` | 239 / 3639 | `Start(1), get_SpawnPoints, OnTriggerEnter, SpawnZombie(1), OnDrawGizmos, .ctor` |
| `ZWZombieManager` | 256 / 3656 | `OnTriggerEnter, .ctor(1)` |
| `ZombieManager` | 949 / 4349 | `OnTriggerEnter, .ctor` |
| `WaveSpawn` | 1299 / 4699 | `OnTriggerEnter, Update(1), OnTriggerExit, .ctor(1)` |
| `WaveSpawnTanks` | 1300 / 4700 | `Start, Update, SpawnEnemy, .ctor` |
| `VP_EnemySpawner` | 1176 / 4576 | `Awake, Start, CreateFirstEnemy, Update, CreateEnemy, MaskFix, OnRestart(1), .ctor` |

Поля `GeneralZombieSpawnTrigger` (heap 533582–533635):

```
mySpawnedBots        (heap 533608)
MaxBotsCount         (heap 533622)
```

Раз метода удаления у спавнера нет, возможны ровно три варианта, и все три в этой игре
чем-то подтверждены:

* **(a) Обратный вызов из бота.** Бот при `DestroySelf` сам вычёркивает себя из списка спавнера.
  Косвенный признак: `mySpawnedBots` — единственное поле-коллекция у триггера, а `MaxBotsCount`
  проверяется в `SpawnMob`/`SpawnZombies`.
* **(b) Фильтрация «мёртвых» ссылок.** В Unity уничтоженный объект сравнивается с `null`,
  поэтому список можно не чистить вообще, а отфильтровывать на лету. В игре есть готовый
  образец такого метода: **`CrashArenaBaseGun.RemoveNullTargets` (rid 7269)**.
* **(c) Очистка сцены целиком.** При смене раунда/карты объекты умирают вместе со сценой.
  Для этого в игре есть `ObjectPool.DestroyPooled` (rid 524 — 3 пар., rid 525 — 1 пар.) и
  `ObjectPool.DestroyAll` (rid 526, 527), `GeneralUtils.RemoveAllChilds` (rid 6580, 2 пар.),
  а также штатные `OnDestroy` у контроллеров режимов (`EliteSquadHudManager`,
  `RacingLobbyManager`, `DuelLobbyManager`, `CaptureFlagManager`, `PlantBombManager`,
  `GameController.OnDestroy` rid 2631).

`GameController.CheckIsSpawnedBot` (rid 2666, 0 параметров) — это **проверка лимита**, а не
удаление: у неё два замыкания, статическое `<>c.<CheckIsSpawnedBot>b__99_0` (rid 2683,
кэшированное поле-делегат `<>9__99_0`, heap 530008) и экземплярное
`<>c__DisplayClass99_0.<CheckIsSpawnedBot>b__1` (rid 2689, heap 530107) — т.е. что-то вроде
`bots.Any(b => …)` / `bots.Count(b => …)`. Рядом те же лимитные проверки:
`IsMyLimitReached` ×2 (rid 2662, 2663), `IsInvObjLimitReached` (2664),
`IsVehiclesLimitReached` (2665) + `<IsVehiclesLimitReached>b__97_0`.

---

## 6. Корутина `<DestroySelf>d__6` — это `ItemControl`, не бот

Открытый вопрос из прошлого разбора закрыт. Тип rid **273** (dt 3673), 6 «машинных» методов.
Окно кучи вокруг его имени (heap 503006) даёт недвусмысленный контекст:

```
502927  ItemControl          ← имя класса
502939  InitBullet           ← его метод
502950  wait                 ← ИМЯ ПАРАМЕТРА DestroySelf(float wait)
502955  DestroySelf          ← его метод
502967  ChangeTexture
502981  ChangeTextureRandom
503001  coll                 ← имя параметра (Collider)
503006  <DestroySelf>d__6    ← корутина этого метода
```

Методы `ItemControl` (rid 276 / dt 3676) это подтверждают:
`InitBullet(s7), DestroyItem, DestroySelf(1 пар.), ChangeTexture(1), ChangeTextureRandom(1), .ctor`.
Единственный параметр `DestroySelf` — `wait`; значит тело метода
`IEnumerator DestroySelf(float wait)` ⇒ `yield return new WaitForSeconds(wait); DestroyItem();`.
Это удаление **предметов/ящиков**, к ботам отношения не имеет.

Тот же приём (параметр-задержка) объясняет и `destroyingDuration` у `BotController` — но у бота
задержка вынесена в поле, а не в параметр, поэтому корутины `<DestroySelf>d__N` у
`BotController` нет: `DestroySelf` у него без параметров и, судя по всему, обычный `void`.

---

## 7. Что в этом регионе метаданных ненадёжно

Честный список оговорок — он важен, чтобы не принять артефакт декодирования за факт.

* **Дубликат `nameIndex` у записей типов 940 и 943**: обе показывают heap-индекс 583638
  (`<AttackPlayer>d__9`). Одна из двух расшифровок имени ошибочна. По набору методов
  (rid 5745–5751: `Awake, Update, MoveToTarget, DamageTarget, AttackEndEvent, DieR, .ctor`)
  и по содержимому кучи сразу за именем `InvZombie` (heap 583657: `MoveToTarget, useNavMesh,
  attackFX, lookRotation, moveDelta`) класс rid 943 — это **`InvZombie`**, а rid 941
  (машинные методы `.ctor, Dispose, MoveNext, get_Current, GetEnumerator, Reset`) — корутина
  `<AttackPlayer>d__9`. Но это реконструкция по совпадению имён, а не доказанный факт.
  На выводы об удалении это не влияет: в обоих случаях есть `DieR` и нет `DestroySelf`.
* **Колонка `+20` («slot») — это индекс в vtable своего типа, а не признак родства.**
  Одинаковый slot у методов с разными именами — совпадение, а не общий предок:
  `BotController.DestroySelf` (flags `0x1C4`, бит **NewSlot** — объявляет новый виртуал,
  slot 14), `OtchimBot.DamageTarget` (rid 5755, flags `0xC4` = Virtual|HideBySig без
  NewSlot — переопределение, slot 14), `HuggyWuggyBot.DamageTarget` (rid 5734, то же) и
  `BombMonster.Explode` (rid 5675, то же) лежат в трёх несвязанных иерархиях. Прежний
  вывод «переопределение не может менять имя ⇒ имена сдвинуты или slot врёт» снят.
  Родство по vtable восстанавливается только парой (имя виртуала, slot):
  `T.infer_base_classes()` находит в игровой сборке **23 уверенных связи**
  (`JSONLazyCreator : JSONNode` — 13 совпавших виртуалов, `CarController : Vehicle` — 9,
  `HoverMotor : Motor` — 2, `DynamiteTNTInvObj : ExplodableObject` — по `Explode`/slot 50);
  в `Dump.cs` они напечатаны как `// [эвристика по vtable]`. У ботов уверенных связей нет:
  `BotController.DestroySelf` объявляет новый виртуал, а не переопределяет, то есть
  общего «ботового» предка по vtable не видно. Колонка slot при этом не безупречна:
  `BotController..ctor` (rid 5711) имеет slot 24 и flags `0x1C6` (Virtual|NewSlot),
  чего у конструктора быть не может, — поэтому slot приводится как наблюдение.

* **Базовый класс ботов не установлен.** Ни один игровой тип не объявляет значения колонки
  `+20` для 0–3 (виртуалы `System.Object`), т.е. `BotController`, скорее всего, наследуется
  напрямую от `MonoBehaviour`. Но с учётом пункта выше это вероятный, а не доказанный вывод;
  у `OtchimBot`/`HuggyWuggyBot` значения доходят до 25, что намекает на предка с большим
  числом виртуалов. Таблицы наследования в этом файле не читаются.
* **Тел методов нет.** `global-metadata.dat` хранит только имена и сигнатуры; порядок вызовов
  внутри `DieR`/`DestroySelf` — реконструкция по составу полей и по анимационным событиям.
  `libil2cpp.so` в `apk/` отсутствует, дизассемблировать нечего.
* **Полей игры нет**: в файле 6 301 записей FieldDef и все они библиотечные ⇒ смещения и типы
  полей ботов неизвестны. Имена полей восстановлены по соседству строк в куче имён.
* **Колонка `+0` MethodDef — не индекс типа возврата** (опровергнуто на `CharacterMotor`:
  `set_titer` = 19708, `get_HP`/`get_isInAir` = 36310). Поэтому «`DestroySelf` возвращает void» —
  вывод из отсутствия корутины `<DestroySelf>d__N` у `BotController`, а не из колонки `+0`.

---

## 8. Итоговая схема удаления ботов

```
                       ┌──────────────────────────────────────────────┐
  урон                 │  BotBodyPartDmgReceiver.myBot  →  BotController│
  (по части тела)      │  Damage / DamageRPC / ApplyDamage → UpdateHP   │
                       └───────────────────────┬──────────────────────┘
                                               │ HP <= 0
                                               ▼
                                        DieR(killer)   ← RPC, rid 5699
                                               │
                    ┌──────────────────────────┼───────────────────────────┐
                    ▼                          ▼                           ▼
          PlayDieSound (5709)        Animator: клип смерти          BotAnimEvents (индекс 928)
          myVoiceAudio, dieSound                                    AttackEvent / AttackEnd /
                                                                     PlayDieSound / ShootProjectile
                                               │                     (анимационные события)
                                               ▼
                              ждём destroyingDuration (heap 583143)
                                               │
                                               ▼
                              BotController.DestroySelf  (rid 5700, 0 пар.)
                                               │
                        ┌──────────────────────┴──────────────────────┐
                        ▼                                             ▼
              Object.Destroy(gameObject)                 список mySpawnedBots у
              (без пула: OnRecycle у ботов нет)           GeneralZombieSpawnTrigger
                                                          теряет элемент (§5: a/b/c)
```

Параллельные ветки:

```
Bodyguard.DestroySelf(1) [rid 5668]           ← CharacterMotor.DestroyCurrentBodyguard(1) [5939]
                                               ← BodyguardsWidget.DestroyCurrentBodyguard [3372]

RaceCarController.SetAsBot [3050] → FollowAI (rid 1353) → HideCar(3) [8193] + <HideCar>d__58
                                    (гоночный бот прячется, а не уничтожается)
                                    OnCarCrashed(1) / Explode / OnDestroy [3048]

BotteBullet.DestroyInRadius [6789] / Explode(2) [6788]   — снаряд бота
Egglet.myObjToSpawnAfterDeath (heap 583473)              — посмертный спавн
ItemControl.DestroySelf(wait) [1426] + <DestroySelf>d__6 — предметы, НЕ боты
```

---

## 9. Воспроизвести

```bash
cd /home/user/Iknowthatfeel
python3 -m venv .venv && .venv/bin/pip install -r tools/requirements.txt

# 1. расшифровать метаданные (≈15 с)
.venv/bin/python tools/il2cpp_decrypt.py decrypt apk/global-metadata.dat \
        -o work/global-metadata.dec.dat
#    ВАЖНО: у il2cpp_tables.py --cache идёт ДО позиционного аргумента metadata,
#    у il2cpp_heap.py --cache идёт ПОСЛЕ имени подкоманды.

# 2. класс бота со всеми методами (rid, slot, flags, число параметров)
.venv/bin/python tools/il2cpp_tables.py --cache work/global-metadata.dec.dat \
        apk/global-metadata.dat class --name BotController --methods
.venv/bin/python tools/il2cpp_tables.py --cache work/global-metadata.dec.dat \
        apk/global-metadata.dat class --name Bodyguard --methods
.venv/bin/python tools/il2cpp_tables.py --cache work/global-metadata.dec.dat \
        apk/global-metadata.dat class --name BotAnimEvents --methods

# 3. все «удаляющие» имена в игровой сборке
.venv/bin/python tools/il2cpp_tables.py --cache work/global-metadata.dec.dat \
        apk/global-metadata.dat grep -i --regex 'Destroy|Die|Remove|Recycle|Despawn|Hide|Explode' --limit 400

# 4. поля бота и привязка корутины <DestroySelf>d__6 к ItemControl
.venv/bin/python tools/il2cpp_heap.py context work/global-metadata.dec.dat \
        --name BotController --before 5 --after 90
.venv/bin/python tools/il2cpp_heap.py context work/global-metadata.dec.dat \
        --name '<DestroySelf>d__6' --exact --before 12 --after 6
.venv/bin/python tools/il2cpp_heap.py context work/global-metadata.dec.dat \
        --name GeneralZombieSpawnTrigger --before 3 --after 12

# 5. убедиться, что ClearBots и сетевых символов удаления нет
.venv/bin/python tools/il2cpp_heap.py find work/global-metadata.dec.dat -i \
        --regex 'clearbots|despawn|networkdestroy|removeinstantiated|securedestroy'
```

Готовые дампы: [`bot-heap-blocks.txt`](bot-heap-blocks.txt) (окна кучи по бот-классам),
[`bot-classes.md`](bot-classes.md) (полные списки методов), [`bot-surface.md`](bot-surface.md)
(все 184 строки кучи, содержащие `bot`).
