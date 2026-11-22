# Как устроен «бот» в Chicken Gun 6.5.3 (`com.chaloapps.roosterrudy`)

Разбор флага `isBot`, спавна ботов и их жизненного цикла по расшифрованным
метаданным IL2CPP (`apk/global-metadata.dat`, 14 043 988 байт).

Все факты ниже получены из таблиц `MethodDefinition` / `TypeDefinition` /
`PropertyDefinition` и из кучи имён; тела методов (IL/ASM) в метаданных не
хранятся, поэтому логика внутри методов помечена как **реконструкция**.

Доказательная база: `analysis/bot-heap-blocks.txt` (дампы блоков кучи),
`work/gameprops.json` (карта свойств), `tools/il2cpp_tables.py` (парсер).

Смежные разборы: **как боты удаляются/умирают — `analysis/bot-removal.md`**;
что такое `GameController.CleanTiters` и при чём тут `CharacterMotor.titer` —
`analysis/CleanTiters.md`; поиск несуществующего `ClearBots` — `analysis/ClearBots.md`.

---

## 0. Коротко

В игре **две независимые сущности «бот»**, и они не связаны общим кодом:

| | Гонки (PvP-арена) | PvE-мобы (зомби/боссы) |
|---|---|---|
| Флаг | поле `RaceCarController.isBot` | флага нет — сам класс `BotController` |
| Включение | `RaceCarController.SetAsBot()` → `void`, 0 параметров | `GeneralZombieSpawnTrigger.SpawnZombies(int)` / `SpawnMob()` |
| Учёт | `driverName`, `followAI`, `carID` | список `mySpawnedBots` + лимит `MaxBotsCount` |
| Гейт | — | `GameController.CheckIsSpawnedBot()` → `bool`, 0 параметров |
| ИИ вождения | свойство `CarController.followAI` (getter rid 7198) | `NavMeshAgent` (`EnableNavMeshAgent`, поле `agent`) |

Полный «бот-API» игровой сборки — всего 5 записей методов, содержащих `bot`:

```
rid=2666  CheckIsSpawnedBot            GameController            bool, 0 пар., невиртуальный
rid=2683  <CheckIsSpawnedBot>b__99_0   GameController+<>c        bool, 1 пар.  (статический предикат)
rid=2689  <CheckIsSpawnedBot>b__1      GameController+<>c__DisplayClass99_0  void, 0 пар. (захватывающая лямбда)
rid=3050  SetAsBot                     RaceCarController         void, 0 пар., невиртуальный
rid=8675  ShowBannerBottom             (ложное срабатывание на «Bot» в «Bottom»)
```

Метода `ClearBots` в этой сборке нет — см. `analysis/ClearBots.md`.
`GameController.CleanTiters` тоже **не про ботов**: это зачистка игроков
(свойство `CharacterMotor.titer`) в конце Battle Royale — разбор в
`analysis/CleanTiters.md`.

---

## 1. Откуда взялись имена и принадлежность классам

Заголовок метаданных испорчен обфускатором (sanity `AF 1B B1 FA` отсутствует),
поэтому таблицы восстановлены структурно, без заголовка:

* поблочная дешифровка XOR с периодом 256 (`tools/il2cpp_decrypt.py`) →
  `work/global-metadata.dec.dat`;
* куча имён `0xB8000..0x2DF000`, база `B = 0xB7CA4` (проверено на 300/300 имён);
* игровая сборка: чанк методов `0x411540` (9 006 записей, шаг 30, записи
  невыровненные), чанк типов `0xAC3E74` (1 498 записей, шаг 76), чанк свойств
  `0x2FE698` (673 записи, шаг 20);
* связь «метод → класс»: `MethodDefinition.declaringType` (u16 @ +28) —
  **глобальный** индекс типа; для игровой сборки
  `globalTypeIndex = 3400 + rid_типа` (`work/layout.json`).

Калибровка `OFF = 3400` выполнена по compiler-generated типам: у каждого
`<X>d__N` обязан быть `MoveNext`, у `<>c…` — только `.ctor`/`<…>b__…`.
Контрольные точки сошлись идеально: `BotController` (rid 933 → dt 4333,
27 методов), `GameController` (486 → 3886, 62 метода), `RaceCarController`
(520 → 3920, 15 методов), `GeneralZombieSpawnTrigger` (494 → 3894, 6 методов).

### Как определены владельцы полей

Таблица `FieldDefinition` игровой сборки в этой упаковке не локализована
(находятся только 6 301 библиотечных записей; «совпадения» в `0x6F9548` /
`0x6D07EB` — арифметический мусор: две колонки, растущие на +1 за 10 байт).
Владельцы полей установлены по **порядку кучи имён**:

1. строки в куче дедуплицированы и пишутся в порядке обхода сборки;
2. члены одного типа образуют непрерывный блок, ограниченный именами соседних
   типов;
3. строка, на которую нет ссылки из `MethodDefinition.nameIndex` /
   `TypeDefinition.nameIndex` — это поле, свойство, событие или элемент
   перечисления этого типа;
4. свойства отсекаются таблицей `PropertyDefinition` (чанк `0x2FE698`):
   колонки `get`/`set` — это **номер метода относительно первого метода типа**.
   Проверка: `GameController.MyTeamScore get=37` → 2609+37 = rid 2646
   `get_MyTeamScore` ✓; `RaceCarController.Alive get=12` → 3045+12 = rid 3057
   `get_Alive` ✓; `BotController.IsTopShaderDevice get=8` → 5686+8 = rid 5694
   `get_IsTopShaderDevice` ✓.

Из 673 свойств игровой сборки 252 привязаны к типу однозначно.
`isBot`, `mySpawnedBots`, `MaxBotsCount`, `myBot`, `driverName`, `useNavMesh`,
`spawnFXPrefab`, `targetPoint`, `characterMotor` в таблице свойств **отсутствуют**
→ это поля. `carID`, `Alive` (RaceCarController) и `IsTopShaderDevice`
(BotController) — свойства.

---

## 2. Гонки: `RaceCarController.isBot` и `SetAsBot()`

`RaceCarController` — тип rid 520, `globalTypeIndex` 3920, запись `0xACD83C`,
15 методов (rid 3045–3059):

```
rid   имя                     пар.  slot    тип возврата (id в чанке)
3045  get_carID                0    —       36310 (void-индекс; геттер свойства carID)
3046  Awake                    0    —       33487
3047  Start                    0    —       36310
3048  OnDestroy                0    —       25553 (IEnumerator-подобный)
3049  ResetPhysicsForStart     0    —       36310
3050  SetAsBot                 0    —       36310 (void)          <-- установка флага
3051  SetParticipantInfo       1    —       36310
3052  PlayerName               1    —       36310
3053  GetDamage                0    —       33487
3054  GetCrashed               1    —       36310
3055  Explode                  0    —       25553
3056  HpNormalized             0    —       36310
3057  get_Alive                0    —       32893                 <-- геттер свойства Alive
3058  FindCarTarget            0    —       19708 (bool)
3059  .ctor                    0    —       36310
```

Все методы невиртуальные (`slot = 0xFFFF`), `SetAsBot` — `public void`
(`flags = 0x86` = Public|HideBySig), параметров нет: состояние берётся из полей.

Блок имён `RaceCarController` в куче (индексы 537442–537718,
`analysis/bot-heap-blocks.txt`):

```
537442  RaceCarController        ТИП rid=520
537460  get_carID                метод
537470  ResetPhysicsForStart     метод
537491  SetAsBot                 метод
537500  myParticipantUnit        поле (участник гонки)
537518  SetParticipantInfo       метод (1 параметр)
537537  GetDamage / 537547 GetCrashed / 537558 HpNormalized
537571  get_Alive / 537581 FindCarTarget
537595  RaceCarCreated           событие/поле
537610  RaceCarLeaved            (строка общая с RaceGameController.RaceCarLeaved)
537624  initHP                   поле
537631  HpUpdated                событие/поле
537641  vehicleParent            поле
537655  followAI                 поле (строка общая со свойством CarController.followAI)
537664  CarCrashed               событие/поле
537675  driverName               поле
537686  isBot                    поле  <-- ФЛАГ БОТА
537692  explosionPivot           поле
537707  carID                    свойство (get_carID, prop rid 270, get=0)
537713  Alive                    свойство (get_Alive, prop rid 271, get=12)
537719  <GetCrashed>d__24        ТИП rid=517  -- граница блока
```

**Реконструкция `SetAsBot()`** (по составу полей блока и по соседним классам):

```csharp
public void SetAsBot()
{
    isBot = true;
    followAI = true;                       // управление отдаётся ИИ (CarController.followAI)
    driverName = <случайное/табличное имя>; // имя «пилота» для HUD и SetParticipantInfo
    // initHP / vehicleParent / explosionPivot уже выставлены в Awake/Start
}
```

Подтверждение связи с ИИ вождения: у отдельного класса `CarController`
(тип rid 1201, dt 4601, ~100 методов, rid 7198–7236 и выше) есть свойство
**`followAI`** (prop rid 543, `get=4`, геттер rid 7198). То есть
`RaceCarController.isBot` — флаг «эта машина — бот», а фактическое поведение
ведёт `CarController.followAI`.

Рядом в той же области таблицы — гоночная обвязка: `RaceGameController`
(rid 530), `RaceHudManager` (546), `RaceArenaScript` (516), `Tournament` (518),
`CarID` (521), `PilotID` (522), `RaceDataModel` (523), `GameType` (524,
`GetQuickGameRaceItem`, `get_PlayerSelectedCar`).

---

## 3. PvE-боты: `BotController` (тип rid 933, dt 4333)

27 методов, rid 5686–5712. `slot = 0xFFFF` — невиртуальный;
`flags`: `0x86` = Public|HideBySig, `0x1C4`/`0x1C6` — виртуальные с NewSlot,
`0x1886` — SpecialName|RTSpecialName (геттеры/`.cctor`):

```
rid    имя                     пар. slot  невирт.  назначение
5686   Awake                    0   —      да      инициализация
5687   Start                    0    8             запуск поведения
5688   PlaySpawnFX              0    9             эффект появления (поле spawnFXPrefab/spawnFXPivot)
5689   CheckAttack              0   —      да      проверка возможности атаки
5690   Damage                   0   10             вход урона
5691   Heal                     2   11
5692   ApplyDamage              1   12
5693   FlashDamageFX            2    4             подсветка при уроне
5694   get_IsTopShaderDevice    0   13             геттер свойства (prop rid 414, get=8)
5695   InitColor                0   —      да      ret 19708 (bool в этом чанке)
5696   FlashDamageFXCrt         0   —      да      со-программа (<FlashDamageFXCrt>d__40, rid 932)
5697   DamageRPC                0   —      да      ret 25553 — сетевой вызов урона (Photon RPC)
5698   UpdateHP                 1   —      да
5699   DieR                     1   —      да      «R» = RPC-вариант смерти
5700   DestroySelf              0   14             самоуничтожение (поле destroyingDuration)
5701   ApplyHeal                0   15
5702   UpdateTarget             1    5             смена цели (поля targetPoint, UpdateTargetPeriod)
5703   StartAttack              0   16
5704   StartAttackR             0   17             RPC
5705   StopAttack               0   18
5706   StopAttackR              0   19             RPC
5707   DamageTarget             0   20
5708   AttackEndEvent           0   21             событие из анимации (см. BotAnimEvents)
5709   PlayDieSound             0   22             поля dieSound, myVoiceAudio
5710   ShootProjectile          0   23             поле projectilePivot
5711   .ctor                    0   24
5712   .cctor                   0   —      да
```

### Поля `BotController` (блок кучи 582918–583256)

```
animation2, spawnFXPrefab, projectilePivot, spawnFXPivot, attackAnimsCount,
agent, targetPoint, UpdateTargetPeriod, destroyingDuration, myVoiceAudio,
dieSound, attack, renderSet, initColor, dmgFXCrt, bufMat, AttackIndex
+ свойство IsTopShaderDevice
```

`agent` — `NavMeshAgent`, `renderSet` — ссылка на `BotRenderingSets`,
`dmgFXCrt`/`bufMat`/`initColor` — обслуживание `FlashDamageFXCrt`.

### Помощники и подклассы

| тип | rid | dt | состав |
|---|---|---|---|
| `BotAnimEvents` | 928 | 4328 | `DieR`, `Explode`(slot 14), `DamageInRadius`, `.ctor` — колбэки из анимационных событий |
| `BotBodyPartDmgReceiver` | 929 | 4329 | `Start`, `AttackEvent`, `AttackEnd`, `PlayDieSound`, `ShootProjectile`, `.ctor`; **поле `myBot`** — обратная ссылка на своего бота |
| `BotRenderingSets` | 930 | 4330 | `Damage`, `.ctor`; поля `damageColor`, `topDeviceMaterial`, `emissionFlashColor` |
| `<FlashDamageFXCrt>d__40` | 932 | 4332 | со-программа `BotController.FlashDamageFXCrt`; hoisted-локаль `<isEmission>5__2` |
| `CartoonCatMob` | 931 | — | сосед по блоку |
| `HuggyWuggyBot` | 942 | 4342 | 8 методов, см. ниже; поле `attackSound` |
| `<AttackPlayer>d__9` | 943 | — | со-программа `AttackPlayer`; `MoveToTarget`; поля `useNavMesh`, `attackFX`, `lookRotation`, `moveDelta` |
| `OtchimBot` | 945 | 4345 | 8 методов — **точная копия формы `HuggyWuggyBot`** |
| `ChickenZombieBot` | 935 | — | только `.ctor` |
| `CheaterHunterBot` | 426 | — | только `.ctor` |
| `BotteBullet` | 1108 | 4508 | `Start`, `Throw`, `Explode`, `DestroyInRadius`, `.ctor` |

`OtchimBot` и `HuggyWuggyBot` совпадают по составу и слотам:

```
Start(—) EnableNavMeshAgent(9) DieR(—) DamageTarget(14)
AttackEndEvent(21) OnChildTrigger(22) AttackPlayer(2 пар., 25) .ctor(1 пар.)
```

`AttackEndEvent` занимает тот же слот 21, что и в `BotController` — признак
общего базового класса; при этом `DamageTarget` (14 против 20 у базы) и
`OnChildTrigger` (22 против 22 у `PlayDieSound`) расходятся, то есть колонка
`slot` в этой упаковке достоверна лишь частично.

`banbanBot` — строка кучи рядом с `GreenBanBanSpawnManager` (rid 8),
отдельного типа с таким именем нет.

---

## 4. Спавн: `GeneralZombieSpawnTrigger` (тип rid 494, dt 3894)

6 методов, rid 2845–2850:

```
2845  get_SpawnPoints    0 пар.  slot 7   ret 29442 (коллекция)   свойство SpawnPoints
2846  OnTriggerEnter     0 пар.  —        ret 17424 (Collider)
2847  SpawnZombies       1 пар.  —        void
2848  SpawnMob           0 пар.  —        void
2849  OnDrawGizmos       1 пар.  —        void
2850  .ctor              0 пар.  —        void
```

Блок кучи (533582–533634) содержит ровно две новые строки — **поля класса**:

```
533582  GeneralZombieSpawnTrigger   ТИП rid=494
533608  mySpawnedBots               поле — список заспавненных ботов
533622  MaxBotsCount                поле — лимит одновременно живых ботов
533635  <SpawnMob>b__12_0           лямбда SpawnMob (приписана типу rid 493)
```

### Семейство спавнеров (тот же механизм, блок кучи 499840–500260)

```
ESZombieSpawnEmitter  rid 237  <CreateBossMonster>b__6_0
ESZombieManager       rid 238  get_CurMaxZCount, monsterInfo, CreateMonster,
                               CreateBossMonster(2 пар.), maxBossZombCount, CurMaxZCount
SpawnZType            rid 239  ПЕРЕЧИСЛЕНИЕ: RandomOne, AllAtTime;
                               get_SpawnPoints, SpawnZombie(1 пар.), spawnPeriod,
                               allowedMonsters, spawnZType, spawnIfActivated,
                               triggerCollider, _activated, _spawnPoints, SpawnPoints
ESZombieSpawnTrigger  rid 240  (все имена дедуплицированы)
ESHudItem             rid 241  SpawnZombies(1 пар.), SpawnMob(0 пар.),
                               isBossType, spawnOnEveryTriggerEvent2, activated
GeneralZombieSpawnTrigger rid 494  = копия ESHudItem + mySpawnedBots + MaxBotsCount
```

Имена `SpawnZombies`/`SpawnMob`/`get_SpawnPoints` записаны в кучу один раз
(первое появление — блок `ESHudItem`, индексы 500185/500198/499997) и
используются обоими классами: `GeneralZombieSpawnTrigger` — дубликат
`ESHudItem` с двумя дополнительными полями учёта ботов.

**Реконструкция спавна:**

```csharp
void OnTriggerEnter(Collider c)            // rid 2846
{
    if (!activated) return;
    SpawnZombies(count);                   // rid 2847
}

void SpawnZombies(int count)
{
    for (int i = 0; i < count; i++)
        if (mySpawnedBots.Count < MaxBotsCount && !GameController.CheckIsSpawnedBot())
            SpawnMob();                    // rid 2848
}

void SpawnMob()
{
    var p = SpawnPoints[Random.Range(0, SpawnPoints.Length)];
    var bot = Instantiate(botPrefab, p, ...).GetComponent<BotController>();
    bot.PlaySpawnFX();                     // rid 5688
    mySpawnedBots.Add(bot);                // <= MaxBotsCount
    // лямбда <SpawnMob>b__12_0 — отложенный колбэк (destroy/проверка)
}
```

Порядок вызовов внутри `SpawnZombies`/`SpawnMob` — реконструкция: тела методов
в метаданных отсутствуют.

---

## 5. Гейт спавна: `GameController.CheckIsSpawnedBot()`

Запись `0x424D8E`, rid 2666, тип 3886 (`GameController`, rid 486):

```
+0 = 19708                       -> вероятно bool (см. §7: колонка ненадёжна)
parameterStart = 0xFFFF          -> параметров нет
parameterCount = 0
slot = 0xFFFF                    -> невиртуальный
flags = 0x86                     -> public, HideBySig
```

Метод скомпилирован с **двумя** compiler-generated артефактами:

| артефакт | тип | rid | сигнатура |
|---|---|---|---|
| `<CheckIsSpawnedBot>b__99_0` | `GameController+<>c` (rid 476, dt 3876) | 2683 | 1 параметр → `bool` (19708); статическая лямбда-предикат |
| `<CheckIsSpawnedBot>b__1` | `GameController+<>c__DisplayClass99_0` (rid 479, dt 3879) | 2689 | 0 параметров → `void` (36310); захватывающая лямбда (`Action`) |

Наличие display-класса означает захват локальной переменной или `this`;
наличие предиката в `<>c` — передачу лямбды делегатом (LINQ-стиль:
`Any`/`Where`/`FirstOrDefault`).

Прямое доказательство использования делегата: в куче, сразу за
`<CheckIsSpawnedBot>b__99_0` (индекс 529921), идёт блок кэшированных
делегатов `GameController+<>c`:

```
529955  <>9__81_0   <>9__81_1   <>9__81_2   <>9__81_3
        <>9__88_0   <>9__97_0   <>9__99_0
```

`<>9__NN_M` — стандартное поле кэша делегата Roslyn для лямбды
`<метод>b__NN_M`. То есть `<>9__99_0` кэширует предикат
`<CheckIsSpawnedBot>b__99_0`, и он действительно передаётся как делегат.

Единственное непокрытое имя между `IsVehiclesLimitReached` и
`CheckIsSpawnedBot` — поле `characterMotor` (`GameController`, индекс 529025):

```
529002  IsVehiclesLimitReached   метод rid 2665 (bool, 0 пар.)
529025  characterMotor           поле GameController
529040  CheckIsSpawnedBot        метод rid 2666 (bool, 0 пар.)
```

**Реконструкция:**

```csharp
public bool CheckIsSpawnedBot()
{
    // <>c__DisplayClass99_0 захватывает this / characterMotor
    // <>9__99_0 кэширует предикат bool(x)
    return spawnedBots.Any(b => b != null /* && b.owner != characterMotor */);
    // + захватывающий Action (() => ...) — отложенный колбэк
}
```

Точное содержимое предиката без IL недоступно; достоверно известно:
возвращает `bool`, аргументов не принимает, использует один статический
предикат `bool(X)` и одну захватывающую лямбду `void()`.

### Семейство проверок лимитов `GameController`

`CheckIsSpawnedBot` — часть группы однотипных проверок (rid 2660–2668),
которые гейтят создание объектов в мультиплеере:

```
2660  OnInvObjCreated           0 пар.
2661  OnInvObjDestroyed         1 пар.   (поля invObjId, spawnLimit рядом)
2662  IsMyLimitReached          1 пар.   ret 36310   \ две перегрузки;
2663  IsMyLimitReached          1 пар.   ret 19708   / у каждой свой display-класс
                                                       (<>c__DisplayClass94_0 / 95_0,
                                                        лямбды <IsMyLimitReached>b__0)
2664  IsInvObjLimitReached      2 пар.   ret bool    (параметры: invObjId, spawnLimit)
2665  IsVehiclesLimitReached    0 пар.   ret bool    (+ <>c.<IsVehiclesLimitReached>b__97_0,
                                                       кэш <>9__97_0)
2666  CheckIsSpawnedBot         0 пар.   ret bool    (+ <>9__99_0)
2667  HandleCorruptedPlayer     1 пар.
2668  UpdateFPS                 1 пар.
```

Рядом — `CheckBattleRoyaleAlives` (лямбды `b__81_0..3`, кэши `<>9__81_0..3`)
и `CleanTiters` (`b__88_0`, кэш `<>9__88_0`): все они построены по одной
схеме «LINQ-предикат + кэшированный делегат».

---

## 6. Жизненный цикл PvE-бота (по слотам и именам)

```
спавн      GeneralZombieSpawnTrigger.OnTriggerEnter -> SpawnZombies(int) -> SpawnMob()
           гейт: mySpawnedBots.Count < MaxBotsCount и GameController.CheckIsSpawnedBot()
инициализ. BotController.Awake -> Start -> PlaySpawnFX()            [spawnFXPrefab, spawnFXPivot]
цель       UpdateTarget(...)  каждые UpdateTargetPeriod             [targetPoint, agent]
атака      CheckAttack() -> StartAttack()/StartAttackR() -> DamageTarget()
           -> AttackEndEvent() (из анимации, см. BotAnimEvents) -> StopAttack()/StopAttackR()
урон       Damage() -> ApplyDamage(x) -> FlashDamageFX(..)/FlashDamageFXCrt() [dmgFXCrt, bufMat]
           -> UpdateHP(x) -> DamageRPC(...) (сеть)
части тела BotBodyPartDmgReceiver.AttackEvent/AttackEnd/PlayDieSound/ShootProjectile
           -> через поле myBot передаёт вызов в BotController
смерть     DieR(...) -> PlayDieSound() [dieSound, myVoiceAudio] -> DestroySelf()
           [destroyingDuration] -> BotAnimEvents.DieR/Explode/DamageInRadius
удаление   запись убирается из mySpawnedBots; SpawnMob() добирает до MaxBotsCount
```

Сетевая часть: суффикс `R`/`RPC` (`DieR`, `StartAttackR`, `StopAttackR`,
`DamageRPC`, `OnPlayerSitMeRPC`, `EnablePhysicsCrt`) — Photon-вызовы;
в `GameController` есть `OnPlayerConnected/Disconnected/LeftRoom/Killed/
MakeKill`, `OnMasterClientSwitched`, `SyncTeamScore`, `SendMyEvent`
(поля `eventCode`, `eventContent`, `receivers`), то есть боты живут на
стороне мастер-клиента и синхронизируются событиями.

---

## 7. Что из этих метаданных не получить

* **Тела методов** (IL или машинный код) — только сигнатуры, имена, слоты,
  флаги. Код — в `libil2cpp.so`, нужен дизассемблер и сопоставление
  `MethodSpec`/`codegenOptions` (в этой сборке не восстанавливалось).
* **Типы и смещения полей** — `FieldDefinition` игровой сборки не
  локализована; имена полей восстановлены по куче, типы — только по смыслу.
* **Порядок «поле/параметр»** для строк, стоящих вплотную к имени метода:
  статистика по 2 947 методам с параметрами не выявила правила
  (совпадение «число непокрытых строк рядом == parameterCount»: 9,5 % слева,
  8,7 % справа — обе величины на уровне шума). Поэтому `characterMotor` и
  `myParticipantUnit` помечены как «поле или параметр соседнего метода».
* Колонка `slot` достоверна не для всех записей (см. расхождение слотов
  `DamageTarget` у `BotController` и `OtchimBot`).
* **Колонка `+0` — не надёжный индекс типа возврата.** Раньше она читалась как
  `returnType` (`36310` = void, `19708` = bool внутри игрового чанка). Проверка
  на `CharacterMotor` это опровергла: `get_isInAir`, `get_HP`, `get_MyBodyguard`
  дают `36310`, а `set_titer` — `19708`. Значения годятся только как признак:
  `36310` — самое частое (≈ void / «нет типа»), `19708` — общее для всех
  предикатов и bool-проверок (`IsGrounded`, `get_IsAlive`, `IsMyLimitReached`,
  `IsInvObjLimitReached`, `IsVehiclesLimitReached`, `FindCarTarget`,
  `<CleanTiters>b__88_0`, `<IsVehiclesLimitReached>b__97_0`,
  `<CheckIsSpawnedBot>b__99_0`). Поэтому «`CheckIsSpawnedBot` → `bool`» —
  вероятный, а не доказанный факт. Подробности: `analysis/CleanTiters.md` §6.

---

## 8. Воспроизведение

```bash
.venv/bin/python tools/il2cpp_tables.py apk/global-metadata.dat layout
.venv/bin/python tools/il2cpp_tables.py apk/global-metadata.dat class  --name BotController --methods
.venv/bin/python tools/il2cpp_tables.py apk/global-metadata.dat class  --name RaceCarController --methods
.venv/bin/python tools/il2cpp_tables.py apk/global-metadata.dat class  --name GeneralZombieSpawnTrigger --methods
.venv/bin/python tools/il2cpp_tables.py apk/global-metadata.dat method --name CheckIsSpawnedBot
.venv/bin/python tools/il2cpp_tables.py apk/global-metadata.dat grep   --regex 'bot' -i
.venv/bin/python tools/il2cpp_heap.py context apk/global-metadata.dat --name isBot --before 8 --after 8
```

Дампы блоков кучи, на которых основаны выводы о полях:
`analysis/bot-heap-blocks.txt`. Карта свойств: `work/gameprops.json`.
