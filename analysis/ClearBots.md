# `ClearBots` в Chicken Gun 6.5.3 — результат поиска

**Вывод: метода с именем `ClearBots` (в любом регистре) в этой сборке нет.**
Ни в игровом коде, ни в строковых литералах, ни в обвязке мод-меню.

Проверялось по `apk/global-metadata.dat` (14 043 988 байт) — это полная база имён
IL2CPP-сборки: каждый тип, метод, поле, свойство и параметр игры.

## 1. Как файл был прочитан

Метаданные защищены: 56 % байт выглядят как шум, sanity-магия `0xFAB11BAF`
отсутствует, Il2CppDumper такой файл не берёт. Схема оказалась простой:

```
cipher[i] = plain[i] XOR ((i + C) & 0xFF)
```

* keystream — «пила» с периодом 256, ключ зависит только от `i & 0xFF`;
* применяется **не ко всему файлу**, а к отдельным регионам, у каждого своя фаза `C`;
* часть регионов вообще не тронута (литералы, часть таблиц).

Найденная карта (детектор фаз — `tools/il2cpp_decrypt.py`, оценка «похоже ли на
метаданные» для каждого 256-байтного блока):

| регион | размер | фаза / состояние | что там |
|---|---|---|---|
| `0x00000000–0x00018700` | 100 КБ | смесь (0x4F и др.) | заголовок + начало литералов |
| `0x0002FF00–0x000B7D00` | 553 КБ | `0xE6` | строковые литералы (PlayFab, Photon, Unity SDK) |
| `0x000B7D00–0x002DF300` | 2.26 МБ | **`0x0F`** | **куча имён (`string` heap)** — база `0xC1ECD` |
| `0x002DF300–0x002E5000` | 24 КБ | открыто | таблицы |
| `0x002E5000–0x006C2000` | 4.05 МБ | `0xCD` / `0x6F` | таблицы (свойства: stride 20, токены `0x1700000N`) |
| `0x008CE000–0x00998000` | 0.83 МБ | `0x6B` | таблицы токенов (`0x0400010C…` — поля) |
| `0x00998000–конец` | 4.4 МБ | открыто | attributeData, литералы, хвостовые таблицы |

Проверка корректности: после расшифровки куча даёт **121 886** имён, из них первые —
`TypeAccessException`, `TypeCode`, `Object`, `UInt16`, `UInt32`, `UInt64`, `Decimal`
(реальный порядок типов mscorlib), дальше `PhotonNetwork`, `PlayFab`, `BotController`,
`ChickenZombieBot` и т. д. До расшифровки идентификаторов находилось 4 727, после — 128 301.

## 2. Что именно искалось и где

| Поиск | Область | Результат |
|---|---|---|
| `ClearBots`, `clearbots`, `ClearBot`, `clearBots` | все 256 фаз по всему файлу | **0** |
| `clearbots` | куча имён (121 886 строк) | **0** |
| `^clear.*bot`, `bot.*clear`, `RemoveBots`, `KillBots`, `DeleteBots` | куча имён | **0** |
| `Clear Bots`, `Remove Bots`, `Kill Bots` | строковые литералы (открытый текст) | **0** |
| `ModMenu`, `Mod Menu`, `Cheat`, `Aimbot`, `GodMode`, `MelonLoader`, `BepInEx` | весь файл | **0** |

То есть в сборке нет ни метода, ни кнопки/подписи с таким именем. `_rs` в имени APK —
не след внедрённого мод-меню в C#-слое (по крайней мере, в метаданных IL2CPP).

## 3. Что реально есть по ботам (полный список игровых имён)

```
BotController              BotAnimEvents            BotBodyPartDmgReceiver
BotRenderingSets           ChickenZombieBot         HuggyWuggyBot
OtchimBot                  banbanBot                CheaterHunterBot
CheckIsSpawnedBot          SetAsBot                 isBot
myBot                      mySpawnedBots            MaxBotsCount
```

Плюс `<CheckIsSpawnedBot>b__1`, `<CheckIsSpawnedBot>b__99_0` (компиляторные замыкания),
`<SpawnMob>b__12_0` (лямбда метода `SpawnMob`), `BotteBullet`.

### Классы-владельцы (имена в куче идут по порядку типов → соседи = члены того же класса)

**Главный менеджер игры** (вокруг `CheckIsSpawnedBot`):
`InitializeSavedGame`, `SetSavedPlayerPos`, `AllPlayersNotDublicated`, `GetTeamScore`,
`IsTeamMate`, `CheckBattleRoyaleAlives`, `CleanTiters`, `OnInvObjCreated`,
`IsMyLimitReached`, `IsInvObjLimitReached`, `IsVehiclesLimitReached`, `characterMotor`,
→ **`CheckIsSpawnedBot`** → `HandleCorruptedPlayer`, `UpdateFPS`, `Players`,
`TimeUntilTheEndOfLevel`, `IsLevelFinished`, `teamScores`, `isJoinedRoom`, `isOffline`,
`PlayerJoined`, `PlayerDisconnected`, `PlayerMakeKill`, `OurPlayerKilled`,
`ContinueMatch`, `BattleRoyaleStarted`, `PhotonTime`, `MatchFinidhed`,
`allInventoryObjects`, `allCharacterMotors`, свойства `GameStartTime`, `MyTeamScore`,
`OtherTeamScore`.

**Спавнер мобов** (вокруг `mySpawnedBots`):
`GeneralZombieSpawnTrigger` → **`mySpawnedBots`**, **`MaxBotsCount`**,
`<SpawnMob>b__12_0` (т. е. метод `SpawnMob` с лямбдой), рядом `HPBar`, `SetTeamName`,
`UpdateHP`, `HipPointsWidget`, `UpdateArmor`, `KickOutController`, `StartVote`,
`CheckVotes`, `CancelVote`, `KickVotingWindow`.

**`BotController`** (базовый контроллер моба): `PlaySpawnFX`, `FlashDamageFX`,
`InitColor`, `FlashDamageFXCrt`, `UpdateTarget`, поля `animation2`, `spawnFXPrefab`,
`projectilePivot`, `spawnFXPivot`, `attackAnimsCount`, `agent` (NavMeshAgent),
`targetPoint`, `UpdateTargetPeriod`, **`destroyingDuration`**, `myVoiceAudio`,
`dieSound`, `attack`, `renderSet`, `dmgFXCrt`, свойства `AttackIndex`,
`IsTopShaderDevice`; рядом `Bodyguard`, `DieR`, `DamageRPC`, `ShootProjectile`,
`BombMonster`, `SantaGirlBodyguard`, `CartoonCatMob`, `Egglet`, `InvZombie`,
`UncleAhmedManager`, `EnableNavMeshAgent`, `AttackPlayer`, `MoveToTarget`, `useNavMesh`.

**`RaceCarController`** (боты-гонщики): `SetAsBot`, `isBot`, `followAI`,
`FindCarTarget`, `driverName`, `carID`, `RaceCarCreated`, `RaceCarLeaved`,
`GetDamage`, `GetCrashed`, `HpNormalized`, `Alive`.

## 4. Если `ClearBots` нужно написать/восстановить

Метода нет, но API для него в сборке есть целиком. По найденным членам «очистка ботов»
в этой игре реализуется так (псевдо-C#, все имена — реальные из метаданных):

```csharp
// владелец: спавнер мобов (поля mySpawnedBots / MaxBotsCount, метод SpawnMob)
public void ClearBots()
{
    // mySpawnedBots — список заспавненных ботов; BotController.destroyingDuration
    // отвечает за задержку уничтожения, agent — NavMeshAgent
    for (int i = mySpawnedBots.Count - 1; i >= 0; i--)
    {
        var bot = mySpawnedBots[i];
        if (bot == null) continue;
        if (bot.GetComponent<BotController>() is { } ctrl) ctrl.UpdateTarget(null);
        // в мультиплеере боты синхронизируются через PhotonView/RPC (DamageRPC, DieR)
        Object.Destroy(bot);
        mySpawnedBots.RemoveAt(i);
    }
    // GameManager.CheckIsSpawnedBot(...) после этого начнёт возвращать false,
    // а SpawnMob снова сможет заполнить список до MaxBotsCount
}
```

Точные сигнатуры и тела получатся только из нативного кода — см. ниже.

## 5. Что нужно, чтобы пойти дальше

1. **`lib/arm64-v8a/libil2cpp.so`** из того же APK — там нативный код методов и,
   главное, процедура/ключ дешифровки метаданных (по ней закрываются оставшиеся
   регионы и находится таблица методов: сейчас таблица типов читается
   (`0xB3B3A8`, stride 76, токены `0x0200000N`), но таблица `MethodDef`
   не локализуется — токены `0x0600000N` в ней не выстроены в последовательность
   ни в одной из 256 фаз, значит этот регион закрыт иначе).
2. **Сам APK** — чтобы проверить `classes*.dex`: если «Clear Bots» есть в мод-меню,
   оно живёт в dex-обвязке, а не в C#-слое игры (поиск по мод-ключевым словам в
   метаданных дал ноль).
3. Либо `Script.json` / `DummyDll` от Il2CppDumper, если он у тебя запускается
   (нужен .NET) — тогда `tools/il2cpp_native.py script` выдаст ARM64-дизассемблер
   ровно по найденным методам.

## 6. Артефакты

* `analysis/heap-names.txt.gz` — все 121 886 имён из кучи (gzip, 596 КБ)
* `analysis/bot-surface.md` — имена по группам: bot / spawn / clear / AI
* `analysis/bot-classes.md` — окружение ключевых bot-имён (члены их классов)
* `work/global-metadata.dec.dat` — расшифрованная копия (в git не коммитится)
* регенерация: `python3 tools/il2cpp_heap.py dump apk/global-metadata.dat -o work/names.txt`
