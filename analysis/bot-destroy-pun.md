# Почему бота «дейстроят»: PUN2-протокол против метаданных Chicken Gun

Разбор делает две вещи:

1. раскладывает, **какими способами объект вообще может исчезнуть в Photon PUN2**
   (по исходникам Python-реализации протокола — они воспроизводят декомпилённый C# PUN);
2. накладывает эту схему на то, что реально объявлено в `apk/global-metadata.dat`,
   и отвечает на вопрос «почему бота удаляет `BotController.DestroySelf`, а не сеть».

Продолжение [`bot-removal.md`](bot-removal.md) (кто кого вызывает) и
[`bot-lifecycle.md`](bot-lifecycle.md) (как бот создаётся и помечается).

---

## 0. Откуда взялась протокольная часть

Референс — **`unomyths442-lang/Photon-PUN2-Python-save-fork-`**
(https://github.com/unomyths442-lang/Photon-PUN2-Python-save-fork-, MIT, авторы Pupsik /
Arcuma Hacks): чистая Python-реализация PUN2 без внешних зависимостей (ENet поверх UDP,
GpBinary16/18, LoadBalancing, слой PUN). Константы в `photon/protocol/constants.py`
помечены как «verified against the decompiled C# sources».

`PhotonBot` в этом репозитории — **headless-клиент Photon**, а не игровой бот: обёртка над
`LoadBalancingClient` + `PhotonNetwork` с таймером сериализации 100 мс. К ботам Chicken Gun
отношения не имеет, совпадение названия.

Код завендорен целиком в **`third_party/Photon-PUN2-Python/`** (MIT, LICENSE сохранён;
апстрим `main` = `84cd974970b9b55294900427d5d76e8b9da554ab`, дата вендоринга и причина —
в `third_party/Photon-PUN2-Python/VENDORED.txt`). Все цитаты ниже — из этих файлов, пути
приведены относительно вендора. Наблюдатель трафика:
[`tools/pun_probe.py`](../tools/pun_probe.py) (§7).

Что игра действительно использует PUN2, видно по библиотечной области кучи имён
(`global-metadata.dat`, база кучи `0xB7CA4`):

| имя | heap | что это |
|---|---|---|
| `PhotonNetwork` | 2038651 | фасад PUN |
| `PhotonView` | 2044045 | сетевая идентичность объекта |
| `PunRPC` | 2045285 | атрибут RPC-метода |
| `PhotonMessageInfo` | 2045358 | «кто вызвал RPC» |
| `IPunObservable` | 2038208 | интерфейс покадровой синхронизации |
| `PhotonStream` | 2045575 | поток сериализации |
| `NetworkInstantiate` | 2040101 | сетевой спавн |
| `RemoveInstantiatedGO` | 2040806 | сетевое удаление |
| `DestroyPlayerObjects` | 2040162 | удаление всех объектов игрока |
| `RequestOwnership` / `TransferOwnership` / `OwnershipTransfer` | 2040948 / 2040974 / 2044713 | передача владения |
| `MonoBehaviourPunCallbacks` | 2045332 | базовый класс колбэков PUN2 |
| `PunVersion` | 2041725 | версия PUN |

Все они — в **библиотечной** области (~2 030 000–2 050 000), тогда как имена игровой сборки
лежат в ~470 000–650 000. Единственное имя PUN-семейства в игровой области —
`OnPhotonSerializeView` (heap **585420**), и это метод `CharacterMotor`, а не объявление
библиотеки.

---

## 1. В PUN2 ровно три способа потерять объект

Из `photon/pun/network.py` (цитаты дословные):

```python
# Destroy(204) and DestroyPlayer(207) carry a single value under key 0.
DESTROY_KEY = 0

def destroy(self, view):                       # -> событие 204
    self._remove_views_of(view.view_id)
    self.client.raise_event(PunEvent.DESTROY,
                            Hashtable({PhotonByte(DESTROY_KEY): view.view_id}),
                            receivers=ReceiverGroup.ALL)

def destroy_player_objects(self, actor_number):  # -> событие 207
    for view in self.views.owned_by(actor_number):
        self.views.remove(view.view_id)
    self.client.raise_event(PunEvent.DESTROY_PLAYER,
                            Hashtable({PhotonByte(DESTROY_KEY): actor_number}),
                            receivers=ReceiverGroup.ALL)

def on_event(self, event):
    ...
    elif event.code == EventCode.LEAVE:          # игрок вышел -> то же, что 207
        if sender > 0:
            self._on_destroy_player(sender)
```

| # | как инициируется | событие | payload | что делает каждый клиент |
|---|---|---|---|---|
| 1 | `PhotonNetwork.Destroy(view)` | **204 DESTROY** | `{(byte)0: viewId}` | `_remove_views_of(viewId)` — снять view и уничтожить GameObject |
| 2 | `PhotonNetwork.DestroyPlayerObjects(actorNr)` | **207 DESTROY_PLAYER** | `{(byte)0: actorNr}` | убрать все view, у которых `owner == actorNr` |
| 3 | игрок вышел / kicked | **EventCode.LEAVE (254)** | `ACTOR_NR` | то же, что 207 (`_on_destroy_player(sender)`) |

Полная таблица кодов (`photon/protocol/constants.py`, `class PunEvent`):

```
200 RPC                  201 SEND_SERIALIZE        202 INSTANTIATION
203 CLOSE_CONNECTION     204 DESTROY               205 REMOVE_CACHED_RPCS
206 SEND_SERIALIZE_RELIABLE  207 DESTROY_PLAYER    209 OWNERSHIP_REQUEST
210 OWNERSHIP_TRANSFER   211 VACANT_VIEW_IDS       212 OWNERSHIP_UPDATE
```

**Ключевое: события 200 RPC в этом списке удаления нет.** RPC — это вызов метода:

```python
def dispatch_rpc(views, rpc_registry, content, sender_actor_nr):
    view_id, method_name, shortcut, args, timestamp = parse_rpc(content)
    view = views.get(view_id)
    if view is None: return None
    resolved = rpc_registry.resolve(method_name, shortcut)
    if resolved is None: return None
    return view.call_rpc(resolved, args, RpcInfo(sender_actor_nr, timestamp, view_id))
```

То есть RPC **находит объект по viewId и вызывает на нём метод**. Удалится объект или нет —
решает сам вызванный метод. Это и есть механика, которой пользуется Chicken Gun.

Байтовые ключи Hashtable для RPC (`constants.py`):

```
0 viewId | 1 levelPrefix | 2 timestamp | 3 methodName (строка) | 4 parameters | 5 shortcut (индекс вместо имени)
```

Для INSTANTIATION (202):

```
0 prefabName | 1 position | 2 rotation | 3 group | 4 viewIds | 5 data | 6 timestamp | 7 instantiationId | 8 levelPrefix
```

---

## 2. Владение зашито в viewId

`photon/pun/view.py` + `photon/pun/registry.py`:

```python
MAX_VIEW_IDS = 1000

@property
def owner_actor_nr(self):     return self.view_id // MAX_VIEW_IDS
@property
def is_scene_view(self):      return self.owner_actor_nr == 0
@property
def is_mine(self):            return self.owner_actor_nr == self.local_actor_nr

def allocate_id(self, actor_number):
    view_id = actor_number * MAX_VIEW_IDS + sub_id
```

Отсюда два принципиально разных класса объектов:

* **сетевой инстанс** — создан `PhotonNetwork.Instantiate`, `owner = actorNr != 0`,
  принадлежит конкретному игроку, удаляется событиями 204/207, при выходе владельца исчезает
  автоматически (LEAVE → 207);
* **scene object** — лежит в сцене, `owner = 0` (`instantiate(..., scene_object=True)` шлёт
  `EventCaching.ADD_TO_ROOM_CACHE_GLOBAL`), никому не принадлежит, и «сам» по 207 не удалится.

Для scene-объекта единственный способ что-то сделать на всех клиентах — **RPC**.

---

## 3. Что объявлено в Chicken Gun и чего в нём нет

### 3.1 У бота нет покадровой синхронизации

`CharacterMotor` (игрок, тип rid 966, 120 методов) объявляет:

```
OnPhotonSerializeView(1 пар., slot 12)      get_ViewID      CloneLinearSpeed(2, slot 10)
UpdateClonePosition      UpdateCloneState      DamageRPC(2, slot 11)      RespawnRPC
```

`BotController` (тип rid 933, 27 методов) — **нет ни `OnPhotonSerializeView`, ни `get_ViewID`**.
Вся его сетевая поверхность:

```
rid 5697  DamageRPC      0 пар.   flags 0x84
rid 5699  DieR           1 пар.   flags 0x86      <-- смерть
rid 5704  StartAttackR   0 пар.   flags 0x1C4
rid 5706  StopAttackR    0 пар.   flags 0x1C4
```

Вывод: игрок — это `IPunObservable` (события 201/206, дельта-сжатие `PhotonStream`),
а бот — **RPC-марионетка**: по сети летают только дискретные команды «урон», «умри»,
«начни/кончи атаку». Позицию бота никто не синхронизирует.

### 3.2 Мобы спавнятся без `R`-суффикса

В этой кодовой базе сетевой метод всегда помечен суффиксом `R`/`RPC`
(`RespawnRPC`, `OnEnterCarRPC`, `PushBulletRPC`, `CreateSceneObjR`, `CopySceneObjR`,
`StartBattleRoyaleR`, `RemoveWireGunCommanderR`, `SetClothingItemR`, `InteractR`, …).
Смотрим спавнеры мобов:

```
GeneralZombieSpawnTrigger (rid 494): get_SpawnPoints, OnTriggerEnter, SpawnZombies(1), SpawnMob(0), OnDrawGizmos, .ctor
ESHudItem            (rid 241): тот же набор из 6 методов
ESZombieManager      (rid 238): get_CurMaxZCount, Awake, CreateMonster, CreateBossMonster(2), .ctor(2)
SpawnZType           (rid 239): Start(1), get_SpawnPoints, OnTriggerEnter, SpawnZombie(1), OnDrawGizmos, .ctor
ZWZombieManager      (rid 256): OnTriggerEnter, .ctor(1)
WaveSpawnTanks      (rid 1300): Start, Update, SpawnEnemy, .ctor
VP_EnemySpawner     (rid 1176): Awake, Start, CreateFirstEnemy, Update, CreateEnemy, MaskFix, OnRestart(1), .ctor
```

**Ни одного `R`-суффикса.** Значит спавн моба — локальный `Object.Instantiate` на каждом
клиенте (триггер в сцене срабатывает у всех одинаково), а не `PhotonNetwork.Instantiate`
(событие 202). Это согласуется и с тем, что у `BotController` нет `OnPhotonSerializeView`:
локально заспавненного бота каждый клиент ведёт сам.

### 3.3 `DestroySelf` у бота — без параметров

```
BotController.DestroySelf       rid 5700   0 пар.   flags 0x1C4 = Virtual|NewSlot|HideBySig|Family
```

Сетевое удаление (204) **обязано** нести `viewId`. Метод, который его отправляет,
не может быть нуль-параметрическим: ему нужен либо viewId, либо `photonView`.
Нуль-параметрический `DestroySelf` на самом объекте — это сигнатура
`Object.Destroy(gameObject)` / `Object.Destroy(this.gameObject)`, то есть
**локального** уничтожения.

Сравни с телохранителем — он сетевой объект игрока, и у него параметр есть:

```
SantaGirlBodyguard.DestroySelf        rid 5668   1 пар.   flags 0x86 (public, НЕ виртуальный)
SantaGirlBodyguard.SetOwner(s12) / UpdateCloneState(s13) / OnMyOwnerDamaged(1)
CharacterMotor.DestroyCurrentBodyguard  rid 5939   1 пар.   <-- вызывает его снаружи
CameraDistanceWidget.DestroyCurrentBodyguard  rid 3372   0 пар.
```

`SetOwner` + `UpdateCloneState` — признаки объекта, принадлежащего игроку
(`owner = actorNr`), поэтому его удаление идёт через владельца и с параметром.

### 3.4 Обработка выхода игрока в игре есть — и она отдельная

```
GameController.OnOtherPlayerDisconnected(1)   GameController.OnPlayerLeftRoom(1)
GameController.DestroyDisconnectedPlayer(1 пар.)  + корутина <DestroyDisconnectedPlayer>d__45 (тип rid 480)
HUDManager.OnPlayerDisonnected                DuelLobbyManager.OnPlayerDisconnected
TauntAnimationsEventsHandler.RPC_SecureDestroyPlayer  (rid 6291)
```

Это ровно PUN-овские ветки **LEAVE(254) / DESTROY_PLAYER(207)**: параметр — `actorNumber`,
корутинa — потому что надо дождатьcя таймаута/анимации. К ботам она отношения не имеет:
бот не игрок и не владеет viewId.

---

## 4. Ответ: почему бота дейстроят

Складываем §1–§3. Единственная схема, согласованная со всеми наблюдениями:

```
каждый клиент спавнит моба сам            (нет 202 INSTANTIATION; SpawnMob/SpawnZombies без R)
        │
бот живёт локально, по сети — только RPC  (нет OnPhotonSerializeView у BotController)
        │
кто-то нанёс смертельный урон
        │
BotController.Damage / DamageRPC / ApplyDamage → UpdateHP → HP <= 0
        │
владельцем бота рассылается RPC            событие 200, ключ 3 = "DieR", ключ 0 = viewId бота
        │
НА КАЖДОМ КЛИЕНТЕ dispatch_rpc находит view и вызывает метод (§1)
        │
BotController.DieR(1 пар.)                 rid 5699 — локальное выполнение смерти
        │  PlayDieSound (rid 5709), Animator → BotAnimEvents.DieR / Explode / DamageInRadius
        │  (анимационные события, rid 5674/5675/5676)
        │  ждём destroyingDuration (поле, heap 583143)
        ▼
BotController.DestroySelf()                rid 5700, 0 пар. → Object.Destroy(gameObject)
```

То есть:

* **Бота удаляет не сервер и не Photon, а сам клиент, у себя.** Событие 204 DESTROY для ботов
  не используется: у бота нет сетевого владельца, а `DestroySelf` не принимает viewId.
* **Причина удаления — RPC `DieR`.** В PUN RPC ничего не удаляет; он вызывает метод.
  Удалился бот потому, что вызванный метод (через анимацию смерти и `destroyingDuration`)
  дошёл до `DestroySelf`.
* **Задержка `destroyingDuration` нужна**, чтобы смерть доехала до всех клиентов и доиграла
  анимация: RPC приходит асинхронно, а `BotAnimEvents.DieR`/`Explode` — это события
  анимационных кадров, то есть момент удаления привязан к клипу.
* **Список `mySpawnedBots` не чистится спавнером**, потому что спавнер вообще не знает
  о смерти: в Unity уничтоженный объект сравнивается с `null`, поэтому для лимита
  `MaxBotsCount` и для `GameController.CheckIsSpawnedBot` достаточно отфильтровать список
  (в этой же игре есть готовый образец — `CrashArenaBaseGun.RemoveNullTargets`, rid 7269).
* **Пулы не при чём**: `OnSpawn`/`OnRecycle` объявлены только у снарядов
  (`BaseBulletScript`, `Missile`, `MolotovBullet`, `BaseGrenade`, `GroundMine`, `Arrow`,
  `TankFood`, `ChickenCoinTrigger`). Бот уничтожается по-настоящему.

Исключения из этой схемы (§3.3–§3.4): телохранитель (`SantaGirlBodyguard` — сетевой объект
игрока, удаляется снаружи через `CharacterMotor.DestroyCurrentBodyguard`) и гоночный бот
(`FollowAI.HideCar(3 пар.)` + корутина `<HideCar>d__58` — машина **прячется**, а не
уничтожается; настоящее удаление только через `RaceCarController.OnDestroy`/`Explode`).

---

## 5. Что остаётся недоказуемым (и почему)

* **Вызывает ли игра `PhotonNetwork.Destroy` / `RemoveInstantiatedGO` — по метаданным
  не определить.** Эти имена в куче есть (2038651 / 2040806), но они принадлежат
  библиотеке PUN; *вызовы* библиотечных методов живут в телах методов, а тел в
  `global-metadata.dat` нет, и `libil2cpp.so` в `apk/` отсутствует.
  Доказуемо другое, и этого достаточно: **игровая сборка не объявляет** собственных
  методов сетевого удаления, а у бота есть собственный нуль-параметрический
  `DestroySelf`. Поэтому в [`bot-removal.md`](bot-removal.md) §0 п.6 прежняя формулировка
  «сетевых символов удаления нет вовсе» заменена на точную.
* **`DieR(1 пар.)` — что за параметр.** В PUN RPC-метод может объявить хвостовой
  `PhotonMessageInfo` (тогда PUN добавит его сам — см. `_wants_info` в `photon/pun/view.py`:
  `PhotonMessageInfo` передаётся, только если последний аргумент метода называется `info`).
  Значит 1 параметр — это либо `PhotonMessageInfo info` («кто вызвал»), либо игровой
  аргумент вроде `int killerActorNr`. Различить по метаданным нельзя: типов параметров
  в этом файле не видно (колонка `+0` MethodDef индексом типа возврата **не** является —
  опровергнуто на `CharacterMotor`, см. [`CleanTiters.md`](CleanTiters.md) §6).
  Косвенная зацепка: `CharacterMotor.OnPhotonSerializeView` по метаданным имеет **1**
  параметр, тогда как `IPunObservable` требует двух (`PhotonStream`, `PhotonMessageInfo`) —
  то есть счётчик параметров в этом регионе как минимум для части записей расходится
  с ожидаемой сигнатурой, и на «1 параметр» тем более нельзя опираться жёстко.
* **Кто именно рассылает `DieR`** — владелец урона или мастер-клиент. В PUN RPC шлёт тот,
  кто вызвал `photonView.RPC(...)`; у игры есть `GameController.OnPlayerKilled(1)` /
  `OnPlayerMakeKill(1)` для игроков, но для ботов отдельного «kill-менеджера» в метаданных
  не видно.
* **Наследование ботов.** Значения колонки `+20` («slot») у `BotAnimEvents.Explode`,
  `OtchimBot.DamageTarget` и `HuggyWuggyBot.DamageTarget` совпадают (14, flags `0xC4` =
  ReuseSlot ⇒ переопределение виртуала предка), а у `BotController.DestroySelf` то же 14
  идёт с флагом NewSlot (`0x1C4` ⇒ объявление нового виртуала). Переопределение с разными
  именами в C# невозможно ⇒ либо имена в этом регионе сдвинуты, либо колонка slot врёт;
  у `BotController..ctor` она заведомо врёт (slot 24 + бит Virtual). Выводов о наследовании
  не делаем. Подробности: [`bot-removal.md`](bot-removal.md) §7.

---

## 6. Что дало бы однозначный ответ: живой прогон

Достать `AppId` из метаданных нельзя (32-hex-кандидаты в файле — заполнитель таблиц,
а не литералы: AppId лежит в Unity-ассете `PhotonServerSettings`, которого у нас нет),
поэтому AppId и AppVersion взяты у тебя. **В git они не коммитятся** — AppId лежит в
`work/photon_appid.txt` (каталог `work/` в `.gitignore`) или в переменной `PHOTON_APP_ID`:

```
AppId      : 630f…01d7   (UUID с дефисами, 36 символов)  -> work/photon_appid.txt
AppVersion : 116                                         -> --app-version 116
```

**Из этой песочницы прогон невозможен**: выход в сеть разрешён только на
`github.com`, `codeload.github.com`, `api.github.com`, `registry.npmjs.org`, `pypi.org`,
`files.pythonhosted.org`. Проверено: DNS для `ns.photonengine.io` отдаёт `216.120.180.23`,
но UDP-пакет на порт 5058 уходит в таймаут; `eu.photonengine.io` не резолвится вовсе.

Запускать надо у себя (§7). Что смотреть в итоге прогона:

| наблюдение | что означает |
|---|---|
| на мобов **не** приходит 202 INSTANTIATION | спавн локальный — §3.2 подтверждён |
| на мобов **не** приходит 204 DESTROY | удаление локальное — §3.3 подтверждён |
| приходит 200 RPC с `methodName == "DieR"` | смерть бота — это RPC, §4 подтверждён |
| 204/207 приходят, но у viewId `owner != 0` | это объекты игроков, не ботов |
| 207/LEAVE после выхода игрока | ветка `GameController.DestroyDisconnectedPlayer` |

Два замечания про AppVersion:

* PUN-клиент из референс-репозитория по умолчанию шлёт `"{game_version}_{PUN_VERSION}"`,
  то есть `"116_2.55"` (`PUN_VERSION = "2.55"` в `constants.py`). Матчмейкинг Photon
  требует **точного** совпадения AppVersion, поэтому `tools/pun_probe.py` по умолчанию
  шлёт ровно `116`, а суффикс добавляется только флагом `--pun-suffix 2.55`.
  Если в комнату не пускает — попробуй второй вариант.
* AppId с дефисами (36 символов) при `APP_ID_LENGTH = 32` в протоколе: если authenticate
  отвалится, попробуй тот же id без дефисов: `--app-id '<APP_ID без дефисов>'`.

**Этика:** `pun_probe.py` ничего не отправляет в игровом трафике (ни RPC, ни instantiate,
ни destroy) — только handshake и чтение. Но вход в комнату в живом матче добавляет
фантомного игрока и может помешать остальным, поэтому режим `join` требует явного имени
комнаты и печатает предупреждение; для проверки AppId/версии используй `create`
(своя пустая комната).

---

## 7. Воспроизвести

```bash
cd /home/user/Iknowthatfeel

# библиотека уже завендорена: third_party/Photon-PUN2-Python (--lib не нужен)

# офлайн-справка: коды событий, структура RPC/INSTANTIATION, какие имена искать
.venv/bin/python tools/pun_probe.py check

# AppId — не в git: кладем в gitignored файл (или PHOTON_APP_ID)
echo '<APP_ID>' > work/photon_appid.txt   # AppId — не в git

# своя пустая комната — проверить AppId / AppVersion / регион
.venv/bin/python tools/pun_probe.py create --room MyProbeRoom --app-version 116 --seconds 30

# пассивное наблюдение за своей комнатой, лог в JSONL
.venv/bin/python tools/pun_probe.py join --room ROOM_NAME --app-version 116 \
        --seconds 180 --out work/events.jsonl

# разбор лога: какие RPC летали, были ли 202/204
.venv/bin/python - <<'PY'
import json, collections
c = collections.Counter(); d = collections.Counter()
for line in open('work/events.jsonl', encoding='utf-8'):
    r = json.loads(line)
    c[r['kind']] += 1
    if r['kind'] == 'RPC(200)': d[r.get('method')] += 1
print(c); print(d.most_common(20))
PY
```

Метаданные (как получены rid/heap-позиции, упомянутые выше) —
[`bot-removal.md`](bot-removal.md) §9 и [`bot-lifecycle.md`](bot-lifecycle.md) §8.
