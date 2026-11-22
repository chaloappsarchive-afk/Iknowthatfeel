# Сборка Photon/PUN в обфусцированной метадате: карта чанков и rid

`libil2cpp.so` ещё не получен, но привязка **библиотечной** сборки Photon уже нужна:
без неё переходы `bl` из игрового кода в библиотечный остаются нерасшифрованными
(`tools/il2cpp_so.py calls` печатает для них «вне кода игровой сборки»). Здесь —
что удалось восстановить по `apk/global-metadata.dat` и как это повторить.

Разбор игровой сборки — в [`metadata-repair.md`](metadata-repair.md); почему боты
уничтожаются — в [`bot-destroy-pun.md`](bot-destroy-pun.md).

---

## 1. Где лежит сборка

| таблица | база чанка | шаг | записей | индексы |
|---|---|---|---|---|
| `TypeDefinition` | `0xBAA8E8` … `0xBABB04` | 76 | **62** | 1..62 |
| `MethodDefinition` | `0x66A0F8` | 30 | **473 своих** (+1 хвост) | rid 1..473 |

Граница чанка типов определяется без имён: следующая запись (`0xBABB50`) несёт токен
`0x02000001` и имя `HttpRequestMethod` — это уже другая сборка, **TriLibCore**
(дальше идут `AssetDownloader`, `AssetDownloaderBehaviour`, `<DownloadAsset>d__3`,
то есть загрузчик ассетов); она разобрана в §5. Обход решётки останавливается на
повторе rid.

Чанк найден не по заголовку (его нет), а по именам: `PhotonNetwork` (nameIndex
2 038 651), `IPunObservable` (2 038 208), `PhotonView` (2 044 045), `PunRPC`
(2 045 285) находятся как u32 в куче имён, затем их значения ищутся в файле на всех
четырёх выравниваниях; уникальные попадания дают записи TypeDef, от которых решётка
разворачивается в обе стороны. Кандидаты, отобранные по положению nameIndex в полосе
2,00–2,10 МБ (`0xBAE1E8`, `0xBA60C4`, `0xBB13C8`, `0xBBF308`), этой сборкой **не
являются** — там лежат `PhotonPing` и `PhotonPortDefinition` (сборка Photon Realtime).

Штатный `chunks()` этот чанк **дробит** на несколько «чанков», потому что выводит базу
каждой записи как `rec − (rid−1)·шаг`, а записи здесь переставлены. Пользоваться надо
обходом решётки: `T.lattice_types(m, 0xBAA8E8)` и `T.lattice_methods(m, 0x66A0F8)`.

---

## 2. Связка: индекс = позиция записи, OFF = 15832

`MethodDefinition.declaringType` = **15832 + порядковый номер записи типа в чанке**,
а НЕ rid из её токена: записи переставлены (у 27 из 62 токен расходится с позицией).
Доказательство то же, что и для игровой сборки (см. `metadata-repair.md` §1.6) —
механическая проверка на типах с обязывающим именем:

| связка | согласованных назначений |
|---|---|
| **индекс = позиция, OFF = 15832** | **8 / 8** |
| индекс = rid токена, OFF = 15831 | 7 / 8 |

Плюс смысловая проверка всей таблицы: при OFF = 15832 `CustomTypes` владеет
`SerializePhotonPlayer`/`DeserializePhotonPlayer`, `IPunObservable` —
`OnPhotonSerializeView`, `IPunPrefabPool` — `Instantiate`/`Destroy`, `PhotonHandler` —
`get_Instance`/`Awake`/`OnEnable`, `PhotonTransformViewScaleControl` —
`GetScale`/`GetNetworkScale`/`OnPhotonSerializeView`; то есть **все 49 групп методов
попадают ровно в свои типы**. При OFF = 15831 каждый интерфейс получает метод соседа,
а enum `ObservableSearch` — 8 методов `PhotonStreamQueue`.

**Прежняя нестыковка снята.** Раньше максимальный `declaringType` в чанке (15896)
указывал на индекс 64 при 62 найденных записях, и это читалось как «фрагмент таблицы
короче сборки». На деле у PUN ровно **62 типа** (dt 15833..15894) и **473 своих метода**
(rid 1..473, dt 15833..15893), а последняя запись региона — rid 474 `CreateWebRequest`
(3 пар., dt 15896) — принадлежит **следующей** сборке, TriLibCore: её dt 15896 =
`AssetDownloader` (k=2 при OFF=15894, §5), а порядок кучи имён ставит `CreateWebRequest`
(heap 2048894) ровно между `TriLibCore.dll` (2048845) → `AssetDownloader` (2048860) →
`httpRequestMethod` (2048876) и `unityWebRequest` (2048911). Другого вхождения имени
`CreateWebRequest` в файле нет.

Это общее правило файла, а не особенность PUN — см. §5.1.

У записи с индексом 62 имя затёрто (`nameIndex = 42`, до начала кучи строк) и методов
у неё нет; ровно такой же `nameIndex = 42` у позиции 1498 игровой сборки.

---

## 3. Все 62 типа сборки

| индекс | token rid | namespace | тип | методов | rid методов |
|---|---|---|---|---|---|
| 1 | 1 | — | `CustomTypes` | 3 | 1..3 |
| 2 | 2 | `Photon.Pun` | `ConnectMethod` | 0 | — |
| 3 | 3 | `Photon.Pun` | `PunLogLevel` | 0 | — |
| 4 | 4 | `Photon.Pun` | `RpcTarget` | 0 | — |
| 5 | 5 | `Photon.Pun` | `ViewSynchronization` | 0 | — |
| 6 | 6 | `Photon.Pun` | `OwnershipOption` | 0 | — |
| 7 | 7 | `Photon.Pun` | `IPhotonViewCallback` | 0 | — |
| 8 | 8 | `Photon.Pun` | `IOnPhotonViewPreNetDestroy` | 1 | 4..4 |
| 9 | 9 | `Photon.Pun` | `IOnPhotonViewOwnerChange` | 1 | 5..5 |
| 10 | 10 | `Photon.Pun` | `IOnPhotonViewControllerChange` | 1 | 6..6 |
| 11 | 11 | `Photon.Pun` | `IPunObservable` | 1 | 7..7 |
| 12 | 12 | `Photon.Pun` | `IPunOwnershipCallbacks` | 3 | 8..10 |
| 13 | 13 | `Photon.Pun` | `IPunInstantiateMagicCallback` | 1 | 11..11 |
| 14 | 14 | `Photon.Pun` | `IPunPrefabPool` | 2 | 12..13 |
| 15 | 15 | `Photon.Pun` | `<>c` | 3 | 36..38 |
| 16 | 17 | — | `PhotonHandler` | 22 | 14..35 |
| 17 | 16 | `Photon.Pun` | `InstantiateParameters` | 1 | 39..39 |
| 18 | 18 | `Photon.Pun` | `RaiseEventBatch` | 2 | 226..227 |
| 19 | 20 | — | `SerializeViewBatch` | 7 | 228..234 |
| 20 | 21 | — | `<>c` | 6 | 235..240 |
| 21 | 22 | — | `PhotonNetwork` | 186 | 40..225 |
| 22 | 19 | `Photon.Pun` | `PhotonStreamQueue` | 8 | 241..248 |
| 23 | 23 | `Photon.Pun` | `ObservableSearch` | 0 | — |
| 24 | 25 | — | `CallbackTargetChange` | 1 | 303..303 |
| 25 | 26 | — | `PhotonView` | 54 | 249..302 |
| 26 | 24 | `Photon.Pun` | `PunRPC` | 1 | 304..304 |
| 27 | 27 | `Photon.Pun` | `MonoBehaviourPun` | 2 | 305..306 |
| 28 | 28 | `Photon.Pun` | `MonoBehaviourPunCallbacks` | 27 | 307..333 |
| 29 | 29 | `Photon.Pun` | `PhotonMessageInfo` | 5 | 334..338 |
| 30 | 30 | `Photon.Pun` | `PunEvent` | 1 | 339..339 |
| 31 | 31 | `Photon.Pun` | `PhotonStream` | 25 | 340..364 |
| 32 | 32 | `Photon.Pun` | `SceneManagerHelper` | 3 | 365..367 |
| 33 | 33 | `Photon.Pun` | `DefaultPool` | 3 | 368..370 |
| 34 | 34 | `Photon.Pun` | `PunExtensions` | 10 | 371..380 |
| 35 | 35 | `Photon.Pun` | `ServerSettings` | 6 | 381..386 |
| 36 | 36 | `Photon.Pun` | `NestedComponentUtilities` | 11 | 387..397 |
| 37 | 37 | `Photon.Pun` | `ParameterType` | 0 | — |
| 38 | 39 | — | `SynchronizeType` | 0 | — |
| 39 | 40 | — | `SynchronizedParameter` | 1 | 417..417 |
| 40 | 41 | — | `SynchronizedLayer` | 1 | 418..418 |
| 41 | 42 | — | `<>c__DisplayClass18_0` | 2 | 419..420 |
| 42 | 43 | — | `<>c__DisplayClass19_0` | 2 | 421..422 |
| 43 | 44 | — | `<>c__DisplayClass22_0` | 2 | 423..424 |
| 44 | 45 | — | `<>c__DisplayClass23_0` | 2 | 425..426 |
| 45 | 46 | — | `<>c__DisplayClass24_0` | 2 | 427..428 |
| 46 | 47 | — | `<>c__DisplayClass25_0` | 2 | 429..430 |
| 47 | 48 | — | `PhotonAnimatorView` | 19 | 398..416 |
| 48 | 38 | `Photon.Pun` | `PhotonRigidbody2DView` | 4 | 431..434 |
| 49 | 49 | `Photon.Pun` | `PhotonRigidbodyView` | 4 | 435..438 |
| 50 | 50 | `Photon.Pun` | `PhotonTransformView` | 6 | 439..444 |
| 51 | 51 | `Photon.Pun` | `PhotonTransformViewClassic` | 9 | 445..453 |
| 52 | 52 | `Photon.Pun` | `InterpolateOptions` | 0 | — |
| 53 | 54 | — | `ExtrapolateOptions` | 0 | — |
| 54 | 55 | — | `PhotonTransformViewPositionModel` | 1 | 454..454 |
| 55 | 53 | `Photon.Pun` | `PhotonTransformViewPositionControl` | 9 | 455..463 |
| 56 | 56 | `Photon.Pun` | `InterpolateOptions` | 0 | — |
| 57 | 58 | — | `PhotonTransformViewRotationModel` | 1 | 464..464 |
| 58 | 57 | `Photon.Pun` | `PhotonTransformViewRotationControl` | 4 | 465..468 |
| 59 | 59 | `Photon.Pun` | `InterpolateOptions` | 0 | — |
| 60 | 61 | — | `PhotonTransformViewScaleModel` | 1 | 469..469 |
| 61 | 60 | `Photon.Pun` | `PhotonTransformViewScaleControl` | 4 | 470..473 |
| 62 | 62 | `Photon.Pun` | `<имя затёрто: nameIndex 42>` | 0 | — |

Методы внутри чанка лежат **не** по возрастанию индекса типа (например, `PhotonNetwork`
— rid 40..225, а `PhotonStreamQueue` — 241..248), поэтому диапазон rid печатается
отдельно для каждой строки. Три записи `InterpolateOptions` (индексы 52, 56, 59) — это
вложенные enum'ы внутри `PhotonTransformViewPositionControl`, `…RotationControl` и
`…ScaleControl`; вложенность по метадате не восстанавливается (таблица `nestedTypes`
пуста), но имена и порядок однозначны.

---

## 4. Что уничтожает PUN: rid, которые надо искать в `bl`

`PhotonNetwork` (индекс 21, токен `0x02000016`) — 186 методов, rid 40..225:

| API | rid | параметров |
|---|---|---|
| `Destroy` | **149** | 2 |
| `Destroy` | **150** | 1 |
| `Instantiate` | 142 | 1 |
| `NetworkInstantiate` | 145 / 147 | 5 / 2 |
| `DestroyPlayerObjects` | 151 / 152 / 184 | 1 / 1 / 2 |
| `RemoveInstantiatedGO` | 186 | 1 |
| `AllocateViewID` | 137 / 140 / 141 | 4 / 1 / 1 |
| `RaiseEvent` | 135 | 1 |
| `RPC` | 156 / 157 / 206 | 1 / 5 / 1 |
| `GetPhotonView` | 195 | 1 |
| `SetMasterClient` | 116 | 1 |
| `LeaveRoom` | 126 | 0 |

`RpcEvent` в чанке **нет** — RPC ходит через `RPC`/`RaiseEvent`, что согласуется с
разбором протокола в [`bot-destroy-pun.md`](bot-destroy-pun.md): событие 200 (RPC)
объекты не уничтожает, уничтожают 204 DESTROY и 207 DESTROY_PLAYER.

`PhotonView` (индекс 25, токен `0x0200001A`) — 54 метода, rid 249..302, в том числе
`get_IsMine`, `get_AmOwner`, `get_Owner`, `get_OwnerActorNr`, `get_Controller`,
`get_CreatorActorNr`, `get_ViewID`/`set_ViewID`, `get_IsSceneView`, `get_IsRoomView`,
`get_InstantiationData`, `Awake`, `ResetPhotonView`.

Прочее, что может понадобиться: `IPunObservable` (индекс 11) — rid 7
`OnPhotonSerializeView`; `IPunPrefabPool` (14) — rid 12/13; `PhotonHandler` (16) —
22 метода rid 14..35; `MonoBehaviourPunCallbacks` (28) — 27 методов rid 307..333
(колбэки комнаты: `OnJoinedRoom`, `OnLeftRoom`, `OnPlayerEnteredRoom`, …);
`PhotonStream` (31) — 25 методов rid 340..364; `PunRPC` (26) — rid 304 `.ctor`.

---

## 5. Соседние сборки и «хвост» региона методов

### 5.1 Правило: регион методов заканчивается чужой записью

Во всех четырёх разобранных регионах последняя запись ссылается на тип **следующей**
сборки, а записей с `declaringType` ниже своего диапазона нет вовсе:

| регион методов | своих записей | хвост | dt хвоста | чей это метод |
|---|---|---|---|---|
| игровая `0x411540` | 9 183 (rid 1..9183) | rid 9184 `ReleaseGssBuffer` | 4904 | `System.dll!NetSecurityNative` (k=5) |
| System.dll `0x454980` | 8 627 (rid 1..8627) | rid 8628 `.ctor` | 6125 | следующая сборка (k=1) |
| PUN `0x66A0F8` | 473 (rid 1..473) | rid 474 `CreateWebRequest` | 15896 | `TriLibCore!AssetDownloader` (k=2) |
| TriLibCore `0x66D884` | 673 (rid 1..673) | rid 674 `get_debug` | 15981 | `UnityEngine!AndroidJNIHelper` (k=3; `set_debug` — rid 1 следующего региона) |

**Глобальные индексы типов смежны по сборкам**, поэтому OFF каждой следующей сборки
равен OFF предыдущей плюс число её типов. Правило предсказывает OFF, который потом
подтверждается подбором по compiler-generated типам:

| граница | предсказание | подтверждение |
|---|---|---|
| игровая → System.dll | 3401 + 1498 = **4899** | `solve_type_off` 103/104; чанк типов `0xADFB2C` (1 225 записей: `GssApiException`, `GssBuffer`, `Status`, `GssFlags`, `NetSecurityNative`, …) |
| System.dll → следующая | 4899 + 1225 = **6124** | dt хвоста 6125 = k=1 |
| PUN → TriLibCore | 15832 + 62 = **15894** | `solve_type_off` 52/52 |
| TriLibCore → UnityEngine JNI | 15894 + 84 = **15978** | подбор здесь слабый (1/1: в сборке почти нет compiler-generated типов), но dt 15981 = k=3 чанка `0xBAD440` (`jvalue`, `JNINativeMethod`, `AndroidJNIHelper`, `JStringBinding`, `AndroidJNI`), а `debug` — это свойство именно `AndroidJNIHelper`, не `AndroidJNI` |

Хвост игровой сборки доказан не только порядком кучи, но и механически: у
`NetSecurityNative` (k=5 → dt 4904) в её собственном регионе `0x454980` ровно **14**
методов — `DisplayMinorStatus`, `DisplayMajorStatus`, `ImportUserName`,
`ImportPrincipalName`, `ReleaseName`, `InitiateCredSpNego`, `InitiateCredWithPassword`,
`ReleaseCred`, `InitSecContext`, `DeleteSecContext`, `Wrap`, `Unwrap`, `WrapBuffer`,
`UnwrapBuffer` — и `ReleaseGssBuffer` среди них **нет**: он лежит в хвосте игрового
региона. Куча при этом ставит `ReleaseGssBuffer` (637766) перед `DisplayMinorStatus`
(637807), то есть это первый метод типа, физически оказавшийся в чужом регионе.

Принадлежность хвоста игровой сборки доказана тем же способом — порядком кучи имён:
`System.dll` (heap 637727) → `NetSecurityNative` (637738) → `bufferPtr` (637756) →
`ReleaseGssBuffer` (637766) → `minorStatus` (637783), дальше `DisplayMinorStatus`,
`InitiateCredSpNego`, `GssApiException`, `GssBuffer`, `GSS_S_*` — всё это GSSAPI-обвязка
`System.dll`, а не `Assembly-CSharp`.

Отсюда три следствия:

* «сирота» `ReleaseGssBuffer` в `Dump.cs` больше не сирота — это метод другой сборки,
  и `T.split_tail()` исключает его из артефактов (в game-only метадате теперь 9 183 метода);
* число методов сборки, которое даст `so_recon.sh` (`methodCount` из
  `Il2CppCodeGenModule`), надо сверять с «своими» записями, а не с длиной региона;
* OFF сборки можно **предсказать** по предыдущей (таблица выше), что даёт проверку
  подбору `solve_type_off` там, где compiler-generated типов мало.

### 5.2 TriLibCore (картирована попутно)

| таблица | база чанка | шаг | записей | OFF | подбор |
|---|---|---|---|---|---|
| `TypeDefinition` | `0xBABB50` | 76 | 84 | **15894** | 52 / 52 |
| `MethodDefinition` | `0x66D884` | 30 | 673 своих (+1 хвост) | — | — |

Записи переставлены так же, как в PUN: k=1 `HttpRequestMethod` (token rid 1, enum,
0 методов), k=2 `AssetDownloader` (token rid 3, `LoadModelFromUri` + `.ctor` + хвостовой
`CreateWebRequest`), k=3 `<>c__DisplayClass3_0` (token rid 2), k=4 `<DownloadAsset>d__3`
(token rid 5, 6 методов итератора), k=5 `AssetDownloaderBehaviour` (token rid 6),
k=6 `<>c` (token rid 4). Чанк типов заканчивается на `0xBAD3F4` (k=84, имя затёрто),
следующая запись `0xBAD440` — токен `0x02000001`, имя `jvalue`.
Сборка доступна в CLI: `class --assembly trilib --name AssetDownloader --methods`.

### 5.3 System.dll (картирована по хвосту)

| таблица | база чанка | записей | OFF | подбор |
|---|---|---|---|---|
| `TypeDefinition` | `0xADFB2C` | 1 225 | **4899** | 103 / 104 |
| `MethodDefinition` | `0x454980` | 8 627 своих (+1 хвост) | — | — |

Найдена именно потому, что на неё указал хвост игровой сборки. В CLI:
`class --assembly system --name NetSecurityNative --methods`.

---

## 6. Что с этим делать, когда появится `libil2cpp.so`

1. `tools/so_recon.sh` → `work/so/03-images.txt` даст `methodCount` каждой сборки;
   у Photon/PUN их 473 (у TriLibCore 673, у игровой 9 183) — это и свяжет чанки
   `0x66A0F8` / `0x66D884` / `0x411540` с образами.
2. Индекс RVA расширяется на библиотечные сборки (сейчас `dump-rvas` строится для
   игровой), после чего `tools/il2cpp_so.py who --addr 0x…` начнёт отвечать
   «PhotonNetwork.Destroy» вместо «вне кода игровой сборки».
3. Тогда §5 `bot-destroy-pun.md` закрывается по коду: видно, вызывают ли
   `BotController.DestroySelf` (rid 5700) и `InventoryItem.CallPhotonNetworkDestroy`
   (rid 4464) библиотечные rid 149/150 или только локальный `Object.Destroy`.

---

## 7. Как повторить

```python
import sys; sys.path.insert(0, "tools")
import il2cpp_tables as T

m = T.load("apk/global-metadata.dat", "work/global-metadata.dec.dat")
types = T.lattice_types(m, 0xBAA8E8)          # {token rid: запись}
bypos, toks = T.type_positions(types)         # {позиция: запись}, {позиция: token rid}
meths = T.lattice_methods(m, 0x66A0F8)        # {rid метода: запись}
meths, tail = T.split_tail(m, meths, 15832, len(bypos))   # хвост -> TriLibCore
print(len(meths), tail)                       # 473 [(474, 15896, 'CreateWebRequest')]

off, scored = T.solve_type_off(m, bypos, meths, range(15828, 15838))
print(off, scored[off])                       # 15832 (8, 8)

# соседняя сборка TriLibCore
tlat = T.lattice_types(m, 0xBABB50)
tbypos, ttoks = T.type_positions(tlat)
tmeth = T.lattice_methods(m, 0x66D884)
toff, tscored = T.solve_type_off(m, tbypos, tmeth, range(15890, 15900))
print(toff, tscored[toff])                    # 15894 (52, 52)

# методы PhotonNetwork (индекс 21)
import collections
g = collections.defaultdict(list)
for r, rec in meths.items():
    g[m.u16(rec, T.METH_DECL)].append((r, m.raw_name(m.u32(rec, T.METH_NAME))))
print(sorted(g[off + 21])[:6])
```
