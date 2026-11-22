# Reverse engineering: `com.chaloapps.roosterrudy` (Chicken Gun) — цель: `ClearBots`

Журнал работы. Всё, что ниже, проверялось в этой песочнице.

## 0. Статус

| Шаг | Состояние |
|---|---|
| Скачать APK с `fs293.tbx.su` | ❌ **заблокировано** — исходящий трафик песочницы ограничен хостами `github.com`, `codeload.github.com`, `api.github.com`, `pypi.org`, `files.pythonhosted.org`, `registry.npmjs.org`. TLS-рукопожатие с `fs293.tbx.su` обрывается (`curl: (35) SSL_ERROR_SYSCALL`), по http — `Empty reply`. Для сравнения: `api.github.com` отвечает 200, значит сеть жива, работает именно allowlist. |
| Получить сам файл | ✅ APK залили в репозиторий вручную; из него в репозитории лежит только `apk/global-metadata.dat` (14 043 988 байт). **`libil2cpp.so` отсутствует** ⇒ тела методов недоступны, `tools/il2cpp_native.py` запускать не на чем |
| Установить jadx / apktool / Il2CppDumper | ❌ нет Java и .NET runtime, `apt` и `dot.net` недоступны, GitHub-релизы уезжают на `objects.githubusercontent.com` (тоже закрыт) |
| Собрать собственный пайплайн на Python | ✅ сделано и протестировано (см. `tools/`) |
| Обфускация `global-metadata.dat` | ✅ **вскрыта**: поблочный XOR с периодом 256, `plain[i] = cipher[i] ^ ((i + C) & 0xFF)`, своя фаза `C` на блок; 33 770 блоков пересчитано, число читаемых имён выросло с 4 727 до 128 301 (`tools/il2cpp_decrypt.py`) |
| Таблицы метаданных без заголовка | ✅ восстановлены: `MethodDefinition` (шаг 30), `TypeDefinition` (шаг 76), `PropertyDefinition` (шаг 20); заголовок испорчен намеренно, `il2cpp_meta.py` этот файл не берёт — используется `tools/il2cpp_tables.py` |
| Найти `ClearBots` | ❌ **метода в этой сборке нет**: 0 совпадений в сыром файле, во всех 256 глобальных фазах XOR, в куче имён (121 886 строк) и в литералах; `RemoveBots`/`KillBots`/`DeleteBots`/`despawn`/`Mod Menu`/`Aimbot` — тоже 0. Подробности и реконструкция того, что делала бы такая функция: `analysis/ClearBots.md` |
| Разобрать, как боты устроены на самом деле | ✅ `analysis/bot-lifecycle.md` (+ доказательная база `analysis/bot-heap-blocks.txt`) |
| Что такое `CleanTiters` | ✅ `analysis/CleanTiters.md`: `GameController.CleanTiters` (rid 2657) — зачистка «титров» в конце Battle Royale, свойство `titer` принадлежит `CharacterMotor`; к ботам отношения не имеет. Попутно опровергнуто, что колонка `+0` MethodDef — индекс типа возврата |
| Найти, как боты удаляются | ✅ `analysis/bot-removal.md`: единой функции удаления нет; бот умирает через `BotController.DieR` → `destroyingDuration` → `DestroySelf` (rid 5700, `protected virtual`), боты не пулятся и не удаляются по сети. Корутина `<DestroySelf>d__6` оказалась `ItemControl.DestroySelf(wait)` |
| Почему удаление локальное, а не сетевое | ✅ `analysis/bot-destroy-pun.md`: сверка с протоколом PUN2 (референс — `unomyths442-lang/Photon-PUN2-Python-save-fork-`, завендорен целиком в `third_party/Photon-PUN2-Python/`, MIT + `VENDORED.txt` с SHA апстрима). В PUN объект исчезает только через события 204 DESTROY / 207 DESTROY_PLAYER / LEAVE(254), а RPC(200) лишь вызывает метод; у бота нет `OnPhotonSerializeView`, спавн идёт без `R`-суффикса, `DestroySelf` нуль-параметрический (для 204 нужен viewId) ⇒ бот спавнится и удаляется на каждом клиенте локально, по сети ходит только `DieR` |
| Проверить это живым прогоном | ⚠️ `tools/pun_probe.py` — read-only наблюдатель PUN2-трафика (коды 200/202/204/207/254, владелец viewId, имена RPC). Из песочницы не запускается: UDP-выход на `ns.photonengine.io:5058` закрыт (DNS отдаёт `216.120.180.23`, пакеты тонут). AppId/AppVersion в git не лежат — `work/photon_appid.txt` / `PHOTON_APP_ID` |
| Сделать `Dump.cs` | ✅ `analysis/Dump.cs` (3,78 МБ, 56 864 строки; 1 497 типов, 9 006 методов, 659 свойств с владельцем) — генератор `tools/il2cpp_dump.py`. Факты: имена, namespace, число параметров, флаги, колонка slot, токены, свойства. Заглушки: все возвраты `void`, все параметры `object pN`, всё как `class`, RVA нет; вместо полей — эвристика по куче имён |
| Сделать валидную метадату | ⚠️ частично: `analysis/global-metadata.game-only.dat` (528 068 байт, sanity `0xFAB11BAF`, version 24, раскладка v24.5) — генератор `tools/il2cpp_rebuild.py` с round-trip проверкой. **Починить заголовок нельзя**: таблицы физически разбросаны (TypeDef заполняет 11,2 % размаха позиций, MethodDef 32,1 %, PropertyDef 4,0 %), поэтому файл пересобран сплошными массивами. Только игровая сборка; полей/типов возврата/иерархии/RVA нет. Подробности и честные ограничения: `analysis/metadata-repair.md` |
| Таблица полей игровой сборки | ❌ отсутствует в файле **физически**, а не «не найдена»: известные имена полей (`destroyingDuration`, `dieSound`, `agent`, `mySpawnedBots`, `MaxBotsCount`, `isBot`, `renderSet`, `winnerId`) не встречаются как u32 ни в расшифрованном, ни в сыром файле; поиск по сырому с учётом keystream `(p+i+C)&0xFF` (условие: `raw[p+i]^V[i]` — прогрессия с шагом −1 mod 256) даёт единичные совпадения без решётки шага 12 |
| Таблица `FieldDefinition` игровой сборки | ❌ не локализована (находятся только 6 301 библиотечных записей). Имена полей восстановлены по порядку кучи имён |

## 1. Инструменты (готовы, без Java и .NET)

Ставятся из PyPI (разрешённый хост): `pip install dnfile androguard capstone pyelftools`
или `python3 -m venv .venv && .venv/bin/pip install -r tools/requirements.txt`.

| Скрипт | Зачем | Проверено на |
|---|---|---|
| `tools/apk_recon.py` | классифицирует APK (Mono / IL2CPP / не Unity), читает `AndroidManifest.xml`, грепает **каждую** запись архива (ASCII + UTF-16LE) по имени, распаковывает `Managed/*.dll`, `libil2cpp.so`, `global-metadata.dat`, `classes*.dex`, ищет и дизассемблирует методы в dex | синтетика + androguard 4.1.4 |
| `tools/il_disasm.py` | собственный дизассемблер CIL (ECMA-335): tiny/fat-заголовки, все одно- и двухбайтовые опкоды, ветки с метками, `switch`, EH-клаузы (catch/filter/finally/fault) | реальный .NET-ассемблер |
| `tools/dnscan.py` | поиск методов по regex в `.dll`/папке/APK, восстановление владельца (`TypeDef.MethodList`), сигнатур (blob-парсер), токенов (`MethodDef`/`MemberRef`/`TypeRef`/`Field`/`MethodSpec`), строк из кучи `#US`; полный вывод IL | `iknowthatfeel.dll` из GitHub: `TestModule::.ctor()` и `<TestModule>m__0` разобраны корректно, включая `ldstr "Hello World"` |
| `tools/il2cpp_meta.py` | парсер `global-metadata.dat` без Il2CppDumper: заголовок v24.x–v31, **самокалибровка** размера записей (оценка по валидности `nameIndex` + тегу токена `0x06`), методы/типы/строковые литералы/images | синтетический metadata v24: `ClearBots`, `ClearBotsInternal`, `ModMenu::ClearBots`, литералы `"Clear Bots"`, `"Remove all bots"` найдены верно |
| `tools/il2cpp_native.py` | capstone-дизассемблер `libil2cpp.so`: ELF-сегменты, автоопределение arch (arm64/arm/x86), перевод vaddr↔file offset, символы, grep; умеет есть `Script.json` от Il2CppDumper и дизассемблировать только совпавшие методы | `libc.so.6`: сегменты, символ `malloc`, дизассембляция по vaddr — всё совпало |
| `tools/re.sh` | оркестратор: classify → manifest → grep → extract → IL/IL2CPP/dex по факту найденного бэкенда; результаты пишет в `work/*.txt` | `bash -n` + прогон на синтетике |
| `tools/tests/make_fake_metadata.py` | генератор тестового `global-metadata.dat` для регрессий парсера | — |
| `tools/il2cpp_dump.py` | генератор `Dump.cs` из распознанных таблиц: namespace, типы, методы (число параметров, флаги, slot, токены), свойства с восстановленным владельцем (`resolve_property_owners()`: точное смещение `firstMethodRid + get` → `get_<имя>`, включая явные реализации интерфейса `<интерфейс>.get_X`, плюс мягкое правило и снятие неоднозначности по порядку rid), хвост чанка типов дочитывается через `extend_type_chunk()`, плюс эвристика полей по окну кучи ±520 байт вокруг имени типа | `analysis/Dump.cs`: 1 497 типов, 9 006 методов, 659 свойств с владельцем, 14 без, 1 группа методов-сирот |
| `tools/il2cpp_rebuild.py` | пересобирает metadata с валидным заголовком (sanity `0xFAB11BAF`, version 24, раскладка записей v24.5): укладывает таблицы сплошными массивами, достраивает `methodStart`/`method_count`/`propertyStart`/`property_count`, переводит `get`/`set` из owner-relative в абсолютные индексы, пересобирает кучу строк; встроенная round-trip проверка `--verify` | все проверки пройдены: имена типов 0 расхождений из 1 497, `BotController` 27 методов с `methodStart=5646`, `CharacterMotor` `propertyStart=432`/13 свойств, `JSONNode` 597/12, свойства 673/673, 659 абсолютных get ведут на `get_<имя>` |
| `tools/pun_probe.py` | read-only наблюдатель PUN2-трафика: `check` (офлайн-справка по кодам событий 200/201/202/204/207/254, структуре RPC и INSTANTIATION, формуле `viewId = actorNr*1000 + subId`), `create`/`join` (подключение к Photon и лог входящих событий в JSONL). Ничего не отправляет в игровом трафике; AppId берёт из `--app-id` / `PHOTON_APP_ID` / `work/photon_appid.txt` (в git не лежит). Библиотека — `third_party/Photon-PUN2-Python` | `check` — работает; `create` — импорт и handshake-путь проверены, но UDP-выход на `ns.photonengine.io:5058` из песочницы закрыт (TimeoutError), живой прогон только снаружи |
| `tools/il2cpp_decrypt.py` | `probe`/`decrypt`: подбирает фазу XOR для каждого 256-байтового блока (`plain[i] = cipher[i] ^ ((i + C) & 0xFF)`), собирает карту фаз, пишет расшифрованную копию | реальный `global-metadata.dat`: читаемых имён 4 727 → 128 301 |
| `tools/il2cpp_heap.py` | `stats`/`dump`/`find`/`context` по куче имён: база `B = 0xB7CA4`, поиск по regex, печать соседей строки (`--before/--after`) | 121 886 имён; `ClearBots` — 0, `bot` — 184 |
| `tools/il2cpp_tables.py` | **главный инструмент**: разбирает таблицы без заголовка (`layout`/`chunks`/`class`/`method`/`grep`/`dump`), находит чанки каждой сборки, связывает их (`globalTypeIndex = OFF + rid`), печатает состав класса | `BotController` (27 методов), `GameController` (62), `RaceCarController` (15), `GeneralZombieSpawnTrigger` (6) — сошлось с независимой калибровкой `OFF = 3400` |

Реальные проверки: `apk_recon.py manifest/dex` прогнаны на настоящих APK
(`TestActivity.apk`, `a2dp.Vol_137.apk` из тестовых данных androguard) — манифест
читается (package/version/sdk/permissions/signature), dex-методы дизассемблируются
с полными вызовами и строками, `--xrefs` печатает callers. Весь `tools/re.sh`
прогнан end-to-end на синтетическом APK (Mono-сборка + `global-metadata.dat` +
ELF-библиотека): классификация → grep → extract → IL → metadata → native → dex.

## 2. Что уже известно про цель

* Пакет `com.chaloapps.roosterrudy` — это **Chicken Gun** (chaloapps). Имя файла
  `..._653_rs.apk` читается как версия **6.5.3**, суффикс `rs` — вероятно,
  модифицированная/перепакованная сборка.
* `config.json` в корне этого репозитория — конфиг удалённого управления
  (`appVersion`, `AppIDRealtime`, `photonvoiceid`, блоки `news`/`anonce`).
  То есть игра/мод ходит за конфигом на внешний сервер; `ClearBots`, скорее всего,
  либо метод самой игры (зачистка ботов в лобби), либо функция мод-меню,
  которая дёргает игровой код.
* Поиск по GitHub:
  * `GoldyGame11/Chicken-gun-3.7.0-source` — полный Unity-проект 3.7.0 (~50 000 файлов).
    Поиск `ClearBots` / `clearbots` / `ClearBot` / `DeleteBots` / `RemoveBots` — **0 совпадений**.
  * `Nestor1232323/chicken-gun` — исходники 1.2.6 (~5 800 файлов) — тоже **0**.
  * `chickengame-dev/Chicken-Gun-Mod-for-ChaloApps` → `ModBase.cs` — фанатский
    каркас модов (ModLoader/GameEvents/ModSandbox/RainbowChickenMod), `ClearBots` там нет.
  * `KutKatttt/B200-Gun`, `KyritsaSoft/ChickenGunPrivatesRaw` — почти пустые (README/Servers/Version).
  * Вывод: `ClearBots` — **не** из публичных исходников старой игры. Значит берём его
    из самого APK: либо из `Assembly-CSharp.dll` (Mono), либо из
    `global-metadata.dat` + `libil2cpp.so` (IL2CPP), либо из dex-обвязки мод-меню.

## 3. План (исторический — выполнен, кроме `ClearBots`: его в сборке нет)


1. `tools/apk_recon.py info` → понять бэкенд (Mono или IL2CPP) и список `classes*.dex`.
2. `tools/apk_recon.py grep --find clearbots` → где вообще встречается строка
   (имя метода, подпись кнопки в меню, ключ конфига, URL).
3. **Mono:** `tools/dnscan.py scan Assembly-CSharp.dll --name 'clearbots' --il` →
   полный IL, владелец, сигнатура; по IL восстанавливаю читаемый C#-эквивалент
   (что вызывает: `PhotonNetwork`, `Destroy`, списки ботов, `GameObject.Find`, RPC)
   и складываю в `analysis/ClearBots.cs` + `analysis/ClearBots.md`.
4. **IL2CPP:** `tools/il2cpp_meta.py find --name clearbots` → класс/токен/число
   параметров/литералы. Дальше два пути:
   * если дашь `Script.json`/`DummyDll` от Il2CppDumper — `tools/il2cpp_native.py script`
     выдаст ARM64-дизассембляцию именно этих методов, и я разберу логику по ней;
   * если нет — ищем нативную функцию по токенам/строкам и разбираем её capstone'ом.
5. **dex:** если `ClearBots` — кнопка мод-меню, `tools/apk_recon.py dex --name clearbots`
   покажет smali-цепочку (меню → нативный вызов/UnitySendMessage → игровой метод).
6. Итог: `analysis/ClearBots.md` — что делает метод, какие поля/RPC трогает,
   чем отличается в версиях, и восстановленный C#-листинг.

## 4. Уточни, если можно

* `clearbots.cs` — это **файл** в исходниках мода (тогда ищем его как ресурс внутри
  APK: `assets/`, `Mods/`, `plugins/`) или **метод** `ClearBots()` в коде игры?
  Инструменты покрывают оба случая, но это сэкономит один проход.
* Версия 6.5.3 и суффикс `rs`: это официальная сборка или чужой мод?
  Если мод — интереснее всего diff против оригинала (что именно добавлено в/вокруг `ClearBots`).

## 5. Раскладка `global-metadata.dat` этой сборки (проверено, не выводить заново)

Заголовок испорчен: sanity `AF 1B B1 FA` отсутствует и в файле, и во всех 256
глобальных фазах XOR. Поэтому все смещения найдены структурно. Работать с
`work/global-metadata.dec.dat` (расшифрованная копия), а не с оригиналом.

**Дешифровка.** `plain[i] = cipher[i] ^ ((i + C) & 0xFF)`, фаза `C` своя для
каждого 256-байтового блока (всего 54 859 блоков: 21 089 не тронуты,
33 770 пересчитаны). Карта фаз: `0x700`→0x4F; `0x18600–0xB7D00`→0xE6;
`0xB7D00–0x2DF300`→0x0F (**куча имён**, 2,26 МБ); `0x2DF300–0x2E5000` без
изменений; `0x2E5000–0x6C2000`→0xCD/0x6F; `0x8CE000–0x998000`→0x6B; хвост без
изменений.

**Куча имён.** `0xB8000..0x2DF000`, база `B = 0xB7CA4` (`name = B + nameIndex`,
проверено на 300/300). Строки дедуплицированы и записаны в порядке обхода
сборки, поэтому члены одного класса лежат сплошным блоком — это единственный
способ восстановить принадлежность полей (см. `analysis/bot-lifecycle.md` §1).

**Таблицы** (записи НЕ выровнены; стандартные шаги Il2CppDumper не подходят):

| Таблица | Шаг | Колонки |
|---|---|---|
| `MethodDefinition` | 30 | `+0` u32 returnType (индекс типа, локальный для чанка) · `+4` u16 0x0800 · `+6` u16 parameterStart (`0xFFFF` = нет параметров) · `+8` u32 маркер параметров · `+12` u32 token `0x06xxxxxx` · `+16` u32 MethodAttributes · `+20` u16 slot (`0xFFFF` = невиртуальный) · `+22` u16 parameterCount · `+24` u32 nameIndex · `+28` u16 **declaringType** (глобальный индекс типа) |
| `TypeDefinition` | 76 | `+0` u32 namespaceIndex · `+68` u32 token `0x02xxxxxx` · `+72` u32 nameIndex. `methodStart`/`method_count` в этой упаковке нечитаемы — принадлежность метода определяется по `declaringType` |
| `PropertyDefinition` | 20 | `+0` nameIndex · `+4` get · `+8` set (`0xFFFFFFFF` = нет) · `+12` attrs · `+16` token `0x17xxxxxx`. **`get`/`set` — номер метода относительно первого метода своего типа** |
| `FieldDefinition` | — | найдены только библиотечные записи (тег `0x04`, шаг 10, token@+0, nameIdx@+4); чанк игровой сборки не локализован |

**Чанки.** Каждая сборка имеет свой фрагмент таблицы, rid в нём начинается с 1;
фрагменты перемешаны по файлу. База фрагмента `M = позиция_записи − (rid−1)·шаг`;
группировка по одинаковому `M` (с допуском на нераспознанные записи) даёт чанки.
 RID — не глобальный индекс, склеивать чанки по «rid+1» нельзя.

**Игровая сборка.** методы: `M = 0x411540` (9 006 записей, rid 1..9184,
позиции `0x411540..0x454962`); типы: `M = 0xAC3E74` (1 498 записей, rid 1..1498;
записи внутри чанка **перемешаны** — rid читается из токена, а не из позиции,
хвост с именами `__StaticArrayInitTypeSize=NN` дочитывает `extend_type_chunk()`);
свойства: `M = 0x2FE698` (673 записи). Связь: **`globalTypeIndex = 3400 + rid`**
(`work/layout.json`), калибровка по compiler-generated типам
(`<X>d__N` → обязан быть `MoveNext`; `<>c…` → только `.ctor`/`<…>b__…`).
Другие крупные чанки методов: `0x35714A` (12 711), `0x3B8BA2` (11 777),
`0x536C5E` (9 936), `0x454980` (7 669), `0x4BB70C` (5 897), `0x50CDB4` (5 106).

**Индексы типов возврата локальны для чанка.** В игровом: `36310` = void,
`19708` = bool, `33487` = string/int, `29442` ≈ коллекция, `25553` ≈ IEnumerator.
Переносить эти числа на другие сборки нельзя (в `work/rettypes.json` —
статистика по всем 113 060 методам, она смешивает сборки).

**Проверенные доказательства раскладки.** `parameterStart[i] + parameterCount[i]
== parameterStart[i+1]` для 2 932 из 2 948 соседних пар; `slot` равен `0xFFFF`
у 6 838 методов и < 100 у 2 168, промежуточных значений нет; у всех 188
`MoveNext` единственный returnType (36310 = void) и флаги `0x1E1`
(Private|Final|Virtual|HideBySig|NewSlot) — ровно то, что выдаёт Roslyn.

## 6. Ложные следы (не повторять)

* `il2cpp_meta.py` на этом файле падает на проверке заголовка — не использовать.
* «Совпадения» nameIndex полей в `0x6F9548` (`isBot`) и `0x6D07EB`
  (`mySpawnedBots`) — арифметический мусор: две колонки, растущие на +1 каждые
  10 байт. Индекс имени нужно искать только с проверкой, что предыдущий байт —
  `0x00`, иначе `carID` «находится» внутри `get_carID`.
* Поиск `methodStart`/`method_count` в `TypeDefinition`: исчерпывающий перебор
  пар колонок (u32 × u16) по 1 405 группам методов дал лучшие 5,8 % — колонок нет.
* Имена `Clear*` в куче (158 штук) — это API движка/библиотек, не игра.
* `Spawn*`/`Pool*` в прочих сборках — Photon PunSample, MeshBaker, DOTween
  `PoolingSystem`, VFXSpawnerCallbacks: фильтровать перед тем, как сообщать.
