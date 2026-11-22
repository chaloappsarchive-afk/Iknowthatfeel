# Reverse engineering: `com.chaloapps.roosterrudy` (Chicken Gun) — цель: `ClearBots`

Журнал работы. Всё, что ниже, проверялось в этой песочнице.

## 0. Статус

| Шаг | Состояние |
|---|---|
| Скачать APK с `fs293.tbx.su` | ❌ **заблокировано** — исходящий трафик песочницы ограничен хостами `github.com`, `codeload.github.com`, `api.github.com`, `pypi.org`, `files.pythonhosted.org`, `registry.npmjs.org`. TLS-рукопожатие с `fs293.tbx.su` обрывается (`curl: (35) SSL_ERROR_SYSCALL`), по http — `Empty reply`. Для сравнения: `api.github.com` отвечает 200, значит сеть жива, работает именно allowlist. |
| Установить jadx / apktool / Il2CppDumper | ❌ нет Java и .NET runtime, `apt` и `dot.net` недоступны, GitHub-релизы уезжают на `objects.githubusercontent.com` (тоже закрыт) |
| Собрать собственный пайплайн на Python | ✅ сделано и протестировано (см. `tools/`) |
| Найти `ClearBots` в открытых исходниках Chicken Gun на GitHub | ⚠️ частично: исходники 1.2.6 и 3.7.0 есть, но `ClearBots` там **нет** |

**Что нужно от тебя:** передать APK одним из способов в [`apk/DROP_HERE.md`](apk/DROP_HERE.md).
Дальше всё поедет автоматически: `tools/re.sh apk/game.apk clearbots`.

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

## 3. План, как только файл появится

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
