# Сюда кладём APK

Файл `com.chaloapps.roosterrudy_653_rs.apk` нужно положить в эту папку под именем
`game.apk` (или любым другим — главное расширение `.apk`).

APK **не коммитится** в git (см. `/.gitignore`): GitHub жёстко режет файлы больше
100 МБ, а история раздувается навсегда. В репозиторий идут только инструменты
анализа (`tools/`) и текстовые результаты (`work/*.txt` — по желанию).

## Сейчас нужен только `libil2cpp.so`

Метаданные (`global-metadata.dat`) уже в работе: расшифрованы, таблицы
восстановлены, есть `analysis/Dump.cs` и пересобранный
`analysis/global-metadata.game-only.dat`. Чего до сих пор нет — нативной
библиотеки, и именно она снимает три ограничения:

| чего нет без `.so` | что появится с ним |
|---|---|
| RVA/Offset у методов | `tools/il2cpp_so.py rva --rid 5700` → адрес каждой из 9 006 функций |
| порядок вызовов внутри метода (реконструкция) | `disasm --rid 5700` → реальный ARM64-код `BotController.DestroySelf`/`DieR` |
| `version = 24` в пересобранной метадате стоит по умолчанию | `version` → immediates `cmp` вокруг загрузчика метаданных |

Плюс бонус: в обфусцированной сборке функция, открывающая `global-metadata.dat`
(`loader`), обычно содержит и саму расшифровку — это независимая проверка нашего
XOR-keystream и `OFF = 3400`.

**Куда положить:** `apk/libil2cpp.so` (или `work/libil2cpp.so` — путь везде
передаётся аргументом). Файл **не коммитится**: `.gitignore` строка 8 (`*.so`)
его закрывает, это штатное поведение для бинарника на десятки мегабайт.

**Откуда взять в APK:** `lib/arm64-v8a/libil2cpp.so` (или `lib/armeabi-v7a/`,
если игра собрана под 32 бита — скрипт определяет архитектуру сам).

Проверить инструмент без настоящего файла можно на синтетическом:

```bash
.venv/bin/python tools/tests/make_fake_so.py work/fake-libil2cpp.so
.venv/bin/python tools/il2cpp_so.py module work/fake-libil2cpp.so
```

## Как передать файл агенту

Внешний трафик песочницы ограничен списком хостов:
`github.com`, `codeload.github.com`, `api.github.com`, `pypi.org`,
`files.pythonhosted.org`, `registry.npmjs.org`.
Прямая ссылка на `fs293.tbx.su` недоступна (TLS-рукопожатие обрывается), поэтому
варианты такие:

1. **Вложение в чат** — перетащить APK прямо в диалог. Самый простой путь:
   файл появится в рабочей директории, и я сразу запущу `tools/re.sh`.
2. **Через GitHub** — запушить APK в этот репозиторий
   (`chaloappsarchive-afk/Iknowthatfeel`, ветка `arena/94383fad-iknowthatfeel`),
   я сделаю `git pull`. Работает, только если файл < 100 МБ.
   Git LFS не подойдёт: LFS-объекты лежат на `media.githubusercontent.com`,
   а этот хост тоже закрыт.
3. **Только нужные части** (если APK большой) — достаточно прислать:
   * Mono-сборка: `assets/bin/Data/Managed/Assembly-CSharp.dll`
   * IL2CPP: `assets/bin/Data/Managed/Metadata/global-metadata.dat`
     и `lib/arm64-v8a/libil2cpp.so`
   * мод-меню на Java/Kotlin: `classes.dex`, `classes2.dex`, ...
   Это десятки мегабайт вместо сотен, и для поиска `ClearBots` этого хватает.
