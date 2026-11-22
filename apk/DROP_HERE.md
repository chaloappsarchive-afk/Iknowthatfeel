# Сюда кладём APK

Файл `com.chaloapps.roosterrudy_653_rs.apk` нужно положить в эту папку под именем
`game.apk` (или любым другим — главное расширение `.apk`).

APK **не коммитится** в git (см. `/.gitignore`): GitHub жёстко режет файлы больше
100 МБ, а история раздувается навсегда. В репозиторий идут только инструменты
анализа (`tools/`) и текстовые результаты (`work/*.txt` — по желанию).

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
