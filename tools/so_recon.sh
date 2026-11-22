#!/usr/bin/env bash
# so_recon.sh -- one-shot native recon of libil2cpp.so.
#
#   tools/so_recon.sh                       # ищет apk/libil2cpp.so
#   tools/so_recon.sh work/libil2cpp.so     # или явный путь
#
# Зачем: без .so весь разбор метаданных упирается в потолок — нет RVA, нет
# порядка вызовов внутри метода, а version в пересобранной метадате стоит по
# умолчанию. Скрипт прогоняет всю цепочку tools/il2cpp_so.py и раскладывает
# результаты по work/so/, чтобы дальше читать их, а не перезапускать разбор.
#
# Порядок шагов:
#   1 info      — архитектура, сегменты PT_LOAD, ключевые строки;
#   2 module    — Il2CppCodeGenModule игровой сборки: methodCount против наших
#                 9 006 распознанных записей MethodDef (max rid 9 184);
#   3 images    — все сборки с таблицей кода и их methodCount (по ним потом
#                 подбирается OFF для библиотечных чанков);
#   4 dump-rvas — таблица rid -> RVA в JSON (её берёт il2cpp_dump.py --rvas);
#   5 version   — версии метаданных из immediates `cmp` вокруг загрузчика;
#   6 loader    — где открывается global-metadata.dat (в обфусцированной сборке
#                 там же ожидается рутина расшифровки — независимая проверка
#                 нашего XOR-keystream и OFF = 3400);
#   7 rva+disasm — курируемый список методов бот-системы из analysis/*.md.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PY:-$ROOT/.venv/bin/python}"
[ -x "$PY" ] || PY=python3
SO="${1:-$ROOT/apk/libil2cpp.so}"
OUT="${OUT:-$ROOT/work/so}"
mkdir -p "$OUT/disasm"

if [ ! -f "$SO" ]; then
  cat <<EOF
Файл не найден: $SO

Положи libil2cpp.so в apk/ (в APK он лежит в lib/arm64-v8a/libil2cpp.so) и
запусти снова. Файл не коммитится в git: .gitignore строка 8 (*.so).
Проверить сам скрипт без настоящего бинарника можно на синтетическом:

  $PY tools/tests/make_fake_so.py work/fake-libil2cpp.so
  tools/so_recon.sh work/fake-libil2cpp.so
EOF
  exit 1
fi

TOOL="$ROOT/tools/il2cpp_so.py"
run() {  # run <имя-шага> <аргументы...>
  local name="$1"; shift
  echo
  echo "################ $name ################"
  "$PY" "$TOOL" "$@" 2>&1 | tee "$OUT/$name.txt" || echo "(шаг '$name' завершился ошибкой — см. выше)"
}

echo "файл: $SO ($(stat -c%s "$SO" 2>/dev/null || wc -c <"$SO") байт)"
echo "результаты: $OUT/"

run 01-info    info    "$SO"
run 02-module  module  "$SO"
run 03-images  images  "$SO"

echo
echo "################ 04-dump-rvas ################"
"$PY" "$TOOL" dump-rvas "$SO" -o "$OUT/method_rvas.json" 2>&1 | tee "$OUT/04-dump-rvas.txt" \
  || echo "(таблица RVA не получена — следующие шаги всё равно имеют смысл)"

run 05-version version "$SO"
run 06-loader  loader  "$SO"

# --- курируемый список: что именно смотреть в первую очередь -----------------
# rid и имена взяты из analysis/bot-destroy-pun.md, bot-removal.md,
# bot-lifecycle.md и CleanTiters.md. Формат: "<rid> <подпись>".
read -r -d '' BOTS <<'EOF' || true
5700 BotController.DestroySelf -- 0 параметров: локальный Object.Destroy, а не отправка 204
5699 BotController.DieR -- RPC смерти (1 параметр, flags 0x86): кто и что передаёт
5697 BotController.DamageRPC -- 0 параметров
5704 BotController.StartAttackR -- RPC начала атаки
5706 BotController.StopAttackR -- RPC остановки атаки
5709 BotController.PlayDieSound -- что вызывается из DieR
5674 BotAnimEvents.DieR -- событийная точка анимации смерти
5675 BotAnimEvents.Explode
5676 BotAnimEvents.DamageInRadius
5668 SantaGirlBodyguard.DestroySelf -- 1 параметр, в отличие от BotController
5939 CharacterMotor.DestroyCurrentBodyguard -- кто зовёт DestroySelf с параметром
2657 GameController.CleanTiters -- LINQ-цикл по titer, к ботам не относится
2625 GameController.DestroyDisconnectedPlayer -- удаление отключившегося игрока
2666 GameController.CheckIsSpawnedBot -- проверка лимита спавна
6291 TauntAnimationsEventsHandler.RPC_SecureDestroyPlayer
4464 InventoryMotoObject.CallPhotonNetworkDestroy -- явный вызов PhotonNetwork.Destroy
4240 FirepitInvObj.CallPhotonNetworkDestroy -- второй явный вызов
4518 InventoryObject.DestroySelfR
6159 PlayerInventaryManager.RemoveObjectR
5396 ShopController.DestroyShopCar
6788 BotteBullet.Explode
6938 WeaponsPoolManager.RecycleAfter -- пул снарядов (боты не пулятся)
7269 CrashArenaBaseGun.RemoveNullTargets -- прореживание mySpawnedBots
8193 FollowAI.HideCar -- гоночные боты прячутся, а не удаляются
3048 RaceCarController.OnDestroy
3050 RaceCarController.SetAsBot
EOF

echo
echo "################ 07-rva ################"
RIDS=$(printf '%s\n' "$BOTS" | awk 'NF{printf " --rid %s", $1}')
# shellcheck disable=SC2086
"$PY" "$TOOL" rva "$SO" $RIDS 2>&1 | tee "$OUT/07-rva.txt" \
  || echo "(rid вне таблицы methodPointers — значит methodCount меньше наших 9 184)"

echo
echo "################ 08-calls ################"
# `calls`, а не `disasm`: он подписывает цели bl/b rid-ом и именем метода из
# метаданных. Без подписей bl-цель — просто число, и вопрос «зовёт ли игра
# библиотечный PhotonNetwork.Destroy» по такому листингу не решить.
COUNT="${COUNT:-200}"
META="${META:-$ROOT/apk/global-metadata.dat}"
CACHE="${CACHE:-$ROOT/work/global-metadata.dec.dat}"
NAMES=""
[ -f "$META" ] && [ -f "$CACHE" ] && NAMES="--metadata $META --cache $CACHE"

# Подписи из списка складываем рядом с листингами: в батч-режиме --label один на
# все rid, а пояснения «что именно здесь интересно» терять не хочется.
printf '%s\n' "$BOTS" | awk 'NF{printf "# rid %-6s %s\n", $1, substr($0, index($0,$2))}' \
  > "$OUT/disasm/_index.txt"

# ОДИН вызов на все rid: имена методов из метаданных грузятся один раз. По одному
# rid за прогон расшифрованные метаданные перечитывались каждый раз, и 26 методов
# стоили около четырёх минут вместо нескольких секунд.
RID_ARGS=$(printf '%s\n' "$BOTS" | awk 'NF{printf " --rid %s", $1}')
# shellcheck disable=SC2086
"$PY" "$TOOL" calls "$SO" $RID_ARGS --count "$COUNT" --outdir "$OUT/disasm" $NAMES \
  2>&1 | tee -a "$OUT/08-calls.txt" \
  || echo "(разбор методов завершился ошибкой — см. $OUT/08-calls.txt)"
echo "  пояснения по каждому rid: $OUT/disasm/_index.txt"

echo
echo "################ 09-rvas-в-Dump.cs ################"
cat <<EOF
Таблица RVA лежит в $OUT/method_rvas.json. Чтобы получить Dump.cs с адресами:

  $PY tools/il2cpp_dump.py apk/global-metadata.dat \\
      --cache work/global-metadata.dec.dat \\
      --rvas $OUT/method_rvas.json -o analysis/Dump.cs

Дальше по тексту в $OUT/disasm/: у каждого метода bl-вызовы уже подписаны
(rid + имя из метаданных), поэтому сразу видно, зовёт ли игра библиотечный
PhotonNetwork.Destroy или ограничивается локальным Object.Destroy. Цели, которых
нет в таблице игровой сборки, помечаются как «вне таблицы кода игровой сборки» —
это библиотечные методы; их rid раскроются, если подобрать OFF для нужной
сборки по её methodCount из 03-images.txt.

Обратный поиск отдельного адреса:

  $PY tools/il2cpp_so.py who --json $OUT/method_rvas.json --addr 0x... \
      --metadata apk/global-metadata.dat --cache work/global-metadata.dec.dat
EOF
