#!/usr/bin/env bash
# re.sh -- one-shot recon for a target name inside an APK.
#
#   tools/re.sh <apk> <name-regex>            e.g. tools/re.sh apk/game.apk clearbots
#
# Steps: classify -> grep every code/config entry -> extract the interesting
# files -> run the right disassembler for the scripting backend that was found.
set -uo pipefail

APK="${1:?usage: tools/re.sh <apk> <name-regex>}"
NAME="${2:?usage: tools/re.sh <apk> <name-regex>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${WORK:-$ROOT/work}"
PY="${PY:-$ROOT/.venv/bin/python}"
[ -x "$PY" ] || PY=python3
mkdir -p "$WORK"

echo "################ 1. classify ################"
"$PY" "$ROOT/tools/apk_recon.py" info "$APK" | tee "$WORK/00-info.txt"

echo
echo "################ 2. manifest ################"
"$PY" "$ROOT/tools/apk_recon.py" manifest "$APK" 2>/dev/null | tee "$WORK/01-manifest.txt" \
  || echo "(androguard could not read the manifest -- skipped)"

echo
echo "################ 3. grep '$NAME' across the apk ################"
"$PY" "$ROOT/tools/apk_recon.py" grep "$APK" --find "$NAME" | tee "$WORK/02-grep.txt"

echo
echo "################ 4. extract code containers ################"
"$PY" "$ROOT/tools/apk_recon.py" extract "$APK" --out "$WORK/x" | tail -5

DLLS=$(find "$WORK/x" -iname '*.dll' -path '*Managed*' 2>/dev/null)
META=$(find "$WORK/x" -iname 'global-metadata.dat' 2>/dev/null | head -1)
IL2CPP=$(find "$WORK/x" -iname 'libil2cpp.so' 2>/dev/null | head -1)

if [ -n "$DLLS" ]; then
  echo
  echo "################ 5. MONO: IL of matching methods ################"
  # shellcheck disable=SC2086
  "$PY" "$ROOT/tools/dnscan.py" scan $DLLS --name "$NAME" --il | tee "$WORK/10-mono-il.txt"
  echo
  echo "################ 5b. MONO: string literals ################"
  # shellcheck disable=SC2086
  "$PY" "$ROOT/tools/dnscan.py" strings $DLLS --find "$NAME" | tee "$WORK/11-mono-strings.txt"
fi

if [ -n "$META" ]; then
  echo
  echo "################ 6. IL2CPP: metadata methods ################"
  "$PY" "$ROOT/tools/il2cpp_meta.py" info "$META"        | tee "$WORK/20-meta-info.txt"
  "$PY" "$ROOT/tools/il2cpp_meta.py" find "$META" --name "$NAME" | tee "$WORK/21-meta-methods.txt"
  "$PY" "$ROOT/tools/il2cpp_meta.py" literals "$META" --find "$NAME" | tee "$WORK/22-meta-literals.txt"
  echo
  echo "### declare the owning types, then re-run with --methods:"
  "$PY" "$ROOT/tools/il2cpp_meta.py" types "$META" --name "$NAME" | tee "$WORK/23-meta-types.txt"
fi

if [ -n "$IL2CPP" ]; then
  echo
  echo "################ 7. IL2CPP: native lib summary ################"
  "$PY" "$ROOT/tools/il2cpp_native.py" info "$IL2CPP" | tee "$WORK/30-so-info.txt"
  echo "-> for native disassembly you need method addresses."
  echo "   Run Il2CppDumper on a PC (needs .NET) and drop Script.json in work/,"
  echo "   then:  .venv/bin/python tools/il2cpp_native.py script $IL2CPP \\"
  echo "            --json work/Script.json --name '$NAME'"
fi

echo
echo "################ 8. dex (mod menus live here) ################"
"$PY" "$ROOT/tools/apk_recon.py" dex "$APK" --name "$NAME" | tee "$WORK/40-dex.txt" \
  || echo "(dex pass skipped/failed)"

echo
echo "All outputs in $WORK/"
