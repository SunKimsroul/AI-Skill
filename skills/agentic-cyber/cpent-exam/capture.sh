#!/usr/bin/env bash
# cap — CPENT evidence capture: one command = one step = command+output+screenshot
# Usage:  cap <NN> <command...>          (NN = step number, e.g. 01 02 03)
# Env:    CAP_ZONE=name (default: zoneX)   CAP_DIR=~/loot by default
# Output: $CAP_DIR/$CAP_ZONE/steps/NN-cmd.txt, NN-out.txt, NN.png + steps.log
set -u
ZONE="${CAP_ZONE:-zoneX}"; BASE="${CAP_DIR:-$HOME/loot}/$ZONE/steps"; NN="$1"; shift
mkdir -p "$BASE"
CMD_STR="${*//\"/\\\"}"

printf '%s\n' "$*" > "$BASE/${NN}-cmd.txt"
printf '[%s] STEP %s :: %s\n' "$(date -Iseconds)" "$NN" "$*" >> "$BASE/steps.log"

OUT=$( { "$@" 2>&1; } | tee "$BASE/${NN}-out.txt" )

if command -v flameshot >/dev/null 2>&1 && [ -n "$DISPLAY$WAYLAND_DISPLAY" ]; then
  flameshot full -p "$BASE/${NN}.png" >/dev/null 2>&1 \
    && echo "[cap] screenshot -> $BASE/${NN}.png" \
    || echo "[cap] flameshot failed — TAKE SCREENSHOT MANUALLY: $BASE/${NN}.png"
else
  echo "[cap] no screenshot tool/session — TAKE SCREENSHOT MANUALLY: $BASE/${NN}.png"
fi
echo "[cap] evidence: $BASE/${NN}-cmd.txt ${NN}-out.txt (decisive lines: $(echo "$OUT" | grep -c .))"
echo "[cap] ANSWER-FIGURE rule: this step = Figure <n> = E-${ZONE}-${NN}01"
