#!/usr/bin/env bash
# loophole — CTF learning loop helper
# subcommands:
#   warmup [keywords...]   READ side: recent journal lines + field-notes entries matching keywords
#   entry <skill> "Title (Chal, Event Year)" ["journal lesson"]
#                          WRITE side: scaffold a field-notes entry (+ journal line)
#   stats                  library health: entries + journal mentions per skill
set -euo pipefail

SKILLS_DIR="${SKILLS_DIR:-$HOME/.config/opencode/skills}"
JOURNAL="$SKILLS_DIR/_learning/JOURNAL.md"

case "${1:-}" in
  warmup)
    shift || true
    echo "=== journal (last 15) ==="
    tail -15 "$JOURNAL" 2>/dev/null || echo "(empty)"
    if [ "$#" -gt 0 ]; then
      echo; echo "=== matching entries ==="
      found=0
      for fn in "$SKILLS_DIR"/*/field-notes.md; do
        [ -f "$fn" ] || continue
        out=$(awk -v kws="$*" -v src="$(basename "$(dirname "$fn")")" '
          BEGIN { n = split(kws, K, " ") }
          /^## / { flush(); open = 0; next }
          /^### / { flush(); hdr = substr($0, 5); body = ""; keep = 0; open = 1; next }
          open {
            body = body $0 "\n"
            for (i = 1; i <= n; i++) if (index(tolower($0), tolower(K[i])) > 0) keep = 1
          }
          function flush() {
            if (open && keep) printf "[%s]\n### %s\n%s---\n", src, hdr, body
            open = 0
          }
          END { flush() }
        ' "$fn") || true
        if [ -n "$out" ]; then
          echo "$out"
          found=1
        fi
      done
      [ "$found" = 0 ] && echo "(no matching entries — novel territory)"
    fi
    ;;

  entry)
    SKILL="${2:?usage: loophole.sh entry <skill-name> \"Title\" [\"journal lesson\"]}"
    TITLE="${3:?usage: loophole.sh entry <skill-name> \"Title\" [\"journal lesson\"]}"
    LESSON="${4:-}"
    DIR="$SKILLS_DIR/$SKILL"
    [ -d "$DIR" ] || { echo "no such skill: $DIR" >&2; exit 1; }
    FN="$DIR/field-notes.md"
    if [ ! -f "$FN" ]; then
      printf '# %s Field Notes\n\nDistilled post-solve lessons (loophole loop). Read after SKILL.md when the challenge matches this category. Newest entries at the bottom of each section.\n\n## General\n' \
        "$(echo "$SKILL" | sed 's/^ctf-//; s/^./\U&/')" > "$FN"
      grep -q "field-notes.md" "$DIR/SKILL.md" || sed -i '0,/^## Additional Resources$/s//## Additional Resources\n\n- [field-notes.md](field-notes.md) - distilled lessons from solved challenges/' "$DIR/SKILL.md"
      echo "created $FN (+ SKILL.md index line)"
    fi
    printf '\n### %s\n**Tags:** #%s\n**Env:** \n**Pattern:** \n**Key moves:** \n**Gotchas:** \nSee: \n' \
      "$TITLE" "$SKILL" >> "$FN"
    echo "entry stub appended to $FN"
    if [ -n "$LESSON" ]; then
      echo "- $(date +%Y-%m-%d) $LESSON" >> "$JOURNAL"
      echo "journal line appended to $JOURNAL"
    else
      echo "remember to add the journal line: $JOURNAL"
    fi
    ;;

  stats)
    echo "skill                entries  journal-mentions"
    for d in "$SKILLS_DIR"/*/; do
      n=$(basename "$d")
      [ "$n" = "_learning" ] && continue
      e=$(grep -c '^### ' "$d/field-notes.md" 2>/dev/null || true); e=${e:-0}
      j=$(grep -c " $n:" "$JOURNAL" 2>/dev/null || true); j=${j:-0}
      printf '%-20s %-8s %s\n' "$n" "$e" "$j"
    done
    echo; echo "journal lines total: $(grep -c '^- ' "$JOURNAL" 2>/dev/null || echo 0)"
    ;;

  *)
    sed -n '2,7p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
    ;;
esac
