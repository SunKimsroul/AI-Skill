# Loophole — Portable Learning-Loop Spec for Agent Skill Libraries

Self-contained specification of the CTF learning-loop system. Copy this file plus
`scripts/loophole.sh` into any agent tool to reproduce the system. Nothing here
depends on opencode specifically — only on: markdown skills, a shell, and an
agent that can read/write files.

## 1. The idea

Agents solve the same *classes* of problems repeatedly and forget everything
between sessions. Loophole fixes that with a two-sided loop around a markdown
knowledge library:

```
        ┌──────────── WRITE (post-solve) ────────────┐
challenge ──▶ classify ──▶ novelty check ──▶ field-notes entry ──▶ journal
                                                        │
        ┌──────────── READ (pre-challenge) ────────────┘
next challenge ◀── warm-up: journal + field-notes for the category
```

- **READ side** runs before triage: retrieve prior lessons, start from proven moves.
- **WRITE side** runs after every solve or instructive failure: distill what was
  new into the owning skill's `field-notes.md`, log one line in the journal.
- The library grows by **novelty, not volume** — a novelty check gates every entry.

## 2. Directory layout

```
<skills-root>/                     # tool-specific location, see §7
├── loophole/
│   ├── SKILL.md                   # the loop procedure (this system's brain)
│   ├── SPEC.md                    # this file
│   └── scripts/loophole.sh        # warmup | entry | stats helper
├── _learning/
│   └── JOURNAL.md                 # master log, one line per capture
├── ctf-pwn/
│   ├── SKILL.md                   # domain knowledge + index of files below
│   ├── field-notes.md             # ← distilled lessons live here
│   └── <technique>.md             # extended detail for big techniques
├── ctf-web/ ...                   # one folder per domain skill
```

Rules:
- Every domain skill MAY have a `field-notes.md`; the `entry` subcommand creates
  it (plus an index line in SKILL.md) on first use.
- `field-notes.md` entries are append-only, grouped under `##` sections.
- Big techniques (>30 lines) get their own `<technique>.md`, linked from a short
  field-notes entry.

## 3. Entry format (the contract)

```markdown
### <Technique Name> (<ChallengeName>, <Event> <Year>)
**Tags:** #<skill> #<bugclass> #<tech>        (3–5, lowercase, grep-friendly)
**Env:** <versions the technique depends on — glibc, python, app, arch>
**Pattern:** the bug/insight in 1–3 sentences — what to look for, why it works.
**Key moves:** exact commands or code lines that made it land.
**Gotchas:** dead ends, version quirks, detection traps (omit if none).
See: solve script at <abs path>; [detail.md](detail.md) if extended notes exist.
```

Quality bar: a future agent reading ONLY the entry can decide it applies (Tags +
Env) and reproduce the move (Key moves).

Journal line format:

```markdown
- <YYYY-MM-DD> <event> <ChallengeName> (<category>) → <skill>: <one-line lesson>
```

## 4. The helper script

`scripts/loophole.sh` — POSIX-ish bash, no dependencies. Full source ships
alongside this spec. Subcommands:

| Command | Side | What it does |
|---|---|---|
| `loophole.sh warmup [keywords...]` | READ | journal tail + every field-notes entry matching keywords |
| `loophole.sh entry <skill> "Title" ["lesson"]` | WRITE | append entry stub (creates field-notes.md + SKILL.md index line if missing), append journal line |
| `loophole.sh stats` | health | entries + journal mentions per skill |

Override the library location with `SKILLS_DIR=<path>`.

## 5. Wiring points (what makes it a LOOP)

The script alone does nothing — the agent must be *prompted* at the right moments:

1. **Pre-challenge (READ):** the challenge-triage prompt/skill must say:
   "before triage, run `loophole.sh warmup <keywords>`; if an entry matches,
   start from its Key moves."
2. **Post-solve (WRITE):** the triage skill AND any writeup/report skill must say:
   "after the flag (or any instructive failure), run the loophole debrief."
3. **Slash command (optional):** `/learn` style command that invokes the WRITE
   side on demand: "debrief this session, file entries, log the journal."

## 6. The WRITE-side procedure (full)

1. **Classify** — pick the ONE skill owning the core insight (bug class or
   decisive technique, not incidental tooling). Multi-category → one entry per
   skill, only where genuinely new.
2. **Novelty check (do not skip)** — `grep -ri "<keyword>" <skill-dir>/`
   Already covered → journal one-liner only. New wrinkle → variant entry.
   Genuinely new → full entry.
3. **Distill** — scaffold with `loophole.sh entry`, fill the stub. Only what
   actually happened in session; never invented results.
4. **File** — field-notes.md (auto-created); big technique → own .md file.
5. **Journal** — one line.

Maintenance (every ~25 journal lines):
- Recurring Gotcha across ≥3 entries → promote into that SKILL.md's quick-reference.
- Stale-but-valid entries → prefix heading `[historic]`, never delete.
- Provably wrong entries → fix in place + `(updated <date>: <what changed>)`.

## 7. Adaptation guide per tool

| Tool | Skills root | How to port |
|---|---|---|
| opencode | `~/.config/opencode/skills/` | already done — `loophole/` skill + `/learn` command + wiring in `solve-challenge` & `ctf-writeup` |
| Claude Code | `~/.claude/skills/` | copy `loophole/` folder; add a slash-command `.md` in `~/.claude/commands/learn.md` mirroring §5.3; add §5.1/5.2 lines to your triage/output prompts |
| Cursor | `.cursor/rules/` | paste §1–§6 as a project rule (.mdc); set `SKILLS_DIR` to a repo `skills/` folder; commit the library with the repo |
| Windsurf | `.windsurf/rules/` | same as Cursor |
| Generic agent / MCP | anywhere | keep layout §2, expose §5 wiring as system-prompt text; the script only needs bash |

## 8. Porting checklist

- [ ] copy `loophole/` (SKILL.md, SPEC.md, scripts/loophole.sh) to the tool's skills root
- [ ] create `_learning/JOURNAL.md` with the header from §3
- [ ] `chmod +x scripts/loophole.sh`; run `loophole.sh stats` once to verify
- [ ] wire READ side into the challenge-start prompt
- [ ] wire WRITE side into the challenge-solved + writeup prompts
- [ ] add the `/learn` command equivalent
- [ ] test end-to-end: solve anything → `entry` → `warmup` finds it next session

## 9. Hard rules (the system's constitution)

1. Never invent or guess results — only capture what actually happened.
2. Deduplicate ruthlessly; growth by novelty, not volume.
3. Entries are self-contained: no "see chat above".
4. Append-only except provable errors (fix in place, note the update).
5. WRITE side runs on instructive failures too — a documented dead end saves the
   next agent an hour.
