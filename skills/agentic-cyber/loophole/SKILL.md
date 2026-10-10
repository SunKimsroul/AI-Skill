---
name: loophole
description: "The CTF learning loop — two directions. WRITE side: after solving (or decisively failing) any CTF challenge, exam lab, or pentest finding, distill new techniques, commands, and pitfalls back into the ctf-* skill library. READ side: at challenge start, warm up by retrieving prior lessons for the category. Triggers: \"learn from this\", \"loophole\", \"/learn\", flag captured, or starting a challenge in a known category."
---

# Loophole — the CTF learning loop

Every solved (or instructively failed) challenge is a training sample. Loophole
moves knowledge in both directions so each session starts smarter than the last:

```
        ┌──────────── WRITE (post-solve) ────────────┐
challenge ──▶ classify ──▶ novelty check ──▶ field-notes entry ──▶ journal
                                                        │
        ┌──────────── READ (pre-challenge) ────────────┘
next challenge ◀── warm-up: journal + field-notes for the category
```

## READ side: warm-up (do this FIRST, before triage)

When a new challenge arrives and its category is even guessable:

```bash
bash ~/.config/opencode/skills/loophole/scripts/loophole.sh warmup <tech-keywords>
# e.g.: loophole.sh warmup heap tcache glibc
```

One command = journal tail + every matching field-notes entry across all skills.
If a prior entry matches, start from its Key moves — do not re-derive a solved
technique from scratch. This is the whole point of the library.

## WRITE side: the 5-step debrief

### Step 1: Classify

Pick the ONE skill that owns the core insight (the bug class or the decisive
technique — not the incidental tooling):

| Insight looks like | Skill |
|---|---|
| memory corruption, ROP, heap, sandbox | ctf-pwn |
| static/dynamic analysis, deobfuscation, VMs | ctf-reverse |
| web protocol, injection, auth, deser | ctf-web |
| cipher math, padding, lattice, PRNG | ctf-crypto |
| disk/memory/network artifacts, stego | ctf-forensics |
| AD, Kerberos, delegation, ESC | ctf-ad |
| privesc on a solved box | ctf-privesc |
| tunnels, proxies, multi-host | ctf-pivoting |
| LLM/prompt injection, agents, MCP | ctf-ai-ml |
| encoding, jail, esoteric formats | ctf-misc |
| AWS/Azure/GCP | ctf-cloud |
| recon, services, passwords | ctf-pentest |

Multi-category insight → one entry per skill, only where genuinely new.

### Step 2: Novelty check (do not skip)

```bash
grep -ri "<keyword-from-technique>" ~/.config/opencode/skills/<skill>/
```

- Already covered, nothing new → stop, log a one-liner in the JOURNAL only.
- Covered but with a new wrinkle → short variant entry.
- Genuinely new → full entry.

### Step 3: Distill the entry

Terse, imperative, copy-pasteable. Scaffold it with:

```bash
bash ~/.config/opencode/skills/loophole/scripts/loophole.sh entry ctf-<skill> "Technique Name (ChalName, Event Year)" "<one-line journal lesson>"
```

Template:

```markdown
### <Technique Name> (<ChallengeName>, <CTF event> <year>)
**Tags:** #<skill> #<bugclass> #<tech>            (3-5, lowercase, grep-friendly)
**Env:** <glibc/python/app version, arch — anything the technique depends on>
**Pattern:** the bug/insight in 1-3 sentences — what to look for, why it works.
**Key moves:** exact commands or code lines that made it land.
**Gotchas:** dead ends, version quirks, detection traps (omit if none).
See: solve script at <abs path>; [detail.md](detail.md) if extended notes exist.
```

Quality bar: a future agent reading ONLY the entry (Tags + Env included) can
decide it applies and reproduce the move.

### Step 4: File it

Target: `<skill-dir>/field-notes.md` (pwn, reverse, web, forensics have one —
append under the closest `##` section or add one).

Skill without field-notes.md yet → the `entry` subcommand creates it with the
standard header and adds the index line to SKILL.md automatically.

For a BIG technique (>30 lines: full exploit chain, script, output), create
`<technique-name>.md` with the detail and link it from a short field-notes entry
— that is how pwn's advanced.md ecosystem grew.

### Step 5: Update the journal

The `entry` subcommand appends the line when given the lesson argument; format:

```markdown
- <YYYY-MM-DD> <CTF/event> <ChallengeName> (<category>) → <skill>: <one-line lesson>
```

## Library health

```bash
bash ~/.config/opencode/skills/loophole/scripts/loophole.sh stats
```

Entries + journal mentions per skill. All zeros in a category you play often =
the loop is not firing — fix the wiring, not the library.

## Maintenance pass (run when the journal hits ~25 new lines)

1. `grep -c '^### ' <skill>/field-notes.md` per skill — spot runaway growth.
2. Recurring Gotcha across ≥3 entries of one skill → promote it into that
   SKILL.md's quick-reference section, then trim the repetitions.
3. Entries whose Env is now ancient (EOL glibc, dead service) → prefix the
   heading with `[historic]` instead of deleting.
4. Wrong entries → fix in place + `(updated <date>: <what changed>)`.

## Bonus captures (when they apply)

- **New docker/lab environment** built for the challenge → append the rebuild
  recipe to `~/Documents/CTF/ctf-docker-tools/README.md`.
- **Recurring failure of an existing note** → edit that note in place; fixing
  wrong knowledge beats appending a correction.
- **New tool worth keeping** → note it in the entry, never install globally.

## Hard rules

1. Never invent or guess results — only capture what actually happened in session.
2. Deduplicate ruthlessly; the library grows by novelty, not volume.
3. Keep entries self-contained: no "see chat above".
4. Do not delete or rewrite existing entries unless they are provably wrong.
5. WRITE side runs even on instructive failures — a documented dead end saves
   the next agent an hour.
   the next agent an hour.

## Coverage learning

When recording a lesson, include the coverage gap or pivot that revealed it; update the [`coverage-first`](../coverage-first/SKILL.md) ledger before treating a failure as final.
