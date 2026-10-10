---
name: compact
description: Token-efficient operation mode for long CTF/pentest sessions. Use when the user says "compact", "save tokens", "token budget", when context is getting long, or before/after opencode compaction. Writes a compact state file so nothing is lost, then switches to minimal-token discipline.
---

# Compact — token-efficient mode

Two jobs: (1) snapshot the session so compaction loses nothing, (2) run lean
until the session ends.

## 1. State snapshot (do this FIRST)

Write `session-state.md` into the current challenge directory with exactly this
shape — nothing more:

```markdown
# State — <challenge/target> (<date>)
## Objective
<one line: what wins — flag, shell, report>
## Done
- <verified facts only, one line each>
## Found
- <creds/endpoints/offsets/versions — the reusable facts>
## Next
1. <the single most promising next action, with exact command>
## Open questions
- <max 3>
```

Rules: every line must be actionable or a verified fact. No narrative, no "we
tried". If opencode compaction fires, this file is the recovery point — reread
it instead of re-deriving the session.

## 2. Token discipline (until session end)

**Tool output:**
- Never read whole files: `head`, `tail -n 20`, `wc -l`, `grep -n` first
- Prefer `rg -c` / `grep -c` (counts) over dumps; escalate to line ranges only on hits
- Binary/large output → redirect to a file, then grep the file; reference the path
- Screenshots/dumps/hashes → always to disk, never pasted

**Communication:**
- Terse mode: answers in one line unless asked for detail
- No restating file contents, command output, or previous steps
- No preamble/postamble; code and commands without explanation
- Findings go into `session-state.md`, not chat

**Delegation:**
- Bulky exploration (big greps, dir walks, brute force) → dispatch a subagent/task
  so the output never enters main context; accept back a summary only

**Reuse:**
- Before deriving anything: `loophole.sh warmup <keywords>` — a prior entry is
  cheaper than rediscovery

## 3. When context is nearly full

1. Refresh `session-state.md` (Done/Found/Next current)
2. Say "state saved — safe to compact"
3. After compaction: reread `session-state.md` + continue from Next

## Trigger phrases

"compact", "save tokens", "we're burning tokens", "context is long", silent
auto-use when a session exceeds ~100k tokens of context.
