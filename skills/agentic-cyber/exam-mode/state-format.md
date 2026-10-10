# State format

`exam-state.md` lives in the working directory and is the only thing that survives between invocations. It is written as Markdown on purpose: the user reads it during the exam, and most of it lifts straight into the report at the end.

Treat it as an evidence record, not scratch notes. On every exam listed in this library the report is graded, and the report is only as good as what was captured while it was still true.

## Rules

- **Write back every invocation.** New host, new credential, new finding, path ruled out — it goes in before the turn ends. Not at the end of the exam.
- **Append, never overwrite.** A fact that stops being true gets marked stale with the time it stopped, and stays. "This credential worked at 14:10 and was rejected at 16:40" is evidence; deleting the line destroys it.
- **Contradictions are recorded, not resolved by guessing.** If one scan says Linux and another says Windows, write both and mark the host disputed. Resolve it with a test, then record which test settled it.
- **Every finding names its evidence.** A command, its output, and the host. A finding with no reproduction is not yet a finding.
- **Never invent a timestamp.** Take it from the system clock or from the user. If neither is available, write `UNKNOWN` and move on.
- **If the file is malformed, do not overwrite it.** Read what is legible, tell the user which sections could not be parsed, and ask before rewriting. Silently regenerating this file destroys the exam's only record.

## Sections

### Scope and constraints

Written once at intake, from `constraints.md`. Changed only when the user explicitly changes it. This block is what every enforcement check reads.

### Clock

Start time, declared window, and the deadline. Every invocation compares the current time against the deadline and states the remaining percentage when it drops under 40%. Under 20% is the REPORT trigger in `phase-map.md`.

### Hosts

One row per host, each with its own phase. This is the table that makes per-host phase tracking real rather than aspirational.

### Credentials

Every principal and secret recovered, where it came from, and — separately — where it has actually been tested. Recovered and validated are different columns because assuming a credential works everywhere it *should* is how lateral movement stalls without anyone noticing.

### Findings

The report skeleton, filled in as you go. Each entry gets an ID, the affected host, the privilege required, the reproduction, the impact, and the evidence pointer.

### Rejected paths

What was tried and did not work, with the reason. This prevents the same dead end being re-run at hour eighteen, and the good ones belong in the report — a rejected path with a clear reason is what separates a methodology section from a list of commands.

### Open threads

Anything noticed and not yet followed. Every deferred host from a load-set cap lands here. This is the section to read first when the user asks "what have I missed".

### Objectives and proof

The required artifacts, exactly as the exam specifies them — flag files, proof files, screenshot requirements — and which are captured so far.

## Template

Create this on first run, then extend it.

```markdown
# Exam state

## Scope and constraints
- Exam or engagement name (context only):
- Executor available: none | shell | <MCP name>
- In scope:
- Explicitly out of scope:
- Tool restrictions:
- AI assistance:
- Report format:
- Evasion graded: yes | no | UNDECLARED

## Clock
- Started:
- Deadline (absolute):
- Report time: inside the window | separate window | UNDECLARED

## Hosts
| Host | Hostname | OS | Phase | Access held | Notes |
|---|---|---|---|---|---|

## Credentials
| Principal | Secret type | Source | Validated on | Status |
|---|---|---|---|---|

## Findings
| ID | Host | Title | Privilege needed | Severity + CVSS | Impact | Remediation | PoC path | Fix (file:line) | Status | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|

## Rejected paths
| Host | Attempted | Why it failed |
|---|---|---|

## Open threads
- [ ]

## Objectives and proof
| Objective | Required artifact | Captured |
|---|---|---|
```

## Field notes

**Phase** in the hosts table is one of the phases in `phase-map.md`. It is per host, and hosts routinely sit in different ones at the same time.

**Access held** should say what you can actually do right now — `none`, `www-data shell`, `local admin`, `domain user`, `SYSTEM` — not what you believe you could get.

**Status** on a credential is `valid`, `stale`, or `untested`. A credential recovered but never used is `untested`, and saying so is more useful than implying it works.

**PoC path and Fix** matter on the whitebox web exams, which require working proof-of-concept code and source-level remediation per finding. Record the path to the runnable PoC and the exact `file:line` of the flaw as you confirm it; both are far cheaper to capture with the source open than to reconstruct from a screenshot afterwards.

**Severity, Impact, and Remediation** are filled in when the finding is confirmed, not at report time.
They exist as columns because every graded report template asks for them, and reconstructing a
severity rationale days later — after the shell is gone and the output was never saved — is the
single most common way a technically complete exam produces a weak report. Fill them while the
finding is fresh, in one line each; polish the prose at REPORT.

**Evidence** is a path to captured output, not prose. Keep the actual command output in files beside the state file — an `evidence/` directory works — and point at them. Pasting large output into the state file makes it unreadable exactly when it matters most.

## Evidence capture

**When you have no shell on the exam machine**, the procedure moves to the user rather than disappearing. At intake, tell them once: create `evidence/<host>/` on their attack box and wrap each session in `script` or pipe it through `tee`, then paste back the parts that matter. Record the same paths in the state file as if you had written them, and never describe output as captured when you only saw it in the conversation.

Capture as you go rather than reconstructing afterwards. The reconstruction always costs more time than it saves, and on a timed exam that time comes out of the report.

For each meaningful step record the command, its output, the host, and the time. A shell transcript per host is usually enough:

```bash
mkdir -p evidence
script -q -c "ssh user@10.10.1.15" "evidence/10.10.1.15-session.log"
```

Screenshots are separate and often mandatory. Several exams require the proof file *and* an IP-visible terminal in the same frame — check the declared report format recorded at intake, and capture that framing the first time rather than going back for it.
