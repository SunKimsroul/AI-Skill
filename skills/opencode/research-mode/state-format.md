# State format

`research-state.md` lives in the working directory. Research runs long — a disclosure often spans months between the first grep and the published advisory — and nothing else survives between sessions.

It carries one thing an exam state file does not: **dates you are accountable to**. An embargo that quietly passes is the one mistake in this work that cannot be undone.

## Rules

- **Write back every invocation.** New candidate, new evidence, a maintainer reply, a version ruled out.
- **Append, never overwrite.** A candidate that turns out to be a non-issue stays, marked `invalid`, with the reason. That record stops you re-investigating it in four months and is worth citing if someone else reports the same thing.
- **Every date is real.** Take dates from the system clock or from the user. Never estimate one. The disclosure timeline is the part of this file most likely to be read by someone other than you.
- **Every candidate names its evidence.** A reproducer path, a commit, a stack trace. A candidate with no evidence pointer is a hunch, and should be labelled one.
- **Secrets never land here.** If a reproducer needs a credential or a token, keep it out of the state file and out of the eventual report. Reference it, do not paste it.
- **If the file is malformed, do not overwrite it.** Read what is legible, say which sections did not parse, and ask before rewriting.

## Sections

### Target and basis

Written at intake: the project, the version or commit range under review, where the source came from, the legal basis, and the disclosure policy found or declared. Every checkpoint reads this block.

### Surface

The four answers from `surface-map.md` — entry points, trust boundaries, privilege, dependencies. Written once when SURFACE completes, revised as the codebase teaches you more.

### Candidates

The core table. One row per suspected flaw, each with its own phase. Status is `lead`, `confirmed`, `invalid`, or `duplicate` — a candidate can be at PROVE and still turn out invalid, and recording that is the point.

### Disclosure timeline

Append-only, one row per event, per candidate. This becomes the timeline section of the published advisory verbatim, so write it as you would want it read.

### Rejected paths

What was investigated and found not to be a flaw, with the reason. On a long audit this is the most valuable section in the file — it is what stops the third re-examination of the same safe-looking sink.

### Open threads

Noticed and not yet followed. Anything deferred by a load-set cap lands here.

## Template

```markdown
# Research state

## Target and basis
- Project:
- Why this target:
- Publish-by (proposed / agreed):
- Next check-in:
- Version / commit range:
- Source:
- Legal basis:
- Security policy:
- Security contact:
- Goal:

## Surface
- Entry points:
- Trust boundaries:
- Privileged components:
- Dependencies of interest:

## Candidates
| ID | Summary | Class | Phase | Status | Affected versions | Evidence |
|---|---|---|---|---|---|---|

## Disclosure timeline
| Date | Candidate | Event | Detail |
|---|---|---|---|

## Rejected paths
| Area | Investigated | Why it is not a flaw |
|---|---|---|

## Open threads
- [ ]
```

## The disclosure timeline

Record every event, on the day it happens. The events that matter:

| Event | Why it is recorded |
|---|---|
| `reported` | Starts the clock; the date every later commitment is measured from |
| `acknowledged` | Maintainer confirmed receipt. Silence past a reasonable window changes what you do next |
| `triaged` | Maintainer agrees it is a security issue, and at what severity |
| `disputed` | Maintainer disagrees. Record their reasoning, not just the outcome |
| `embargo-agreed` | The date both sides settled on for publication |
| `patch-proposed` | You sent a fix |
| `fix-merged` | Repaired upstream, not yet released |
| `fix-released` | Version containing the fix, with the version number |
| `cve-requested` / `cve-assigned` | With the ID once issued |
| `published` | Advisory or writeup is public |

If an embargo date is agreed, it is the first thing checked on every invocation from then on. Surface it well before it lands, not on the day.

**Keep a `Next check-in` date alongside it**, because silence is the normal failure mode and nothing else will prompt you. Sensible defaults: **7 days** for an unacknowledged report, **14 days** while a fix is in progress, and **7 days before the publish-by date** regardless. Weeks pass unnoticed otherwise, and a disclosure that quietly lapsed is indistinguishable from one you abandoned.

## Field notes

**Phase** is one of the phases in `surface-map.md`, per candidate. Candidates routinely sit at different ones.

**Class** is the CWE where you know it. Where you do not, write the plain-language class and settle the CWE at ASSESS rather than guessing early.

**Affected versions** should distinguish *confirmed* from *suspected*. Two tested versions and an assumption about the twelve between them is not a version range, and maintainers will check.

**Evidence** is a path to a reproducer or a commit hash, not prose. Keep reproducers in a directory beside the state file:

```bash
mkdir -p reproducers/candidate-01
```

Keep each reproducer runnable on its own. The version of it that goes to the maintainer should need nothing from your working directory.
