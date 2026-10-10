# CPENT zone report — STEP-CENTRIC template — copy per zone to ~/loot/report/<zone>.md

THE LAW OF THIS REPORT: every step has (1) an explanation, (2) the exact
command to reproduce it, (3) expected vs observed, (4) its own screenshot.
One step = one figure. If a step has no figure, capture it before writing
the next line. Fill from `~/loot/engagement-state.md` + `~/loot/<zone>/steps/`
(produced by capture.sh) — never from memory.

---

# Penetration Test Report — <ZONE>

**Tester:** ______  **Date(s):** ______  **Scope:** <CIDR> (exclusions: ______)
**Objective:** <from the exam dashboard>

## 1. Executive Summary

<3-5 sentences: what was tested, posture, headline findings, answers N/N.>

## 2. Answer Summary

| # | Question (short) | Answer | Step | Evidence |
|---|------------------|--------|------|----------|
|   |                  |        | S-<n> | E-<zone>-<NNN> |

## 3. Scope and Rules

Authorized scope: <CIDR minus exclusions, from dashboard>. Rules: <exact
rule text/version as published>; no prohibited tooling; actions within
scope and exam window only.

## 4. Detailed Walkthrough  ← the core: every step = explain + command + screenshot

### Step S-1 — <name> (e.g., "Service discovery on 10.10.99.10")

**Explain:** <why this step, what it proves, what you expect to learn. 2-4
sentences, plain English — a grader should understand the reasoning without
running anything.>

**Reproduce:**
```
<exact command, copyable, no shell prompt, no placeholders>
```

**Expected:** <what a clean result looks like>
**Observed:** <what actually happened — quote the decisive line(s)>
**Evidence:** Figure <n> (E-<zone>-<NNN>) — <what the screenshot shows/proofs>

### Step S-2 — <name>
<same four blocks. Keep one action per step: if you scanned then exploited,
that is two steps with two figures.>

## 5. Technical Findings

### 5.<n> <Finding title> — Severity: <Critical/High/Medium/Low>
- **Host/URL:** ______ (finding ID F-<n>)
- **Root cause:** <the flaw, not the tool name>
- **Reproduce:** command(s) — reference Steps S-<n>
- **Evidence:** Figures <n>, E-<zone>-<NNN>
- **Impact:** <what an attacker gains>
- **Remediation:** <specific fix addressing the root cause> ·
  **Retest:** <how to verify the fix>

## 6. Attack Chain Narrative

<One paragraph per hop, chronological, referencing Steps (S-n) — the story
a non-technical reader follows from zero to objective.>

## 7. Credentials Recovered

| Account | Scope | How obtained (Step) |
|---------|-------|---------------------|

## 8. Tools Used
## 9. Command Index

| ID | Purpose | Command | Result | Step |
|----|---------|---------|--------|------|
| CMD-<zone>-001 |  |  |  | S-1 |

## 10. Evidence Index

| ID | Description | Figure | Path |
|----|-------------|--------|------|
| E-<zone>-001 |  | Figure 1 | ~/loot/<zone>/steps/01-*.png |

## Appendix — Figures

| Figure | Step | Proves | Path |
|--------|------|--------|------|

Independent reproduction: yes / no / not authorized. Time zone: ____ throughout.

---

**Before submitting:** fill every blank · `validate_report.py --strict` PASS ·
answers match dashboard exactly · submitted by day 4 of 7 · dashboard shows
"under review" (screenshot the confirmation).
