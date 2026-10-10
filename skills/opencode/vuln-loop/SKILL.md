---
name: vuln-loop
description: Non-stop CVE-hunt loop for popular repos (>=50k stars) with a security intake channel. Use when the user says "keep hunting", "loop", "don't stop", "auto-loop", "hunt CVEs", or when an AUTO-LOOP continuation prompt arrives. Defines target selection, the 3x clean-env live validation rule, CVE submission packaging, logging, and stop conditions.
---

# Vuln loop protocol

Run every iteration without asking questions. When unsure, pick the
highest-value option and proceed.

## 1. State (before hunting)
- Read `~/CVE-hunt/session-state.md` → `Next`. If context is heavy, rewrite
  state first (Objective / Done / Found / Next / Open questions).
- Read `~/CVE-hunt/TARGET-INDEX-50K.md` for the queued repos.

## 2. Target rule
Only hunt repos that have BOTH:
- `>= 50,000` GitHub stars, and
- a security intake channel: `SECURITY.md` (repo root or `.github/`) or GitHub
  private vulnerability reporting enabled / published security advisories.

**Priority order:**
1. **Paying programs first** — repos in `~/CVE-hunt/PAYING.txt` (marked `$` in
   the index). A paid High/Critical beats an unpaid one.
2. Then the rest by `$`-then-stars order in `~/CVE-hunt/TARGET-INDEX-50K.md`.

**Severity gate:** only **High (CVSS >= 7.0) or Critical** findings get
packaged and submitted. Medium/Low go to `LEADS.md` as parked — do not spend
submission effort on them.

One repo at a time, one vulnerability at a time. Rebuild the index with
`python3 ~/CVE-hunt/targets.py` when empty.


## 2b. Tool-assisted pass (do this FIRST on every repo)
- Run `bash ~/CVE-hunt/sast.sh <repo-dir>` → semgrep (p/security-audit, p/owasp-top-ten), gosec (Go),
  bandit (Python), osv-scanner. Triage its hits before manual reading; use them as leads only.
- API targets with an OpenAPI spec: `schemathesis run <spec-url> --checks all` for authz/5xx anomalies.
- C/C++ parsers: fuzz with afl-fuzz/libFuzzer (ASAN+UBSAN) rather than reading.
- `nuclei` only for exposed-service/known-CVE checks, never as the finding itself.
- If GitHub API is rate-limited: check `gh auth status` first; when authenticated, prefer `gh api`/`gh search`
  (5000 req/h). Otherwise use raw.githubusercontent.com (unlimited) and keep API calls minimal.
- Tools sharpen leads; the 3x live + novelty gates still gate every package.

## 3. Validation rule (mandatory) — 3x live test, clean environments
A finding is valid ONLY after it is triggered **live 3 times** in **clean,
fresh environments**:
- Each run uses a fresh container/venv, a freshly downloaded latest release
  (tarball/npm/pip/docker digest), recorded hashes.
- The vulnerability is actually triggered (real request/parse/exec outcome),
  not inferred from reading code.
- The 3 runs must be identical in outcome; any flakiness = not valid.
- Confirm the tested version is the newest release; otherwise retest newest.
- No fake proofs: empty/silent result = UNKNOWN, re-run until real.
- Novelty check MUST cover: project issues/PRs, dismissals and tracker entries
  (GitHub issues/advisories, the project's OWN tracker - e.g. Bugzilla for
  Mozilla, GitLab/Jira if that's where they work), NVD, OSV, changelog,
  mailing lists. Prior art OR an already-dismissed class → drop.

## 4. Packaging (per finding, CVE-ready)
Create `~/CVE-hunt/<year>-<project>-<slug>/` with:
- `SUBMIT-THIS-ONE.md` or `H1-DESCRIPTION.md` + `H1-IMPACT.md` (paste-ready
  for GitHub private advisory / H1 / email),
- `poc/` — runnable PoC, few files (`bash poc.sh` reproduces),
- `evidence/` — the 3 fresh-run logs,
- CVSS 3.1 AND 4.0 vectors computed with the `cvss` lib
  (`/tmp/opencode/cvssvenv` if present, else `python3 -m venv`), never inflated,
- CVE request text when the project is a CNA / uses GitHub advisories.

## 5. Logging
- Append a row to `~/CVE-hunt/SUBMISSIONS.md` and a line to `LEADS.md`.
- Update `session-state.md` Next with the single most promising next action.

## 6. Loop
After a finding is packaged and logged, DO NOT stop: move to the next repo /
next vulnerability and repeat. Stop only on `~/CVE-hunt/STOP` or the
AUTO-LOOP max-iteration cap.
