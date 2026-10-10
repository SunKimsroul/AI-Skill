# CPENT exam-day runbook — timeline, time budget, escalation rules

Pre-computed so zero exam time goes to planning. Times assume the 24h form;
for 12+12, run hours 0–12 in session 1 and 12–24 in session 2, report draft
BETWEEN sessions.

## Hour 0 — setup (before touching targets)

```bash
bash ~/.config/opencode/skills/cpent-exam/preflight.sh <range-cidr>   # fix FAILs
cp ~/.config/opencode/skills/cpent-exam/state-template.md ~/loot/engagement-state.md
mkdir -p ~/loot/report ~/loot/evidence
script -f ~/loot/evidence/session-$(date +%H%M).log    # terminal capture ON
```
Proctor checklist: ID ready · timer page visible · single screen · break
protocol understood · screenshot every proctor exchange.

## Time budget — 5 zones × 500 pts, cheap questions first

| Hours | Activity | Rule |
|-------|----------|------|
| 0.0–0.5 | Preflight, state init, VPN check, read exam dashboard, SAVE nothing yet | — |
| 0.5–1.0 | Sweep ALL five /24s (`nxc smb` / `nmap --top-ports`), record hosts+roles in state | never deep-scan yet |
| 1.0–2.0 | **Cheap-question sweep across every zone**: version strings, IPs, FQDNs, counts, binwalk signature lines | each answer ≤ 10 min or defer |
| 2.0–5.0 | Zone 1 (AD) full chain | see escalation rules |
| 5.0–8.0 | Zone 5+4 (binary + IoT — often shared segment/hosts) | — |
| 8.0–11.0 | Zone 2 (CTF) | — |
| 11.0–13.5 | Zone 3 (web): scrape-first, then Next.js battery | — |
| 13.5–14.5 | MEAL + rest + state cleanup + save-all check | non-negotiable |
| 14.5–20.0 | Return to blockers in point-value order; finish partial chains | — |
| 20.0–22.0 | Final answer sweep: every `working` → `answered` or `dead-end`; verify masks | — |
| 22.0–24.0 | Evidence pass: screenshots for every answer, dashboard save-all, report skeleton filled | report due in 7 days — start NOW |

## Escalation rules (points per minute)

- **Value density:** 500 pts / ~4.5 productive hours per zone ≈ 110 pts/hour.
  A question worth 20 pts gets **max 15 minutes**; 50 pts → 30 min; 100 pts →
  1 hour. Timer fires → write the dead end in state → next question.
- **Three failures of one idea = the idea is wrong** (contract #7). Change
  technique, not parameters.
- Stuck 30+ min on a zone at all → switch zones; the answer table decides
  what's left, not curiosity.
- Cracking jobs run in BACKGROUND (`john … &` in a logged shell) while working
  other questions — check pots at each checkpoint.

## Checkpoints (every 2 hours, 5 minutes)

1. `john --show` on all pot files → harvest cracked → answer table.
2. State file updated (answers, creds, phases, blockers).
3. Dashboard: everything entered SAVED.
4. Screenshot the current terminal context (evidence continuity).
5. One-glance clock check vs the budget table above — behind? cut the lowest-
   value `working` item.

## Incident protocol

| Event | Action |
|---|---|
| Target dead / no OT traffic | tell proctor NOW · screenshot chat · note time · move on, revisit after 1h |
| Missing/fewer questions than expected | screenshot dashboard + proctor chat immediately (documented case: 48 vs 51) |
| Accidental service crash | report to proctor, note in state, do not retry blindly |
| VPN drop | screenshot timer page (proves time lost), reconnect, log gap |
| Dashboard answer-save fails | retry once, screenshot failure, proctor chat |

## Post-exam — 7-day report window

- Day 0 (exam day): report skeletons filled (report-template.md per zone),
  figures organized while memory is fresh. Use **`ctf-exam-report` draft mode**
  to convert `~/loot/engagement-state.md` + evidence ledger into report sections.
- Day 1–2: full drafts, remediation wording, answer cross-check vs dashboard.
- Day 3: QA gate —
  `python3 ~/.config/opencode/skills/ctf-exam-report/scripts/validate_report.py --strict <zone>.md`
  fix every defect; peer/self review — every command reproducible from text alone.
- Day 4: export + submit. **Confirm dashboard shows "under review"** — the
  silent-upload-failure bug is real; if it spins: email + live chat, screenshot,
  keep pushing until confirmed.
- Day 5–7: buffer for support tickets.

## Prep drills (before the window — from exam-intel.md gaps)

1. OT: Wireshark Modbus PCAP walk-through ×3 (function codes, unit IDs, MACs).
2. Double pivot: chisel→chisel lab, and ssh -J chains, until it's 10 minutes.
3. Next.js: web-nextjs.md battery on a deliberately vulnerable local container
   (middleware bypass, _next/image SSRF, upload traversal).
4. Key List attack end-to-end once (it cost question 12 last time).
5. Preflight.sh on a clean VM — prove the provisioning section reproduces the kit.
