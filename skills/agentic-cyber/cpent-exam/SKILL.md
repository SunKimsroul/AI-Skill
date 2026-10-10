---
name: cpent-exam
description: Run the EC-Council CPENT practical exam across its five zones — Active Directory (RODC attack chains), IoT firmware analysis, binary exploitation, Linux CTF, and web application security. Use when the user mentions CPENT, CPENT-MAP, CPENTv2025, or any of the five exam sections; provides per-zone playbooks distilled from a prior 52/53 attempt, answer-mask verification, and lab-environment workarounds.
---

# CPENT Exam Operations

You are working the EC-Council CPENT (Certified Penetration Testing Professional)
practical exam. The exam is five independent zones over VPN, each a /24 with one or
two excluded hosts, each zone asking 10–13 short-answer questions worth 20–100 points.
The deliverable is the answer set plus a professional report per zone.

Three layers, load per need:
- **[exam-intel.md](exam-intel.md)** — official exam mechanics (24h/12+12h,
  v2 scoring: 2300 max / 1750 pass / LPT at 2300, 7-day report), section-form
  variance (v1: OT + Pivot/Double Pivot vs v2: Web + IoT), OT/Modbus and
  double-pivot add-ons, candidate-tested tactics, prep gaps. **Read this first
  on exam day.**
- **[toolkit.md](toolkit.md)** — this laptop's verified tool bindings
  (task → binary → command), live-checked tool status, wordlist locations, and
  provisioning commands for a fresh laptop.
- **[answer-key.md](answer-key.md)** — full memory of the prior 52/53 attempt:
  every question's answer, all credentials and hashes, and the technique that
  produced it. Exam forms rotate — verify answers against the live target, but
  reuse the patterns (`Name@123` passwords, archetypes, constants).
- **[pivot-core.md](pivot-core.md)** — segmentation doctrine (dual-homed
  edge hosts, `-sT -Pn` rule, in-segment callbacks, reverse SOCKS) + the
  forwarder toolbox and double-pivot chains. Read whenever any zone has
  filtering/tiering.
- **Zone playbooks** below. Full prior-attempt evidence (complete reports,
  answers, creds, compiled PDF) lives in **[private/](private/)** inside this
  skill — never publish, never include in shared copies of the skill; the
  redacted methodology copies in `~/Documents/CPENT/Notes/review_notes/`
  are the shareable versions.
- **User's master notes** — `~/Documents/CPENT/Notes/review_notes/Engagement_Day_Reference.md`:
  the human's single-file exam-day reference (all domains + tools + cracking
  table + time budget). Keep answers in sync with it when working together.
- **Per-domain method notes** (shareable, redacted) — `~/Documents/CPENT/
  {ActiveDirectory,BinaryExploitation,CTF,IoT,WebApplicationSecurity}/*_Notes.md`.
- **Practice labs** — [labs.md](labs.md): OT/Modbus pcap drill (verified),
  pymodbus round-trip, docker double-pivot, Next.js gate battery, report drill.
- **Evidence capture** — [capture.sh](capture.sh): `cap NN <cmd>` records
  command+output+screenshot per step into `~/loot/<zone>/steps/`; feeds the
  step-centric [report-template.md](report-template.md) (every step = explain
  + command + observed + Figure). Worked sample: [report-example.md](report-example.md)
  (passes `validate_report.py --strict`).

**Session assets** — instantiate at exam start (runbook.md hour 0):
- **[preflight.sh](preflight.sh)** — `bash` it with the range CIDR; verifies
  tools, wordlists, cracker sanity, disk, VPN. Fix every FAIL before starting.
- **[state-template.md](state-template.md)** — copy to `~/loot/engagement-state.md`;
  the answer table + hosts + creds + evidence log, updated after every step.
- **[runbook.md](runbook.md)** — hour-by-hour time budget, escalation rules
  (points-per-minute), checkpoints, incident/proctor protocol, 7-day report plan.
- **[report-template.md](report-template.md)** — per-zone report skeleton for
  the 7-day window, filled from the state evidence log.

A prior attempt scored 52/53 using these playbooks.

## Operating contract — work like a human operator, step by step

This is a HARD contract. A human pentester runs one command, watches the
output, thinks, and only then types the next one. Work exactly that way:

1. **One action at a time against targets.** NEVER batch, chain, or parallelize
   commands that touch a target. Local file reads (notes, loot) may batch —
   target interaction is strictly serial.
2. **Run → READ → decide.** After every command, actually read the full output
   before the next one. The next command is chosen BY the output, not by a plan
   written before it. If you caught yourself about to run step 4 without having
   digested step 3's result — stop and read it.
3. **Narrate briefly before acting.** One line: what you're about to run and
   why ("checking if null SMB enumeration works on the writable DC"). Like a
   human talking over their shoulder — no essays.
4. **Never claim unobserved results.** If a command didn't run or returned
   nothing, say so. No invented output, no assumed versions, no "this should
   work" recorded as fact.
5. **One challenge at a time.** Pick the highest-value unsolved question from
   the answer table, drive it to an answer or a documented dead end, update the
   table, then pick the next. No context-switching between five hosts mid-step.
6. **Finish the phase before starting the next** on a host: recon complete →
   then enumerate → then exploit. Jumping ahead wastes ammo and evidence.
7. **On failure: diagnose, don't loop.** One retry with ONE changed variable
   after understanding the error. Three failures on the same idea = stop,
   write the dead end down, change approach (or ask the user).
8. **Verify before recording.** Every answer checked against its mask AND the
   live target. Every credential validated (`nxc smb <ip> -u u -p p`) before
   it enters the state file.
9. **Notes after every step, not at the end.** Command + key output + what it
   proved goes into the working notes immediately (this is also the report
   evidence — reconstructing later always fails).
10. **Ask the human when a human decides.** Scope doubt, proctor problems,
    risky/destructive actions, "is this lead worth another hour" — surface it,
    don't silently choose.

## Zone map

| Zone | Prior range | Playbook | Load alongside |
|------|-------------|----------|----------------|
| 1. Active Directory | `172.25.170.0/24` (excl `.1`, `.250`) | [zone-ad.md](zone-ad.md) | `ctf-ad`, `ctf-privesc` |
| 2. Linux / CTF | `192.168.200.0/24` (excl `.1`, `.100`) | [zone-ctf.md](zone-ctf.md) | `ctf-web`, `ctf-privesc` |
| 3. Web Applications | `10.10.1.0/24` (excl `.1`, `.2`) | [zone-web.md](zone-web.md) + [web-nextjs.md](web-nextjs.md) + [web-scrape.md](web-scrape.md) | `ctf-web`, `terminal-browser` |
| 4. IoT & Firmware | `172.25.120.0/24` (excl `.250`) | [zone-iot.md](zone-iot.md) | `ctf-reverse` |
| 5. Binary Exploitation | `172.25.65.0/24` (excl `.250`) | [zone-binary.md](zone-binary.md) | `ctf-pwn`, `ctf-pivoting` |

Load the zone playbook AND the listed skill packs together, up front, per zone —
not one per turn. `exam-mode` carries per-host phase state and the clock across the
whole run; start it for the exam session itself.

The `.250` (or `.1`/`.2`) excluded host in each range is a **filtering device**,
not a target. Never scan it. Its presence matters in the binary zone: it blocks
egress from the filtered segment, which dictates payload choice (see zone-binary.md).

## Answer-mask system — check every answer before submitting

Every question ships a character mask: **X = capital letter, x = lowercase letter,
N = digit** (e.g. `XxxxNx`, `xNxxN`, `NNN.NN.NNN.NN`, `NNNx`). Two uses:

1. **Sanity-check the answer.** `H3l3nn` fits `XNxNxx`; if your candidate does not
   fit the mask exactly, it is wrong or mis-parsed (0 vs O, 1 vs l).
2. **Guide cracking.** Convert the mask to a regex, then filter wordlists and
   on-box strings before brute-forcing:

```bash
# mask → regex (one command, no thinking):
python3 ~/.config/opencode/skills/cpent-exam/range-helpers.py mask xxxxxN   # → ^[a-z]{5}[0-9]$
grep -aE "$(… range-helpers.py mask xxxxxN)" ~/rockyou.txt
# same regex against every string on a compromised box
grep -rhoaE "[A-Z][a-z]{3}[0-9][a-z]{3}[0-9]" /home /root /opt /var 2>/dev/null | sort -u
# name-scheme mutations (cap/@123/years/leet) straight into john:
python3 …/range-helpers.py mutate users.txt | john --pipe --format=nt hashes.txt
```

Partial-answer questions are common: "first 6 chars of…", "last 4 chars of the NT
hash", "number of entries". Read exactly how many characters and from which end.

If two candidates both fit the mask (prior attempt: `brent3` vs `admhc1`), submit
the one from the later, written-up notes first and keep the other on record.

## Lab environment workarounds (this Kali box + exam lab)

| Problem | Workaround |
|---|---|
| Cracker status ROTATES | **Run preflight.sh — it live-tests both.** 2026-08-31: hashcat WORKS; jumbo john installed (`~/.local/bin/john` wrapper → `~/tools/john-jumbo`) with NT/krb5* formats |
| `/etc/hosts` not writable (no passwordless sudo) | Pin KDC/hostnames via `KRB5_CONFIG=$PWD/krb5.conf` + a Python `socket` resolver shim (`dnspatch.py`) for Kerberos tools |
| `nxc ldap` module errors (Python 3.14 logging bug) | Use `ldapsearch -x -H ldap://<dc> -D user@dom -w pass -b <base>` |
| Password auth scripting | `sshpass -p 'pw' ssh u@ip` (installed); `paramiko` for complex flows |
| Reverse shells never connect in binary zone | Egress is filtered — use **socket-reuse shellcode** on the accepted connection |
| Range-provided wordlist unknown location | Check the foothold/given-cred host (prior range: `~/CPENT/AD2/Passwords.txt`, 201 entries). It is THE wordlist — try it before rockyou |

## Cross-zone method

1. **Recon each /24 first**: `nxc smb <cidr>` / `nmap --top-ports` sweep, identify
   roles before deep scans. One host per zone usually holds the questions' context
   (a DC pair, a web stack, an analysis SSH box).
2. **Record given credentials** in the state file immediately; validate them
   against every host with `nxc smb <ip> -u u -p p`.
3. **Answer cheap questions first.** Version strings, IPs, hostnames, and counts
   (PRP list size, file size, block size) are worth as much as the exploit chains
   and often fall out of recon output alone.
4. **Keep a per-zone answer table** (question #, points, mask, answer, status) in a
   markdown next to the working notes — same shape as `~/Documents/CPENT/Notes/review_notes/*`.
5. **Chain credentials across zones** only when reuse is plausible (same password
   policy patterns: `Name@123`, `WordN1`) — never assume, always test.
6. **No lockout domains** (`lockoutThreshold = 0`) → spray freely; check the policy
   via LDAP before any brute-force elsewhere.

## Reporting

Per zone: executive summary, answer table, recon, exploitation chain with commands
and evidence, findings table with severity + remediation, tooling list. Start from
[report-template.md](report-template.md), then run **`ctf-exam-report`** for the
full workflow: its capture mode maintains the evidence ledger during the exam, and
its `validate_report.py --strict` is the final QA gate before submission.
Follow `ctf-writeup` / `ctf-pentest` reporting standards. Evidence = command +
output + figure number, captured as you go.

## Answer-format quick reference (from the prior attempt)

- Password fragments: mask applies to the *plaintext*, often 3–8 chars
- NT hash fragments: `NNNx` style masks apply to the **hex hash**, not the password
- `root.txt`/`flag.txt` fragments: masks apply to file contents, sometimes excluding
  wrapper characters (`flag{...}` → count/first-chars of inner text only)
- File sizes: exact byte count via `stat -c "%s"`, not `ls` rounding
- Addresses: full `0x0000000000401186` form when the question says "full hex address"

## Related skills

- `exam-mode` — session state, clock, per-host phases across the whole exam
- `solve-challenge` — single-challenge triage when working outside the zone pattern
- `ctf-ad` / `ctf-privesc` — zone 1 depth (Kerberos, RODC, DCSync, spraying)
- `ctf-web` — zones 2 and 3 depth (SQLi, upload bypass, CMS chains, JWT, LFI)
- `ctf-reverse` — zone 4 depth (firmware, filesystems, embedded credentials)
- `ctf-pwn` — zone 5 depth (overflow offsets, shellcode, ret2win)
- `ctf-pivoting` — when a zone needs tunneling to reach the filtered segment
- `terminal-browser` — render web targets in-terminal: visual verification,
  screenshots for report evidence, driving JS-heavy pages curl can't
- `f0undm3-ctf-operations` — search the prior-public-writeup index
  (`scripts/search_writeup_index.py`) when a target technique looks published
- `ctf-exam-report` — **the report engine**: capture-mode evidence ledger
  during the exam, draft mode to turn the state file into a report, audit mode
  + `scripts/validate_report.py` as the QA gate before submission. Use it
  together with this skill's `report-template.md`
- `ctf-writeup` / `ctf-pentest` — final report per zone

## Conditional routing — if the exam form contains it, also load

| Signal in scope | Load |
|---|---|
| Modbus/PLC/tcpdump 502 (OT section, v1 form) | `ctf-misc` (industrial protocol notes) + exam-intel.md §OT |
| Wi-Fi in scope (self-study module) | `ctf-wireless` |
| Cloud/hosting assets | `ctf-cloud` |
| OSINT section | `ctf-osint` |
| Crypto/encoding puzzles | `ctf-crypto` |
| Forensic artifacts (pcap/disk/memory) | `ctf-forensics` |
| Suspicious binary behavior analysis | `ctf-malware` |
| Suspicious binary behavior analysis | `ctf-malware` |

## Coverage-first gate

For a new authorized target, load [`coverage-first`](../coverage-first/SKILL.md) before exploitation and keep its coverage ledger through every pivot. Apply the relevant checks for this specialty; record any skipped or blocked surface rather than assuming it is absent.
