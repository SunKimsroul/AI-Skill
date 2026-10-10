# CPENT exam intel — official spec + community consensus

Compiled from EC-Council's official program page (CPENT AI era) and passed-candidate
write-ups (LPT-Master blog 2024, Rexturnull CPENT-CheatSheet). Verified against the
prior 52/53 attempt on this laptop. Sources: keep this file, not the browser history.

## Official exam mechanics (EC-Council)

- **Format:** 100% practical, proctored, over VPN (OpenVPN to the exam range).
  Attack machine: your own Kali. Result appears IMMEDIATELY after submit.
- **Duration options:** single 24-hour session OR two 12-hour sessions (must
  complete within 30 days of scheduling; exam voucher valid 1 year).
  **Two-session is the community-consensus choice** — rest + review/research
  between sessions is allowed and is a documented strategy (gaps of ~3 days).
- **Report:** pentest report due **within 7 days** of the final session — a $100
  fee applies after. Template is on the exam dashboard.
- **Scoring — v1 vs v2 differ, learn YOUR form:**
  - v1/classic: 2500 pts, 5×500. 70% (1750) = CPENT, ≥90% = LPT Master.
  - **v2 (2025/2026 — the form on this laptop): 53 questions, max 2300**
    (AD 500 + CTF 500 + IoT 500 + Binary 500 + Web 300), **pass 1750**,
    **LPT Master requires 2300** (near-perfect). Author data point: 2190 =
    pass, LPT missed.
- **~53 questions** across the exam, short-answer with character masks, worth
  20/30/40/50/100. Types: versions, keys, passwords, flags, counts, addresses,
  **file hashes (md5sum/sha256sum/sha512sum)**.
- **Built-in exam AI is allowed (proctor-confirmed 2026).** Ask the proctor
  about external AI tooling policy before using anything beyond the dashboard.
- **Proctoring:** passport/ID, webcam, single screen only (no virtual desktops),
  no music (ask), meals OK on camera, breaks with proctor notification. Timer
  page must stay visible. Weekdays only, book ≥3 days ahead via Exam
  Specialists; proctor unlocks through Aspen.
- **Vouchers:** course on CodeRed (iLabs = guided); Practice Range + Exam on
  **Aspen** (voucher doubles as dashboard code; Practice Range = 90 days).
  iLabs ≠ Practice Range. Only ~5-6 of 53 exam questions overlapped the
  Practice Range — the exam range is deliberately different; don't
  pattern-match practice answers.
- You can finish early (candidates finishing session 2 in 4-7h, documented).
- **SAVE button under EVERY question** — two independent candidates lost
  first-session answers to unsaved boxes. Save after every group, every time.

## Section forms VARY between exam versions — train both splits

| v1 / classic form (community write-ups) | v2 / 2025 form (prior attempt here) |
|---|---|
| AD (500) | AD — RODC chains (500) |
| Binary + IoT (500) | IoT firmware analysis (500) |
| CTF (500) | Linux CTF — web2rce + privesc (500) |
| **OT / Modbus (500)** | Web applications — Next.js/Socket.IO (500) |
| **Pivot & Double Pivot (500)** | Binary exploitation, egress-filtered (500) |

The official module list spans BOTH: PT methodology/scoping, OSINT, social
engineering, web app + **API/JWT/GraphQL** testing, perimeter evasion
(firewall/IDS/WAF), Windows privesc, AD, Linux privesc, RE/fuzzing/binary,
**lateral movement + single/double pivoting + DNS/HTTP/ICMP tunneling**, IoT
firmware (+ emulation), **OT/SCADA Modbus/PLC**, wireless, cloud, DB, mobile
(self-study), report writing. Current program is "CPENT AI" — AI-assisted
tooling is now in the curriculum, ranges keep getting targets added.

**Implication:** the playbooks in this skill cover the union. If the exam form
contains OT or dedicated pivot sections, use the add-ons below.

## Sections not in the prior attempt — quick add-ons

### OT / SCADA (Modbus) section
- **Passive first:** `tcpdump -i any port 502 -w ot.pcap`, analyze in Wireshark
  (Modbus filter: `modbus`). Questions are read-the-pcap simple: "destination MAC
  of the device making the Modbus request", function codes, unit IDs, register
  values.
- If no traffic appears, the PLC sim may be stalled — **tell the proctor
  immediately** (documented case: required tech-team restart; proctor chats are
  your evidence trail).
- Active interaction: `mbtget`/`mbpoll` (install to /tmp/opencode or pipx), or
  a Python `pymodbus` script for register reads/writes.

### Pivot & Double Pivot section
Four documented routes (Rexturnull): SSH tunneling/port forwarding, Meterpreter
`route`/`portfwd`, chisel. This laptop: chisel + proxychains4 + asysocks
(toolkit.md §7). Method: identify the filtering device (the excluded .250),
pwn the edge host, tunnel THROUGH it, then repeat one level deeper for the
double pivot. Load `ctf-pivoting` for the full workflow.

### Egress busting (binary/filtered zones)
When reverse shells fail: forward connections still work — socket-reuse
shellcode (zone-binary.md), bind shells, `socat` relays, or meterpreter
reverse_tcp over an established chisel tunnel.

## Candidate-tested tactics (from LPT-Master + Rexturnull + this laptop)

1. **Screenshot WHILE answering, not after** — every answer needs evidence in
   the report; you WILL forget.
2. **Hit "save" after every question group** on the dashboard.
3. **Reorder wordlists** — put likely passwords (range-themed, usernames,
   `Name@123` patterns) first; brute force time is the real enemy. Try the
   range-provided wordlist before rockyou (prior attempt: 201-entry list solved
   4 of 5 crack challenges).
4. **Kernel privesc sometimes suffices** — the question wants the file, not a
   pretty chain: PwnKit, DirtyCow, MS17-010, Baron Samedit all named in
   write-ups.
5. **Don't trust leaked walkthroughs blindly** — IPs/hosts rotate between
   attempts; the technique transfers, the commands don't. Re-enumerate.
6. **Report between sessions** (12+12 format) — capture, structure, screenshot
   while fresh; the 7-day window evaporates.
7. **Dashboard submission bug is real** — if the report upload button spins
   silently, email + live-chat support immediately and keep pushing; confirm
   the dashboard shows "under review".
8. **Proctor issues = document** — missing questions (one candidate got 48
   instead of 51 in session 2), dead targets, stalled OT traffic: report, and
   screenshot the conversation.
9. **Practice range ≠ exam** — candidates who finished <half the practice range
   passed; the exam range is more approachable. Don't burn confidence on iLabs.
10. **Answer masks** (X/x/N) are sanity checks AND cracking guides — see SKILL.md.

## Prep recommendations (what to strengthen before next attempt)

Gaps exposed by the 52/53 attempt and by the v1 form possibly returning:

| Gap | Why it matters | Fix |
|---|---|---|
| OT/Modbus analysis | Entire 500-pt section in v1 form | Practice: Wireshark Modbus PCAPs, `pymodbus` lab; tcpdump filters |
| Double pivoting | Required in v1 form; binary zone edge here | `ctf-pivoting` pack; lab chisel→chisel chains |
| JWT/report-gated challenges | 3 web questions unanswered in prior attempt | Hunt signing secrets on OTHER in-scope hosts (config/git/env), not bigger wordlists |
| Method-graded questions | Ch12 unsubmitted because method (Key List attack) wasn't performed despite having the hash | Always execute the named technique |
| wpscan/binwalk/radare2 missing on this laptop | IoT + WordPress + RE questions stall | toolkit.md §Provisioning — install BEFORE the window |
| API/GraphQL testing | In official modules, untouched in prior form | `ctf-web` API notes; arjun + schemathesis bindings ready |

## External resources (kept for reference)

- Official program: eccouncil.org/programs/certified-penetration-testing-professional-cpent/
- offsecexams.com RedBlock CPENT v2 field guide (2026-07) — pivoting doctrine;
  distilled into pivot-core.md; reference copy in review_notes/redblock-fieldguide-ref.md
- Rexturnull/CPENT-CheatSheet (GitHub) — section-by-section commands, v1 form
- hackerstouch.in CPENT/LPT Master exam blog — scoring, OT experience, proctor tips
- hackmd.io/@alrex5401/CTF_Ranger — CTF range write-up
- 0xffsec.com/handbook — general pentest reference
- Prior attempt evidence: `private/` inside this skill (full) and
  `~/Documents/CPENT/Notes/review_notes/` (redacted methodology copies)
