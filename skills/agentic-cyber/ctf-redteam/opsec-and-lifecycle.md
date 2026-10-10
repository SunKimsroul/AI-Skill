# Red Team - Operations, OPSEC & Lifecycle

## Table of Contents
- [Engagement Lifecycle](#engagement-lifecycle)
- [Scoping and Rules of Engagement](#scoping-and-rules-of-engagement)
- [Assumed-Breach vs Full-Scope](#assumed-breach-vs-full-scope)
- [Deconfliction and Safety](#deconfliction-and-safety)
- [OPSEC Discipline](#opsec-discipline)
- [Cleanup and Teardown](#cleanup-and-teardown)
- [Operator Logging and Evidence](#operator-logging-and-evidence)
- [MITRE ATT&CK: Plan and Map](#mitre-attck-plan-and-map)
- [Tactic to Technique Map (This Pack)](#tactic-to-technique-map-this-pack)
- [Detection Awareness by Phase](#detection-awareness-by-phase)
- [Purple-Team Alignment](#purple-team-alignment)
- [Reporting](#reporting)
- [Exam Notes (CRTO/CRTL/CRTP/CRTE)](#exam-notes-crtocrtlcrtpcrte)

This is the operational wrapper for the pack. Infrastructure lives in [c2-infrastructure.md](c2-infrastructure.md); delivery in [initial-access.md](initial-access.md); loaders in [payloads-and-execution.md](payloads-and-execution.md); evasion in [edr-evasion.md](edr-evasion.md); C2 driving in [c2-frameworks.md](c2-frameworks.md); staying-in/moving in [persistence-and-lateral.md](persistence-and-lateral.md). Domain-attack event-ID detail is in `ctf-ad/opsec-and-detection.md` — cross-referenced, never duplicated here.

---

The observation that drives everything below: the deliverable is not access, it is a reconstructable story a defender can act on. An engagement where you reach the crown jewels but cannot say *when, from where, with what command, and whether it alerted* is a failed engagement — and on real work, an unlogged action you cannot deconflict is worse than one you never ran. Log as you go, because the detail you skip is gone. Match your noise to the goal, not to your ego: sometimes the finding *is* that nobody noticed, and sometimes it is that they did.

---

## Engagement Lifecycle

Phases, and what must be locked before you touch a target:

1. **Pre-engagement / scoping** — ROE signed, scope defined, objectives agreed, PoCs and comms channels established, get-out-of-jail letter in hand. No packets before this.
2. **Infrastructure standup** — C2, redirectors, domains, mail infra proportioned to the OPSEC posture. Register/warm domains days-to-weeks ahead. See [c2-infrastructure.md](c2-infrastructure.md).
3. **Initial access** — phishing / assumed-breach foothold, tested small first. See [initial-access.md](initial-access.md).
4. **Foothold + situational awareness** — establish resilient C2, understand the host and its telemetry before acting.
5. **Escalation and lateral movement** — local privesc (`ctf-privesc`), domain graph (`ctf-ad`), through the C2.
6. **Objective / actions on target** — reach crown jewels, prove impact, collect evidence. No exfil or impact beyond ROE.
7. **Persistence** (only if scoped) — deliberate, tracked, survivable-but-removable.
8. **Cleanup / teardown** — remove every artifact; reconcile against your activity log.
9. **Reporting + retest** — attack-path narrative, findings, detection observations, remediation; often a retest window.

Time-box each phase against the engagement clock. If a phase overruns, deconflict and re-plan rather than burning the window on one path — a documented "we ran out of time at X" is a valid, useful finding.

## Scoping and Rules of Engagement

The ROE is the contract you operate inside; know it cold. Capture in writing before start:

- **In-scope targets** — IP ranges, CIDRs, domains, hostnames, cloud tenants/subscriptions, specific apps. **Explicit out-of-scope** — third-party SaaS, shared infra, partner networks, anything you do not own the authorization for.
- **Objectives / flags / crown jewels** — the specific outcomes that define success (DA, access to a named DB, a document, a payment path). Agree what "proof" looks like *before* you need it.
- **Allowed techniques** — is phishing in scope? DoS/destructive actions (almost always **no**)? Password spraying with lockout risk? Social engineering of named staff? Physical? Persistence?
- **OPSEC posture** — evasive covert red team vs loud pentest-style. Determines whether the blue team knows an assessment is running (double-blind vs coordinated).
- **Time box** — start/end dates, permitted hours (e.g. business hours only, or explicitly 24/7), blackout windows (quarter-end, maintenance).
- **Data handling** — what you may access/exfil, redaction requirements, storage/encryption of loot, destruction timeline.
- **Get-out-of-jail letter** — signed authorization naming the assessing org, the client sponsor, dates, scope, and an emergency contact. Carry it (physical + digital) for any onsite/physical component; it is your legal cover if challenged.
- **Points of contact** — technical PoC, executive sponsor, blue-team/white-cell deconfliction contact, out-of-hours emergency contact. Names, phone, and secure channel (Signal/encrypted email), not just email.

Pre-flight checklist (all must be green before first packet):

```
[ ] ROE signed by client sponsor with legal authority
[ ] In-scope targets enumerated; out-of-scope explicitly listed
[ ] Objectives / crown jewels defined; "proof" criteria agreed
[ ] Allowed & forbidden techniques listed (phishing? spray? persistence? destructive = no)
[ ] OPSEC posture set (covert double-blind / coordinated / loud)
[ ] Time box + permitted hours + blackout windows
[ ] Data-handling & destruction rules
[ ] Get-out-of-jail letter signed and carried (onsite/physical)
[ ] PoCs: technical, sponsor, white-cell/deconfliction, out-of-hours emergency
[ ] Deconfliction protocol + secure comms channel tested
[ ] Source infra (C2 domains/IPs) recorded and shared with white cell (if coordinated)
```

If it is not in the ROE, it is out of scope. When in doubt, ask the PoC and get it in writing before proceeding.

## Assumed-Breach vs Full-Scope

- **Full-scope / black-box** — you start from the outside (OSINT, external perimeter, phishing) and must earn the foothold. Realistic, but a hardened perimeter can burn the entire time box before any internal testing happens.
- **Assumed-breach** — the client hands you a foothold (a low-priv user, a workstation, VPN creds, or a planted implant), so time is spent on internal detection/response and lateral movement rather than the front door. Now the default for mature clients — most value is inside.
- **Hybrid** — attempt initial access with a fixed deadline; if it fails, fall back to an assumed-breach grant so the internal test still runs. Agree the fallback trigger in the ROE.

Assumed-breach maps directly to how AD exams start you (a domain user on a jump host); full-scope maps to CRTO-style "get in first" labs. Pick infrastructure and noise level accordingly.

## Deconfliction and Safety

Deconfliction = letting the right people distinguish *your* activity from a real intrusion, and stopping harm fast.

- **Deconfliction protocol** — agree upfront how the blue team / white cell confirms an alert is you. Standard method: you maintain a real-time activity log (source IPs, C2 domains, timestamps, target hosts) the white cell can query. When blue escalates an alert, the white cell checks it against your log and either stands down ("that's the red team") or confirms a real attacker — the latter is itself a valuable finding.
- **Attribution markers** — some engagements ask you to tag activity (a known source IP, a benign string in payloads, a specific user-agent) so it is trivially deconflictable. Covert double-blind engagements deliberately do *not* — resolution goes through the white cell only.
- **Avoiding production impact** — no exploits with a crash/DoS risk on production without explicit sign-off; prefer read/prove over modify/destroy; never run destructive cleanup of *client* data; test disruptive actions in a lab first. Password spraying: respect lockout thresholds (know the policy; spray slow, one attempt per account per window) — locking out a division is a production incident.
- **Data-handling rules** — access only what proves the objective; do not read PII/PHI/customer data beyond what the ROE allows; redact in evidence; encrypt loot at rest; store on approved systems; destroy on the agreed timeline and confirm destruction in the report.
- **When to stop** — you find evidence of a *real* prior/ongoing compromise; you hit a system or data class outside scope; you risk a safety-of-life/critical system (medical, ICS/OT, life-safety); an action could cause outage; or the PoC calls a halt. Stop, preserve state, and notify the emergency contact immediately.
- **Emergency contacts** — one reachable human, out-of-hours, on a channel you have tested. If you cause an outage or find a live breach, this call comes before continuing.

Deconfliction register the white cell queries (share and keep current):

| Field | Purpose |
|---|---|
| C2 domains / redirector IPs | Match SIEM/proxy alerts to red-team infra |
| Source IPs you operate from | Match firewall/VPN/auth logs |
| Active target hosts + times | Confirm "was that us on HOST at TIME?" |
| Payload / user-agent markers | Fast-path attribution on coordinated ops |
| Current phase / stop-state | White cell knows if you are paused |

## OPSEC Discipline

OPSEC is a dial set by the engagement goal, not a constant maximum.

- **Match noise to the goal.** Evasive covert red team (double-blind, testing detection & response) → minimal footprint, slow, disposable infra, in-memory only. Loud coordinated pentest / "assumed the blue team knows" → speed and coverage over stealth; noise is acceptable and you cover more ground. Setting the dial too stealthy on a coverage engagement wastes the window; too loud on a detection test invalidates the result.
- **Stage from disposable infrastructure.** Redirectors and mail infra are burnable front-ends; never expose the C2 team server directly (see [c2-infrastructure.md](c2-infrastructure.md)). Assume every domain/IP/payload you touch the target with may be burned — keep clean infra in reserve and test hypotheses with throwaways first.
- **Test before you commit.** A loader, delivery method, or lateral technique is a hypothesis until the target's controls confirm it. Send a benign canary, detonate a throwaway payload against the actual EDR, verify egress — *then* spend real infrastructure. Detail in [payloads-and-execution.md](payloads-and-execution.md) and [edr-evasion.md](edr-evasion.md).
- **Minimize on-disk artifacts.** Prefer in-memory execution (reflective/PE-in-memory, BOFs, .NET assembly load) over dropping binaries; if you must drop, know where and clean it. Avoid touching AV-scanned paths; expect MOTW and script-block logging.
- **Blend with the environment.** Malleable profiles, jittered sleep, realistic user-agents/domains, business-hours activity on a covert op, LOLBins over foreign tooling. The environment's own noise floor is your cover.
- **Log your own actions** (below) — not optional even on covert ops; it is what makes activity deconfliction and the report possible.

## Cleanup and Teardown

Track every mutation as you make it (the activity log is the source of truth) and reverse it at the end:

- **Payloads/tools** — delete dropped binaries, scripts, staged archives, output files, `.ccache`/PFX/ticket files, loot staging dirs.
- **Persistence** — remove services, scheduled tasks, run keys, WMI subscriptions, startup items, planted webshells/implants. See [persistence-and-lateral.md](persistence-and-lateral.md).
- **Accounts/AD changes** — delete created users and computer objects; revert added group memberships, RBCD writes (`msDS-AllowedToActOnBehalfOfOtherIdentity`), shadow-cred writes (`msDS-KeyCredentialLink`), added SPNs, ACL/DACL edits. These are the highest-risk residuals — an unremoved DA-capable backdoor is a liability you own.
- **Credentials** — note that dumped creds/tickets exist so the client can force rotation (krbtgt ×2, service accounts, any cracked passwords).
- **Infrastructure** — decommission redirectors/team servers after the report is accepted (keep C2 logs for the deliverable first), release/burn domains.

Teardown reconciliation (walk against the activity log; each item either reverted-by-you or handed-to-client):

```
[ ] Dropped files/tools deleted (binaries, scripts, archives, output)
[ ] Ticket/cred artifacts removed (.ccache, .kirbi, PFX, hashes on disk)
[ ] Services / scheduled tasks / run keys / WMI subs removed
[ ] Startup items, planted webshells/implants removed
[ ] Created users & computer objects deleted
[ ] Group memberships / RBCD / shadow-cred / SPN / ACL edits reverted
[ ] Client informed of creds to rotate (krbtgt x2, service, cracked pw)
[ ] Redirectors/team servers decommissioned (after C2 logs archived)
[ ] Domains released/burned; loot destroyed per ROE, destruction recorded
```

Reconcile the teardown line-by-line against the activity log and record confirmation of each reversal in the report. What you cannot remove yourself, hand to the client explicitly.

## Operator Logging and Evidence

Keep a running activity log — one row per meaningful action — written *as you act*, not reconstructed after.

Minimum fields per entry:

| Field | Example |
|---|---|
| Timestamp (with TZ/UTC) | `2026-07-27 14:03:11 UTC` |
| Operator | `op-alice` |
| Source | team server / redirector / host you ran from + source IP |
| Target host / IP | `WKSTN-07 / 10.10.5.23` |
| Action / command | exact command or C2 task (`execute-assembly Rubeus.exe kerberoast ...`) |
| Tool | Beacon, Rubeus, impacket, etc. |
| Result | success/fail, output summary, creds/tickets obtained |
| ATT&CK technique | `T1558.003 Kerberoasting` |
| Expected artifact | event(s) it should generate (`4769 RC4 for SPN`) |
| Detected? | alerted / blocked / silent — filled during purple readout |

Worked example row (curated later into the timeline):

```
2026-07-27 14:03:11 UTC | op-alice | redir-01 203.0.113.10 | WKSTN-07 10.10.5.23
  action:  execute-assembly Rubeus.exe kerberoast /nowrap /outfile:roast.txt
  tool:    Beacon (SMB, via WKSTN-07)
  result:  1 SPN roasted (svc_sql), hash captured, cracked offline -> Summer2026!
  attack:  T1558.003 Kerberoasting
  expect:  DC 4769 TGS-REQ, RC4 (0x17), SPN MSSQLSvc/... from WKSTN-07
  detected: (filled at purple readout) -> ALERTED, no response within window
```

Practical capture: Cobalt Strike logs beacon tasking automatically (archive `logs/`), Sliver/Mythic keep operation logs, `ttp-tracker`/`vectr`/a shared spreadsheet for the human-readable timeline. Timestamp screenshots for proof-of-access (redact sensitive data per ROE), and note *where* each credential/ticket artifact was written so cleanup can find it.

This one log feeds three things: **deconfliction** (white cell matches alerts against it in real time), the **report** (it *is* the attack-path timeline), and **cleanup** (every mutation to reverse is a row). Detail you skip now is unrecoverable later.

## MITRE ATT&CK: Plan and Map

Use ATT&CK two ways: to **plan** (walk the tactics in kill-chain order and pick a technique per phase from what the environment allows) and to **map findings** (tag every activity-log row with its technique ID so coverage and detection gaps are quantifiable). Tactic IDs (Enterprise matrix):

`TA0043` Reconnaissance · `TA0042` Resource Development · `TA0001` Initial Access · `TA0002` Execution · `TA0003` Persistence · `TA0004` Privilege Escalation · `TA0005` Defense Evasion · `TA0006` Credential Access · `TA0007` Discovery · `TA0008` Lateral Movement · `TA0009` Collection · `TA0011` Command and Control · `TA0010` Exfiltration · `TA0040` Impact

Do not invent technique IDs; if unsure, verify against attack.mitre.org. A finding tagged with a real technique lets the client cross-reference their detection engineering and threat intel directly.

## Tactic to Technique Map (This Pack)

What each file exercises, in ATT&CK terms:

| Tactic | Technique (ID) | Pack coverage |
|---|---|---|
| Resource Development (TA0042) | Acquire Infrastructure (T1583) · Stage Capabilities (T1608) · Compromise Infrastructure (T1584) | [c2-infrastructure.md](c2-infrastructure.md) — domains, redirectors, mail |
| Initial Access (TA0001) | Phishing (T1566, .001 Attachment / .002 Link / .003 Service) · Valid Accounts (T1078) | [initial-access.md](initial-access.md) |
| Execution (TA0002) | User Execution (T1204) · Command/Scripting Interpreter (T1059, .001 PowerShell / .003 cmd) · System Binary Proxy (T1218, LOLBins) · Reflective Code Loading (T1620) | [payloads-and-execution.md](payloads-and-execution.md) |
| Defense Evasion (TA0005) | Process Injection (T1055) · Obfuscated Files/Info (T1027) · Impair Defenses: Disable/Modify Tools (T1562.001, AMSI/ETW) · Reflective Loading (T1620) · Access Token Manipulation (T1134) | [edr-evasion.md](edr-evasion.md), [payloads-and-execution.md](payloads-and-execution.md) |
| Command and Control (TA0011) | Application Layer Protocol (T1071, .001 Web / .004 DNS) · Encrypted Channel (T1573) · Proxy (T1090, .004 Domain Fronting) · Ingress Tool Transfer (T1105) | [c2-infrastructure.md](c2-infrastructure.md), [c2-frameworks.md](c2-frameworks.md) |
| Persistence (TA0003) | Scheduled Task (T1053.005) · Windows Service (T1543.003) · Registry Run/Startup (T1547.001) · WMI Event Sub (T1546.003) · Create/Manipulate Account (T1136 / T1098) | [persistence-and-lateral.md](persistence-and-lateral.md) |
| Priv Esc (TA0004) | Valid Accounts (T1078) · Access Token Manipulation (T1134) · local techniques | `ctf-privesc`, [persistence-and-lateral.md](persistence-and-lateral.md) |
| Credential Access (TA0006) | OS Credential Dumping (T1003, .001 LSASS / .006 DCSync) · Steal/Forge Kerberos Tickets (T1558, .003 Kerberoast / .004 AS-REP / .001 Golden / .002 Silver) | `ctf-ad` |
| Discovery (TA0007) | Domain Trust (T1482) · Account (T1087) · Permission Groups (T1069) · Remote System (T1018) | `ctf-ad` (BloodHound) |
| Lateral Movement (TA0008) | Remote Services (T1021, .002 SMB / .006 WinRM / .001 RDP) · Use Alt Auth Material (T1550, .002 PtH / .003 PtT) · Lateral Tool Transfer (T1570) | [persistence-and-lateral.md](persistence-and-lateral.md), `ctf-ad` |
| Collection / Exfil (TA0009 / TA0010) | Archive Collected Data (T1560) · Data Staged (T1074) · Exfil Over C2 Channel (T1041) · Over Web Service (T1567) · Over Alt Protocol (T1048) | this file (actions-on-objective), ROE-bounded |

## Detection Awareness by Phase

What the blue team typically sees per phase. For AD-specific **event IDs, logon types, and per-attack telemetry**, use `ctf-ad/opsec-and-detection.md` — not repeated here.

- **Initial access** — mail gateway logs (sender, attachment/URL detonation in sandbox), proxy logs for the click, MOTW-tagged file execution, first-stage process spawned by Office/browser (Word->cmd/PowerShell is a classic parent-child alert).
  - *Reduce:* aged/categorized domains, HTML smuggling to dodge attachment scanning, container formats that strip MOTW, delivery tested against the actual filter first. See [initial-access.md](initial-access.md).
- **Execution** — process creation (4688) with command line, PowerShell script-block logging (4104) and AMSI, EDR telemetry on injection/unusual parent-child, LOLBin abuse patterns. Encoded/obfuscated command lines are high-signal.
  - *Reduce:* in-memory/.NET execution, AMSI/ETW patching, spawn-to a plausible sacrificial process, avoid `-enc` one-liners. See [payloads-and-execution.md](payloads-and-execution.md), [edr-evasion.md](edr-evasion.md).
- **Persistence** — service install (7045 System / 4697 Security), scheduled task create (4698/4702), run-key/registry writes, WMI subscription creation, new account (4720) / group add (4728/4732/4756). Highest-signal for hunters because it is durable and rare for benign users.
  - *Reduce:* persist only if scoped, prefer user-context over SYSTEM-level installs, name to blend, and track every artifact for cleanup. See [persistence-and-lateral.md](persistence-and-lateral.md).
- **Credential access** — LSASS handle-open from an unusual process (EDR / Sysmon 10), DCSync = 4662 on replication GUIDs by a non-DC, Kerberoast = mass 4769 with RC4 (0x17), AS-REP roast = 4768 with preauth-not-required.
  - *Reduce:* roast targeted single SPNs not en masse, request AES where possible to avoid RC4-downgrade flags, avoid touching LSASS directly (SAM/registry, tickets, BOF-based dumps). Detail in `ctf-ad/opsec-and-detection.md`.
- **Lateral movement** — 4624 Logon Type 3 (network/PtH) and Type 9 (`runas /netonly`, over-PtH), 4648 explicit-cred logon, remote service/task creation on the target, WinRM (5985/5986) and SMB admin-share access, anomalous account-to-host pairings.
  - *Reduce:* reuse existing sessions/tickets over new logons, use the account expected on that host, prefer WMI/WinRM over service-drop where it fits the baseline. See [persistence-and-lateral.md](persistence-and-lateral.md).
- **Exfiltration** — egress volume anomalies, DLP triggers, connections to newly-seen domains/IPs, DNS tunneling (high query volume/entropy to one domain), uploads to web services. C2 beaconing shows as regular-interval connections.
  - *Reduce:* exfil only what proves the objective (ROE-bounded), over the existing C2 channel (T1041) rather than a new path, chunked and jittered; malleable profiles and sleep jitter blunt beacon-interval detection.

For each phase, log the *expected* artifact (activity-log column) so the purple readout can confirm whether the control fired.

## Purple-Team Alignment

Every activity-log row already carries technique + expected artifact + detected-flag — that structure is a purple-team deliverable with no extra work. In coordinated (non-double-blind) engagements, run a live or post-hoc readout with the blue team: for each technique, did they **alert**, **block**, or **miss**? A miss is a detection-engineering gap tied to a concrete ATT&CK ID; an alert-no-response is a process gap. This converts "we got DA" into "here is exactly which of your controls to fix," which is the higher-value outcome for a mature client. Map results onto the client's ATT&CK Navigator coverage layer.

## Reporting

Red-team report structure (differs from a pentest report — see below):

1. **Executive narrative** — non-technical story: what an attacker achieved, business impact, whether they were detected/stopped, top strategic recommendations. Written for leadership.
2. **Attack-path / kill-chain timeline** — the core artifact. The chronological story from initial access to objective: each step, the technique (ATT&CK ID), what it yielded, and the pivot to the next step. This is your activity log, curated into a narrative — a defender should be able to walk the exact path. Include a diagram (foothold -> escalation -> lateral hops -> crown jewel). Shape:

```
Phishing (T1566.002) -> JBLOGGS clicks -> Beacon on WKSTN-07 (T1204 / T1059.001)
  -> Kerberoast svc_sql (T1558.003) -> cracked -> local admin on SQL-01 (T1078)
  -> LSASS dump on SQL-01 (T1003.001) -> DA-adjacent creds
  -> DCSync (T1003.006) -> krbtgt -> Golden Ticket (T1558.001)
  -> access to FIN-DB crown jewel   [objective met day 3, undetected until DCSync]
```
3. **Findings** — the discrete weaknesses that enabled the path (e.g. kerberoastable DA-adjacent SPN, unconstrained delegation, no egress filtering, phishing bypassed MFA). Each with evidence, risk, and affected assets.
4. **Detection & response observations** — per phase/technique: alerted / blocked / missed, time-to-detect, time-to-respond, and the specific control gap. The purple deliverable.
5. **Remediation** — concrete, prioritized, mapped to each finding and to the specific technique it defeats; strategic (architecture, tiering, detection engineering) not just point fixes.

**vs a pentest report:** a pentest report is a *vulnerability-centric* enumeration — a list of findings, each with CVSS/severity, ranked by count and criticality, aiming for coverage. A red-team report is *narrative-centric* — one (or few) attack paths to specific objectives, emphasizing whether the org's people/process/technology detected and responded. Pentest answers "what's vulnerable?"; red team answers "could a determined adversary reach the crown jewels, and would we notice?" Fewer findings, deeper story, detection/response front and center.

Follow the **F0undM3 writeup standard** for structure and evidence rigor (see `ctf-writeup` and the `ctf-ad/SKILL.md` reference to the F0undM3 report standard; per-exam reporting notes in `f0undm3` `references/certification-prep.md`). Reproducible steps, exact commands, timestamps, redacted proof — the same standard that makes a CTF writeup gradeable makes a red-team report actionable.

## Exam Notes (CRTO/CRTL/CRTP/CRTE)

- **CRTP / CRTE / CRTO-AD-style AD exams (Altered Security)** — reward **correct technique + a clear, reproducible report** over evasion. AV/EDR is minimal or off; you are not primarily graded on stealth. Enumerate methodically (BloodHound, PowerView), walk the shortest path to DA/objectives, and **document every step with exact commands, output, and screenshots** — the report is a graded deliverable. Lean on `ctf-ad` + `ctf-ad/methodology.md` for the technique; this pack supplies the reporting/lifecycle wrapper. Do not overthink OPSEC; do get the writeup right.
- **CRTO / CRTL (Zero-Point Security)** — grade you on **operating a C2 (Cobalt Strike) and OPSEC**: malleable profiles, redirectors, initial access, in-memory execution, AV/EDR evasion, and disciplined tradecraft. CRTL adds deeper evasion/tooling and lab-specific objectives. Here evasion and infrastructure hygiene *are* the exam — the pack's [c2-infrastructure.md](c2-infrastructure.md), [initial-access.md](initial-access.md), [payloads-and-execution.md](payloads-and-execution.md), [edr-evasion.md](edr-evasion.md), and [c2-frameworks.md](c2-frameworks.md) are the core. Objectives are flag-style; capture proof as you go.
- **Universal exam discipline** — read the exam's ROE/rules (some forbid tooling like automated exploit frameworks or shared write-ups), manage the time box, screenshot proof the moment you have it (not after the lab resets), and keep the same activity log you would on an engagement. Whether the exam values technique-and-report or C2-and-OPSEC, a clean documented path is what passes.
- **Common failure mode** — reaching all objectives but failing the report: missing screenshots, unreproducible steps, or flags without the command that captured them. Treat the writeup as the graded artifact from the first flag, not an afterthought at the end.
