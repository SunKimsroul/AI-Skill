# Certification prep and exam operating notes

This library is exam-agnostic tradecraft; this file maps it onto specific certifications and records how each exam expects you to operate. Exam rules, durations, and tool policies change — **always confirm the current rules against the official exam guide before you sit it.** Treat everything below as the shape of the exam, not the authority on its current terms.

**This file is for preparing. While you are actually sitting the exam, use the `exam-mode` skill instead** — it works from evidence rather than from the exam's name, so it also covers the certifications missing from the table below (OSEP, OSED, PNPT, CRTL, eCPPT and anything newer). The mapping here stays useful for study planning and for knowing what a given exam emphasises; `exam-mode` handles the live run, the state, and the constraints.

The single most valuable habit across every one of these: **take structured notes and screenshots as you go.** Every one of these certs is graded on a report, and the report is only as good as the evidence you captured live. Capture the command, the output, the timestamp, and the host for each step. Reconstructing proof afterwards loses time you do not have.

## AI-tool policy differs by provider — do not generalize

The split tracks proctoring more than anything else, and conflating the two regimes is a common and consequential mistake.

| Provider / exam | Proctored | Interactive AI during the exam |
|---|---|---|
| **OffSec** — OSCP, OSWE, OSEP, OSED | Yes | **Banned.** An interactive LLM or AI chatbot is classed as third-party assistance |
| **Hack The Box** — CPTS, CWES, CWEE | No | **No blanket ban.** Unproctored practicals graded on targets compromised and the report; AI for syntax, scripting, debugging, and querying your own notes is acceptable |
| **The SecOps Group** — CRTeamer | No | **Explicitly permitted**, stated on the exam page |
| **Altered Security** — CRTP, CRTE | No | Not confidently known — check the current exam guide rather than assuming either way |
| **Zero-Point Security** — CRTO, CRTL | No | Not confidently known — check the current exam guide |

The reasoning behind the HTB position is worth understanding rather than memorizing: these are unproctored, multi-day, objective-based exams where you are judged on what you actually compromised and how well you documented it. Restricting helper software would be unenforceable and beside the point. OffSec's proctored format makes the opposite call for the same reason — with a proctor watching, outside help is exactly what is being excluded.

Where a policy is unknown, treat it as unknown and confirm it — not as forbidden, and not as permitted. Rules change, and a provider can differ between two of its own certifications.

## Pack-loading map

These are pack names. For an uploaded-skill setup they correspond to ZIP files — `ctf-ad` is `ctf-ad.zip`, and so on. If a pack named below is not installed, say so plainly and name the ZIP rather than pointing at a file the user cannot open. Minimum sets: **CPTS/OSCP** need `ctf-pentest`, `ctf-web`, `ctf-privesc`, `ctf-pivoting`, `ctf-ad`, `ctf-writeup`; **CRTP/CRTE** need `ctf-ad` and `ctf-privesc`; **CRTeamer/CRTO** add `ctf-redteam`; **CWEE/CWES** need `ctf-web` above all.

| Need | Pack |
|---|---|
| Network/service enumeration, common services, shells, file transfer | `ctf-pentest` (enumeration-recon, common-services, shells-and-payloads, file-transfers) |
| Enumeration, Kerberos, AD CS, ACLs, trusts, DCSync, MSSQL | `ctf-ad` (and `ctf-ad/methodology.md` for the end-to-end playbook; `ctf-ad/mssql.md` for SQL Server) |
| Windows / Linux local privilege escalation | `ctf-privesc` |
| Reaching internal networks, tunneling | `ctf-pivoting` |
| Web application exploitation (incl. whitebox) | `ctf-web` |
| Binary exploitation / buffer overflow | `ctf-pwn` |
| Reversing a binary or bytecode | `ctf-reverse` |
| Password cracking, hash identification | `ctf-ad/credential-access.md` (mode table), `ctf-privesc` |
| Writing the exam report (professional pentest report) | `ctf-pentest/reporting.md`; CTF-style handoff via `ctf-writeup` + `references/writeup-standard.md` |
| Defender-aware tradecraft (CRTP/CRTE/CRTeamer) | `ctf-ad/evasion.md` |
| C2, initial access, payloads, red-team OPSEC/reporting | `ctf-redteam` |

## The certifications

### CRTeamer — Certified Red Teamer (The SecOps Group / PentestingExams.com)
- **Shape:** 5-hour 15-minute practical, on-demand, online over VPN. **Assumed-breach**: you start with **low-privileged domain-user credentials** on a hardened Windows/AD client and must perform vertical and lateral movement to reach **full domain compromise**, capturing flags. Pass at **60%**, merit at **75%**. One free retake. Intermediate level (~2 years red-team experience recommended).
- **Exam mechanics that catch people out:** you get a **bare out-of-the-box Kali** with **no C2 installed** — you choose and set up your own C2 in the exam time, so have a **ready-to-go, pre-configured C2 and tooling** rehearsed cold. No tool limit / any C2 allowed. **AI tools ARE permitted during the CRTeamer exam** — so this library may be used both to rehearse beforehand and as a live reference during the exam. (Confirm this against the current exam guide before you sit it; policies change.)
- **Emphasis:** modern AD exploitation TTPs + stealth; Windows internals; AV/Defender bypass; post-exploitation (hashes, tickets, tokens); LOLBAS/native-binary abuse; PowerShell & .NET tradecraft (AMSI/CLM/AppLocker/JEA); C2 operation and OPSEC. Content overlaps CRTP/CRTE (AD) plus CRTO/"Red Team Ops" (C2/evasion).
- **Load:** this is the flagship fit for the whole red-team stack — `ctf-redteam` (C2 infra, initial access, payloads/evasion orientation, OPSEC), `ctf-ad` (all of it + `methodology.md`), `ctf-privesc/windows-privesc.md`, `ctf-pivoting`, `ctf-ad/evasion.md`.
- **Syllabus → pack map:**

  | CRTeamer syllabus topic | Where |
  |---|---|
  | Red Team Infrastructure & OPSEC (redirectors, staging, C2 profiles, domain fronting) | `ctf-redteam/c2-infrastructure.md`, `opsec-and-lifecycle.md` |
  | Payload Development & Execution (in-memory, unmanaged PowerShell, Defender evasion) | `ctf-redteam/payloads-and-execution.md`, `edr-evasion.md`, `ctf-ad/evasion.md` |
  | Initial Access (weaponized docs, LNK, signed binaries, misconfigured services) | `ctf-redteam/initial-access.md` |
  | Local Enumeration & Recon | `ctf-privesc/windows-privesc.md` (enum section) |
  | Windows Privilege Escalation (service perms, UAC, DLL hijack, unquoted, token/SID/named-pipe) | `ctf-privesc/windows-privesc.md` |
  | Credential Access & Replay (LSASS/vaults, process-protection bypass, hash/token/ticket reuse) | `ctf-ad/credential-access.md` |
  | Lateral Movement (WMI/WinRM/SMB, cred/session reuse, SOCKS pivoting) | `ctf-ad/lateral-movement.md`, `ctf-pivoting/pivoting.md` |
  | Active Directory Enumeration (stealthy) | `ctf-ad/enumeration.md` |
  | Kerberos-Based Attacks (roasting, delegation, ticket forging, persistence) | `ctf-ad/kerberos.md` |
  | Domain Privilege Escalation (weak ACLs, group membership, misconfig) | `ctf-ad/acl-abuse.md`, `ctf-ad/methodology.md` |
  | Active Directory Persistence (autoruns/registry/WMI/tasks; domain-level) | `ctf-redteam/persistence-and-lateral.md`, `ctf-ad/domain-dominance.md` |
  | Living-off-the-Land & Native Binary Abuse (LOLBAS) | `ctf-ad/evasion.md` (LOLBAS section) |
  | PowerShell & .NET Tradecraft (AMSI/CLM/AppLocker/JEA, in-memory .NET) | `ctf-ad/evasion.md`, `ctf-redteam/payloads-and-execution.md` |
  | Offensive .NET & Tool Modification | `ctf-redteam/payloads-and-execution.md` (orientation — see caveat below) |
  | Privilege Maintenance & Access Expansion | `ctf-redteam/persistence-and-lateral.md`, `ctf-ad/domain-dominance.md` |

- **Caveat — build the hands-on evasion in your lab.** The payload-injection, EDR-evasion, and offensive-.NET-tool-modification files are deliberately **orientation-level** (technique → ATT&CK ID → public tool/course → detection profile), because generating weaponized loader/bypass code was out of scope. Even though AI is allowed in the exam, a reference map is not a working loader — you must *practise these hands-on beforehand* from the official learning resources below and walk in with your own tested tooling.
- **Official learning resources (from the exam page):** Active Directory Security; Harmj0y blog; Red Team Notes (TrustedSec) incl. its Defense Evasion section; MITRE ATT&CK for Enterprise; HackTricks; Hacking Articles – Active Directory Attacks; TryHackMe Red Team labs; SpecterOps blog; Red Team Path (Lorenzo Meacci). Most of these are already in the local writeup index — `python scripts\search_writeup_index.py <topic>` to pull specific articles.


### CPTS — HTB Certified Penetration Testing Specialist
- **Shape:** long, multi-day hands-on exam against a networked environment; you must reach specified objectives and submit a **professional penetration-test report**. A minimum number of flags/objectives plus an acceptable report are required to pass.
- **Emphasis:** full external-to-internal chain — recon, web, service exploitation, Linux/Windows privesc, pivoting across segments, and heavy Active Directory. This is the closest cert to a realistic engagement.
- **Load:** `ctf-ad` + `ctf-ad/methodology.md`, `ctf-privesc`, `ctf-pivoting`, `ctf-web`. Report via `ctf-writeup`.
- **Operating notes:** enumerate exhaustively; the environment rewards breadth. Keep a running host/credential inventory. The report is graded seriously — a working chain with a poor report can still fail.

### CRTP — Certified Red Team Professional (Altered Security / Pentester Academy)
- **Shape:** hands-on exam in a **single Active Directory forest** (historically ~24 hours of lab access plus report time). Objective is to compromise machines and reach domain/enterprise admin, then report.
- **Emphasis:** AD enumeration with PowerShell/PowerView, Kerberoasting, unconstrained/constrained delegation, ACL abuse, local privilege escalation, lateral movement, and domain dominance (DCSync, tickets). Some defender awareness (AMSI/CLM) but exploitation of standard misconfigurations is the core — not evasion.
- **Load:** `ctf-ad` (all of it), `ctf-ad/methodology.md` (CRTP single-domain workflow), `ctf-privesc/windows-privesc.md`, `ctf-ad/evasion.md`.
- **Operating notes:** PowerShell-centric. Enumerate the whole domain before acting. Chain trust of one machine into credentials for the next.

### CRTE — Certified Red Team Expert (Altered Security)
- **Shape:** hands-on exam across a **multi-domain / multi-forest** environment (larger and longer than CRTP), plus report.
- **Emphasis:** everything in CRTP plus cross-domain and cross-forest attacks — child→parent escalation (SID history / ExtraSids), trust key abuse, cross-forest Kerberos, AD CS across trusts, and more delegation. Constrained Language Mode, AppLocker, and defender-aware operation feature more heavily than in CRTP.
- **Load:** `ctf-ad` (especially `trusts.md`, `kerberos.md`, `adcs.md`, `acl-abuse.md`), `ctf-ad/methodology.md` (CRTE/forest workflow), `ctf-ad/evasion.md`, `ctf-pivoting`.
- **Operating notes:** map every trust before crossing it; know which SID-filtering boundary you are up against (intra-forest is permissive, inter-forest is not).

### OSCP — OffSec Certified Professional (PEN-200)
- **Shape:** 24-hour hands-on exam (plus a separate ~24-hour window to write and submit the report). A points threshold is required. The exam includes standalone targets and a small **Active Directory set** that is worth a large, often decisive block of points.
- **Emphasis:** enumeration, web and service exploitation, Linux and Windows privilege escalation, and the AD chain. Manual skill is tested; **tool restrictions apply** — historically automated exploitation tools and the Metasploit framework are heavily restricted (e.g. usable on only one target), and commercial/automated scanners are disallowed. Confirm the current tool policy in the exam guide.
- **Load:** `ctf-privesc` (both files — privesc is where OSCP candidates most often stall), `ctf-web`, `ctf-ad` + `ctf-ad/methodology.md`, `ctf-pivoting`. Report via `ctf-writeup`.
- **Operating notes:** work manually by default; do not rely on a tool the exam forbids. Enumerate first, exploit second. The AD set is usually the highest-value block — budget time for it. Screenshot the required proof files (`local.txt`/`proof.txt`) with the required context.

### CWEE — HTB Certified Web Exploitation Expert
- **Shape:** long hands-on **whitebox** web-exploitation exam with a required report; you are typically given source code and must find and chain vulnerabilities.
- **Emphasis:** advanced and chained web bugs — deep SQLi, server-side template injection with sandbox escapes, deserialization POP-chain construction from source, advanced file-upload/LFI-to-RCE, prototype pollution to RCE, XXE, request smuggling, and business-logic/race conditions. Source-code review is central.
- **Load:** `ctf-web` (all of it, especially the server-side-advanced, deser, exec, and whitebox files), plus `ctf-privesc` if a web RCE drops you onto a host that must be escalated.
- **Operating notes:** read the source first and trace user input to dangerous sinks. Build the exploit chain deliberately; single bugs rarely reach the objective. Document each link in the chain for the report.

### CWES — HTB Certified Web Exploitation Specialist
- **What it is:** HTB renamed **CBBH (Certified Bug Bounty Hunter)** to **CWES** (effective Oct 2025) and refreshed the syllabus. It is the **associate/practitioner** web tier — a rung below the expert-level CWEE — mapped to the HTB Academy **Bug Bounty Hunter** path. Confirm the current name/format on HTB before sitting it.
- **Shape:** hands-on exam against a live web application with a required report; broad practical web coverage rather than CWEE's deep whitebox chaining.
- **Emphasis:** the full bug-bounty web surface — recon and content discovery, SQLi/SQLMap, XSS, file inclusion/upload, command injection, HTTP verb/IDOR/business-logic, plus the refreshed additions (**API/GraphQL, SPA, server-side parameter pollution (SSPP), and "zombie/forgotten endpoints"**). Breadth and methodology over expert-tier depth.
- **Load:** `ctf-web` broadly (sql-injection, client-side, server-side, api-security, auth-*, web-recon, common-applications) and `ctf-pentest/web`-adjacent recon (`ctf-web/web-recon.md`). Lighter on the advanced whitebox files than CWEE.
- **Operating notes:** methodical enumeration first (web-recon), then work the OWASP-style surface. SSPP and forgotten-endpoint discovery are the newest additions — enumerate parameters and legacy routes deliberately.

## Exams this file does not profile in depth

The profiles above are the ones this library covers deepest. These are common enough to be worth
naming, with the packs that carry them — but confirm shape and rules against the current exam guide,
since none of them has been walked end to end here.

| Exam | Provider | Shape | Load |
|---|---|---|---|
| **LEE** — Linux Exploitation Expert | HackTricks | Binary exploitation across x86_64 userland → heap → AArch64 → kernel → V8 | `ctf-pwn` (all of it, and it is the pack's best fit); `ctf-pwn/aarch64-exploitation.md` for the ARM half; `ctf-reverse` where the blocker is understanding the target |
| **BSCP** | PortSwigger | Practical Burp-driven web exam, two hosts, fixed time | `ctf-web` broadly; Burp Pro is required rather than restricted here |
| **eWPT / eWPTX** | INE | Web application pentest with a report | `ctf-web`, `ctf-pentest/reporting.md` |
| **eCPPT** | INE | Network pentest with pivoting, report-graded | `ctf-pentest`, `ctf-pivoting`, `ctf-privesc`, `ctf-ad` |
| **eJPT** | INE | Entry-level practical, multiple choice against a live lab | `ctf-pentest` |
| **OSWP** | OffSec | Wireless attacks | Thin here — `ctf-misc/rf-sdr.md` is signal-level, not WPA attack methodology |
| **ARTE / AZRTE / CARTP** | HackTricks, Altered Security | Cloud red team, AWS and Azure | **Genuine gap** — the library has almost no cloud IAM or cloud-native attack material. `ctf-web/modern-identity-and-cloud.md` is the closest, and it is not enough |
| **CDSA / BTL1 / OSDA / eCIR / CCD-L1** | HTB, SBT, OffSec, INE, CyberDefenders | Defensive: SOC analysis, incident response, detection | **Out of scope by design.** This library is offensive. `ctf-forensics` covers artifact analysis and `ctf-forensics/incident-response-evidence-chain.md` the evidence discipline, but there is no detection-engineering or SIEM material |
| **C-AgAIPen** | — | Agentic AI pentesting | `ctf-ai-ml` (prompt injection, tool poisoning, agentic/MCP attacks) |

Two of these are worth calling out as real gaps rather than thin spots. **Cloud red team**
(ARTE/AZRTE/CARTP) has no meaningful coverage — no cloud IAM abuse, no metadata-service pivoting, no
cross-tenant paths. **Wireless** (OSWP) likewise. If either becomes a goal, they need building rather
than routing.

## Report expectations (all of the above)

Every one of these certs is pass/fail partly on the report. Follow `references/writeup-standard.md`, and where the exam publishes its own template, **use that template** and apply this library's standard for the quality of the prose inside it. Minimum contents graders expect:

- Executive summary and scope.
- Methodology / approach.
- Per-finding: description, affected host, prerequisite privilege, step-by-step reproduction with commands and screenshots, impact, and remediation.
- The required proof artifacts (flag/proof-file contents and IP-visible screenshots) exactly as the exam specifies.
- No fabricated steps. Every claim must map to captured evidence.

## Practice environments

- **HTB / HTB Academy** — machines and guided modules; the retired-machine writeups indexed by `scripts/search_writeup_index.py` (0xdf, ippsec, etc.) are the best practice companions.
- **Proving Grounds (OffSec)** — OSCP-aligned practice boxes; TJnull's PEN-200 list (also in the index) marks the most representative ones.
- **GOAD (Game of Active Directory)** — free local multi-domain AD lab; the single best environment to drill the `ctf-ad` and `ctf-pivoting` material. See `ctf-ad/tooling.md` for setup.
- **PortSwigger Web Security Academy** — free, best drill for the `ctf-web` / CWEE topics.

Use the local writeup index to find practice-target walkthroughs by name or technique:

```
python scripts\search_writeup_index.py <box or technique>
python scripts\search_writeup_index.py --source ippsec <box name>
```
