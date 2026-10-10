# Practice-target drill plan

This is **not** a study guide. It is a per-exam map from *skill area* → *where to rehearse it for free (or cheapest)* → *specific named boxes/labs to drill, with public writeup links* → *the pack file to keep open while drilling*. Load a target, attempt it cold, then read the linked writeup and compare against the pack.

- **Named targets and writeup URLs are pulled from the local writeup index** (`scripts/search_writeup_index.py`); box names are real, not invented. Most links are 0xdf (`0xdf.gitlab.io`); S4vitar video walkthroughs for the same boxes are in the index under `--source htbmachines`.
- For exam *shape, rules, and pack-loading*, see `references/certification-prep.md`. This file only covers **where to practice**.
- HTB boxes must be **retired** to have public writeups; free HTB accounts see active boxes only, so retired-box drilling needs VIP, or use the writeup to follow along on a similar free box.
- Confirm exam rules against the official guide before sitting — venues and box lists here are for rehearsal, not exam content.

## Venue quick-reference

| Venue | Cost | Best for |
|---|---|---|
| **GOAD (Game of Active Directory)** | Free (self-hosted; needs a beefy host, ~5 VMs) | Multi-domain/forest AD — the single best free drill for CRTP/CRTE/CRTeamer. Setup in `ctf-ad/tooling.md`. |
| **HackTheBox retired machines** | VIP (~low monthly) | Named AD/Windows/Linux/web boxes with 0xdf + S4vitar writeups indexed. |
| **Proving Grounds Practice (OffSec)** | Low monthly | OSCP-representative standalones; drill the TJnull PEN-200 list. |
| **TryHackMe** (Red Team / AD / Offensive Pentesting paths) | Free tier + low sub | Guided AD and red-team rooms; gentlest ramp for CRTeamer/OSCP AD. |
| **PortSwigger Web Security Academy** | **Free** | Every web bug class for CWES/CWEE, with official labs graded per category. |
| **Altered Security labs** (CRTP/CRTE/PACES) | Paid (course-bundled) | The only faithful rehearsal for CRTP/CRTE mechanics — no free equal for the multi-domain exam range. |
| **CRTO lab (Zero-Point Security)** | Paid (course-bundled) | The only faithful C2/evasion rehearsal for CRTO; GOAD covers the AD half but not the Cobalt-Strike-vs-Defender half. |

---

## CRTeamer — Certified Red Teamer (assumed-breach AD + evasion)

Assumed-breach from a low-priv domain user → full domain compromise, **with defender awareness**. Two halves to drill: (1) the AD attack chain, (2) operating stealthily under Defender/AMSI/CLM/AppLocker with your own C2. AI is permitted in this exam, so this library doubles as a live reference — but you must walk in with tested tooling.

| Skill area | Best free practice venue | Specific targets to drill (with writeups) | Pack file |
|---|---|---|---|
| Full multi-host assumed-breach chain | **GOAD** (free) | GOAD full lab + [GOAD minilab walkthrough](https://systemweakness.com/goad-minilab-walkthrough-c4038e70bde7); [install notes](https://systemweakness.com/install-goad-on-macos-e0dc22822c91) | `ctf-ad/methodology.md` |
| Stealthy AD enumeration | HTB retired | [Support](https://0xdf.gitlab.io/2022/12/17/htb-support.html), [Cicada](https://0xdf.gitlab.io/2025/02/15/htb-cicada.html) | `ctf-ad/enumeration.md` |
| Kerberos attacks (roast/delegation/tickets) | HTB retired | [Scrambled](https://0xdf.gitlab.io/2022/10/01/htb-scrambled.html) (Kerberos-only, silver ticket), [Absolute](https://0xdf.gitlab.io/2023/05/27/htb-absolute.html) (Kerberos-only, RBCD) | `ctf-ad/kerberos.md` |
| Credential access / replay (LSASS, tickets) | HTB retired | [Blackfield](https://0xdf.gitlab.io/2020/10/03/htb-blackfield.html) (LSASS dump → ticket), [Sauna](https://0xdf.gitlab.io/2020/07/18/htb-sauna.html) | `ctf-ad/credential-access.md` |
| Lateral movement (WMI/WinRM/SMB, RBCD) | HTB retired | [Rebound](https://0xdf.gitlab.io/2024/03/30/htb-rebound.html) (RBCD + constrained delegation, hard), [Vintage](https://0xdf.gitlab.io/2025/04/26/htb-vintage.html) | `ctf-ad/lateral-movement.md`, `ctf-pivoting/pivoting.md` |
| Windows local privesc | HTB retired | [Outdated](https://0xdf.gitlab.io/2022/12/10/htb-outdated.html) (PrintNightmare/shadow creds), [Jeeves](https://0xdf.gitlab.io/2022/04/14/htb-jeeves.html) | `ctf-privesc/windows-privesc.md` |
| Domain privesc / dominance (ACL, DCSync) | HTB retired | [Administrator](https://0xdf.gitlab.io/2025/04/19/htb-administrator.html) (ACL chain → DCSync), [Forest](https://0xdf.gitlab.io/2020/03/21/htb-forest.html) | `ctf-ad/acl-abuse.md`, `ctf-ad/domain-dominance.md` |
| C2 infra + payload/EDR evasion, LOLBAS | **CRTO lab (paid)** — no free equal; GOAD for the AD half | Rehearse your own C2 profile against Defender in your lab; no public box reproduces this. | `ctf-redteam/c2-infrastructure.md`, `edr-evasion.md`, `ctf-ad/evasion.md` |
| Report | — | Use exam template | `ctf-writeup`, `references/writeup-standard.md` |

**Drill order:** GOAD end-to-end (own C2) → single-domain AD chain boxes (Forest, Sauna, Support) → Kerberos/RBCD depth (Scrambled, Absolute, Rebound) → evasion/C2 in your own lab (or CRTO) → dominance boxes (Administrator, Blackfield) → full assumed-breach rerun on GOAD under stealth constraints.

---

## CRTP — Certified Red Team Professional (single-domain AD, misconfig-focused)

Single AD forest; exploit standard misconfigurations to Enterprise Admin. PowerShell/PowerView-centric. Evasion is light — this is about the attack graph, not beating Defender.

| Skill area | Best free practice venue | Specific targets to drill (with writeups) | Pack file |
|---|---|---|---|
| Domain enumeration (PowerView) | **GOAD** (free) | GOAD single-domain path; [Forest](https://0xdf.gitlab.io/2020/03/21/htb-forest.html), [Cascade](https://0xdf.gitlab.io/2020/07/25/htb-cascade.html) | `ctf-ad/enumeration.md` |
| AS-REP roast / Kerberoast | HTB retired | [Sauna](https://0xdf.gitlab.io/2020/07/18/htb-sauna.html) (AS-REP), [Active](https://0xdf.gitlab.io/2018/12/08/htb-active.html) (GPP → Kerberoast) | `ctf-ad/kerberos.md` |
| ACL abuse (GenericAll/WriteDACL) | HTB retired | [Forest](https://0xdf.gitlab.io/2020/03/21/htb-forest.html) (Exchange ACL → DCSync), [Object](https://0xdf.gitlab.io/2022/02/28/htb-object.html) (WriteOwner chain) | `ctf-ad/acl-abuse.md` |
| Local + domain privesc (DnsAdmins, groups) | HTB retired | [Resolute](https://0xdf.gitlab.io/2020/05/30/htb-resolute.html) (DnsAdmins), [Return](https://0xdf.gitlab.io/2022/05/05/htb-return.html) (Server Operators) | `ctf-privesc/windows-privesc.md` |
| Delegation (unconstrained/constrained/RBCD) | HTB retired | [Intelligence](https://0xdf.gitlab.io/2021/11/27/htb-intelligence.html), [Support](https://0xdf.gitlab.io/2022/12/17/htb-support.html) (RBCD) | `ctf-ad/kerberos.md` |
| AD CS misconfig (ESC1) | HTB retired | [Escape](https://0xdf.gitlab.io/2023/06/17/htb-escape.html) (ESC1), [Authority](https://0xdf.gitlab.io/2023/12/09/htb-authority.html) (ESC1 + PWM) | `ctf-ad/adcs.md` |
| Domain dominance (DCSync, golden ticket) | HTB retired | [Blackfield](https://0xdf.gitlab.io/2020/10/03/htb-blackfield.html), [Administrator](https://0xdf.gitlab.io/2025/04/19/htb-administrator.html) | `ctf-ad/domain-dominance.md` |
| Full single-domain rehearsal | **Altered Security CRTP lab (paid)** | The CRTP lab itself is the faithful rehearsal; no free box reproduces the exam network. | `ctf-ad/methodology.md` |

**Drill order:** GOAD single domain → enumeration+roasting (Sauna, Active) → ACL chains (Forest, Object) → delegation + AD CS (Support, Escape, Authority) → dominance (Administrator, Blackfield). Do the CRTP lab last as the dress rehearsal.

---

## CRTE — Certified Red Team Expert (multi-domain / multi-forest)

Everything in CRTP **plus** cross-domain and cross-forest: child→parent (SID history / ExtraSids), trust-key abuse, cross-forest Kerberos, AD CS across trusts. CLM/AppLocker feature more. HTB rarely gives true multi-forest, so **GOAD is the primary free venue** for the trust work.

| Skill area | Best free practice venue | Specific targets to drill (with writeups) | Pack file |
|---|---|---|---|
| Multi-domain/forest enumeration + trust mapping | **GOAD** (free) | GOAD full lab (three domains, two forests) — the core CRTE rehearsal | `ctf-ad/trusts.md`, `ctf-ad/methodology.md` |
| Cross-domain escalation (SID history / ExtraSids) | **GOAD** (free) | GOAD child→parent path; concept boxes: [Multimaster](https://0xdf.gitlab.io/2020/09/19/htb-multimaster.html) | `ctf-ad/trusts.md`, `ctf-ad/domain-dominance.md` |
| Cross-forest Kerberos / trust-key abuse | **GOAD** (free) | GOAD forest trust path | `ctf-ad/kerberos.md`, `ctf-ad/trusts.md` |
| AD CS across trusts (ESC1–ESC8) | HTB retired | [Certified](https://0xdf.gitlab.io/2025/03/15/htb-certified.html) (ESC9/shadow), [Manager](https://0xdf.gitlab.io/2024/03/16/htb-manager.html) (ESC7), [EscapeTwo](https://0xdf.gitlab.io/2025/05/24/htb-escapetwo.html) | `ctf-ad/adcs.md` |
| Delegation depth (constrained/RBCD/S4U) | HTB retired | [Rebound](https://0xdf.gitlab.io/2024/03/30/htb-rebound.html), [Vintage](https://0xdf.gitlab.io/2025/04/26/htb-vintage.html) (gMSA + RBCD + timeroast) | `ctf-ad/kerberos.md` |
| MSSQL links across domains | HTB retired | [Freelancer](https://0xdf.gitlab.io/2024/10/05/htb-freelancer.html) (MSSQL AD), [StreamIO](https://0xdf.gitlab.io/2022/09/17/htb-streamio.html) | `ctf-ad/mssql.md` |
| CLM / AppLocker-aware operation | HTB retired + GOAD | [Absolute](https://0xdf.gitlab.io/2023/05/27/htb-absolute.html), GOAD hardened hosts | `ctf-ad/evasion.md` |
| Pivoting across segments | HTB retired | [Reel2](https://0xdf.gitlab.io/2021/03/15/reel2-root-shell.html), [Flight](https://0xdf.gitlab.io/2023/05/06/htb-flight.html) | `ctf-pivoting/pivoting.md` |
| Full multi-forest rehearsal | **Altered Security CRTE lab (paid)** | The CRTE lab is the faithful rehearsal for the forest range. | `ctf-ad/methodology.md` |

**Drill order:** master CRTP material first → GOAD full forest (trusts, SID history, cross-forest Kerberos) → AD CS across trusts (Certified, Manager, EscapeTwo) → delegation + MSSQL links (Rebound, Freelancer) → CRTE lab as dress rehearsal.

---

## CRTO — Certified Red Team Operator (C2 tradecraft + evasion)

C2 operation, malleable profiles, in-memory tradecraft, and beating modern defenses. The **CRTO lab (paid)** is essentially mandatory — no free environment reproduces Cobalt Strike vs. Defender/EDR. Free venues cover only the AD chain the C2 delivers.

| Skill area | Best free practice venue | Specific targets to drill (with writeups) | Pack file |
|---|---|---|---|
| C2 setup, redirectors, malleable profiles | **CRTO lab (paid)** — no free equal | CRTO lab exercises; rehearse profiles in your own lab | `ctf-redteam/c2-infrastructure.md`, `opsec-and-lifecycle.md` |
| Initial access (weaponized docs/LNK) | **CRTO lab (paid)** / own lab | No public box reproduces phishing delivery; build in lab | `ctf-redteam/initial-access.md` |
| Payload dev + AMSI/ETW/Defender bypass | own lab (paid guidance) | Rehearse loaders against Defender in your VM | `ctf-redteam/payloads-and-execution.md`, `edr-evasion.md` |
| AD attack chain the C2 delivers | **GOAD** (free) | GOAD full lab driven through your C2 | `ctf-ad/methodology.md` |
| Kerberos / lateral movement in-C2 | HTB retired (technique ref) | [Blackfield](https://0xdf.gitlab.io/2020/10/03/htb-blackfield.html), [Scrambled](https://0xdf.gitlab.io/2022/10/01/htb-scrambled.html) | `ctf-ad/lateral-movement.md`, `ctf-ad/kerberos.md` |
| Persistence + privilege maintenance | GOAD / own lab | GOAD domain persistence | `ctf-redteam/persistence-and-lateral.md`, `ctf-ad/domain-dominance.md` |
| Report | — | CRTO template | `ctf-writeup`, `references/writeup-standard.md` |

**Drill order:** CRTO lab modules in order (C2 → access → evasion → AD) → replay the AD half on GOAD through your own C2 to prove the chain without hand-holding.

---

## OSCP — OffSec Certified Professional (PEN-200)

Standalone Linux/Windows boxes + a small, high-value AD set. Manual skill tested; Metasploit heavily restricted. **Proving Grounds Practice (TJnull PEN-200 list)** is the closest-to-exam free-ish venue; HTB retired boxes fill the gaps.

| Skill area | Best free practice venue | Specific targets to drill (with writeups) | Pack file |
|---|---|---|---|
| Recon + service enumeration | PG Practice / HTB retired | [Cronos](https://0xdf.gitlab.io/2020/04/14/htb-cronos.html), [Nibbles](https://0xdf.gitlab.io/2018/06/30/htb-nibbles.html) | `ctf-pentest/enumeration-recon` |
| Web-to-foothold (CVE / injection) | HTB retired | [Sau](https://0xdf.gitlab.io/2024/01/06/htb-sau.html) (SSRF+CVE), [Broker](https://0xdf.gitlab.io/2023/11/09/htb-broker.html) (ActiveMQ), [Analytics](https://0xdf.gitlab.io/2024/03/23/htb-analytics.html) (Metabase) | `ctf-web`, `ctf-pentest/common-services` |
| Linux privesc | HTB retired | [Shocker](https://0xdf.gitlab.io/2021/05/25/htb-shocker.html), [Photobomb](https://0xdf.gitlab.io/2023/02/11/htb-photobomb.html) (sudo PATH), [Traverxec](https://0xdf.gitlab.io/2020/04/11/htb-traverxec.html) (GTFOBins), [Tabby](https://0xdf.gitlab.io/2020/11/07/htb-tabby.html) (LXD) | `ctf-privesc/linux-privesc.md` |
| Windows privesc | HTB retired | [Optimum](https://0xdf.gitlab.io/2021/03/17/htb-optimum.html) (MS16-032), [Jeeves](https://0xdf.gitlab.io/2022/04/14/htb-jeeves.html), [Bounty](https://0xdf.gitlab.io/2018/10/27/htb-bounty.html) (web.config) | `ctf-privesc/windows-privesc.md` |
| Classic remote-exploit Windows | HTB retired | [Legacy](https://0xdf.gitlab.io/2019/02/21/htb-legacy.html) (MS08-067/MS17-010), [Devel](https://0xdf.gitlab.io/2019/03/05/htb-devel.html), [Granny](https://0xdf.gitlab.io/2019/03/06/htb-granny.html)/[Bastard](https://0xdf.gitlab.io/2019/03/12/htb-bastard.html) | `ctf-privesc/windows-privesc.md` |
| Simple Linux CVE + config | HTB retired | [Lame](https://0xdf.gitlab.io/2020/04/07/htb-lame.html), [Beep](https://0xdf.gitlab.io/2021/02/23/htb-beep.html), [Irked](https://0xdf.gitlab.io/2019/04/27/htb-irked.html), [SolidState](https://0xdf.gitlab.io/2020/04/30/htb-solidstate.html) | `ctf-pentest/common-services` |
| AD set (foothold → DA) | **GOAD** (free) + HTB retired | GOAD single domain; [Sauna](https://0xdf.gitlab.io/2020/07/18/htb-sauna.html), [Active](https://0xdf.gitlab.io/2018/12/08/htb-active.html), [Forest](https://0xdf.gitlab.io/2020/03/21/htb-forest.html), [Resolute](https://0xdf.gitlab.io/2020/05/30/htb-resolute.html) | `ctf-ad/methodology.md` |
| Report + proof files | — | OffSec report template | `ctf-writeup`, `ctf-pentest/reporting.md` |

**Drill order:** easy Linux (Lame, Shocker, Beep) → easy Windows (Legacy, Devel, Optimum) → privesc depth (Photobomb, Traverxec, Jeeves, Bounty) → PG Practice TJnull list for volume → the AD set (GOAD + Sauna/Active/Forest) last, since it is the decisive point block. Practice manually — no Metasploit crutch.

---

## CPTS — HTB Certified Penetration Testing Specialist

Full external→internal chain: recon, web, service exploitation, Linux/Windows privesc, pivoting, heavy AD. Broadest of the set; drill breadth. Aligns tightly with HTB's own retired machines.

| Skill area | Best free practice venue | Specific targets to drill (with writeups) | Pack file |
|---|---|---|---|
| Recon + web foothold | HTB retired | [CozyHosting](https://0xdf.gitlab.io/2024/03/02/htb-cozyhosting.html) (Spring), [Usage](https://0xdf.gitlab.io/2024/08/10/htb-usage.html) (SQLi), [Editorial](https://0xdf.gitlab.io/2024/10/19/htb-editorial.html) (SSRF) | `ctf-web`, `ctf-pentest/enumeration-recon` |
| Linux privesc | HTB retired | [Keeper](https://0xdf.gitlab.io/2024/02/10/htb-keeper.html), [Precious](https://0xdf.gitlab.io/2023/05/20/htb-precious.html), [Pilgrimage](https://0xdf.gitlab.io/2023/11/25/htb-pilgrimage.html) | `ctf-privesc/linux-privesc.md` |
| Windows privesc | HTB retired | [Jeeves](https://0xdf.gitlab.io/2022/04/14/htb-jeeves.html), [Outdated](https://0xdf.gitlab.io/2022/12/10/htb-outdated.html) | `ctf-privesc/windows-privesc.md` |
| Pivoting across segments | HTB retired | [Flight](https://0xdf.gitlab.io/2023/05/06/htb-flight.html), [Reel2](https://0xdf.gitlab.io/2021/03/15/reel2-root-shell.html) | `ctf-pivoting/pivoting.md` |
| Active Directory chain | **GOAD** (free) + HTB retired | GOAD; [Support](https://0xdf.gitlab.io/2022/12/17/htb-support.html), [Timelapse](https://0xdf.gitlab.io/2022/08/20/htb-timelapse.html), [Cascade](https://0xdf.gitlab.io/2020/07/25/htb-cascade.html), [Monteverde](https://0xdf.gitlab.io/2020/06/13/htb-monteverde.html) | `ctf-ad/methodology.md` |
| AD CS | HTB retired | [Escape](https://0xdf.gitlab.io/2023/06/17/htb-escape.html), [Certified](https://0xdf.gitlab.io/2025/03/15/htb-certified.html) | `ctf-ad/adcs.md` |
| Professional report | — | CPTS report | `ctf-writeup`, `ctf-pentest/reporting.md` |

**Drill order:** web-foothold boxes → privesc breadth (Linux + Windows) → pivoting (Flight, Reel2) → AD on GOAD then chained HTB AD boxes → write a full report on one chained box to rehearse the deliverable.

---

## CWEE — HTB Certified Web Exploitation Expert (whitebox, chained bugs)

Deep, chained web bugs from **source code**. **PortSwigger Web Security Academy (free)** is the per-technique drill; HTB web-heavy boxes give the end-to-end chain-plus-privesc rehearsal.

| Skill area | Best free practice venue | Specific targets to drill (with writeups) | Pack file |
|---|---|---|---|
| Advanced SQLi (2nd-order, blind) | **PortSwigger Academy** (free): *SQL injection* labs | [Intentions](https://0xdf.gitlab.io/2023/10/14/htb-intentions.html) (2nd-order SQLi), [Usage](https://0xdf.gitlab.io/2024/08/10/htb-usage.html) | `ctf-web/sql-injection` |
| SSTI + sandbox escape | **PortSwigger Academy**: *Server-side template injection* | [Nunchucks](https://0xdf.gitlab.io/2021/11/02/htb-nunchucks.html) (nunjucks), [Bolt](https://0xdf.gitlab.io/2022/02/19/htb-bolt.html) | `ctf-web/server-side` (advanced) |
| Deserialization POP chains | **PortSwigger Academy**: *Insecure deserialization* | [Precious](https://0xdf.gitlab.io/2023/05/20/htb-precious.html) (Ruby YAML), [Bagel](https://0xdf.gitlab.io/2023/06/03/htb-bagel.html) (.NET), [NodeBlog](https://0xdf.gitlab.io/2022/01/10/htb-nodeblog.html) (Node) | `ctf-web/deserialization` |
| Prototype pollution → RCE | **PortSwigger Academy**: *Prototype pollution* | [Vessel](https://0xdf.gitlab.io/2023/03/25/htb-vessel.html) (source review) | `ctf-web/server-side` |
| SSRF | **PortSwigger Academy**: *SSRF* | [Editorial](https://0xdf.gitlab.io/2024/10/19/htb-editorial.html), [Sau](https://0xdf.gitlab.io/2024/01/06/htb-sau.html) | `ctf-web/server-side` |
| HTTP request smuggling | **PortSwigger Academy**: *Request smuggling* | [Sink](https://0xdf.gitlab.io/2021/09/18/htb-sink.html) | `ctf-web/server-side` |
| File-upload / LFI → RCE | **PortSwigger Academy**: *File upload / Path traversal* | [Pilgrimage](https://0xdf.gitlab.io/2023/11/25/htb-pilgrimage.html) (ImageMagick), [Bagel](https://0xdf.gitlab.io/2023/06/03/htb-bagel.html) | `ctf-web/server-side` |
| Web-RCE → host privesc | HTB retired | any of the above; then escalate | `ctf-privesc/linux-privesc.md` |
| Whitebox / report | — | HTB CWEE template | `ctf-web` (whitebox), `ctf-writeup` |

**Drill order:** grind one PortSwigger category per bug class to fluency (SQLi → SSTI → deser → prototype pollution → smuggling) → chain them on source-code boxes (Vessel, Precious, Bagel) → finish with a web-foothold-plus-privesc box (Intentions) and write the whitebox chain up.

---

## CWES — HTB Certified Web Exploitation Specialist (broad bug-bounty surface)

Renamed from CBBH (Oct 2025). Associate-tier breadth across the OWASP surface + newer additions (API/GraphQL, SPA, SSPP, forgotten endpoints). **PortSwigger Academy (free)** is again the primary venue — breadth over depth.

| Skill area | Best free practice venue | Specific targets to drill (with writeups) | Pack file |
|---|---|---|---|
| Web recon / content discovery | **PortSwigger Academy** + own targets | practice ffuf/dirsearch on retired web boxes | `ctf-web/web-recon.md` |
| SQLi + SQLMap | **PortSwigger Academy**: *SQL injection* | [Usage](https://0xdf.gitlab.io/2024/08/10/htb-usage.html), [Cronos](https://0xdf.gitlab.io/2020/04/14/htb-cronos.html) | `ctf-web/sql-injection` |
| XSS (reflected/stored/DOM) | **PortSwigger Academy**: *XSS* | [Sea](https://0xdf.gitlab.io/2024/12/21/htb-sea.html) (WonderCMS XSS→RCE) | `ctf-web/client-side` |
| File inclusion / upload | **PortSwigger Academy**: *File upload / Directory traversal* | [Bounty](https://0xdf.gitlab.io/2018/10/27/htb-bounty.html), [Pilgrimage](https://0xdf.gitlab.io/2023/11/25/htb-pilgrimage.html) | `ctf-web/server-side` |
| Command injection | **PortSwigger Academy**: *OS command injection* | [Photobomb](https://0xdf.gitlab.io/2023/02/11/htb-photobomb.html), [CozyHosting](https://0xdf.gitlab.io/2024/03/02/htb-cozyhosting.html) | `ctf-web/server-side` |
| IDOR / access control / business logic | **PortSwigger Academy**: *Access control / Business logic* | [Intentions](https://0xdf.gitlab.io/2023/10/14/htb-intentions.html) | `ctf-web/auth` |
| API / GraphQL (newer syllabus) | **PortSwigger Academy**: *API testing / GraphQL* | [NodeBlog](https://0xdf.gitlab.io/2022/01/10/htb-nodeblog.html) (NoSQLi/API) | `ctf-web/api-security` |
| Common apps + SSPP / forgotten endpoints | **PortSwigger Academy** + HTB retired | [Bolt](https://0xdf.gitlab.io/2022/02/19/htb-bolt.html), [Broker](https://0xdf.gitlab.io/2023/11/09/htb-broker.html) | `ctf-web/common-applications` |
| Report | — | HTB template | `ctf-writeup` |

**Drill order:** web-recon fluency first → one PortSwigger lab per OWASP class (SQLi, XSS, LFI/upload, cmdi, access control) → newer surface (API/GraphQL, SSPP, forgotten endpoints) → consolidate on breadth boxes (Usage, Sea, CozyHosting) and write each up as a bug-bounty-style finding.

---

## Master target index (all cited boxes)

Every named box above, with the primary technique it drills and which exams it serves. Attempt cold, then read the writeup. `--source htbmachines` / `--source ippsec` have video walkthroughs for most of these.

### Active Directory boxes (CRTeamer / CRTP / CRTE / CPTS / OSCP-AD)

| Box | Primary technique | Serves | Writeup |
|---|---|---|---|
| Active | GPP cpassword → Kerberoast | CRTP, OSCP | https://0xdf.gitlab.io/2018/12/08/htb-active.html |
| Sauna | AS-REP roast → autologon creds → DCSync | CRTP, OSCP | https://0xdf.gitlab.io/2020/07/18/htb-sauna.html |
| Forest | AS-REP roast → Exchange ACL → DCSync | CRTP, OSCP | https://0xdf.gitlab.io/2020/03/21/htb-forest.html |
| Resolute | Password spray → DnsAdmins DLL | CRTP, OSCP | https://0xdf.gitlab.io/2020/05/30/htb-resolute.html |
| Cascade | LDAP recon → AD recycle-bin recovery | CRTP, CPTS | https://0xdf.gitlab.io/2020/07/25/htb-cascade.html |
| Monteverde | Azure AD Connect password recovery | CPTS | https://0xdf.gitlab.io/2020/06/13/htb-monteverde.html |
| Blackfield | AS-REP → forced pw-reset ACL → LSASS/SeBackup | CRTeamer, CRTP, CRTO | https://0xdf.gitlab.io/2020/10/03/htb-blackfield.html |
| Support | LDAP creds → RBCD | CRTeamer, CRTP, CPTS | https://0xdf.gitlab.io/2022/12/17/htb-support.html |
| Object | Jenkins → WriteOwner ACL chain | CRTP | https://0xdf.gitlab.io/2022/02/28/htb-object.html |
| Return | Printer LDAP capture → Server Operators | CRTP | https://0xdf.gitlab.io/2022/05/05/htb-return.html |
| Intelligence | ADIDNS + gMSA → constrained delegation | CRTP | https://0xdf.gitlab.io/2021/11/27/htb-intelligence.html |
| Timelapse | PFX crack → LAPS read | CPTS | https://0xdf.gitlab.io/2022/08/20/htb-timelapse.html |
| Search | gMSA → certificate auth | CPTS | https://0xdf.gitlab.io/2022/04/30/htb-search.html |
| StreamIO | SQLi → LAPS → AD CS | CRTE, CPTS | https://0xdf.gitlab.io/2022/09/17/htb-streamio.html |
| Scrambled | Kerberos-only → silver ticket → MSSQL | CRTeamer, CRTO | https://0xdf.gitlab.io/2022/10/01/htb-scrambled.html |
| Absolute | Kerberos-only → RBCD/KrbRelay (CLM-aware) | CRTeamer, CRTE | https://0xdf.gitlab.io/2023/05/27/htb-absolute.html |
| Rebound | RBCD + constrained delegation (hard) | CRTeamer, CRTE | https://0xdf.gitlab.io/2024/03/30/htb-rebound.html |
| Vintage | gMSA + RBCD + pre-created computer + timeroast | CRTeamer, CRTE | https://0xdf.gitlab.io/2025/04/26/htb-vintage.html |
| Multimaster | SQLi → AS-REP → ACL escalation | CRTE | https://0xdf.gitlab.io/2020/09/19/htb-multimaster.html |
| Flight | Multi-user, ASREP/Kerberoast, cross-host | CRTE, CPTS | https://0xdf.gitlab.io/2023/05/06/htb-flight.html |
| Reel2 | ACL abuse chain | CRTE, CPTS | https://0xdf.gitlab.io/2021/03/15/reel2-root-shell.html |
| Outdated | WSUS + PrintNightmare + shadow creds | CRTeamer | https://0xdf.gitlab.io/2022/12/10/htb-outdated.html |
| Cicada | Guest enum → password in description → SeBackup | CRTeamer | https://0xdf.gitlab.io/2025/02/15/htb-cicada.html |
| Administrator | ACL chain → DCSync | CRTeamer, CRTP | https://0xdf.gitlab.io/2025/04/19/htb-administrator.html |
| Freelancer | MSSQL links in AD | CRTE | https://0xdf.gitlab.io/2024/10/05/htb-freelancer.html |
| Sizzle | AD CS ESC1 (classic) + unconstrained | CRTP, CRTE | https://0xdf.gitlab.io/2019/06/01/htb-sizzle.html |
| Mantis | MS14-068 (legacy Kerberos) | CRTP | https://0xdf.gitlab.io/2020/09/03/htb-mantis.html |

### AD CS boxes (ESC1–ESC9)

| Box | ESC technique | Serves | Writeup |
|---|---|---|---|
| Escape | ESC1 | CRTP, CPTS | https://0xdf.gitlab.io/2023/06/17/htb-escape.html |
| Authority | ESC1 + PWM + Ansible | CRTP | https://0xdf.gitlab.io/2023/12/09/htb-authority.html |
| Manager | ESC7 + MSSQL | CRTE | https://0xdf.gitlab.io/2024/03/16/htb-manager.html |
| Certified | ESC9 / shadow creds + ACL chain | CRTE, CPTS | https://0xdf.gitlab.io/2025/03/15/htb-certified.html |
| EscapeTwo | AD CS ESC + MSSQL | CRTE | https://0xdf.gitlab.io/2025/05/24/htb-escapetwo.html |

### Windows standalone (OSCP privesc)

| Box | Primary technique | Writeup |
|---|---|---|
| Legacy | MS08-067 / MS17-010 | https://0xdf.gitlab.io/2019/02/21/htb-legacy.html |
| Devel | ASPX upload → kernel exploit | https://0xdf.gitlab.io/2019/03/05/htb-devel.html |
| Granny | IIS WebDAV → Churrasco | https://0xdf.gitlab.io/2019/03/06/htb-granny.html |
| Bastard | Drupalgeddon → kernel exploit | https://0xdf.gitlab.io/2019/03/12/htb-bastard.html |
| Optimum | HFS CVE → MS16-032 | https://0xdf.gitlab.io/2021/03/17/htb-optimum.html |
| Arctic | ColdFusion → kernel exploit | https://0xdf.gitlab.io/2020/05/19/htb-arctic.html |
| Bounty | web.config upload → MS16-032 | https://0xdf.gitlab.io/2018/10/27/htb-bounty.html |
| Jeeves | Jenkins → KeePass → alt data stream | https://0xdf.gitlab.io/2022/04/14/htb-jeeves.html |

### Linux standalone (OSCP / CPTS privesc)

| Box | Primary technique | Writeup |
|---|---|---|
| Lame | Samba / distcc CVE | https://0xdf.gitlab.io/2020/04/07/htb-lame.html |
| Beep | Elastix LFI → cred reuse | https://0xdf.gitlab.io/2021/02/23/htb-beep.html |
| Shocker | Shellshock → sudo perl | https://0xdf.gitlab.io/2021/05/25/htb-shocker.html |
| Irked | UnrealIRCd → steg → SUID | https://0xdf.gitlab.io/2019/04/27/htb-irked.html |
| SolidState | Apache James → cron | https://0xdf.gitlab.io/2020/04/30/htb-solidstate.html |
| Nibbles | Nibbleblog upload → sudo script | https://0xdf.gitlab.io/2018/06/30/htb-nibbles.html |
| Bashed | phpbash → cron | https://0xdf.gitlab.io/2018/04/29/htb-bashed.html |
| Cronos | SQLi → cron job | https://0xdf.gitlab.io/2020/04/14/htb-cronos.html |
| Traverxec | nostromo CVE → journalctl GTFOBins | https://0xdf.gitlab.io/2020/04/11/htb-traverxec.html |
| Tabby | Tomcat manager → LXD group | https://0xdf.gitlab.io/2020/11/07/htb-tabby.html |
| Knife | PHP 8 backdoor → sudo knife | https://0xdf.gitlab.io/2021/08/28/htb-knife.html |
| Photobomb | Command injection → sudo PATH | https://0xdf.gitlab.io/2023/02/11/htb-photobomb.html |
| Sau | SSRF (Request Baskets) + Maltrail → sudo systemctl | https://0xdf.gitlab.io/2024/01/06/htb-sau.html |
| Broker | ActiveMQ CVE → sudo nginx | https://0xdf.gitlab.io/2023/11/09/htb-broker.html |
| Keeper | KeePass dump CVE | https://0xdf.gitlab.io/2024/02/10/htb-keeper.html |
| Analytics | Metabase CVE → GameOver(lay) | https://0xdf.gitlab.io/2024/03/23/htb-analytics.html |

### Web boxes (CWEE / CWES / CPTS foothold)

| Box | Primary web bug | Serves | Writeup |
|---|---|---|---|
| Nunchucks | SSTI (nunjucks) | CWEE | https://0xdf.gitlab.io/2021/11/02/htb-nunchucks.html |
| Bolt | SSTI + Docker | CWEE, CWES | https://0xdf.gitlab.io/2022/02/19/htb-bolt.html |
| Precious | Ruby YAML deserialization (pdfkit RCE) | CWEE, CPTS | https://0xdf.gitlab.io/2023/05/20/htb-precious.html |
| Bagel | Path traversal → .NET deserialization | CWEE | https://0xdf.gitlab.io/2023/06/03/htb-bagel.html |
| NodeBlog | NoSQLi → Node deserialization / API | CWEE, CWES | https://0xdf.gitlab.io/2022/01/10/htb-nodeblog.html |
| Vessel | Prototype pollution (source review) | CWEE | https://0xdf.gitlab.io/2023/03/25/htb-vessel.html |
| Sink | HTTP request smuggling | CWEE | https://0xdf.gitlab.io/2021/09/18/htb-sink.html |
| Editorial | SSRF | CWEE, CPTS | https://0xdf.gitlab.io/2024/10/19/htb-editorial.html |
| Intentions | 2nd-order SQLi + business logic | CWEE, CWES | https://0xdf.gitlab.io/2023/10/14/htb-intentions.html |
| Usage | SQLi → laravel-admin | CWES, CPTS | https://0xdf.gitlab.io/2024/08/10/htb-usage.html |
| Sea | Stored XSS → WonderCMS RCE | CWES | https://0xdf.gitlab.io/2024/12/21/htb-sea.html |
| CozyHosting | Spring Boot Actuator → cmd injection | CWES, CPTS | https://0xdf.gitlab.io/2024/03/02/htb-cozyhosting.html |
| Pilgrimage | ImageMagick + binwalk CVE | CWEE, CWES | https://0xdf.gitlab.io/2023/11/25/htb-pilgrimage.html |

## How to use the index for more targets

To find additional named practice targets by box name or technique:

```
python scripts\search_writeup_index.py <box or technique>
python scripts\search_writeup_index.py --source 0xdf <box name>      # 0xdf writeups
python scripts\search_writeup_index.py --source htbmachines <box>    # S4vitar video walkthroughs
python scripts\search_writeup_index.py --source ippsec <box name>    # IppSec videos
python scripts\search_writeup_index.py --regex "adcs|esc[0-9]"       # technique sweep
```

Attempt each box **cold** first; read the linked writeup only after you are stuck or done, then reconcile your notes against the pack file in the last column.
