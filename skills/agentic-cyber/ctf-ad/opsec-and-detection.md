# AD - OPSEC & Detection

## Table of Contents
- [Key Windows Event IDs](#key-windows-event-ids)
- [Logon Types Table (4624/4625)](#logon-types-table-46244625)
- [Sysmon Events That Matter](#sysmon-events-that-matter)
- [What Each Attack Looks Like in Telemetry](#what-each-attack-looks-like-in-telemetry)
- [Honeypot / Canary Accounts](#honeypot--canary-accounts)
- [Noisy vs Quiet Enumeration](#noisy-vs-quiet-enumeration)
- [Pacing Recon & DCSync to Avoid MDI](#pacing-recon--dcsync-to-avoid-mdi)
- [BloodHound Collection Footprint](#bloodhound-collection-footprint)
- [Artifacts by Execution Method](#artifacts-by-execution-method)
- [Log Sources That Matter](#log-sources-that-matter)
- [Hunting Queries](#hunting-queries)
- [Defensive Hardening Checklist](#defensive-hardening-checklist)
- [What to Record for the Report](#what-to-record-for-the-report)

For the attacks referenced here see [ntlm-relay.md](ntlm-relay.md), [acl-abuse.md](acl-abuse.md), [entra-hybrid.md](entra-hybrid.md), and [adcs.md](adcs.md). This file serves both the operator scoping detection risk and the defender validating coverage.

---

## Key Windows Event IDs
Logged on the **DC security log** unless noted. These are the events that reveal AD attacks.

| Event ID | Meaning | Attack relevance |
|---|---|---|
| 4768 | Kerberos TGT requested (AS-REQ) | AS-REP roasting (preauth-not-required), password spray, ticket requests. Encryption type field flags RC4 (0x17) downgrade. |
| 4769 | Kerberos service ticket requested (TGS-REQ) | Kerberoasting — mass 4769 for many SPNs with RC4 (0x17) from one host is the classic signature. |
| 4770 | Kerberos service ticket renewed | Ticket reuse / long-lived tickets. |
| 4771 | Kerberos pre-auth failed | Failed spray / bad password; code 0x18 = wrong password, 0x12 = disabled/locked. |
| 4624 | Successful logon | Lateral movement; check Logon Type + source IP (see table). |
| 4625 | Failed logon | Password spray / brute force; many 4625 across accounts from one source. |
| 4648 | Logon with explicit credentials | `runas`, over-pass-the-hash, tooling passing creds; source process is telling. |
| 4672 | Special privileges assigned at logon | Admin/Tier-0 logon; SeDebug/SeTcb etc. |
| 4662 | Operation on an AD object | **DCSync** — access to `DS-Replication-Get-Changes` GUID `1131f6aa-...`/`1131f6ad-...` by a non-DC principal. |
| 4661 | Handle to an object requested | SAM/DS object access; supports 4662 correlation. |
| 5136 | Directory service object modified | ACL edits (WriteDACL), RBCD writes (`msDS-AllowedToAct...`), shadow creds (`msDS-KeyCredentialLink`), SPN adds. Requires DS-access auditing. |
| 5137/5139/5141 | DS object created/moved/deleted | Rogue computer add (MachineAccountQuota abuse), OU changes. |
| 4670 | Permissions on an object changed | DACL/owner changes — AdminSDHolder tampering, WriteOwner abuse. |
| 4720/4722/4724/4728/4732/4756 | User created / enabled / pw reset / added to global/local/universal group | Persistence, privilege group changes (Domain Admins membership = 4728/4756). |
| 4738 | User account changed | UAC flag flips (e.g., DONT_REQ_PREAUTH for AS-REP, TRUSTED_FOR_DELEGATION). |
| 7045 | Service installed (System log) | **PsExec / SMB exec** drops a service — classic remote exec artifact. |
| 4697 | Service installed (Security log) | Same as 7045 with DS auditing; includes account context. |
| 4698/4702 | Scheduled task created/updated | atexec, schtasks lateral exec, GPO immediate-task abuse. |
| 4688 | Process creation (w/ cmdline if enabled) | Tooling execution, LOLBins, encoded PowerShell. |
| 1102 | Security log cleared | Anti-forensics; itself a high-signal alert. |
| 4776 | NTLM credential validation | NTLM auth on DC — relay/pass-the-hash correlation. |

ADCS-specific: **4886/4887** (cert request received / issued) and **4899/4900** on the CA reveal ESC abuse; correlate an issued cert with an unexpected SAN.

## Logon Types Table (4624/4625)
| Type | Name | Meaning / attack note |
|---|---|---|
| 2 | Interactive | Console/RDP-console logon. Credentials in LSASS. |
| 3 | Network | SMB/share, PtH, most lateral auth. Highest-volume; relay/PtH show here. |
| 4 | Batch | Scheduled task context. |
| 5 | Service | Service account start. |
| 7 | Unlock | Workstation unlock. |
| 8 | NetworkCleartext | Basic-auth / IIS / cleartext over network — creds exposed. |
| 9 | NewCredentials | `runas /netonly`, over-pass-the-hash (Rubeus /netonly, mimikatz sekurlsa). |
| 10 | RemoteInteractive | RDP. Creds cached on target. |
| 11 | CachedInteractive | Cached-credential logon (offline DC). |

Type 3 + NTLM + admin from an unusual workstation = likely PtH/relay. Type 9 from a non-admin tool = over-PtH.

## Sysmon Events That Matter
| Sysmon ID | Event | Attack relevance |
|---|---|---|
| 1 | Process creation (full cmdline, hashes, parent) | Tool exec, encoded PS, LOLBins; parent-child anomalies (e.g., `services.exe`->cmd = PsExec). |
| 3 | Network connection | C2 beacons, relay listener connections, lateral SMB/WinRM. |
| 7 | Image/DLL loaded | Unsigned DLL / injected module. |
| 8 | CreateRemoteThread | Process injection (mimikatz into lsass, Cobalt Strike). |
| 10 | Process access | **LSASS access** — credential dumping (`GrantedAccess 0x1010/0x1410` to lsass.exe). |
| 11 | File created | Payload drops, `.ccache`/ticket files, ntds dumps, SharpHound zip. |
| 12/13/14 | Registry create/set/delete | Persistence keys, WDigest UseLogonCredential, LSA protection tamper. |
| 15 | FileCreateStreamHash | ADS / download mark-of-the-web. |
| 17/18 | Named pipe created/connected | PsExec/Cobalt pipe names, SMB exec pipes. |
| 22 | DNS query | mitm6/WPAD, C2 domains, tooling resolution. |
| 25 | Process tampering | Process hollowing / herpaderping. |

## What Each Attack Looks Like in Telemetry
- **Kerberoasting**: burst of **4769** for multiple service SPNs, `Ticket Encryption Type 0x17` (RC4) from a single account/host within seconds. Targeted kerberoast also fires **5136** (SPN added then removed) and **4738**.
- **AS-REP Roasting**: **4768** AS-REQ for accounts with `DONT_REQ_PREAUTH` set; often preceded by an LDAP query for `userAccountControl:1.2.840.113556.1.4.803:=4194304`. Setting the flag = **4738**.
- **Password spray**: many **4625/4771** across distinct accounts, low attempts each, one/few source IPs; then a lone **4624**. On Entra: sign-in logs with error 50126 across users.
- **DCSync**: **4662** with replication extended-right GUIDs (`1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` GetChanges, `1131f6ad-...` GetChangesAll) requested by a **non-DC** account, plus **4624 Type 3** from a non-DC host to the DC. No 4776 needed.
- **Golden Ticket**: TGS use (**4769**) with no preceding **4768** (TGT never legitimately issued); anomalies like a TGT lifetime of 10 years, or account name not in AD; RC4 where AES expected.
- **Silver Ticket**: service access with **no 4768/4769 on the DC at all** (ticket forged offline, DC never contacted) — detect on the *member server* by 4624 without corresponding DC Kerberos logs.
- **NTLM Relay / coercion**: **4624 Type 3 NTLM** on the target from the relay host IP but the *account* is a user/machine that doesn't normally log on there; **4662/5136** if relayed to LDAP (RBCD/shadow write); PrinterBug/PetitPotam leave **5145** (file share detailed access to `\pipe\spoolss`/`efsrpc`) on the coerced host and a **4624** from the coerced host to the attacker.
- **Overpass/Pass-the-Hash**: **4624 Type 3/9**, NTLM package, from unexpected host; **4776** on DC.
- **ADCS ESC1/ESC8**: **4886/4887** cert issued with a **SAN mismatching the requester** (UPN of a different/privileged user); ESC8 also shows the relay **4624** on the CA.

## Honeypot / Canary Accounts
Defenders plant fake privileged/SPN accounts to trip roasters. Spot them before touching:
- **Never logged on** or a `lastLogonTimestamp` of years ago, yet `adminCount=1` or a juicy SPN → suspicious.
- SPN on an account with **no real service host**, generic name (`svc_sql`, `backup_admin`) but `pwdLastSet` ancient and `logonCount = 0`.
- Description/notes hinting monitoring; membership in a group with an odd name.
- Check before roasting:
```powershell
Get-DomainUser -SPN -Properties samaccountname,lastlogon,pwdlastset,logoncount,admincount,whencreated |
    Sort logoncount   # logoncount 0 + old pwdlastset + SPN = probable canary
# Also compare lastLogon across DCs; a real account logs on somewhere.
```
Roasting a canary generates the exact **4769 RC4** the SOC is watching for — filter these out first.

## Noisy vs Quiet Enumeration
- **Quiet**: authenticated LDAP queries that mirror normal client traffic — targeted `Get-DomainUser`/`ldapsearch` for specific attributes; paged, scoped filters; querying a single non-DC replica; using existing tooling on-host. No 4662/5136 for reads unless SACL auditing of the specific object is on.
- **Loud**: full `SharpHound -c All` (thousands of LDAP + SAMR + session/loggedon calls), `GetUserSPNs -request` for *all* SPNs at once, mass ldap `(objectClass=*)` dumps, LLMNR/mDNS poisoning (Responder), mitm6 (rogue DHCPv6/DNS = network IDS bait).
- Prefer: query specific attributes over `-Properties *`; avoid `SAMR`/`NetSessionEnum` sweeps if session data isn't needed (`-c DCOnly` collects from the DC only); throttle; run from a host that already talks to the DC.
```powershell
# Quieter BloodHound: LDAP-only, no session/localadmin enumeration across every host
SharpHound.exe -c DCOnly                      # single collection against the DC, no host touch
bloodhound-python -c DCOnly -u u -p p -d d -ns <DC>
# vs the loud default:
SharpHound.exe -c All                         # Sessions + LocalAdmin + LoggedOn hit every host
```

## Pacing Recon & DCSync to Avoid MDI
Microsoft Defender for Identity (MDI) is behavioral, not signature-based: sensors on DCs (and AD FS/AD CS) profile normal activity over a **learning period** and alert on deviations, so *volume, novelty, and source* matter more than any single packet. Know what it watches, then pace around it.

**What MDI flags (alert name — external ID):**
- **Security principal reconnaissance (LDAP)** — 2038. Fires on suspicious/novel LDAP enumeration queries or queries targeting sensitive groups from a computer, after a ~10-day/15-day-per-machine learning window. This catches SharpHound-style LDAP sweeps and the LDAP phase of Kerberoasting.
- **Account enumeration reconnaissance (LDAP)** — 2437. cLDAP/LDAP-ping username guessing (e.g. ldapnomnom).
- **User and Group membership reconnaissance (SAMR)** — 2021. SAM-R enumeration of users/groups (`net`/BloodHound `NetLocalGroupGetMembers` via MS-SAMR); ~4-week per-DC learning period.
- **Network-mapping reconnaissance (DNS)** — 2007. AXFR zone transfers / excessive DNS from non-DNS-servers.
- **Suspected DCSync attack (replication of directory services)** — 2006. A `DrsGetNCChanges` **replication request from a machine that is not a domain controller** — the single most reliable "you ran secretsdump/mimikatz DCSync" tell. No learning period; fires immediately.
- **Golden-ticket family**: **Suspected Golden Ticket usage (nonexistent account)** — 2027; **(ticket anomaly)** — 2032; **(forged authorization data)** — 2013 (this is the **ExtraSids / forged PAC** case — extra SID history injected into the ticket); **(encryption downgrade)** — 2009; **(time anomaly)** — 2022; **(ticket anomaly using RBCD)** — 2040. Forged/anomalous TGT characteristics: nonexistent principal, over-long lifetime, RC4 where AES is expected, injected SIDs.
- **Honeytoken alerts** (no learning period, fire on *any* touch): **Honeytoken authentication activity** — 2014; **Honeytoken was queried via LDAP** — 2429 (and the SAM-R variant); **Honeytoken user attributes modified** — 2427; **Honeytoken group membership changed** — 2428. Any interaction with a decoy account is high-signal.

**Operator pacing & alternatives:**
- **Throttle and scope enumeration.** MDI recon alerts trigger on *unusual volume/novelty*, so avoid full `(objectClass=*)` dumps and `SharpHound -c All`. Prefer targeted `Get-DomainUser <name>`/scoped filters, collect over time with jitter (`--throttle`/`--jitter`), and use `-c DCOnly` to skip SAM-R/session fan-out entirely.
- **Prefer targeted queries over sweeps.** Ask for the *specific* objects/attributes you need rather than sweeping every principal — a handful of scoped LDAP reads blends into normal client traffic; a mass privileged-group enumeration does not.
- **Avoid honeytoken accounts.** Identify decoys before touching anything (stale/never-logged-on accounts with a juicy SPN or `adminCount=1`, generic bait names like `SQL-Admin`/`backup_admin`, `logonCount=0`) — see Honeypot / Canary Accounts above. A single auth/LDAP/SAMR touch of a honeytoken is an instant alert with no learning period to hide behind.
- **DCSync from a DC context, not a random workstation.** Alert 2006 keys on the replication source being a **non-DC**. Running the replication *from* a domain controller (or a host MDI already trusts as a DC), or dumping NTDS via a method that doesn't ride DRSR from a workstation (e.g. `ntdsutil`/VSS snapshot of `NTDS.dit` on the DC, or a scheduled task executing on the DC itself), avoids the classic non-DC replication signature. If you must DCSync remotely, expect 2006 and pace it as a one-shot rather than repeated pulls.
- **Golden tickets**: use **AES** keys (not RC4), realistic lifetimes (≤ the domain max, default 10h), an **existing** privileged account name, and avoid gratuitous ExtraSids — the anomalies in 2013/2022/2027/2032/2009 are exactly these tells. A diamond ticket (modifying a real TGT) is quieter than a from-scratch golden ticket.
- Remember the learning period cuts both ways: novel activity early in an MDI deployment may *not* alert, but sensitive-group and honeytoken/DCSync detections have **no learning period** and fire on the first occurrence regardless.

## BloodHound Collection Footprint
- `-c All` performs LDAP enumeration on the DC **and** connects to every workstation/server for `NetSessionEnum`, `NetLocalGroupGetMembers`, `NetWkstaUserEnum`, and RPC — generating **4624 Type 3** across the fleet from the collector, plus SMB/RPC connections (Sysmon 3) to hundreds of hosts in a short window. This fan-out is the loudest single tell.
- LDAP volume: a full collect issues many broad LDAP searches; MDI (Defender for Identity) flags "reconnaissance using directory services queries" and honeytoken SAMR enumeration.
- Quieter alternatives: `-c DCOnly` (no host contact), `--stealth` (touch each host once), collect over time with jitter (`--throttle`, `--jitter`), and scope to needed collection methods (`Group,ACL,Trusts`) rather than `All`.
- `NetSessionEnum` hardening on targets (KB restricting anonymous SAM/SAM-R) will null-out session data and can itself surface failed enum attempts.

## Artifacts by Execution Method
| Method | Artifacts |
|---|---|
| **PsExec (impacket/SysInternals)** | **7045/4697** service install (random or `PSEXESVC` name), service binary drop in `C:\Windows`, named pipe (Sysmon 17/18), 4624 Type 3, 5145 to `ADMIN$`/`IPC$`. |
| **wmiexec.py** | No service; **4688** `wmiprvse.exe` spawning `cmd.exe /Q /c ... > \\127.0.0.1\ADMIN$\__<ts>` (output redirection), 4624 Type 3, DCOM (Sysmon 3), WMI-Activity ETW (Operational log 5857/5860/5861). |
| **smbexec.py** | Creates a temp service per command (**7045** repeatedly), `%COMSPEC%` cmd, output via share; noisier than wmiexec. |
| **atexec.py** | **4698/4702** scheduled task create/update, task runs then deletes; 4624 Type 3. |
| **dcomexec.py** | DCOM object instantiation (MMC20/ShellWindows), 4688 under `mmc.exe`/`explorer.exe`. |
| **WinRM (evil-winrm)** | 4624 Type 3, WSMan Operational log, `wsmprovhost.exe` parent (4688/Sysmon 1). |
| **scheduled task GPO abuse** | 4698 on affected hosts, SYSVOL GPO file writes (5145 to `SYSVOL`), 5136 gPCMachineExtensionNames change. |
| **credential dump (lsass)** | Sysmon 10 access to lsass with high GrantedAccess; 4656/4663 handle to lsass if SACL set; minidump file (Sysmon 11). |

## Log Sources That Matter
- **DC Security log**: the primary source for Kerberos (4768/4769/4771), DCSync (4662), directory changes (5136/4670), group changes (4728/4756). Ensure "Audit Directory Service Changes" SACL is configured or 5136 won't fire.
- **Sysmon**: process/cmdline (1), lsass access (10), network (3), pipes (17/18) — fills the gaps native auditing misses; requires a good config (e.g. SwiftOnSecurity / Olaf Hartong).
- **ETW providers**: `Microsoft-Windows-Kerberos`, PowerShell Script Block Logging (4104 in `Microsoft-Windows-PowerShell/Operational`), WMI-Activity, WSMan.
- **Microsoft Defender for Identity (MDI)**: sensor on DCs — detects DCSync, kerberoasting, golden/silver tickets, recon, lateral movement, honeytoken hits behaviorally rather than by single event.
- **Entra ID sign-in & audit logs**: cloud auth, consent grants, app credential adds, device joins, PRT anomalies; MDI/Defender for Cloud Apps for cross-signal.
- **Network IDS**: LLMNR/NBT-NS poisoning, DHCPv6 (mitm6), SMB to odd hosts, Kerberos RC4 downgrade.

## Hunting Queries
Concrete, copy-pasteable detections. Adjust IDs/paths to your collection.

```powershell
# Kerberoasting: 4769 with RC4 (0x17), excluding krbtgt & machine accounts, from the local DC log
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4769} |
  Where-Object { $_.Properties[5].Value -eq '0x17' -and $_.Properties[8].Value -ne '::1' } |
  Select-Object TimeCreated, @{n='User';e={$_.Properties[0].Value}},
                             @{n='Service';e={$_.Properties[2].Value}}

# DCSync: 4662 referencing the replication extended-right GUIDs by a non-DC principal
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4662} |
  Where-Object { $_.Message -match '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' -or
                 $_.Message -match '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' }

# AS-REP roastable accounts (defender-side enumeration to build a canary/watchlist)
Get-ADUser -Filter 'useraccountcontrol -band 4194304' -Properties useraccountcontrol

# PsExec-style service installs
Get-WinEvent -FilterHashtable @{LogName='System';Id=7045} |
  Where-Object { $_.Message -match 'PSEXESVC|\\Windows\\[a-zA-Z0-9]{8}\.exe' }

# Log clear (anti-forensics) — always alert
Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102}
```

```kusto
// Microsoft Sentinel / MDE — LSASS credential dumping via Sysmon-style process access
DeviceEvents
| where ActionType == "OpenProcessApiCall" and FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsMpEng.exe","wininit.exe","csrss.exe")

// Entra: consent grant / app credential added (audit logs)
AuditLogs
| where OperationName in ("Consent to application","Add service principal credentials",
                          "Update application - Certificates and secrets management")

// Entra: password spray pattern (many users, error 50126, few source IPs)
SigninLogs
| where ResultType == 50126
| summarize FailedUsers=dcount(UserPrincipalName) by IPAddress, bin(TimeGenerated, 10m)
| where FailedUsers > 10
```

## Defensive Hardening Checklist
- **SMB signing required** on all hosts; **LDAP signing + channel binding (EPA)** enforced on DCs → kills most NTLM relay. Disable NTLM where possible; audit with `Restrict NTLM` policies.
- **EPA on ADCS Web Enrollment and AD FS**; disable NTLM on `/certsrv`; review ESC1-ESC8/ESC15 template settings (no `ENROLLEE_SUPPLIES_SUBJECT`, no dangerous EKUs, manager approval on sensitive templates).
- **LAPS** (Windows LAPS) for unique, rotated local admin passwords; scope read rights tightly.
- **Tiered admin model** (Tier 0/1/2), separate admin workstations (PAWs), no Domain Admin logon to workstations → limits credential harvesting.
- **Protected Users group** + **Authentication Policies/Silos** for Tier-0 accounts (no NTLM, no delegation, short TGT, no cached creds).
- **AES-only Kerberos** (`msDS-SupportedEncryptionTypes`), disable RC4 → guts kerberoast/roast crackability and RC4-downgrade tricks; watch for 0x17 in 4768/4769.
- **gMSA** for service accounts (128-char rotated passwords, uncrackable) instead of user SPN accounts.
- **MachineAccountQuota = 0** → blocks unprivileged computer creation used for RBCD/shadow-cred pivots.
- **ADCS template review** + enable CA auditing (4886/4887), enforce EPA, restrict enrollment.
- **Disable LLMNR/NBT-NS/mDNS**, disable/monitor IPv6 or block rogue DHCPv6 (RA Guard) → defeats Responder/mitm6.
- **Remove unconstrained delegation**; audit RBCD writes (5136 on `msDS-AllowedToAct...`).
- **Enable Sysmon + Script Block Logging + Command-line auditing (4688)**; forward to SIEM; alert on 1102, 4662 replication rights, 7045 unusual services.
- **Rotate krbtgt twice**, rotate AD FS token-signing cert twice, rotate AZUREADSSOACC$ periodically.
- **Canary/honeytoken accounts** with SPNs and MDI honeytokens to trip roasters.
- **Conditional Access**: block legacy auth, require compliant devices, phishing-resistant MFA; monitor PRT/device anomalies.

## What to Record for the Report
Frame all evasion decisions as engagement scoping and detection-testing, and capture evidence a defender can act on:
- **Timeline**: timestamp (with TZ), source host/IP, target, technique, tool + exact command, and the resulting artifact/event IDs it *should* have produced.
- **Detection outcome**: was it alerted/blocked? Which control caught it (MDI, SIEM rule, EDR)? This turns the test into a purple-team deliverable.
- **Proof of access**: screenshots/hashes with sensitive material redacted per rules of engagement; note where creds/tickets were written (`.ccache`, PFX) so they can be cleaned up.
- **Cleanup log**: every persistence artifact created (added users, RBCD/shadow-cred writes, SPNs, services, scheduled tasks, added group memberships, computer objects) and confirmation it was reverted.
- **Blast radius / scope adherence**: confirm coercion/poisoning (Responder allowlist, mitm6 domain filter) stayed within authorized targets; record any out-of-scope auth that arrived and how it was handled.
- **Recommendations**: map each successful technique to the specific hardening item above so remediation is concrete.
