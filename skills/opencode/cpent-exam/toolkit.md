# CPENT Toolkit — this laptop's verified tool bindings

Every tool below was verified present on THIS laptop (paths checked). Bindings are
task-first: find the exam job, get the exact binary + invocation. For a fresh
laptop, the provisioning section at the end reproduces this setup.

Quirks first — these bite mid-exam:

| Quirk | Reality |
|---|---|
| Cracker status rotates | **preflight.sh live-tests both every session.** 2026-08-31: hashcat WORKS; **jumbo john installed** as wrapper `~/.local/bin/john` → `~/tools/john-jumbo/run/john` (NT/krb5*/netntlmv2/HMAC-SHA256 all present) |
| radare2 user build | 6.2.1 at `~/.local/bin`, libs rpath-patched via patchelf — works without env vars |
| rockyou | Full single file at `~/rockyou.txt` (14,344,391 lines, extracted from `/snap/seclists/current/Passwords/Leaked-Databases/rockyou.txt.tar.gz`). The `rockyou-XX.txt` split parts are frequency buckets only — ignore them |
| `certipy` | pipx symlink broken — call as `python3 ~/.local/share/pipx/venvs/certipy-ad/bin/certipy` or `pipx ensurepath && pipx reinstall certipy-ad` |
| `nxc ldap` | module errors (Python 3.14 logging bug) — use `ldapsearch` |
| msf pattern tools | NOT on PATH — full paths under `/opt/metasploit-framework/` (below) |
| `~/CPENT` | prior range's wordlist dir no longer exists — on the next exam, hunt for the range wordlist on the given-credentials host FIRST |

## 1. Recon & network

| Task | Command |
|---|---|
| Host discovery /24 | `nxc smb <cidr>` or `masscan -p 22,80,443,445,88,389,1337,3389,5000 --rate 2000 <cidr>` |
| Deep port scan | `nmap -sC -sV -Pn -T4 --top-ports 100 <ip>` / full: `-p- --min-rate 2000` |
| Service-specific | `onesixtyone` (SNMP), `snmpcheck <ip>`, `testssl <host:port>`, `whatweb <url>`, `wafw00f <url>` |
| Web recon | `ffuf -u http://IP/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt` (also: gobuster, feroxbuster, dirsearch, kiterunner, arjun for params) |
| Vuln scanning | `nuclei -u <url> -t ~/nuclei-templates` (templates auto-update), `nikto -h <url>` |
| OSINT/web archive | `waymore -d domain.com`, `uro` |

## 2. Active Directory (zone 1)

All impacket 0.13.1 tools are in `~/.local/bin` — both `impacket-foo` and `foo.py` forms.

| Task | Command |
|---|---|
| SMB sweep/null session | `nxc smb <cidr>` / `nxc smb <dc> -u '' -p '' --users` |
| Validate creds | `nxc smb <ip> -u <u> -p <p>` (+ `nxc winrm` for shells) |
| LDAP queries | `ldapsearch -x -H ldap://<dc> -D 'u@d' -w 'p' -b '<base>' <filter> <attrs>` |
| Domain dump | `ldapdomaindump -u 'd\u' -p 'pw' <dc>` (outputs bloodhound-ingestable JSON: `ldd2bloodhound`) |
| BloodHound | `bloodhound-python -u u -p 'pw' -d dom -ns <dc> -c All --zip` |
| AS-REP roast | `impacket-GetNPUsers d/u -no-pass -dc-ip <dc> -format hashcat` |
| Kerberoast | `impacket-GetUserSPNs d/u:'p' -dc-ip <dc> -request` / targeted: `~/tools/targetedKerberoast/targetedKerberoast.py` |
| Spray (no lockout) | `kerbrute bruteuser -d dom --dc <ip> <wordlist> <user>` / `nxc smb <ip> -u users -p pwds --no-bruteforce --continue-on-success` |
| Secret dump | `impacket-secretsdump 'd/u:p@ip'` (+ `-just-dc` for DCSync) |
| LSASS via SMB | `lsassy <ip> -u u -p 'p' -d dom` |
| **Key List attack** | `keylistattack.py` (badKerberos suite, `~/.local/bin`) or `minikerberos-keylist`; needs `KRB5_CONFIG=$PWD/krb5.conf` pinning — see zone-ad.md |
| MsCacheV2 roast | `badccacheroast` / `badccache2kirbi` (~/.local/bin) — for DCC2 suffix questions |
| ADCS | `python3 ~/.local/share/pipx/venvs/certipy-ad/bin/certipy find -u u@d -p 'pw' -dc-ip <ip> -vulnerable` |
| Coercion/relay | `coercer coerce -u u -p 'pw' -l tun0 -t <ip>`, `ntlmrelayx.py -tf targets.txt -smb2support`, `mitm6 -d dom` |
| Delegation/ACL | `findDelegation.py`, `rbcd.py`, `dacledit.py`, `owneredit.py`, `pywhisker`, `getST.py`, `ticketer.py`, `raiseChild.py`, `describeTicket.py` |
| PKINIT tricks | `~/tools/PKINITtools/gettgtpkinit.py`, `getnthash.py`, `gets4uticket.py` |
| Shells | `evil-winrm -i <ip> -u u -p 'p'`, `impacket-psexec` / `impacket-wmiexec`, `xfreerdp /v:<ip> /u:d\\u /p:'pw'` |
| On-box (upload) | `~/tools/Responder`, `~/tools/Snaffler`, `~/tools/PowerSploit`, `~/tools/enum4linux-ng/enum4linux-ng.py` |

## 3. Linux CTF (zone 2)

| Task | Command |
|---|---|
| Web fuzz | `ffuf` / `gobuster dir -u URL -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,txt,html,bak` |
| SQLi | `sqlmap -u 'URL?search=x' --batch --dbs --threads 10` (manual UNION faster for masks: see zone-ctf.md) |
| WordPress | `wpscan --url URL --enumerate ap,at,u` (gem user-install 4.1.0) or manual: author enum `/?author=N`, plugin `readme.txt`, `wp-login.php` brute script |
| CMS enum | `droopescan scan -u URL` (Drupal), `whatweb` |
| SSH brute | `hydra -l u -P rockyou.txt ssh://IP -t 25` (medusa missing, hydra suffices) |
| Privesc enum | run the one-liner from zone-ctf.md; GTFOBins for SUID/caps findings |
| XSS/commix probes | `dalfox url URL`, `commix -u URL` |
| Local file analysis | `python3 -m http.server 8000` exfil, `sqlite3`, `base64 -w0` |

## 4. Web apps (zone 3)

| Task | Command |
|---|---|
| Content | `ffuf -u https://host/FUZZ -w seclists/.../raft-*.txt -mc 200-399 -k` |
| Param discovery | `arjun -u URL` |
| Proxy | `mitmproxy` / `mitmdump` (Burp if user drives GUI) |
| JWT | `hashcat -m 16500 jwt.txt <wl>` or `john jwt.txt --wordlist=<wl> --format=HMAC-SHA256` (jumbo) |
| NoSQL/Mongo | manual `type[$ne]=x` operators; verbose error reading |
| WebSocket (Socket.IO) | `python3` + `pip install python-socketio` client — see zone-web.md bot takeover pattern |
| Framework scans | `nuclei`, `nikto`, `schemathesis` (API), `xsstrike` |

## 5. IoT & firmware (zone 4)

| Task | Command |
|---|---|
| Firmware ID/extract | `binwalk` / `binwalk -e` (pipx 2.1.0). Non-standard SquashFS carve needs `sasquatch` — NOT built; signature scan + `jefferson` (JFFS2, pipx) + system `unsquashfs` cover most questions |
| Carved file triage | `file <offset-named-file>`, `strings … | grep -i`, `sqlite3 <db>` |
| Credentials hunt | `find . \( -name passwd -o -name shadow \)` → `usr/etc/passwd` pattern; `grep -i DeviceID` |

## 6. Binary exploitation (zone 5)

| Task | Command |
|---|---|
| Pattern create/offset | `/opt/metasploit-framework/embedded/framework/tools/exploit/pattern_create.rb -l 200` and `…/pattern_offset.rb -l 200 -q 0x64413764` |
| Debug | `gdb` (pwndbg installed at `~/tools/pwndbg` — `source ~/tools/pwndbg/gdbinit.py` if not auto-loaded) |
| Exploit dev | `pwn` (pwntools CLI) / `python3 -c "from pwn import *"` — `cyclic()`, `cyclic_find()`, `p64()` |
| Protections | `checksec --file=<bin>` |
| Unpack | `upx -d <bin> -o unpacked` |
| Disassembly | `radare2` / `rabin2` (user build 6.2.1, `~/.local/bin`); fallback `objdump -d -M intel`, gdb disas |
| Payloads | `msfvenom` at `/opt/metasploit-framework/bin/msfvenom` |
| Listener | `nc -lvnp 443`, `rlwrap nc -lvnp 443`, `socat TCP-LISTEN:1337,reuseaddr,fork EXEC:./bin` (replicate exam services locally) |
| Exploit-db | `searchsploit <term>` (db at /opt/exploitdb) |
| Libc offsets | `~/tools/libc-database/` |

## 7. Pivoting & transfer (all zones)

| Task | Command |
|---|---|
| SOCKS tunnel | `chisel server -p 8000 --reverse` (target) + `chisel client <ip>:8000 R:socks` → `proxychains4 <cmd>` |
| SSH | `sshpass -p 'pw' ssh u@ip` (NOW installed — prior notes' expect workaround obsolete) |
| Port forward | `sshpass -p 'pw' ssh -L 8080:internal:80 u@pivot` / asysocks suite in `~/.local/bin` |
| Exfil over socket | `base64 -w0 <file>` paste → `base64 -d` locally |

## 8. Cracking (all zones) — verify with preflight.sh first

```bash
# hashcat (verified working 2026-08-31):
hashcat -m 1000 nt.txt <wl>            # NT
hashcat -m 5600 ntlmv2.txt <wl>        # NTLMv2
hashcat -m 18200 krb5asrep.txt <wl>    # AS-REP
hashcat -m 13100 tgs.txt <wl>        # Kerberoast
hashcat -m 3200 bcrypt.txt <wl>
hashcat -m 16500 jwt.txt <wl>          # JWT HS256
# john (jumbo needed for NT-family — system john is core-only):
john --wordlist=<wl> shadow.txt                  # SHA-512 crypt works on core
john --format=nt --wordlist=<wl> hashes.txt      # needs jumbo
# Rules: --rules=Jumbo / All / KoreLogic   |  hashcat rules: -r /usr/share/hashcat/rules/best64.rule
# Mask-filter wordlists first: grep -aE '^[a-z]{5}[0-9]$' rockyou.txt > mask.txt
```

Wordlists: `/usr/share/seclists/` (snap; Discovery, Passwords, Usernames, Fuzzing,
Payloads). Build single rockyou once per session in `/tmp/opencode/` (see quirk table).

## Provisioning a new laptop (or fixing this one)

All of the 2026-08-31 gap-fills were done WITHOUT root — reproduce anywhere:

```bash
pipx install binwalk jefferson            # firmware scan + JFFS2
gem install --user-install wpscan && ln -sf ~/.local/share/gem/ruby/*/bin/wpscan ~/.local/bin/wpscan
git clone --depth 1 https://github.com/radareorg/radare2 /tmp/opencode/radare2
(cd /tmp/opencode/radare2 && ./configure --prefix=$HOME/.local >/dev/null && make -sj$(nproc) >/dev/null && make install >/dev/null)
for f in ~/.local/bin/*; do ldd "$f" 2>/dev/null | grep -q 'libr_.*not found' && patchelf --set-rpath $HOME/.local/lib "$f"; done
git clone --depth 1 https://github.com/openwall/john ~/tools/john-jumbo
(cd ~/tools/john-jumbo/src && ./configure >/dev/null && make -sj$(nproc) >/dev/null)
printf '#!/bin/bash\nexec %s/tools/john-jumbo/run/john "$@"\n' $HOME > ~/.local/bin/john && chmod +x ~/.local/bin/john
# still outstanding (needs sudo): apt install binwalk radare2 (system copies), sasquatch build
# single rockyou:
cat /snap/seclists/*/Passwords/Leaked-Databases/rockyou-*.txt > ~/rockyou.txt
# cracker status rotates — preflight.sh live-tests both every session
```

Full-stack reproduction of this laptop (another machine):

```bash
# base: Kali (or Debian + these)
sudo apt install -y nmap masscan john hydra gobuster ffuf feroxbuster nikto sqlmap \
  testssl sslscan whatweb wafw00f onesixtyone snmpcheck gdb checksec upx socat nc \
  rlwrap chisel proxychains4 sshpass sqlite3 file strings exploitdb metasploit-framework
pipx install impacket netexec bloodhound certipy-ad ldapdomaindump lsassy mitm6 \
  mitmproxy arjun commix dirsearch droopescan xsstrike schemathesis uro waymore
# pwntools: pipx install pwntools ; pwndbg: git clone https://github.com/pwndbg/pwndbg ~/tools/pwndbg && ./setup.sh
# repos to ~/tools: Responder, enum4linux-ng, PowerSploit, Snaffler, targetedKerberoast, pywhisker, PKINITtools, libc-database, hashcat-utils
# badKerberos suite (keylistattack, badccacheroast): pipx install badkerberos  (or clone from skelsec)
# wordlists: sudo apt install -y seclists
```

Ephemeral-only rule: install challenge-specific extras into `/tmp/opencode` or a
pipx/venv — never global — and clean them up after the exam session.
