# CTF Web - Reconnaissance & Tooling

## Table of Contents
- [Passive Recon](#passive-recon)
  - [WHOIS & ASN](#whois--asn)
  - [DNS Enumeration](#dns-enumeration)
  - [Subdomain Enumeration](#subdomain-enumeration)
  - [Wayback / Historical URLs](#wayback--historical-urls)
  - [Google Dorking](#google-dorking)
  - [Fingerprinting](#fingerprinting)
- [Active Content Discovery](#active-content-discovery)
  - [gobuster](#gobuster)
  - [feroxbuster](#feroxbuster)
  - [ffuf](#ffuf)
  - [dirb / dirsearch](#dirb--dirsearch)
  - [nikto](#nikto)
  - [CMS Scanners](#cms-scanners)
- [Virtual Host Discovery](#virtual-host-discovery)
- [Web Proxy Workflow](#web-proxy-workflow)
  - [Burp Suite Community](#burp-suite-community)
  - [OWASP ZAP](#owasp-zap)
  - [Proxying CLI Tools & Mobile](#proxying-cli-tools--mobile)
- [WAF Detection & Bypass Pointers](#waf-detection--bypass-pointers)
- [Recon -> Technique Routing Table](#recon---technique-routing-table)

For attacking specific known applications (WordPress, Tomcat, Jenkins, etc.), see [common-applications.md](common-applications.md). For payload-level injection after a target is mapped, see [sql-injection.md](sql-injection.md), [server-side.md](server-side.md), and [client-side.md](client-side.md).

---

## Passive Recon

### WHOIS & ASN
```bash
whois example.com                          # registrar, name servers, dates
whois 10.10.10.10                          # netblock owner, ASN
# ASN -> CIDR ranges (scope expansion)
whois -h whois.radb.net -- '-i origin AS12345' | grep -Eo "([0-9.]+){4}/[0-9]+"
```

### DNS Enumeration
```bash
# dig: targeted record queries
dig example.com ANY +noall +answer
dig A example.com; dig AAAA example.com; dig MX example.com; dig TXT example.com; dig NS example.com
dig CNAME www.example.com
dig +short example.com
dig -x 10.10.10.10                         # reverse PTR

# Zone transfer (AXFR) - always try, often misconfigured on internal boxes
dig AXFR @ns1.example.com example.com
dig axfr @10.10.10.10 example.htb

# dnsenum: brute + zone transfer + google scraping
dnsenum --enum example.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
dnsenum --dnsserver 10.10.10.10 example.htb

# dnsrecon: multiple modes
dnsrecon -d example.com -t std             # standard (A, MX, NS, SOA, TXT, SRV)
dnsrecon -d example.com -t axfr            # zone transfer attempt
dnsrecon -d example.com -D wordlist.txt -t brt   # brute force
dnsrecon -d example.com -t brt -n 10.10.10.10    # against a specific NS
```
On HTB/OSCP add the box hostname to `/etc/hosts` before DNS tooling that expects resolution.

### Subdomain Enumeration
```bash
# subfinder (passive, fast, many sources)
subfinder -d example.com -all -silent -o subs.txt
subfinder -dL domains.txt -silent

# amass (passive + active; slower, thorough)
amass enum -passive -d example.com -o amass.txt
amass enum -active -d example.com -brute -w wordlist.txt

# assetfinder
assetfinder --subs-only example.com | tee -a subs.txt

# crt.sh (certificate transparency logs) - no tooling required
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u

# Resolve + probe live hosts, dedupe pipeline
cat subs.txt | httpx -silent -o live.txt
```

### Wayback / Historical URLs
```bash
# gau (getallurls): wayback + commoncrawl + otx + urlscan
gau example.com | tee gau.txt
gau --subs example.com                     # include subdomains
cat subs.txt | gau | sort -u

# waybackurls
waybackurls example.com | tee wayback.txt

# Extract interesting endpoints / params from harvested URLs
cat gau.txt | grep -Ei "\.(bak|old|sql|zip|tar|gz|conf|env|log)$"
cat gau.txt | grep "=" | qsreplace FUZZ | sort -u   # param mining
cat gau.txt | unfurl keys | sort -u                 # unique param names
```

### Google Dorking
```
site:example.com                       # indexed pages
site:example.com -www                  # non-www subdomains
site:example.com ext:php               # by extension
site:example.com inurl:admin
site:example.com intitle:"index of"    # directory listing
site:example.com filetype:pdf
site:example.com intext:"password"
cache:example.com                      # cached copy
```
Related: `inurl:`, `intitle:`, `intext:`, `filetype:`, `ext:`, `-` (exclude), `"..."` (exact). GHDB (exploit-db Google Hacking Database) for prebuilt dorks.

### Fingerprinting
```bash
# whatweb: aggressive fingerprint of stack, CMS, versions, headers
whatweb -a 3 http://example.com
whatweb --log-verbose=whatweb.txt -i live.txt

# httpx: probe + tech detect + titles + status + CDN + hashes
httpx -l subs.txt -title -tech-detect -status-code -web-server -cdn -follow-redirects -o httpx.txt
httpx -l subs.txt -sc -cl -location -favicon    # favicon mmh3 hash -> shodan pivot

# wappalyzer: browser extension or CLI (webappalyzer / wappalyzer npm)
# Manual header/cookie tells:
curl -sI http://example.com | grep -iE "server|x-powered-by|set-cookie|x-aspnet|x-generator"
# Cookie tells: PHPSESSID=PHP, JSESSIONID=Java, ASP.NET_SessionId=.NET,
#   laravel_session=Laravel, connect.sid=Express, csrftoken=Django
# Header tells: X-Powered-By, X-Generator (Drupal), X-Drupal-Cache, X-AspNet-Version
```
Favicon hash pivot: `curl -s http://host/favicon.ico | python3 -c "import mmh3,sys,base64;print(mmh3.hash(base64.encodebytes(sys.stdin.buffer.read())))"` then search Shodan `http.favicon.hash:<hash>`.

---

## Active Content Discovery

Wordlists: `/usr/share/seclists/Discovery/Web-Content/` (raft-*, directory-list-2.3-medium.txt, common.txt) and `/usr/share/wordlists/dirb/`.

### gobuster
```bash
# dir mode
gobuster dir -u http://example.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 50
gobuster dir -u http://example.com -w common.txt -x php,html,txt,bak -t 50    # extensions
gobuster dir -u https://example.com -k -b 404,403 -s 200,204,301,302,307      # tls skip + status filter
gobuster dir -u http://example.com -w list.txt -c "PHPSESSID=abc" -H "Authorization: Bearer x"   # auth

# dns mode (subdomain brute - needs resolvable base domain)
gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 50

# vhost mode (Host-header based, same IP)
gobuster vhost -u http://10.10.10.10 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain
# older gobuster: omit --append-domain and supply FQDN wordlist
```

### feroxbuster
```bash
# recursive by default, fast
feroxbuster -u http://example.com -w raft-medium-directories.txt
feroxbuster -u http://example.com -x php,txt,html -d 3 -t 100     # depth 3
feroxbuster -u http://example.com -C 404,403 -s 200,301,302        # filter by status
feroxbuster -u http://example.com --filter-size 1234               # filter response size
feroxbuster -u http://example.com -H "Cookie: session=x" --dont-scan logout
feroxbuster -u http://example.com -w list.txt --extract-links      # parse responses for new paths
```

### ffuf
Most flexible fuzzer; `FUZZ` is the injection marker.
```bash
# Directory / file discovery
ffuf -u http://example.com/FUZZ -w raft-medium-directories.txt
ffuf -u http://example.com/FUZZ -w common.txt -e .php,.html,.bak,.txt   # extension fuzz
ffuf -u http://example.com/FUZZ -w list.txt -recursion -recursion-depth 2 -v

# Filtering (critical for signal): -fc status, -fs size, -fw words, -fl lines, -fr regex
ffuf -u http://example.com/FUZZ -w list.txt -fc 404,403
ffuf -u http://example.com/FUZZ -w list.txt -fs 4242            # filter noise page by size
ffuf -u http://example.com/FUZZ -w list.txt -mc 200,301,302     # match only these codes
ffuf -u http://example.com/FUZZ -w list.txt -ac                 # auto-calibrate filtering

# VHOST discovery via Host header
ffuf -u http://10.10.10.10 -H "Host: FUZZ.example.htb" -w subdomains.txt -fs 4242

# GET parameter name fuzzing
ffuf -u "http://example.com/page?FUZZ=value" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs 100
# GET parameter VALUE fuzzing (e.g., IDOR/id sweep)
ffuf -u "http://example.com/api?id=FUZZ" -w ids.txt -mc 200

# POST body fuzzing
ffuf -u http://example.com/login -X POST -d "username=admin&password=FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" -w passwords.txt -fc 401
# POST param NAME fuzzing
ffuf -u http://example.com/api -X POST -d "FUZZ=test" -H "Content-Type: application/x-www-form-urlencoded" -w params.txt

# Multiple wordlists / clusterbomb (user+pass spray)
ffuf -u http://example.com/login -X POST -d "user=U&pass=P" -w users.txt:U -w pass.txt:P -mode clusterbomb -fc 401

# Rate limiting / stability
ffuf -u http://example.com/FUZZ -w list.txt -rate 50 -p 0.1    # req/s + delay
```

### dirb / dirsearch
```bash
dirb http://example.com /usr/share/wordlists/dirb/common.txt
dirb http://example.com -X .php,.bak                 # append extensions
dirsearch -u http://example.com -e php,html,js -x 403,404 --recursive
```

### nikto
```bash
nikto -h http://example.com
nikto -h http://10.10.10.10 -p 80,443,8080
nikto -h http://example.com -useproxy http://127.0.0.1:8080    # through Burp
nikto -h http://example.com -Tuning 9                          # SQLi tests only
```
Flags outdated software, default files, dangerous methods, misconfig headers. Noisy — not for stealth.

### CMS Scanners
```bash
# WordPress
wpscan --url http://example.com --enumerate u,vp,vt,tt --api-token <WPVULNDB_TOKEN>
#   u=users vp=vuln plugins vt=vuln themes tt=timthumbs ap=all plugins at=all themes

# Drupal
droopescan scan drupal -u http://example.com
droopescan scan drupal -u http://example.com -t 32

# Joomla
joomscan --url http://example.com
joomscan -u http://example.com --enumerate-components

# Generic (Drupal/Joomla/SilverStripe/WordPress/Moodle)
droopescan scan -u http://example.com     # auto-detect
```
Full authenticated-to-RCE paths per app in [common-applications.md](common-applications.md).

---

## Virtual Host Discovery
Many boxes serve multiple sites on one IP, keyed off the HTTP `Host` header. The default IP page hides them.

Signals a vhost exists: a redirect to a hostname you can't resolve, a certificate CN/SAN with a domain, an app that references `example.htb` in links.

```bash
# Detect: does changing Host change the response?
curl -s -H "Host: admin.example.htb" http://10.10.10.10/ | wc -c

# ffuf vhost sweep - filter the default-page size first
ffuf -u http://10.10.10.10 -H "Host: FUZZ.example.htb" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs <default_size>

# gobuster vhost mode
gobuster vhost -u http://10.10.10.10 --append-domain --domain example.htb -w subdomains.txt
```

**When to edit `/etc/hosts`:** a discovered vhost must be added so the browser/tools send the right Host and any absolute links/redirects resolve. Add the box IP mapped to each vhost:
```bash
echo "10.10.10.10  example.htb admin.example.htb dev.example.htb" | sudo tee -a /etc/hosts
```
Difference: **subdomain enum** finds names in public DNS; **vhost enum** finds names served on one IP that are *not* in DNS (internal-only). Do both — they return different sets.

---

## Web Proxy Workflow

### Burp Suite Community
Set browser/system proxy to `127.0.0.1:8080`, install Burp CA cert (`http://burp` -> CA Certificate) to intercept HTTPS.

- **Proxy > Intercept:** toggle interception; edit requests in flight; forward/drop.
- **Proxy > HTTP history:** passive log of everything; right-click -> "Send to Repeater/Intruder".
- **Target > Site map:** tree of discovered content; right-click host -> "Add to scope".
- **Target > Scope:** define in-scope hosts; enable "show only in-scope" to cut noise; set Proxy to intercept in-scope only.
- **Repeater:** manual request iteration — the core manual-testing tool. Send, tweak header/param, resend; `Ctrl+R` send-to-repeater, `Ctrl+Space` send request.
- **Intruder:** automated payload injection. Set `§markers§`, choose attack type (Sniper 1 payload/1 position, Battering ram same payload all positions, Pitchfork parallel lists, Cluster bomb all combinations). **Community caveat:** Intruder is heavily throttled (~1 req/s after a short burst) — use `ffuf`/`wfuzz` for real brute force and reserve Intruder for small, structured sets.
- **Decoder:** URL/Base64/HTML/hex/gzip encode-decode and hashing.
- **Match and Replace:** Proxy > Options (Burp 2023: Settings > Tools > Proxy > Match and replace) — auto-rewrite requests/responses (e.g., force `X-Forwarded-For`, strip CSP, replace a header on every request).
- **Comparer / Inspector:** diff two responses; Inspector decodes params live.
- Extensions via BApp Store need Community-compatible ones; many need Pro/Jython.

### OWASP ZAP
Free, no Intruder throttle. Set proxy `127.0.0.1:8080`, import ZAP CA.
```bash
zap.sh -daemon -host 127.0.0.1 -port 8080 -config api.disablekey=true   # headless
# Automated active scan from CLI (packaged scan)
zap-cli quick-scan --self-contained --spider -r http://example.com
```
- **HUD** (heads-up display) overlays controls in the browser.
- **Spider** (crawl) + **AJAX Spider** (JS-heavy apps via headless browser).
- **Fuzzer** = ZAP's Intruder equivalent, unthrottled.
- **Manual Request Editor** = Repeater equivalent.
- **Active Scan** does automated vuln detection (SQLi/XSS/etc.) — noisy.

### Proxying CLI Tools & Mobile
```bash
# Route CLI tools through Burp/ZAP for logging + manual replay
curl -x http://127.0.0.1:8080 -k http://example.com/
export HTTP_PROXY=http://127.0.0.1:8080 HTTPS_PROXY=http://127.0.0.1:8080
sqlmap -u "http://example.com/?id=1" --proxy=http://127.0.0.1:8080
ffuf -u http://example.com/FUZZ -w list.txt -x http://127.0.0.1:8080
nikto -h http://example.com -useproxy http://127.0.0.1:8080
gobuster dir -u http://example.com -w list.txt --proxy http://127.0.0.1:8080
wpscan --url http://example.com --proxy http://127.0.0.1:8080

# Mobile: set device Wi-Fi proxy to your host IP:8080, install Burp CA on device.
#   Android 7+ pins system CA store — need user cert accepted by app or Frida/objection unpinning.
```

---

## WAF Detection & Bypass Pointers
```bash
wafw00f http://example.com                 # identify WAF vendor
wafw00f -a http://example.com              # test all signatures, don't stop at first
nmap --script http-waf-detect,http-waf-fingerprint -p80,443 example.com
```
Behavioral tells: sudden 403/406/429/501 on a payload that structurally should 200, generic block page, `Server: cloudflare`, `X-Sucuri-*`, `X-CDN`, request timeouts on injection chars.

General evasion levers (payload-level specifics live in the injection files):
- **Encoding:** URL / double-URL / Unicode / mixed-case / HTML-entity / hex.
- **Whitespace/comments:** `/**/`, `%0a`, `%09`, tab, newline splitting keywords.
- **Case & concatenation:** `SeLeCt`, `un/**/ion`, string concat.
- **HTTP layer:** alternate methods, `X-Forwarded-For`/`X-Original-URL` to spoof origin, chunked transfer-encoding, HTTP/2 downgrade, parameter pollution.
- **Origin IP:** if WAF is a CDN, find the real backend IP (crt.sh history, DNS history, favicon hash, SSRF) and hit it directly with the Host header set.

For SQLi WAF bypass payloads see [sql-injection.md](sql-injection.md); for XSS filter bypass see [client-side.md](client-side.md); for SSRF/parser tricks see [server-side.md](server-side.md) and [request-smuggling.md](request-smuggling.md).

---

## Recon -> Technique Routing Table

| Recon finding | Go to |
| --- | --- |
| Login form, session cookie, password reset, JWT/`ey...` token | [auth-and-access.md](auth-and-access.md), [auth-jwt.md](auth-jwt.md) |
| `id=`, `?search=`, DB error strings, ORDER BY reflect | [sql-injection.md](sql-injection.md) |
| `?url=`, `?file=`, `?path=`, image/PDF fetcher, webhook | [server-side.md](server-side.md) (SSRF/LFI/RFI) |
| Reflected input, DOM sinks, `innerHTML`, template `{{ }}` | [client-side.md](client-side.md), [server-side.md](server-side.md) (SSTI) |
| Upload form, `cmd=`, `exec`, ping/lookup utility | [server-side-exec.md](server-side-exec.md) |
| `/api/`, GraphQL `/graphql`, REST, Swagger/OpenAPI JSON | [api-security.md](api-security.md), [graph-query-injection.md](graph-query-injection.md) |
| Serialized blob (`O:`, `rO0`, `AAEAAAD`, `gASV`), cookie deser | [server-side-deser.md](server-side-deser.md) |
| Known app banner (WordPress/Tomcat/Jenkins/Drupal/etc.) | [common-applications.md](common-applications.md) |
| Version string in banner/page/JS | [cves.md](cves.md), searchsploit workflow in [common-applications.md](common-applications.md) |
| Node/Express, prototype pollution gadget | [node-and-prototype.md](node-and-prototype.md) |
| Multiple front-end proxies, chunked/CL.TE oddities | [request-smuggling.md](request-smuggling.md) |
| Source archive / WAR / container supplied | [whitebox-review.md](whitebox-review.md), [tomcat-local-triage.md](tomcat-local-triage.md) |

## IIS 8.3 Shortname Enumeration for Hidden Paths

**Trigger:** Target is IIS (Server header, .aspx/.asp extensions, X-AspNet-Version) and ordinary wordlist directory brute-forcing came back empty or thin. Especially worth doing when you suspect custom-named admin panels, backup archives, or config files that no wordlist will ever contain.

NTFS keeps an 8.3 alias for every long filename, and IIS resolves those aliases through a request path. The bug is a response differential: a request for a path containing a valid short-name prefix followed by a wildcard returns a different status or error than one containing an invalid prefix (classically 404 versus 400). That turns filename discovery into character-by-character brute force independent of any wordlist — you recover the first six characters of the name, the `~1` sequence number, and the three-character extension. Run iis_shortname_scanner against the root and against every directory it discovers, since the technique recurses. The output is deliberately lossy: you get `SECRET~1.ASP`, not `secretadmin.aspx`, so treat each hit as a constrained prefix and feed it back into a targeted brute force — generate a wordlist filtered to entries starting with the recovered six characters and re-run gobuster with the plausible extensions expanded, because the 8.3 extension is truncated to three characters and `.ASP` may really be .aspx, .asax, or .asmx. Names shorter than nine characters with no spaces may have no alias generated at all, so an empty result is not proof of an empty directory. This is a discovery primitive, distinct from using an 8.3 alias to slip past a filename blocklist.

```bash
# enumerate 8.3 aliases (threads=0 disables proxy, 5 = request rate)
java -jar iis_shortname_scanner.jar 0 5 http://TARGET/
# recurse into every directory it reports
java -jar iis_shortname_scanner.jar 0 5 http://TARGET/DISCOV~1/

# turn a recovered prefix into a real name
grep -i '^secret' /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt > /tmp/list.txt
gobuster dir -u http://TARGET/ -w /tmp/list.txt -x aspx,asp,asmx,asax,config,bak,zip
```

Source: https://offsecexams.com/cheatsheets/cwes-exam---guided-by-redblock

