# Red Team - C2 Infrastructure

Observation first: infrastructure is not a fixed recipe. What you stand up follows from the target's egress controls, TLS inspection, proxy/category filtering, and the detection team's maturity. A flat SOC tolerates a single VPS on HTTPS; a mature one with full TLS break-and-inspect, JA3/JA4 fingerprinting, and newly-registered-domain blocking forces categorized domains, redirectors, and long-haul channels. Build to the environment you actually observe, not the one in a blog post.

## Table of Contents
- [Design Principles](#design-principles)
- [Short-Haul vs Long-Haul C2](#short-haul-vs-long-haul-c2)
- [Redirector-to-Teamserver Separation](#redirector-to-teamserver-separation)
- [Apache mod_rewrite HTTP Redirector](#apache-modrewrite-http-redirector)
- [.htaccess Filtering Example](#htaccess-filtering-example)
- [Nginx Reverse-Proxy Redirector](#nginx-reverse-proxy-redirector)
- [socat / iptables Dumb Pipe Redirector](#socat--iptables-dumb-pipe-redirector)
- [HTTPS with Valid Certificates (Let's Encrypt)](#https-with-valid-certificates-lets-encrypt)
- [Domain Categorization and Reputation](#domain-categorization-and-reputation)
- [Domain Fronting and Domainless Fronting](#domain-fronting-and-domainless-fronting)
- [Cloud / CDN Redirectors](#cloud--cdn-redirectors)
- [DNS C2](#dns-c2)
- [Malleable C2 Profiles (Concepts)](#malleable-c2-profiles-concepts)
- [Redirector Health and Monitoring](#redirector-health-and-monitoring)
- [Mail Infrastructure (SPF/DKIM/DMARC)](#mail-infrastructure-spfdkimdmarc)
- [OPSEC of Infrastructure](#opsec-of-infrastructure)

For agent/profile specifics (Cobalt Strike, Sliver, Mythic, Havoc, Nighthawk) see [c2-frameworks.md](c2-frameworks.md). For what the payload does after callback see [payloads-and-execution.md](payloads-and-execution.md) and [edr-evasion.md](edr-evasion.md). For getting the first foothold see [initial-access.md](initial-access.md). For post-exploitation persistence and movement see [persistence-and-lateral.md](persistence-and-lateral.md). For infra teardown and campaign hygiene see [opsec-and-lifecycle.md](opsec-and-lifecycle.md).

---

## Design Principles
Never expose the team server. Everything the target touches is a disposable redirector; the team server sits on a private/restricted interface reachable only from redirectors (or over a VPN/SSH tunnel). Segment channels by function so burning one does not burn all.

- **Team server**: internal only, no public listener on the C2 port. Bind to loopback or a private VPN interface.
- **Redirectors**: cheap, disposable VPS or cloud functions. One redirector per domain/channel. Assume each will be discovered and blocked.
- **Separation of roles**: phishing/staging infra, short-haul C2, long-haul C2, and exfil should be *different* hosts and *different* domains. Losing the phishing domain must not reveal the C2 domain.

---

## Short-Haul vs Long-Haul C2
Two channels with different jobs. Short-haul is your interactive/working channel (low sleep, fast tasking). Long-haul is your insurance policy (very long sleep, minimal footprint) that re-establishes access if the short-haul channel is discovered and blocked.

- **Short-haul**: seconds-to-low-minutes sleep with jitter, HTTPS or DNS, used for active operations. Higher volume => higher detection risk => more likely to be burned.
- **Long-haul**: hours-to-days sleep, often over a different protocol/domain/CDN, sometimes a different C2 framework entirely. Only used to redeploy a short-haul beacon if the primary dies. Keep it silent.
- Do not run both channels through the same redirector, domain, or provider. Diversity is the whole point.

```
# Typical layout
[ target host ]
   |-- short-haul beacon  --> https redirector A (domain-a, CDN X) --> team server 1
   |-- long-haul beacon   --> dns redirector B  (domain-b)         --> team server 2
```

---

## Redirector-to-Teamserver Separation
The redirector receives target traffic, filters it, and forwards only legitimate C2 to the hidden team server. Two forwarding styles:

- **Dumb pipe (layer 4)**: socat/iptables blindly forward the TCP port. Simple, protocol-agnostic, but the redirector applies no filtering and the team server sees the redirector's IP unless you preserve source.
- **Filtering reverse proxy (layer 7)**: Apache/nginx inspect HTTP, enforce URI/User-Agent/method allow-lists, serve a decoy to everything else, and forward only matching requests. Preferred for HTTP(S) C2.

Lock the team server so it only accepts C2 from redirector IPs:

```bash
# On the team server, restrict the C2 port to known redirector IPs
sudo ufw default deny incoming
sudo ufw allow from <redirector-ip> to any port 443 proto tcp
sudo ufw allow OpenSSH        # management from your bastion only, ideally
```

---

## Apache mod_rewrite HTTP Redirector
Apache with `mod_rewrite` + `mod_proxy` is the classic filtering redirector: match legitimate C2 on URI/UA/method, proxy it to the team server, and 302 everything else to a decoy site.

```apache
# /etc/apache2/sites-enabled/redirector.conf
# a2enmod rewrite proxy proxy_http ssl headers
<VirtualHost *:443>
    ServerName cdn.example-content.com
    SSLEngine On
    SSLCertificateFile      /etc/letsencrypt/live/cdn.example-content.com/fullchain.pem
    SSLCertificateKeyFile   /etc/letsencrypt/live/cdn.example-content.com/privkey.pem

    SSLProxyEngine On
    ProxyPreserveHost On
    RewriteEngine On

    # Only forward requests whose URI matches the profile's C2 paths
    RewriteCond %{REQUEST_URI}    ^/(api/v2/updates|jquery-3.3.1.min.js|load)$   [NC]
    # AND whose User-Agent matches the beacon's exact UA
    RewriteCond %{HTTP_USER_AGENT} "Mozilla/5.0 \(Windows NT 10.0; Win64; x64\)" [NC]
    RewriteRule ^.*$  https://127.0.0.1:8443%{REQUEST_URI}  [P,L]

    # Everything else -> decoy (real, categorized site)
    RewriteRule ^.*$  https://www.microsoft.com/  [L,R=302]
</VirtualHost>
```

Keep the URI/UA conditions in exact sync with the C2 profile. A mismatch means beacons get 302'd to the decoy and silently die.

---

## .htaccess Filtering Example
Same idea in a per-directory `.htaccess` (requires `AllowOverride All`). Filters on URI and User-Agent; forwards matches to the team server, sends everything else to a decoy. This is the requested filtering example.

```apache
# .htaccess in the redirector web root
RewriteEngine On

# 1. Block known sandbox / scanner / research User-Agents outright
RewriteCond %{HTTP_USER_AGENT} (curl|wget|python-requests|Go-http|libwww|masscan|zgrab|nmap|VirusTotal|urlscan) [NC]
RewriteRule ^.*$ https://www.google.com/ [L,R=302]

# 2. Valid C2: exact beacon URIs + exact beacon User-Agent -> proxy to hidden team server
RewriteCond %{REQUEST_URI} ^/(assets/main\.js|api/health|pixel\.gif)$ [NC]
RewriteCond %{HTTP_USER_AGENT} ^Mozilla/5\.0\ \(Windows\ NT\ 10\.0;\ Win64;\ x64\)\ AppleWebKit [NC]
RewriteRule ^.*$ https://10.10.10.5:8443%{REQUEST_URI} [P,L]

# 3. Anything else (wrong URI, wrong UA, direct browse, blue-team poke) -> decoy
RewriteRule ^.*$ https://learn.microsoft.com/en-us/ [L,R=302]
```

Notes: escape regex metacharacters in the UA string; anchor with `^`/`$` so partial matches do not leak; test with the real beacon before going live. Filtering on source-country or ASN (via a GeoIP module) further trims scanner noise.

---

## Nginx Reverse-Proxy Redirector
Nginx equivalent: `location` blocks act as the URI allow-list, everything else returns a decoy or a 404.

```nginx
server {
    listen 443 ssl;
    server_name cdn.example-content.com;
    ssl_certificate     /etc/letsencrypt/live/cdn.example-content.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cdn.example-content.com/privkey.pem;

    # Valid C2 paths only
    location ~ ^/(api/v2/updates|load|jquery-3\.3\.1\.min\.js)$ {
        if ($http_user_agent !~ "Windows NT 10.0; Win64; x64") { return 302 https://www.microsoft.com/; }
        proxy_pass https://127.0.0.1:8443;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
    }

    # Default: decoy
    location / { return 302 https://www.microsoft.com/; }
}
```

---

## socat / iptables Dumb Pipe Redirector
Layer-4 forwarding when you do not need HTTP filtering (e.g., forwarding an already-fronted channel, or a non-HTTP protocol). No inspection — the team server relies on the C2 profile itself to reject junk.

```bash
# socat: forward inbound 443 to the hidden team server, run under systemd or tmux
socat TCP4-LISTEN:443,fork,reuseaddr TCP4:10.10.10.5:443

# iptables DNAT + MASQUERADE (preserves nothing to the client, hides team server)
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 10.10.10.5:443
iptables -t nat -A POSTROUTING -p tcp -d 10.10.10.5 --dport 443 -j MASQUERADE
```

Dumb pipes are fragile against scanning: anyone hitting the redirector IP reaches the team server directly. Prefer a filtering L7 redirector for anything internet-facing.

---

## HTTPS with Valid Certificates (Let's Encrypt)
Self-signed or default framework certs are trivially fingerprinted and often JA3/JARM-flagged. Always terminate on a valid, publicly-trusted cert for the C2 domain.

```bash
# On the redirector (has the DNS pointing at it), issue a cert
sudo certbot certonly --standalone -d cdn.example-content.com --agree-tos -m ops@example-content.com
# or webroot mode if Apache/nginx is already serving :80
sudo certbot certonly --webroot -w /var/www/html -d cdn.example-content.com

# Auto-renew (certbot installs a systemd timer / cron by default); verify:
sudo certbot renew --dry-run
```

The team server can present its own internal cert to the redirector (proxy verification disabled on the redirector side). Only the cert the *target* sees needs to be publicly valid. Also mind the TLS fingerprint (JARM/JA3S) of the listener itself — see [c2-frameworks.md](c2-frameworks.md) for tuning that.

---

## Domain Categorization and Reputation
Proxies and secure web gateways block uncategorized and newly-registered domains. You want an aged domain in a benign category (e.g., "business", "technology", "health") before the engagement.

- **Aged / expired domains**: buy a previously-registered domain with existing category and clean reputation (ExpiredDomains.net; check history on the Wayback Machine). Fresh registrations trip newly-registered-domain (NRD) filters for weeks.
- **Categorization**: submit/verify category with the target's proxy vendor's tools (e.g., Palo Alto Test-A-Site / URL category, Bluecoat/Symantec SiteReview, Cisco Talos, Zscaler ZULU, Forcepoint). Recategorize your domain to something innocuous *before* go-live.
- **Reputation warmup**: serve a plausible benign site on `/` (a copy of a real corporate/blog page) so a manual analyst visit looks legitimate, not a blank Apache page.
- **Check for burns**: verify the domain/IP is not already on threat feeds (VirusTotal, urlscan.io, ThreatFox). Never use domains a scanner has already fingerprinted as C2.

---

## Domain Fronting and Domainless Fronting
Domain fronting hides the true C2 host behind a high-reputation CDN domain: the TLS SNI / outer Host says `allowed-cdn-domain.com`, while the inner HTTP `Host:` header routes to your origin on the same CDN. Egress filtering sees only the trusted domain.

**Current viability caveat (time-dependent, verify before relying on it):** the major providers that made fronting powerful have all disabled it — AWS CloudFront and Google (2018), Cloudflare (2015), Microsoft Azure Front Door / CDN (new resources Nov 8 2022; existing resources Jan 8 2024), and Fastly (Feb 27 2024). These platforms now reject requests where the SNI and Host header mismatch. Public research in 2024 reported fronting still functional on a majority of *smaller* CDNs, but it lost the property that mattered: fronting through a domain a censor/defender cannot afford to block. **Treat classic domain fronting on Tier-1 CDNs as dead; confirm the specific provider's current policy before designing around it.**

```
# Concept only — outer TLS to the CDN edge, inner Host to your origin
GET /api/v2/updates HTTP/1.1
Host: your-c2-origin.cdn-provider.net      <-- inner: real origin
# TLS SNI / connect target: ajax.trusted-cdn.com   <-- outer: fronted domain
```

**Domainless fronting** (a.k.a. SNI-less / empty-SNI or "front without a front domain"): rather than borrowing another tenant's domain, you omit or manipulate the SNI while still routing via the CDN, so no *victim* domain is impersonated. Viability is equally CDN- and time-dependent; some CDNs that block SNI/Host mismatch still route on an absent SNI. Test against the actual provider — do not assume.

**CDN behavior that matters**: the front works only when the CDN routes on the inner Host header independently of SNI, and only when the fronted domain and your origin sit on the *same* CDN edge. When a provider "blocks fronting" it starts enforcing SNI==Host.

---

## Cloud / CDN Redirectors
Fronting aside, cloud services still make excellent *redirectors* because their domains are inherently categorized and trusted, and the egress just sees `*.cloudprovider.com`.

- **CDN pull-through**: point a CDN distribution at your redirector origin; targets talk to the CDN edge domain. Traffic is TLS to a trusted provider.
- **Serverless redirectors**: AWS Lambda + API Gateway, Azure Functions, Cloudflare Workers, or GCP Cloud Functions can forward matching requests to the team server. Cheap, elastic, hard to attribute, and the domain is trusted.
- **Reputable-service C2 (a.k.a. "living off trusted sites")**: some operations tunnel C2 through legitimate SaaS APIs (cloud storage, collaboration, code-hosting, or serverless-app domains). Blends into normal egress but is increasingly monitored — check the target's DLP/CASB posture.

Cloud redirectors still front nothing sensitive: keep the team server private and only the redirector's egress reaches it.

---

## DNS C2
DNS C2 tunnels beacon traffic in DNS queries/responses to an authoritative name server you control. Slow and noisy in volume, but survives environments that only allow DNS egress, making it a solid long-haul channel.

Setup requires delegating a subdomain to your server:

```
# At your domain registrar / DNS host, delegate a zone to your C2 host:
#   ns1.c2domain.com    A       <c2-server-ip>          (glue / A record)
#   c2.c2domain.com     NS      ns1.c2domain.com        (delegate the zone)
# The C2 framework runs an authoritative resolver for c2.c2domain.com and
# reads data out of subdomain labels of queries it receives.
```

```bash
# Verify delegation resolves to your box before deploying the beacon
dig NS c2.c2domain.com +short
dig A test.c2.c2domain.com @ns1.c2domain.com +short

# On the C2 host, free port 53 if systemd-resolved is holding it
sudo systemctl disable --now systemd-resolved
```

OPSEC: keep query rate low (long sleep) and label lengths/entropy plausible — high-entropy, high-frequency TXT/A lookups to one zone are a classic tunneling signature. Prefer it as long-haul, not interactive. Framework-specific DNS listener config lives in [c2-frameworks.md](c2-frameworks.md).

---

## Malleable C2 Profiles (Concepts)
A malleable profile is a spec that shapes what the C2 traffic looks like on the wire so it mimics benign traffic and matches your redirector's filter rules. Concepts are portable across frameworks even though syntax differs — keep tool-specifics in [c2-frameworks.md](c2-frameworks.md).

What a profile controls:
- **URIs / paths**: the request paths the beacon uses (must match the redirector allow-list exactly).
- **HTTP verbs and structure**: GET for polling, POST for data; where tasking/output is carried (URI param, header, cookie, body).
- **Headers**: `Host`, `User-Agent`, `Accept`, `Cookie`, custom headers — set to impersonate a specific browser/app or legitimate API client.
- **User-Agent**: one exact string; the redirector filters on it, so it must be identical on both sides.
- **Data transforms**: how tasking/output is encoded and wrapped — base64/base64url, netbios, mask/XOR, prepend/append, appended to a header or nested in a JSON/HTML body so it reads as normal content.
- **Sleep and jitter**: base callback interval plus random jitter percentage; long sleep + high jitter defeats fixed-beacon-interval detection.
- **TLS characteristics**: cert fields and, where supported, the JA3/JARM-affecting settings of the listener.
- **Server-side response**: what the C2 returns to non-beacon/decoy requests, and the fake headers/body wrapping real responses.

The profile, the redirector filter, and the served decoy must all tell the same story. A UA in the profile that the `.htaccess` does not allow = dead beacons.

---

## Redirector Health and Monitoring
A silently-dead redirector loses your access. Monitor them, but from infra that is not attributable to the operation.

```bash
# Simple external health check (run from a neutral monitoring box, not the team server)
# - confirms TLS is up and the decoy/redirect still responds
curl -sS -o /dev/null -w "%{http_code} %{ssl_verify_result}\n" https://cdn.example-content.com/

# Confirm the C2 path still proxies (expect the team server's expected response/redirect)
curl -sS -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit" \
     -o /dev/null -w "%{http_code}\n" https://cdn.example-content.com/api/health

# Watch for the redirector being scanned/blocked: tail proxy logs for unexpected UAs/paths
```

Signals a redirector is burned: sudden 302-to-decoy for your own beacons (filter drift or block), the domain flipping category to "malware"/"command and control", or the VPS IP appearing on urlscan/VT. Rotate to a warm standby redirector/domain immediately (this is what the long-haul channel buys you).

---

## Mail Infrastructure (SPF/DKIM/DMARC)
For phishing delivery (see [initial-access.md](initial-access.md)), the sending domain must pass sender authentication or it lands in spam/quarantine. Configure all three on your phishing domain.

```dns
; SPF — authorize your sending host(s)
example-content.com.   TXT   "v=spf1 a mx ip4:<sending-server-ip> -all"

; DMARC — publish a policy so receivers trust aligned mail (start at p=none while warming)
_dmarc.example-content.com.  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@example-content.com; adkim=r; aspf=r"
```

```bash
# DKIM: generate a key, publish the public half, sign outbound mail (OpenDKIM/postfix)
opendkim-genkey -s selector1 -d example-content.com
# publish selector1._domainkey.example-content.com  TXT  "v=DKIM1; k=rsa; p=<public-key>"

# Verify before sending campaign traffic
dig TXT example-content.com +short
dig TXT selector1._domainkey.example-content.com +short
dig TXT _dmarc.example-content.com +short
# Send a test to a mail-tester service and confirm SPF/DKIM/DMARC all pass + not on RBLs
```

Notes: warm the domain (low volume first, `p=none` initially), keep sending IP off blocklists (check Spamhaus etc.), and align the visible From domain with the authenticated domain. Look-alike/typo-squat domains help pretext but hurt deliverability if brand-new — age and warm them.

---

## OPSEC of Infrastructure
- **Segmentation**: separate hosts and domains per function (phish / staging / short-haul / long-haul / exfil). One burn must not cascade.
- **Disposable VPS**: treat redirectors as cattle. Provision with automation (Terraform/Ansible) so you can rebuild a burned redirector in minutes with a fresh IP.
- **Team server is never exposed**: no public C2 listener; firewall to redirector IPs only; manage over SSH/VPN from a bastion, not from your daily machine.
- **Attribution hygiene**: register domains and buy VPS through channels not tied to your identity/organization; avoid reusing IPs, SSH keys, TLS certs, or WHOIS details across engagements or between infra tiers.
- **Logging**: keep redirector and team-server logs (they are engagement evidence and help deconflict with the blue team), but store them off the exposed hosts and scrub before any hits the target's view.
- **Deconfliction**: keep an inventory of every domain/IP/cert so you can answer the client "was that you?" and so you can cleanly tear everything down at end of engagement (see [opsec-and-lifecycle.md](opsec-and-lifecycle.md)).
- **Rotation**: rotate redirectors/domains on a schedule and immediately on any burn indicator; keep warm standbys so the long-haul channel can redeploy a fresh short-haul channel.
