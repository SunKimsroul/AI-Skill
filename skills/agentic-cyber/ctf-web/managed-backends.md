# CTF Web - Managed backends and direct client APIs

Use this only for the supplied CTF service, source bundle, or an explicitly authorized local lab. A browser-visible project URL or anonymous client key is not automatically a vulnerability; the question is whether the server's policy mistakenly grants the browser role access to challenge data.

## Recognize the pattern

Look for SDK initialization in JavaScript bundles, mobile clients, environment files, or browser requests:

- Supabase project URL plus an anonymous key, PostgREST `/rest/v1`, storage, realtime, or edge-function routes;
- Firebase/Appwrite-style client configuration, direct database calls, public storage references, or user-token claims;
- a UI that reads/writes tables directly rather than through a custom backend.

Map the identities separately: unauthenticated/anonymous client, normal challenge account, elevated account, service role (if any), and the backend's row/object policy. Never equate a public client configuration value with a privileged service secret.

## CTF-first workflow

1. Capture one normal UI action and preserve the exact endpoint, method, identity headers, table/bucket/function name, filters, and response shape.
2. Inspect the shipped client source to determine which backend object the feature is intended to access. Prefer challenge-provided names and paths over blind enumeration.
3. Test the smallest policy hypothesis on the declared target: can the anonymous role read only its expected object, or does the backend return a row/object that should be restricted?
4. Compare select, insert, update, delete, storage, realtime subscription, and RPC/function surfaces separately. A policy can protect one operation while exposing another.
5. Confirm the result through a clean request that uses only the role/configuration available to the challenge client. Record the request/response evidence and stop once the intended flag-bearing record is proven.

## Common reasoning errors

- **Treating an anonymous key as a credential leak:** in many managed-backend designs it is intentionally client-visible; the security boundary is server-side authorization.
- **Confusing authentication with authorization:** a valid user session does not prove that a row-level/object-level rule is correct.
- **Ignoring alternate surfaces:** a table policy may be strict while storage, realtime, an RPC function, or an older API path is permissive.
- **Over-enumerating:** start from the client behavior and the challenge description; broad probing is unnecessary for a reproducible CTF solve.

## Pivot rules

- Load `/ctf-crypto` when a challenge depends on JWT signature verification or custom token math rather than backend policy.
- Load `/ctf-forensics` when the input is a cloud audit log, database export, or CI artifact rather than a live CTF service.
- Load `/ctf-web` auth notes for OAuth/OIDC account linking or application-side session confusion.

## Source-backed pattern

ImaginaryCTF 2025's *imaginary-notes* used a frontend Supabase configuration plus an overly permissive row-level policy on a challenge table. The transferable lesson is to distinguish the intended public client configuration from the backend authorization policy and to validate the smallest direct API read against the declared CTF target: [CTFtime writeup](https://ctftime.org/writeup/40428).
