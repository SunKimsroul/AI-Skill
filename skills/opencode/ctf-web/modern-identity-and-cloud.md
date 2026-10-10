# Modern identity, passkeys, and cloud-IaC CTF workflow

Use this note when a CTF web target exposes WebAuthn/passkeys, an identity-provider callback, a cloud deployment artifact, or infrastructure-as-code. Work only against the supplied challenge instance or an explicitly authorized lab.

## WebAuthn / passkey triage

The browser submits a signed assertion; the server must bind it to the exact authentication ceremony. Do not treat a credential ID or a successful browser prompt as proof that the backend validation is correct.

1. Record the registration and authentication endpoints, JSON payloads, cookies, and the relying-party domain.
2. Locate where the server persists the challenge, credential ID, public key, user handle, counter, and user-verification requirement.
3. Compare every assertion check with the expected ceremony state:
   - challenge is fresh, single-use, and tied to the current session;
   - `type` is `webauthn.get` or `webauthn.create` as appropriate;
   - origin and RP ID hash are exact, not suffix or substring matches;
   - credential belongs to the account selected by the server, not merely an attacker-provided user ID;
   - signature is verified over `authenticatorData || SHA256(clientDataJSON)` with the stored public key;
   - user-presence and, where required, user-verification flags are enforced;
   - sign-counter handling has an explicit policy for rollback, cloned authenticators, and zero counters.
4. In a CTF, turn a suspected omission into the smallest local proof: replay a captured assertion only after isolating which server-side binding is absent. Do not test real accounts without scope.

### Common challenge shapes

- **Challenge replay:** the server accepts a signed assertion after the session, action, or challenge lifetime changed.
- **Origin/RP confusion:** a loose origin parser, proxy header, or tenant/domain mapping validates the wrong origin or RP ID.
- **Credential/account confusion:** the request chooses `user_id`, `credential_id`, or `allowCredentials` while the server fails to bind all three to the same account.
- **Registration-to-admin chain:** a registration option, attestation result, or “resident key” branch grants a role before the credential is correctly verified.
- **Fallback downgrade:** password, recovery, OAuth, or API-token endpoints bypass a constraint that the passkey-protected route enforces.

Avoid assuming that a missing counter increment alone is an exploit: many authenticators legitimately report a zero counter. The decisive question is whether a replay changes an authorization-relevant state in the supplied challenge.

## Identity-flow adjacency

For OAuth/OIDC/SAML, use `auth-infra.md`; add this checklist before chaining it with passkeys:

- bind `state` and `nonce` to the initiating browser session and intended provider;
- require PKCE where a public client uses an authorization code;
- normalize and compare redirect URIs as parsed origins/paths, never with prefix checks;
- validate issuer, audience, authorized party, key selection, and token type before linking an identity;
- treat account linking, recovery, and invite acceptance as separate authorization transitions.

## Cloud and IaC artifacts

CTF cloud challenges commonly hide the useful boundary in a repository, CI definition, Terraform state, Docker image, or deployment manifest rather than a live cloud console.

1. Inventory supplied `.tf`, `.tfstate`, plan JSON, Helm chart, Kubernetes manifest, workflow, image layer, and environment sample files.
2. Search state and outputs for identifiers, buckets, roles, endpoints, image tags, callback URLs, and intentionally seeded credentials. Treat any secret as challenge-only evidence; never reuse it outside the declared instance.
3. Reconstruct trust edges: CI identity -> cloud role -> artifact registry -> deployment -> workload identity -> internal service.
4. Compare intended policy with effective policy. Look for wildcard principals, overly broad workload identity bindings, mutable artifact tags, public object ACLs, metadata-token forwarding, and unscoped deployment variables.
5. Prefer an offline proof from the supplied plan/state. Query a live cloud API only when the CTF explicitly provides that target and credentials.

### Useful files and clues

| Artifact | Questions |
|---|---|
| `terraform.tfstate` / plan JSON | Does it expose outputs, role ARNs, service-account bindings, bucket names, or old values? |
| CI workflow | Which branch, event, actor, or artifact controls the cloud identity? |
| Helm/Kubernetes manifest | Is a service account, hostPath, token mount, image tag, or admission policy over-trusted? |
| Container image | Are build arguments, layers, package registries, or entrypoints different from the repository? |
| Proxy/config map | Can host, scheme, callback, or metadata URL be influenced across a trust boundary? |

## Repository-to-CI Artifact Trust

For supplied Gitea/GitLab/GitHub-like repositories and CI definitions, model the execution provenance before treating a pipeline as a black box:

1. Map each trigger to the revision and actor it executes: branch push, pull/merge request, fork, manual run, scheduled job, tag, or cached rebuild.
2. Trace every fetched executable or build input—provider/plugin, action, container image, package, script, artifact, and remote module—to its URL, version pin, hash/signature check, and cache location.
3. Compare repository write permission with CI token, secret exposure, runner scope, and deployment identity. A read-only repository view can still expose a challenge-specific artifact substitution or trigger boundary.
4. Reproduce only with the supplied CTF repository/runner or an offline mock. Prefer proving that a mutable ref or unverified artifact reaches a privileged build step over guessing the final effect.

**Validation:** Record the exact revision, triggering event, artifact digest/path, and CI job that establishes the edge. Separate a source-code change, a configuration change, a dependency/artifact change, and a deployment action—they are different authorization boundaries.

## Evidence record

Preserve the original assertion/options JSON, a redacted state/plan excerpt, request/response pairs, and the exact validation delta that explains the solve. State whether a result is a fact from source, a hypothesis, or a verified challenge-only proof.

## Sources for further reading

- [MDN: Passkeys and WebAuthn](https://developer.mozilla.org/en-US/docs/Web/Security/Authentication/Passkeys)
- [DiceCTF/Hacking the Cloud: CI/CDon't CTF walkthrough](https://hackingthe.cloud/aws/capture_the_flag/cicdont/)
