# Surface map

Phases describe where a **candidate** is, inferred from evidence. Several candidates sit at different phases at once, and the load set for a turn is the union of what the live ones need, deduplicated and capped at roughly six files.

## Phases

| Phase | A candidate is here when | Load set |
|---|---|---|
| **SURFACE** | Target chosen, attack surface not yet mapped | `ctf-web/whitebox-review.md`; add `ctf-web/api-security.md` for a service, `ctf-reverse` for a native or compiled target |
| **HUNT** | Surface mapped, looking for the flaw | The sink files for the language and bug class — see the table below |
| **PROVE** | A suspected flaw needs a reproducer | `ctf-pwn` for memory safety, otherwise the bug-class file already loaded; plus a local lab |
| **ASSESS** | It reproduces; impact and versions unknown | `ctf-pentest/reporting.md` for CVSS vector construction and severity rationale; `ctf-web/cves.md` for comparable published CVEs in the same bug class |
| **DISCLOSE** | Validated, going to the maintainer | `disclosure.md`, `ctf-writeup` |
| **PUBLISH** | Fix shipped or embargo expired | `disclosure.md` (Publishing), plus the `f0undm3` pack's `references/writeup-standard.md` if installed. `ctf-writeup` is CTF-shaped — use its prose guidance, not its flag/event template |

## Mapping the surface

Before hunting, know what an attacker can actually reach. Answer these four in the state file — vague answers here produce weeks of unfocused grepping.

1. **Entry points.** What accepts untrusted input? Network listeners, HTTP routes, CLI arguments, file parsers, environment variables, deserializers, IPC.
2. **Trust boundaries.** Where does data cross from untrusted to trusted? That line is where the bugs are.
3. **Privilege.** What runs as root, as a service account, or inside a sandbox that something else relies on?
4. **Dependencies.** What does it pull in, and what does it expose *through* those dependencies? A flaw in a parser reached from your target's public API is your target's problem too.

```bash
# Orient in an unfamiliar repository
cloc . 2>/dev/null || tokei
git log --oneline -20
cat SECURITY.md 2>/dev/null

# Entry points, roughly
grep -rnE "@(app|router)\.(get|post|put|delete)" --include=*.py .
grep -rnE "(app|router)\.(get|post|use)\(" --include=*.js .
grep -rn "func main" --include=*.go .
```

## Hunting: sinks by bug class

Taint tracking is the method — find a dangerous sink, then walk backwards to see whether untrusted input reaches it. `ctf-web/whitebox-review.md` carries the per-language sink tables; this is the routing to the file that covers each class.

| Suspected class | Load |
|---|---|
| Command execution from user input | `ctf-web/server-side-exec.md` |
| Deserialization, gadget chains | `ctf-web/server-side-deser.md` |
| SQL and query injection | `ctf-web/sql-injection.md` |
| Path traversal, LFI | `ctf-web/server-side.md`; `ctf-web/server-side-advanced.md` for traversal bypasses and zip-symlink traversal |
| File upload, archive extraction, ZipSlip | `ctf-web/server-side-exec.md` |
| Prototype pollution, Node internals | `ctf-web/node-and-prototype.md` |
| SSRF, URL fetchers, webhooks | `ctf-web/server-side.md`, `ctf-web/api-security.md` |
| Request smuggling, parser differentials | `ctf-web/request-smuggling.md`, `ctf-web/json-parser-differentials.md`, `ctf-web/html-parser-differentials.md` |
| Authentication, session, token handling | `ctf-web/auth-and-access.md`, `ctf-web/auth-jwt.md` |
| Race conditions, TOCTOU | `ctf-web/race-conditions.md` |
| Memory safety in C/C++/Rust `unsafe` | `ctf-pwn`, `ctf-reverse` |
| Allocator or parser internals | `ctf-pwn/custom-allocator-audit.md` |
| Cryptographic implementation | `ctf-crypto` |
| A dependency that looks deliberately hostile | `ctf-malware`, and read `disclosure.md` first |

Two shortcuts worth taking early on any codebase:

- **Grep the test suite for security tests.** What a project already tests for tells you what it has been bitten by, and adjacent untested paths are where the same mistake survives.
- **Read the last two years of security fixes.** Same authors, same idioms, same blind spots.

## Patch diffing

The highest-yield way into an unfamiliar project. A shipped security fix tells you where the author knew they had a problem — and fixes are frequently incomplete.

```bash
# The commit that fixed it
git log --oneline --grep="security\|CVE\|vulnerab\|overflow\|injection" -i | head -30
git show <commit>

# What changed between the vulnerable and fixed release
git diff v1.2.3..v1.2.4 -- src/
```

Read the diff for four things:

1. **What was the bug?** Reconstruct the flaw from the fix. The fix's shape usually reveals it — a bounds check added, an escape introduced, a type coerced.
2. **Is the fix complete?** Does it cover every path to the sink, or only the one that was reported? Incomplete fixes are the single most productive finding in this whole method.
3. **Does the same mistake appear elsewhere?** Grep the codebase for the pattern that was fixed. Authors repeat themselves.
4. **Do forks and vendored copies still carry it?** Widely-vendored code stays vulnerable in downstream projects long after upstream ships a fix.

A silent fix — a security bug repaired with no advisory and a vague commit message — is worth attention. Users on old versions do not know they need to upgrade, and that is worth raising with the maintainer even when you were not the one who found the original bug.

## Proving it

A candidate becomes a finding when it reproduces on a build you control.

```bash
# Build the vulnerable version in a container you own
git checkout v1.2.3
docker build -t target-audit:1.2.3 .

# Establish which versions are affected
git bisect start <bad-commit> <known-good-commit>
```

**For package-manager targets, the repository is not the artifact.** What users install is the published tarball or wheel, which routinely differs from the tagged source — build steps, bundled dependencies, and files excluded by `.npmignore` all diverge. Enumerate published versions with `npm view <pkg> versions --json` or `pip index versions <pkg>`, fetch the actual artifact with `npm pack <pkg>@<ver>` or `pip download --no-deps --no-binary :all:`, and test **that**. Bisect over published versions to bound the affected range, then use `git bisect` only to find the introducing commit once the range is known.

Minimize hard. Cut input, configuration, and setup until removing anything else makes it stop reproducing. Then write it down as exact steps someone else can follow without asking you a question.

Never confirm a source-code finding by testing it against a live third-party deployment. That converts legitimate research into unauthorized access, and it is unnecessary — a local build proves the same thing.

## Assessing

Before disclosure, settle four things and record them:

- **Affected versions**, ideally an introducing commit and the first fixed one.
- **CWE class** — the standard category for the flaw.
- **Attacker prerequisites** — network position, authentication, configuration, timing. A bug needing an unusual non-default setting is still real but rates lower, and saying so plainly builds trust.
- **What the attacker gains** — code execution, data disclosure, privilege escalation, denial of service.

Rate severity honestly with a CVSS vector. Inflated severity is the fastest way to lose a maintainer's attention, and it tends to get corrected in public.
