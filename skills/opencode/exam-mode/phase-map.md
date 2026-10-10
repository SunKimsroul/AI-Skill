# Phase map

A phase is a description of **where a given host currently is**, inferred from evidence. It is not a stage you advance through on a schedule, and the table is not an order of operations. A host can sit in one phase for hours, skip three, or move backwards when a credential turns out to be stale.

Every host in the state file carries its own phase. The load set for a turn is the union of what the live host phases need.

## The phases

Each phase has a **core** — one or two files loaded whenever any host is in that phase — and
**conditionals**, loaded only when their signal is actually present. Cores are what makes the union
fit: several hosts in different phases contribute two files each, not six.

| Phase | You are here when | Core (always) | Conditional (only on its signal) |
|---|---|---|---|
| **SCOPE** | No state file exists yet | Intake only — see `constraints.md` | — |
| **RECON** | Targets known, no access to them | `ctf-pentest/enumeration-recon.md` | `ctf-web/web-recon.md` if an HTTP port; `ctf-ad/enumeration.md` if a domain is visible |
| **FOOTHOLD** | A service or application is identified, no shell yet | `ctf-pentest/common-services.md` | the surface file from the signal table; `ctf-pentest/shells-and-payloads.md` once a payload is needed; `ctf-pentest/password-attacks.md` if a login is the surface |
| **PRIVESC** | A shell is held, but not root, SYSTEM, or Administrator | `ctf-privesc/linux-privesc.md` **or** `ctf-privesc/windows-privesc.md` (never both) | `ctf-pentest/password-attacks.md` if hashes or a keystore were found |
| **LATERAL** | A credential, hash, or ticket is in hand and other hosts exist | `ctf-ad/credential-access.md`, `ctf-ad/enumeration.md` | `ctf-ad/kerberos.md` for roasting/delegation; `ctf-ad/lateral-movement.md` once a target host is chosen; `ctf-ad/ntlm-relay.md` if signing is not required or a machine account is coercible; `ctf-pivoting/pivoting.md` if a segment is unreachable; `ctf-pentest/password-attacks.md` before any spray |
| **DOMINANCE** | A path to domain or enterprise admin is visible | `ctf-ad/domain-dominance.md`, `ctf-ad/acl-abuse.md` | `ctf-ad/adcs.md` only if a CA is present; `ctf-ad/trusts.md` only if a second domain or forest exists; `ctf-ad/sccm.md` only if SCCM is present |
| **REPORT** | See the trigger below | `ctf-pentest/reporting.md`, `ctf-writeup` | the `f0undm3` pack's `references/writeup-standard.md` **if that pack is installed** — the core two are self-sufficient without it |

**Check the domain lockout policy before spraying a recovered credential across hosts.** Locking out the account you just earned, or a real user's, is the classic self-inflicted wound in this phase and it is unrecoverable inside an exam window. `ctf-pentest/password-attacks.md` carries the policy and lockout section; read it before the first spray, not after.

`ctf-ad/enumeration.md` is in LATERAL's **core**, not just RECON's, and that placement is deliberate:
the first move on obtaining any domain credential is authenticated enumeration — BloodHound
collection above all — and that file is where it lives. A LATERAL set that omits it sends you
hunting for a path you have not yet mapped.

Load `ctf-ad/methodology.md` once, the first time a domain enters the picture, as the end-to-end
playbook that orients the rest of the AD files. Count it against the cap for that turn only; after
it has been read once it does not need re-emitting.

## Entering somewhere other than RECON

Read the start condition before assuming a scan is the first move.

- **Assumed breach** — credentials are issued with the exam and no exploitation is needed to get a session. Enter at **LATERAL** directly. Do not burn the first hour port-scanning an external perimeter that was never part of the task.
- **Whitebox** — application source code is supplied. Enter at **FOOTHOLD** with `ctf-web/whitebox-review.md` loaded, and trace user input to dangerous sinks before touching the running application at all.
- **Single host, no network** — no LATERAL or DOMINANCE will ever apply. Say so, and put the saved time into enumeration depth and the report.
- **Shell already provided** — enter at **PRIVESC**.

## Signal table

Evidence to material. Deliberately short: `solve-challenge` already owns the broad keyword-to-category table, and duplicating it here would only let the two drift apart. These are the signals that actually show up on exam infrastructure.

| Observation | Add to the load set |
|---|---|
| 88, 389, 636, 445, or 464 open; a `DC*` hostname; a domain in a certificate | `ctf-ad/enumeration.md` |
| 80, 443, 8080, 8443, or any HTTP title | `ctf-web/web-recon.md` |
| Application source code supplied | `ctf-web/whitebox-review.md` |
| `unserialize` / `pickle` / `readObject` / `BinaryFormatter` reachable from user input | `ctf-web/server-side-deser.md` |
| A login form, API, or token in the response | `ctf-web/auth-and-access.md`, `ctf-web/auth-jwt.md` |
| Database error text or a parameter that changes result sets | `ctf-web/sql-injection.md` |
| A file upload or import feature, a writable path over HTTP, or `move_uploaded_file` in source | `ctf-web/server-side-exec.md` (upload-to-RCE, ZipSlip, phar) |
| A template rendering user input, or a command built from a parameter | `ctf-web/server-side.md`, `ctf-web/server-side-exec.md` |
| Low-privileged shell held | `ctf-privesc/linux-privesc.md` or `windows-privesc.md` |
| A host reachable only through another host | `ctf-pivoting/pivoting.md` |
| Hash, ticket, or cleartext credential recovered | `ctf-ad/credential-access.md` |
| SMB signing not required, or a coercible machine account (PetitPotam, PrinterBug) | `ctf-ad/ntlm-relay.md` |
| MSSQL on 1433 inside a domain | `ctf-ad/mssql.md` |
| A certificate authority, or `ADCS`/`certipy` in evidence | `ctf-ad/adcs.md` |
| SCCM or MECM present | `ctf-ad/sccm.md` |
| A second domain or a trust relationship visible | `ctf-ad/trusts.md` |
| Native binary plus a reproducible crash | `ctf-pwn` (the SKILL.md routes from there) |
| A binary whose behaviour is the blocker | `ctf-reverse` (the SKILL.md routes from there) |
| Intake recorded that evasion is graded | `ctf-redteam`, `ctf-ad/evasion.md` — on every phase |

## Building the union

With several hosts live, build the set in this order rather than concatenating whole phases:

1. **Take every live phase's core.** Deduplicate. Two hosts in the same phase contribute those files once.
2. **Add conditionals whose signal is actually present**, newest evidence first. A conditional whose
   signal has not been observed is not loaded — `adcs.md` without a CA and `trusts.md` without a
   second domain are the usual offenders, and each one spends a slot that the live path needed.
3. **Stop at six.** Anything that did not fit goes to Open threads by name.

**One host in two phases is routine, not an error.** A `www-data` shell that yielded a domain
credential is simultaneously PRIVESC and LATERAL. Take the **newer** phase's core in full and the
older phase's core only if a slot remains — progress usually lies along the newer one. Record both
phases on the host row so the older one is not lost.

If the cores alone exceed six, you have too many hosts genuinely live at once. Work the host that
unblocks the most others first — usually the one holding a credential others will accept, or the
only route into a segment — and defer the rest **by name**, in the response and in the state file.
A deferred host that nobody wrote down is exactly the host found unenumerated at hour twenty.

## Moving backwards

Phases regress, and a regression is information rather than a mistake.

- A credential stops working — that host returns to LATERAL, and the credential is marked stale in the state file rather than deleted. Knowing it *was* valid and when it stopped is evidence.
- A shell dies and will not come back — return to FOOTHOLD and record what the access was, since the report needs the original path regardless of whether the session survived.
- Enumeration turns up a service missed the first time — that host is RECON again for that service, even while another service on it is at PRIVESC.

## Entering REPORT

REPORT is entered when **every objective in the state file's Objectives and proof table is captured**,
or on the time trigger below. Because objectives are recorded at intake, "every objective is met" is
a table you can actually check rather than a judgement call.

**The time trigger depends on the clock answer recorded at intake.** Intake asks whether report time
sits inside the exam window or is a separate window afterwards, and the two cases behave differently:

- **Report time inside the window** (HTB CPTS-style, one clock for everything) — enter REPORT at
  **20% of the window remaining**. Writing has to come out of the same budget as hacking, so the
  reserve is not negotiable.
- **Report time separate** (OffSec OSCP-style, a lab window then a distinct report window) — do
  **not** stop hacking at 20%. Keep working the network to the end of the lab window. What the 20%
  mark triggers instead is an **evidence-completeness check**: for every finding so far, confirm the
  command, output, screenshot, and proof artifact are already captured, because the lab disappears
  when the window closes and anything not captured by then is gone for good.
- **Undeclared** — treat it as inside the window. The conservative reading costs some hacking time;
  the wrong reading in the other direction costs the report.

When you do switch, say plainly that you are switching and why. A confirmed chain with no written
evidence scores nothing on any of these exams, while an unfinished network with a clean report on
what was actually achieved still scores. If the user wants to keep hunting after the warning, that
is their call — record the time and keep going.
