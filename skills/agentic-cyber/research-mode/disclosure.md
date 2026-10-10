# Disclosure

Finding the bug is the short part. This is where research either helps a project or damages it, and the difference is mostly process.

## Legal basis

Settle this at intake, before any code runs.

| Situation | What you may do |
|---|---|
| Open-source code you can read | Read it, build it, run it, and attack it **on infrastructure you control** |
| A published bug-bounty or VDP policy | Exactly what the policy's scope allows, and nothing outside it |
| Written permission from the owner | What the permission says |
| Someone else's live deployment, no policy, no permission | Nothing |

The line that matters in practice: **reading source is always fine; running your exploit against someone else's server is not.** A source-code finding never needs a third-party host to confirm it — a local build proves the same thing with none of the exposure.

If a project publishes no security policy and no contact, that is not permission to test their hosted service. It is a reason to look harder for a contact.

## Finding the contact

In order:

1. `SECURITY.md` in the repository root, or the **Security** tab on GitHub.
2. GitHub private vulnerability reporting, if the project has enabled it. This is the best channel when available — it is private, it threads, and it leads directly into a CVE.
3. A security address in the README, the website, or `.well-known/security.txt`.
4. A maintainer's published contact address, for a small project with no process.

**Never open a public issue for a security bug.** A public issue is a disclosure — it tells attackers before it tells users, and it removes the maintainer's ability to ship a fix first. If there is genuinely no private channel, ask the maintainer publicly for one *without describing the bug*.

For a package registry compromise — a package that appears deliberately backdoored rather than merely buggy — go to the registry's security team as well as the project, and go immediately. That is an active incident affecting everyone who installs it, and normal disclosure timelines do not apply.

## The report

Written for a volunteer reading it at the end of a long day. Lead with what matters and keep it plain.

1. **One-sentence summary** — the flaw, the component, the impact.
2. **Affected versions** — confirmed, and how you established them.
3. **Impact** — what an attacker gains, and what they need first. Be honest about prerequisites.
4. **Reproduction** — minimal, exact, and runnable without asking you anything.
5. **Root cause** — the specific code path, with a file and line.
6. **Suggested fix** — a patch if you can write one.
7. **Disclosure intent** — that you will coordinate, and roughly what timeline you have in mind.
8. **Credit preference** — how you would like to be named, or that you would rather not be.

Redact anything sensitive from the reproducer: credentials, tokens, personal data, internal hostnames. The `f0undm3` pack's `references/writeup-standard.md` carries the full redaction rules, and they apply to the report body as much as to the eventual writeup.

State severity with a CVSS vector and be conservative. A maintainer who finds your rating inflated will discount everything else you wrote.

## Coordinated disclosure

The norm is straightforward: report privately, give the maintainer a reasonable window to fix, publish after the fix ships or the window expires.

Common practice is **90 days**, and it is a default rather than a rule. What actually matters:

- **Agree the date explicitly.** An assumed deadline is not an agreed one. Get it written down and record it in the state file.
- **Extend for good-faith effort.** A maintainer who is engaged, has a patch in review, and asks for three more weeks should generally get them. A volunteer project is not a vendor with a security team.
- **Do not extend indefinitely.** Silence, or repeated deferral with no progress, eventually leaves users worse off than publication would. If you reach that point, say clearly and in writing that you intend to publish on a specific date, and why.
- **A shipped fix ends the embargo.** Once users can patch, publication helps them find out they should.

Where a bug affects safety — medical devices, industrial control, vehicles, aviation — the path is different and slower. Involve a national CERT rather than handling it yourself.

## Getting a CVE

A CVE identifies a flaw in a **product**: a library, an application, a plugin, firmware. It is not for a flaw in one organization's own deployment or custom code — that is a bounty or disclosure finding with no CVE at the end.

Routes, easiest first:

1. **GitHub Security Advisory.** For anything hosted on GitHub, the maintainer drafts an advisory in the repository and requests a CVE through it. GitHub is a CNA and issues the ID directly. This is the smoothest path by a distance, and it keeps the maintainer in control — which is where they should be.
2. **The vendor, if they are a CNA.** Most large vendors issue their own CVEs for their own products. Report to them and they assign it.
3. **MITRE's request form.** The fallback when no CNA covers the product.

You will be asked for the affected product and versions, the vulnerability type, the impact, and references.

**Request the ID during the embargo, not after.** CNAs reserve IDs for issues that are not yet public — that is what the RESERVED state exists for. The reserved ID stays private until the record is published, normally at the same moment as the advisory. Getting it early is what lets the maintainer's release notes, the advisory, and downstream distro and scanner tooling all cite the same identifier on the day the fix ships. Waiting until after publication leaves the release with no ID to reference and forces a retroactive fix-up.

**Let the maintainer request it where they are willing.** It is their product, the advisory carries their assessment, and researchers who route around maintainers to claim IDs earn a reputation that follows them.

Do not pursue a CVE for something that is not a vulnerability. Hardening suggestions, theoretical weaknesses with no attacker path, and intended behaviour you disagree with are not CVEs. Filing them wastes maintainer time, and disputed CVEs are a real and ongoing problem for open-source projects.

## Publishing

Once the fix has shipped or the agreed date has passed:

- Use `ctf-writeup` and the `f0undm3` pack's `references/writeup-standard.md`.
- Include the timeline from the state file verbatim. It is what makes a disclosure auditable.
- Open with a vulnerability metadata block rather than a CTF-style header — an advisory is not a challenge writeup, and `ctf-writeup`'s template (event name, category, flag) does not fit:

```markdown
| CVE | CVE-2026-XXXXX |
| CWE | CWE-22 Path Traversal |
| CVSS | 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) |
| Affected | >= 2.1.0, < 2.4.3 |
| Fixed in | 2.4.3 |
| Reported | 2026-03-04 |
| Published | 2026-06-02 |
| Credit | <name, or anonymous> |
```
- Credit the maintainer's responsiveness where it was good. It costs nothing and it makes the next researcher's report more welcome.
- Keep working exploit code out of it where the fix is young. Explaining the flaw fully does not require handing over a weapon while users are still upgrading.

## When it goes wrong

**No response.** Wait a reasonable period, follow up once through a second channel, then state a publication date in writing.

**The maintainer disputes it.** Record their reasoning in the timeline. Sometimes they are right and you have misread the threat model — that is a rejected path, not a defeat. Where you still believe it is real, ask what evidence would change their view, and provide it.

**Someone else reports it first.** Mark the candidate `duplicate` and move on. This happens; it is not worth contesting.

**It is worse than you thought.** If the impact grows during disclosure — the same flaw reaches further than the original report — tell the maintainer immediately rather than saving it. Severity revised upward mid-embargo is normal and manageable; severity discovered after publication is not.
