# Report quality gates

Use these gates in audit mode and before delivery. An error blocks a claim of “submission-ready.” A warning requires manual review because official formats vary.

## Gate 1 — Rule compliance

- The current official rules or their absence are stated.
- Required format, filename, identifiers, objective evidence, and deadline/time-zone rules are mapped to the report.
- No material is included that the rules prohibit.
- Generic template guidance has not been presented as an official vendor requirement.

## Gate 2 — Scope and factual integrity

- Every target and action described is inside the stated authorized scope.
- Observations, inferences, recollections, and unverified claims are distinguishable.
- No command, result, screenshot, timestamp, CVE, CVSS score, identity, or objective was fabricated.
- Contradictory source material is resolved transparently or documented as a limitation.

## Gate 3 — Traceability

- Every successful transition in the attack path has a command/action record, decisive output, explanation, and direct evidence reference. Source-only transitions are labeled partial or unverified.
- Every result-table claim maps to a detailed section.
- Every figure is cited in the prose and indexed.
- Every evidence and command ID resolves to one canonical item.
- Note-derived transcripts are cited as `SRC-*`, not promoted to `E-*`, and their missing originals are tracked when material.
- Each final objective has direct proof that satisfies the verified rules.

## Gate 4 — Reproducibility

- The starting state, source host, target, user/privilege, working directory, prerequisites, and dependency versions are present where material.
- Commands are exact, copyable, ordered, and separated from output.
- Non-obvious flags and substituted values are explained.
- Interactive or GUI actions include navigation and input details.
- Expected and observed results are both stated.
- Side effects, cleanup, timing sensitivity, and known nondeterminism are documented.
- A safe independent reproduction was performed when authorized and feasible; otherwise the report says `Not independently retested`.

## Gate 5 — Evidence quality

- Screenshot links resolve and images are legible.
- Captions state what each image proves.
- Target and decisive result context are visible as required.
- Originals are preserved; redactions or crops are labeled and do not alter meaning.
- Large output is preserved separately and report excerpts are faithful.
- Evidence gaps are visible to the author and never filled with simulated material.

## Gate 6 — Technical and narrative quality

- The root cause is identified; the report does not confuse a tool name with a vulnerability.
- The attack chain is chronological or explicitly dependency ordered.
- The executive summary agrees with the detailed results.
- Severity and impact are proportionate to demonstrated evidence.
- Remediation addresses the root cause and includes a usable retest.
- Failed attempts are included only when they add reproducibility or decision context.
- Terminology, target IDs, hostnames, addresses, usernames, and time zone are consistent.

## Gate 7 — Submission hygiene

- No unresolved `{{placeholder}}`, `TODO`, `TBD`, instructional comment, broken link, or empty section remains.
- No shell prompts were accidentally included in copyable command blocks.
- Secrets and personal data follow the intended controlled or sanitized version policy.
- The table of contents, figure numbering, internal links, page conversion, and file naming have been checked in the final delivery format.
- The final file opens correctly on a second machine or clean viewer when practical.
- The author retains a backup of the submitted file and permitted supporting evidence.

## Manual sign-off

Record the result in a private checklist:

```text
Official rules verified: yes / no — source:
All objectives traced to proof: yes / no — gaps:
All commands checked against raw records: yes / no
All image links and captions checked: yes / no
Independent reproduction: yes / no / not authorized
Strict validator result: pass / fail
Final-format visual inspection: pass / fail / not performed
Submission-ready: yes / no
Reviewer/date/time zone:
```

Do not leave this sign-off in the official report if the exam format disallows it.
