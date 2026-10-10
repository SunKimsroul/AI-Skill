# Evidence capture guide

Use this guide in capture mode or whenever raw artifacts are incomplete.

## Establish the evidence set

Keep report material in a portable structure when the environment permits it:

```text
report-project/
|-- report.md
|-- evidence/
|   |-- screenshots/
|   |-- terminal/
|   |-- web/
|   `-- files/
`-- private-notes/
```

The final report should use relative links into `evidence/`. Keep sensitive working notes separate from submission content. Do not copy prohibited exam material into an unapproved location.

## Classify provenance

Use the evidence ID only for an original artifact or a controlled derivative whose original is retained:

| Class | ID | Examples | Permitted claim strength |
|---|---|---|---|
| Direct evidence | `E-<target>-###` | Original terminal log, screenshot, HTTP capture, tool export, proof file | Supports the fact it directly records, subject to integrity and rule checks |
| Secondary source | `SRC-###` | Handwritten notes, copied transcript without the original, recollection, imported narrative | Supports drafting and attribution; does not become direct proof |
| Evidence gap | `GAP-<target>-###` | Missing screenshot, raw output, timestamp, rule source, or target fact | Supports no claim; records what must be resolved |

If only notes remain, preserve the exact note text, assign the notes a `SRC-*` ID, label quoted output `Note-derived transcript`, and create a gap for the missing original when it matters. Never relabel the transcript as raw output.

## Record each decisive action

Capture a ledger row as close to execution time as possible:

| Field | Record |
|---|---|
| Command ID | `CMD-<target>-###` |
| Evidence/source ID | `E-<target>-###` for a direct artifact, or `SRC-###` when the record exists only in a secondary source |
| Timestamp | ISO 8601 with time zone when known |
| Target | Canonical target ID, hostname, and address as allowed |
| Starting state | Source host, user, privilege, working directory, prerequisite access |
| Objective | What the action is meant to determine or achieve |
| Exact action | Exact command, request, UI path, or code used |
| Full output/source | Raw log or capture path; if missing, the `SRC-*` record containing the transcript |
| Decisive observation | The smallest faithful output excerpt supporting the next decision |
| Interpretation | Observed fact, inference, and confidence |
| Resulting state | New access, artifact, knowledge, failure, or no change |
| Next decision | Why the following step is justified |

Do not rely on shell history alone: it omits context, output, working directory, and often multiline content.

## Command capture standard

- Capture the exact command before adapting it for presentation.
- Record the executing host, shell, privilege level, current directory, important environment values, and dependency versions when they affect reproducibility.
- Save large output as a raw text artifact and quote only decisive lines in the report.
- When a command is interactive, record the sequence of inputs, prompts, and responses without exposing secrets contrary to the rules.
- When a GUI or browser action replaces a command, record the URL or application, navigation path, values entered, and visible result.
- Record generated file names and hashes when later steps depend on those files.

## Screenshot capture standard

A strong screenshot proves one important fact. It should normally show:

- enough application or terminal context to identify the real interface;
- the relevant target identity, command, request, or page location;
- the decisive result at readable scale;
- the candidate/exam identifier only when official rules require or permit it;
- no unrelated sensitive data.

Use filenames such as:

```text
E-web01-001-port-discovery.png
E-web01-002-initial-access.png
E-web01-003-objective-proof.png
```

Use a caption that states the evidentiary meaning:

```markdown
![E-web01-002 — Successful authenticated session as the service account](evidence/screenshots/E-web01-002-initial-access.png)

*Figure E-web01-002 — The response and session identity confirm initial access to T-web01 as the service account.*
```

Avoid captions such as “Screenshot of terminal.”

## Preserve integrity

- Keep original artifacts read-only when practical.
- If hashing is allowed and useful, record SHA-256 hashes in the evidence index.
- Store redacted derivatives beside originals with a suffix such as `-redacted`; record what was changed and why.
- Do not resize an image until text becomes unreadable. Do not crop away context that changes interpretation.
- Use a consistent time zone and document any known clock skew.
- Maintain a mapping between each figure in the report and its original artifact.

## Minimum evidence by attack phase

| Phase | Minimum defensible evidence |
|---|---|
| Discovery | Target identity, exact discovery action, decisive result |
| Enumeration | Service or condition found, supporting output, reason it matters |
| Initial access | Exact access path and proof of resulting identity/context |
| Privilege escalation | Starting identity, exploited condition or misconfiguration, elevated identity proof |
| Lateral movement | Source context, destination, prerequisite credential/session, destination identity proof |
| Objective | Required flag/proof/result shown according to official rules |
| Remediation/retest | Change tested, retest action, and observed fixed or remaining behavior |

The official rules may require additional identifiers or screenshot composition. Follow those rules over this baseline.

## Evidence gaps

Use explicit gap records:

```text
GAP-<target>-###
Claim affected:
Missing artifact:
Why current material is insufficient:
Safest authorized recapture action:
Deadline or submission impact:
```

If recapture would require target activity not currently authorized, stop at the gap record.
