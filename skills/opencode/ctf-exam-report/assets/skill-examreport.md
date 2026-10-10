<!--
CTF / CERTIFICATION EXAM REPORT TEMPLATE

Use only for an authorized environment. Duplicate the target walkthrough block for
each target or objective. Replace all {{placeholders}}, remove unused optional
sections, and delete instructional comments before submission. Current official
rules override this generic template.
-->

# {{Assessment or Exam Name}} — Technical Report

> **Classification:** {{Confidential / Exam submission / Sanitized shareable copy}}

| Field | Value |
|---|---|
| Candidate | {{Candidate name or permitted identifier}} |
| Candidate/Exam ID | {{Identifier required by current official rules}} |
| Assessment | {{Exam or CTF name and version}} |
| Authorized window | {{Start and end, with time zone}} |
| Report version | {{Version}} |
| Report date | {{YYYY-MM-DD and time zone}} |
| Rules source | {{Current official guide/portal reference, version, or “Not verified”}} |

## Document control

| Version | Date | Author | Change |
|---|---|---|---|
| {{1.0}} | {{YYYY-MM-DD}} | {{Author}} | {{Initial submission}} |

## Table of contents

- [Executive summary](#executive-summary)
- [Scope, rules, and starting conditions](#scope-rules-and-starting-conditions)
- [Source ledger](#source-ledger)
- [Methodology and notation](#methodology-and-notation)
- [Attack-path overview](#attack-path-overview)
- [Detailed target walkthroughs](#detailed-target-walkthroughs)
- [Cross-target findings and remediation priorities](#cross-target-findings-and-remediation-priorities)
- [Evidence index](#evidence-index)
- [Command index](#command-index)
- [Reproduction checklist](#reproduction-checklist)

## Submission compliance

| Official requirement | Source | How this report satisfies it | Status |
|---|---|---|---|
| {{Required format}} | {{Rule reference}} | {{Delivery format}} | {{Verified / Unverified}} |
| {{Required proof}} | {{Rule reference}} | {{Section and evidence IDs}} | {{Verified / Gap}} |
| {{Required identifier}} | {{Rule reference}} | {{Location}} | {{Verified / Gap}} |
| {{Filename/size rule}} | {{Rule reference}} | {{Result}} | {{Verified / Unverified}} |

## Executive summary

### Outcome

{{State the number of authorized objectives achieved and not achieved. Describe the shortest evidence-supported attack path and the final access or result. Do not introduce facts absent from the detailed walkthroughs.}}

### Results at a glance

| Target / objective | Status | Highest demonstrated access | Primary root cause | Proof evidence |
|---|---|---|---|---|
| `T-{{target}}` / {{objective}} | {{Achieved / Partial / Not achieved}} | {{Identity/privilege}} | `F-{{001}}` — {{title}} | {{`E-*` for direct proof; `SRC-*`/`GAP-*` and Partial if direct proof is missing}} |

### Material limitations

{{State evidence gaps, inaccessible systems, timing restrictions, unverified official rules, or steps that were not independently retested. Write “None known” only after checking.}}

## Scope, rules, and starting conditions

### Authorization and scope

| Target ID | Hostname / URL | Address | Objective | In-scope services/actions | Exclusions |
|---|---|---|---|---|---|
| `T-{{target}}` | {{Hostname or URL}} | {{IP/port if permitted}} | {{Objective}} | {{Authorized scope}} | {{Out-of-scope items}} |

### Starting conditions

- Source system: {{Host, OS, and relevant tool environment}}
- Starting identity/access: {{User, role, VPN, credentials, or “none”}}
- Starting directory/context: {{Path or UI starting point}}
- Provided artifacts: {{Files, credentials, wordlists, code, or none}}
- Time zone used: {{IANA or UTC offset}}
- Known clock skew: {{None known or details}}

### Rules and evidence handling

{{Summarize only verified rules that affect actions, screenshots, proof, redaction, or delivery. Explain how originals and any redacted derivatives were handled.}}

## Source ledger

<!-- Use SRC-* for notes and other secondary sources. Do not relabel copied transcripts as original evidence. -->

| Source ID | Source / path | Provenance | Contents used | Integrity / availability | Limitation |
|---|---|---|---|---|---|
| `SRC-001` | {{Notes, recollection, imported report, or other secondary source}} | {{Who/what supplied it and when}} | {{Facts or transcripts used}} | {{Present/hash/unknown}} | {{Why it is not direct proof, or none}} |

## Methodology and notation

The report distinguishes direct observations from interpretation and uses these IDs:

| Prefix | Meaning |
|---|---|
| `T-*` | Target |
| `F-*` | Finding or root cause |
| `CMD-*` | Exact executed command or action record |
| `E-*` | Original or controlled-derivative screenshot, raw output, HTTP capture, or proof artifact |
| `SRC-*` | Notes, recollections, copied transcripts, or another secondary source |
| `GAP-*` | Missing fact or artifact |

{{Briefly describe the actual methodology used. Do not paste a generic methodology that was not followed.}}

## Attack-path overview

```text
{{Discovery observation}}
  -> {{Exploitable condition}}
  -> {{Initial access and identity}}
  -> {{Escalation or pivot}}
  -> {{Final identity/objective proof}}
```

| Transition | Prerequisite | Action / command | Evidence / source | Resulting state |
|---|---|---|---|---|
| {{Discovery -> condition}} | {{Starting state}} | `CMD-{{target}}-{{001}}` | {{`E-*` direct artifact or `SRC-*` secondary record}} | {{Knowledge/access gained}} |
| {{Condition -> access}} | {{Required artifact/access}} | `CMD-{{target}}-{{002}}` | {{`E-*` direct artifact or `SRC-*` secondary record}} | {{Knowledge/access gained}} |

## Detailed target walkthroughs

<!-- Duplicate this entire target block for each target or objective. -->

### T-{{target}} — {{Hostname or objective}}

#### Target summary

| Field | Value |
|---|---|
| Objective | {{Required objective}} |
| Starting state | {{Initial access and prerequisites}} |
| Final status | {{Achieved / Partial / Not achieved}} |
| Highest demonstrated access | {{Identity and privilege}} |
| Proof / supporting source | {{`E-*` direct proof, or `SRC-*` plus `GAP-*` with status Partial}} |
| Independent retest | {{Passed / Failed / Not performed / Not authorized}} |

#### Attack-path summary

{{In one short paragraph, explain the dependency chain from the starting state to the final result.}}

#### Phase 1 — Discovery and enumeration

##### Step 1 — {{Decision-focused title}}

**Purpose.** {{Why this step was necessary now.}}

**Starting state.** {{Executing host, identity/privilege, working directory, target, and prerequisites.}}

**Exact command — `CMD-{{target}}-001`.**

```bash
{{Exact command as executed; do not include the shell prompt}}
```

**Option and value explanation.**

- `{{option/value}}`: {{Why it was used and what it means.}}

**Decisive output.** {{If no original exists, change this label to “Note-derived transcript,” cite `SRC-*`, and create a gap.}}

```text
{{Faithful output excerpt}}
[... omitted: {{what and why}} ...]
```

Full raw output / source: {{[`E-{{target}}-001`](evidence/terminal/E-{{target}}-001.txt) if the original exists; otherwise `SRC-*` plus `GAP-*`}}

**Observation.** {{State only what the output directly proves.}}

**Inference and next decision.** {{Explain the interpretation, confidence, and why the following action is justified.}}

**Expected result.** {{What success or failure was expected to look like.}}

**Observed result / resulting state.** {{What actually occurred and what changed.}}

![E-{{target}}-002 — {{Concise evidentiary alt text}}](evidence/screenshots/E-{{target}}-002-{{description}}.png)

*Figure E-{{target}}-002 — {{State exactly what the real screenshot proves.}}*

#### Phase 2 — Initial access

<!-- Repeat the same step structure. Preserve the starting identity and prove the resulting identity. -->

##### Step 2 — {{Initial-access action}}

**Purpose.** {{Why this path was selected over alternatives.}}

**Starting state.** {{Required service, credential, artifact, source host, and identity.}}

**Exact command — `CMD-{{target}}-002`.**

```bash
{{Exact command as executed}}
```

**Decisive output.**

```text
{{Faithful output showing the access result}}
```

**Explanation.** {{Explain the root condition used, the command’s important options, and how the output proves access.}}

**Expected result.** {{Expected access or failure indicator.}}

**Observed result / resulting state.** {{Actual identity, privilege, host, directory, and limitations.}}

Evidence / source: {{`E-{{target}}-003`, `E-{{target}}-004`; or `SRC-*` with an explicit gap}}

#### Phase 3 — Post-access enumeration and privilege escalation

<!-- Repeat the step structure for each dependency. Show starting and ending identity. -->

##### Step 3 — {{Escalation condition and action}}

**Purpose.** {{Reason for the check or action.}}

**Starting state.** {{Current user, privilege, host, directory, and prerequisite.}}

**Exact command — `CMD-{{target}}-003`.**

```bash
{{Exact command as executed}}
```

**Decisive output.**

```text
{{Faithful output excerpt}}
```

**Observation.** {{Directly observed misconfiguration, permission, credential, version, or behavior.}}

**Inference and technical explanation.** {{Why it enables escalation; distinguish inference from proof.}}

**Observed result / resulting state.** {{Elevated identity and validation command/result.}}

Evidence / source: {{`E-{{target}}-005`, `E-{{target}}-006`; or `SRC-*` with an explicit gap}}

#### Phase 4 — Objective and proof

##### Step 4 — {{Objective verification}}

**Purpose.** {{Official objective being verified.}}

**Starting state.** {{Final host, identity, and privilege.}}

**Exact command/action — `CMD-{{target}}-004`.**

```bash
{{Exact proof command or a precise UI action record}}
```

**Observed result.** {{State the proof without exaggeration.}}

![E-{{target}}-007 — {{Objective proof alt text}}](evidence/screenshots/E-{{target}}-007-objective-proof.png)

*Figure E-{{target}}-007 — {{Explain how this satisfies the verified objective-proof rule.}}*

#### Findings and root causes

##### F-{{001}} — {{Concise root-cause title}}

| Field | Value |
|---|---|
| Affected target | `T-{{target}}` |
| Status | {{Confirmed / Partially confirmed / Unverified}} |
| Severity | {{Critical/High/Medium/Low/Informational or Not assessed}} |
| CWE/CVE/CVSS | {{Verified identifier/score with source, or Not assessed}} |
| Supporting evidence / source | {{`E-*` and `CMD-*`; or `SRC-*` with a partial/unverified status}} |

**Technical root cause.** {{Explain the actual vulnerable condition or control failure, not merely the tool used.}}

**Demonstrated impact.** {{Tie impact to access and actions actually proved in this environment.}}

**Remediation.** {{Describe the minimum root-cause fix and useful defense-in-depth controls.}}

**Retest.** {{Give a specific authorized check and the expected fixed behavior.}}

#### Target limitations and cleanup

- Unverified claims or evidence gaps: {{None / list}}
- Failed attempts material to reproduction: {{None / concise list and reason}}
- Side effects or artifacts created: {{None / list}}
- Cleanup performed: {{Action and evidence / Not performed / Not authorized}}
- Reproduction caveats: {{Timing, nondeterminism, versions, reset requirements, or none known}}

## Cross-target findings and remediation priorities

| Priority | Finding | Targets | Demonstrated risk | Recommended action | Retest |
|---|---|---|---|---|---|
| {{1}} | `F-{{001}}` — {{Title}} | `T-{{target}}` | {{Evidence-based risk}} | {{Root-cause fix}} | {{Concrete verification}} |

## Evidence index

| Evidence ID | Type | Provenance | Target | Related step/finding | File | Captured at | SHA-256 (optional) | What it proves |
|---|---|---|---|---|---|---|---|---|
| `E-{{target}}-001` | Raw terminal output | {{Original / controlled derivative}} | `T-{{target}}` | `CMD-{{target}}-001` | `evidence/terminal/E-{{target}}-001.txt` | {{ISO 8601 / unknown}} | {{Hash / not recorded}} | {{Decisive fact}} |
| `E-{{target}}-002` | Screenshot | {{Original / redacted derivative; original retained at ...}} | `T-{{target}}` | {{Step/figure}} | `evidence/screenshots/E-{{target}}-002-{{description}}.png` | {{ISO 8601 / unknown}} | {{Hash / not recorded}} | {{Decisive fact}} |

## Command index

| Command ID | Target | Executing context | Purpose | Report section | Raw output evidence / source |
|---|---|---|---|---|---|
| `CMD-{{target}}-001` | `T-{{target}}` | {{Host/user/directory}} | {{Purpose}} | [Step 1](#step-1--decision-focused-title) | {{`E-*` direct output, `SRC-*` transcript, or `GAP-*`}} |

## Reproduction checklist

- [ ] Current official report and proof rules were verified and cited.
- [ ] Every target and action is inside the authorized scope.
- [ ] Starting state and prerequisites are explicit for every attack-path stage.
- [ ] Exact commands were checked against raw records; no shell prompts or visual wrapping remain.
- [ ] Decisive output is faithful, and omissions are marked.
- [ ] Every material claim maps to a command/action and an `E-*` or `SRC-*` ID with provenance.
- [ ] Notes and copied transcripts are indexed as `SRC-*`; they are not presented as original evidence.
- [ ] Every screenshot is real, legible, captioned, referenced, and linked successfully.
- [ ] Final identity and objective proof are present for every claimed success.
- [ ] Observations, inferences, failures, and evidence gaps are labeled accurately.
- [ ] Root cause, demonstrated impact, remediation, and retest are proportionate and supported.
- [ ] Target names, addresses, users, timestamps, and time zone are consistent.
- [ ] Independent reproduction was performed when authorized, or its absence is stated.
- [ ] All placeholders, TODOs, unused sections, and instructional comments were removed.
- [ ] Controlled and sanitized versions were handled without overwriting originals.
- [ ] The final delivery file was visually inspected in its submission format.

## Appendix A — Evidence gaps for the author

<!-- Resolve and remove this private section before submission unless the report must disclose limitations. -->

| Gap ID | Claim affected | Missing artifact or fact | Why current evidence is insufficient | Authorized action to close it | Submission impact |
|---|---|---|---|---|---|
| `GAP-{{target}}-001` | {{Claim}} | {{Missing command/output/screenshot/rule}} | {{Reason}} | {{Specific recapture or verification}} | {{Blocker / limitation / none}} |

## Appendix B — Relevant failed attempts

<!-- Include only attempts that clarify reproduction or a key decision. -->

| Attempt | Starting state | Exact action | Observed failure | Evidence | Lesson / next decision |
|---|---|---|---|---|---|
| {{Attempt ID}} | {{Context}} | `CMD-{{target}}-{{###}}` | {{Faithful result}} | {{`E-*` or `SRC-*` with provenance}} | {{Why the path was abandoned}} |
