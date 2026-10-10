# Report assembly workflow

Use this workflow in draft mode. Start from `assets/skill-examreport.md` and remove instructional comments in the submission copy.

## 1. Confirm the report contract

Extract the current official requirements into a short compliance matrix:

| Requirement | Source | Planned section/evidence | Status |
|---|---|---|---|
| Required file type | Official rule reference | Delivery | Verified / unverified |
| Required candidate identifier | Official rule reference | Cover/evidence | Verified / unverified |
| Required proof per target | Official rule reference | Target objective | Verified / gap |
| Naming and size rules | Official rule reference | Delivery | Verified / unverified |

Do not copy a remembered vendor rule into the `Verified` state. The source must be supplied or checked against the current authoritative rule set.

## 2. Build the source ledger

Inventory every note, command, raw output, screenshot, objective, and rules document. Assign `SRC-*` IDs to secondary sources and `E-*` IDs only to direct artifacts or controlled derivatives. Record provenance and integrity. Group sources by target and attack-path phase, then flag contradictions and gaps before writing prose.

## 3. Make an attack-path map

For each achieved objective, trace dependencies backwards:

```text
objective proof
<- elevated access
<- escalation condition
<- initial access
<- exploitable condition
<- enumeration observation
<- discovery
```

Attach command and evidence IDs to every transition. A transition with no support becomes an evidence gap, not a narrative bridge.

## 4. Create the result and traceability matrices

The result matrix gives the reviewer a fast status overview. The traceability matrix is the private drafting control that prevents missing proof.

| Target/objective | Status | Root cause/finding | Reproduction section | Command IDs | Evidence/source IDs | Gap |
|---|---|---|---|---|---|---|

Every achieved objective should have a continuous row from target through direct proof. If a transition is supported only by `SRC-*`, label the outcome partial or unverified and create the applicable gap.

## 5. Draft target walkthroughs first

Write the technically dense target chapters before the executive summary. For each target:

1. state the objective, target facts, starting condition, and final result;
2. summarize the attack path in a few sentences;
3. present the steps in dependency order;
4. separate exact commands, decisive output, and explanation;
5. identify the root cause rather than describing only a tool result;
6. prove the final identity, access level, and objective;
7. state limitations and whether the sequence was independently retested.

If the official exam expects discovery-to-proof chronology, preserve it. If the chain spans targets, explain source and destination context at each transition.

## 6. Write explanations at three levels

- **Action:** what was run or clicked.
- **Evidence:** what the system directly returned or displayed.
- **Reasoning:** why the evidence supports the conclusion and next step.

Keep these separate. This prevents retrospective reasoning from being presented as observed fact.

## 7. Add impact and remediation

Tie impact to demonstrated access and the authorized environment. Avoid inflated business claims. Explain the technical root cause, the minimum corrective control, defense in depth where useful, and a concrete retest. Use `Not assessed` rather than inventing a CVE, CWE, CVSS score, affected version, or organizational impact.

## 8. Write the summary last

The executive summary must match the detailed evidence exactly:

- count only objectives actually proved;
- describe the shortest defensible attack path;
- name the most important root causes;
- state material limitations;
- avoid introducing facts absent from the walkthroughs.

## 9. Build indexes

Create:

- an evidence index mapping every `E-*` item to its file, target, step, description, and optional hash;
- a source ledger mapping every `SRC-*` item to its provenance, contents used, and limitation;
- a command index mapping every `CMD-*` item to its section and purpose;
- an evidence-gap list for the author, removed or resolved before final submission unless transparency requires it.

## 10. Produce two logical views when secrets matter

When allowed and useful, maintain:

- a controlled submission version containing the proof required by official rules; and
- a shareable/sanitized version with credentials, tokens, flags, personal identifiers, and prohibited details consistently redacted.

Never overwrite the only original with a redacted copy. Clearly label the version and do not assume a sanitized report satisfies official proof requirements.
