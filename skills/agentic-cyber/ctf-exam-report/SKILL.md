---
name: ctf-exam-report
description: Capture, draft, and audit reproducible Markdown reports for authorized CTFs and certification exams, with exact commands, evidence-linked screenshots, technical reasoning, attack-path narration, and submission QA. Use while collecting evidence, turning notes into a report, or checking an existing report; it does not authorize new scanning, exploitation, or activity outside the stated scope.
---

# CTF Exam Report

Produce an evidence-first report that a technically competent reader can follow from a stated starting condition and use to reproduce every claimed result within the authorized environment.

## Preserve authority and truth

- Treat report writing as permission to inspect supplied notes and artifacts, not as permission to run new scans, exploits, persistence, cleanup, or other target-changing actions.
- Work only with an explicitly authorized CTF, lab, or exam scope. Before executing any target-facing command, confirm that the command, target, and timing are in scope under the current task.
- Treat the current official exam guide, portal instructions, and supplied rules as controlling. If they are unavailable, mark the rules as unverified and produce a vendor-neutral draft; never invent official requirements.
- Never fabricate, recreate, stage, or cosmetically alter evidence. Do not use image generation for screenshots. Preserve an original if a redacted derivative is required.
- Do not claim that a command ran, a vulnerability exists, access was obtained, or an objective was met unless supplied evidence supports the claim. Label interpretation as `Inference` and missing proof as `Evidence gap`.

## Choose the operating mode

1. **Capture mode** — use while an authorized exercise is in progress. Read [references/evidence-guide.md](references/evidence-guide.md), establish IDs, and maintain an evidence ledger as actions occur.
2. **Draft mode** — use when turning notes, logs, commands, screenshots, and objectives into a complete report. Read [references/report-workflow.md](references/report-workflow.md) and use [assets/skill-examreport.md](assets/skill-examreport.md) as the starting document.
3. **Audit mode** — use to review an existing Markdown report. Read [references/quality-gates.md](references/quality-gates.md) and run `scripts/validate_report.py` when local files are available.

Modes may be combined. For example, capture evidence during the exercise, then draft and audit the final report.

## Build a source ledger first

Before drafting prose, inventory the available material:

- official rules and required submission format;
- candidate and exam identifiers that are permitted in the report;
- authorized targets, objectives, starting access, and exclusions;
- raw terminal logs, browser captures, screenshots, tool exports, notes, and timestamps;
- objective or proof evidence for each target;
- known evidence gaps, contradictions, and unverified recollections.

Normalize target names, IP addresses, usernames, timestamps, and time zone once. Do not silently choose between conflicting sources. Record the conflict and use the best-supported value only after explaining the choice.

## Maintain traceability

Use stable identifiers throughout:

- `T-<short-target>` for a target;
- `F-###` for a finding or root cause;
- `CMD-<target>-###` for an exact command record;
- `E-<target>-###` for an original or controlled-derivative screenshot, raw output, HTTP capture, or proof artifact;
- `SRC-###` for notes, recollections, imported prose, or another secondary source that is not direct system evidence;
- `GAP-<target>-###` for a missing fact or artifact.

Do not promote a note-derived transcript to original evidence. Cite the note as `SRC-*`, quote it as a recorded transcript, and create a gap for the missing original. A secondary source may support an accurate draft but does not independently satisfy a direct-proof requirement. Every material claim must point to one or more `E-*` or `SRC-*` IDs and state the provenance. Every evidence item must identify the target, action or step, capture time when known, source path, and what it proves. Every successful attack-path transition must link the command, decisive output, explanation, and direct evidence; otherwise label the result partial or unverified.

## Write reproducible steps

For each decisive step, include:

1. **Purpose** — why the action was necessary at that point.
2. **Starting state** — access level, host, directory, prerequisite artifacts, and assumptions.
3. **Exact command or request** — as executed, without a copied shell prompt or visual line wrapping. Preserve quoting, ports, switches, paths, and environment variables.
4. **Flag explanation** — explain non-obvious options and any substituted values.
5. **Key output** — a faithful excerpt that supports the decision. Mark omitted material explicitly and link the full raw output when available.
6. **Interpretation** — what is directly observed, what is inferred, and why the next action follows.
7. **Expected and observed result** — state both; do not rewrite a failure as a success.
8. **Evidence** — cite the relevant `E-*` item and embed a legible screenshot when it materially proves the result or the official rules require it.
9. **Next state** — describe the access, knowledge, or artifact gained, including any limitation.

Include failed attempts only when they prevent repetition of a misleading path, explain a key decision, or are required by the exam. Label them clearly as unsuccessful.

## Handle commands and output precisely

- Put copyable commands in language-appropriate fenced code blocks. Keep prompts, commentary, and output out of the command block. If the command exists only in secondary notes, call it an `Exact recorded command`, not an independently verified execution record.
- Use a separate `text` block for output. Never edit output in a way that changes its meaning.
- If a command contains a secret that must be protected, retain the exact unredacted original in the controlled evidence set when rules allow and show a consistently redacted display copy. Document the redaction.
- Do not replace actual command values with generic placeholders inside the claimed execution record. If a reusable generic command is helpful, place it after the actual record and label it `Generic form`.
- Explain commands at the decision level. Avoid narrating obvious syntax word by word.

## Handle screenshots as evidence

- Capture the real interface or terminal at the time of the action. A screenshot should make the target identity and decisive result legible when the official rules permit that information.
- Give each image a unique evidence ID, descriptive filename, concise alt text, and a caption stating exactly what it proves.
- Refer to every figure in the surrounding prose. Do not insert unexplained image dumps.
- Keep the original untouched. If redaction or cropping is necessary, retain the original and label the derivative and modification. Never add or move proof elements.
- A screenshot supplements text; it does not replace the exact command and decisive output.
- If evidence is missing, add a visible evidence-gap entry and specify what must be recaptured. Never create a simulated screenshot.

## Shape the final report

Default to the supplied template, then adapt headings to the official rules. Preserve these outcomes even if names or ordering change:

- document control and rule-compliance statement;
- executive summary and result table;
- authorized scope, assumptions, limitations, and starting conditions;
- methodology and evidence conventions;
- chronological or dependency-aware attack narrative;
- a self-contained walkthrough for each target or objective;
- root cause, technical impact, and proportionate remediation for each material finding;
- objective/proof verification;
- evidence index and command index;
- reproduction and submission QA checklist.

Prefer one authoritative explanation over duplicated prose. Cross-reference shared steps when an attack chain spans multiple targets, but make prerequisites explicit so each walkthrough remains understandable.

## Finish with an evidence-gap report

If the available material cannot support a complete official report, still produce the strongest accurate draft. End with a private author checklist that lists each missing command, output, screenshot, rule confirmation, target fact, or proof artifact and the exact action needed to close the gap. Do not present unresolved placeholders as final content.

## Validate before delivery

Apply [references/quality-gates.md](references/quality-gates.md). When the report is a local Markdown file, run:

```bash
python <skill-directory>/scripts/validate_report.py path/to/report.md --strict --require-images
```

Resolve `<skill-directory>` to this skill's installed folder; do not assume the current directory is the skill root. Use `--require-images` when screenshots are requested or required, and omit it only when the verified report contract does not require images. Resolve all errors. Review warnings manually because official formats vary. A strict failure caused by an intentional limitation is not waived silently: retain the limitation, state that the report is not submission-ready, and identify the authoritative decision needed. Report what was verified, what was not re-executed, and any remaining evidence gaps.
