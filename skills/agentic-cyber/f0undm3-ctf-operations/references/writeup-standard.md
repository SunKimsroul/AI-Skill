# F0undM3 writeup standard

Use this standard for CTF writeups, certification exam reports, penetration-test and bug-bounty reports, and research disclosures. Write in clear, human prose. Make every claim traceable to evidence; do not turn a list of commands into a story without explaining why each result mattered.

Where an exam or program publishes its own report template, that template wins — follow its required sections, screenshot and proof-file rules, and submission format exactly, and use this standard for the quality of the prose inside it.

## Metadata

The title is a level-one heading, followed immediately by a two-column table. This is the exact
shape `scripts/render_academic_writeup.py` parses — it reads the first `# ` line as the title and
then consumes consecutive `|` rows as metadata. Any other layout renders with the metadata missing.

```markdown
# <challenge, target, or finding title>

| Team | F0undM3 |
| Author | numpav |
| Category | pwn \| reverse \| web \| forensics \| crypto \| misc \| osint \| pentest \| exam \| research |
| Event | <CTF or exam name; omit the row if there is none> |
| Date | <month year> |
| Scope | <CTF instance, exam target list, engagement boundary, or bounty program> |
```

## Required structure

1. **Abstract** — State the target condition, the core weakness, the prerequisite, the result, and why the chain mattered. Keep it to one focused paragraph.
2. **Introduction and target condition** — Name the services or artifacts, the desired state, and the constraints that prevented a direct route.
3. **Attack surface or initial triage** — Record versions, formats, endpoints, protections, inputs, and trust boundaries. Use a table where it reduces ambiguity.
4. **Evidence-led discovery** — Give each meaningful primitive or finding its own subsection. Include the relevant code, request, trace, or decompiler observation and explain the type/control-flow/data-flow reasoning.
5. **Rejected paths** — Summarize credible tests that failed and what each failure ruled out. This prevents readers from repeating dead ends and shows why the final route was necessary.
6. **Chain construction** — Explain how the findings connect. Use a compact sequence or diagram when several services or trust boundaries are involved.
7. **Reproduction** — Provide a minimal, deterministic solver or command sequence. State assumptions, required inputs, expected intermediate outputs, and final verification. For a **research disclosure or an exam report**, where a maintainer or grader must reproduce this without you, hold it to the stricter bar in [Reproduction from zero](#reproduction-from-zero).
8. **Impact and remediation** — Required for pentests, bounty submissions, exam reports, and disclosures. Describe impact, affected scope, severity rationale, and specific fixes. Redact passwords, tokens, personal data, and unnecessary operational details. For exams, include the proof artifacts the grader requires (proof/local file contents, IP-visible screenshots) exactly as specified.
9. **Evidence manifest** — List captures, logs, request/response pairs, hashes, screenshots, and source paths used to support the report.
10. **Conclusion** — Restate the root cause and the shortest lesson for defenders or future solvers.

## Reproduction from zero

**Scope: research disclosures and exam reports.** A maintainer or a grader has to reproduce your result without being able to ask you a question, so the reproduction has to stand alone.

**This is not the CTF format.** A CTF writeup keeps the dense evidence-led narrative described above — reasoning, artifacts, and the chain, at full technical depth. Do not flatten it into a beginner tutorial; the reader is another CTF player and the interesting content is *why* each observation mattered, not how to install `curl`. Add screenshots to that narrative, keep the reproduction minimal and deterministic, and leave the structure alone.

Assume the reader knows nothing. Not the tool, not the flags, not your directory layout, not what
"the usual" means. They should be able to work top to bottom, copying each command as written, and
reach the same outcome without stopping to ask a question or make a decision.

That standard rules out most of what normally passes for a reproduction section. It is also what
makes a writeup useful a year later, to a teammate, to a grader, or to you.

**Start before the first command.** Open with the starting state: operating system and version,
tools required and how to install them, files needed and where to obtain them, and the exact
directory the reader should be sitting in. If a step needs a virtual environment, a lab network,
a container, or a hosts-file entry, that is step one — not an aside.

```bash
# Environment: Kali 2025.1, from an empty working directory
sudo apt install -y gobuster
python3 -m venv .venv && source .venv/bin/activate
pip install pwntools==4.13.1
mkdir -p loot evidence
```

**Number every step and give each one all four parts.** A step that is missing any of these is not
reproducible:

1. **What this step does**, in one sentence, and why it comes here rather than earlier or later.
2. **The exact command**, copy-pasteable, with every flag written out. No `...`, no "adjust as
   needed", no shell aliases, no abbreviated flags where the long form is clearer.
3. **The expected output**, or the specific part of it that matters — the line, the field, the
   status code, the offset. State what tells the reader it worked.
4. **A screenshot**, per the rule below.

**Pin every value the reader must substitute.** Define target IPs, ports, usernames, hashes, and
offsets as shell variables at the top, then use the variables throughout, so there is exactly one
place to edit:

```bash
TARGET=10.10.110.15
USER=svc_web
export TARGET USER
```

**Say what changes between runs.** Anything non-deterministic — an ASLR offset, a session token, a
generated filename, a timestamp — must be called out where it appears, with how to obtain the
current value. A reader who copies your leaked address verbatim and fails will assume the whole
writeup is wrong.

**Finish with a single verification.** End with one command whose output proves the whole chain
worked, and show that output. For a CTF that is the flag where the event permits printing it; for
an exam the required proof artifact; for a disclosure the minimal reproducer's success condition.

**Prefer a runnable script for anything over about ten steps.** Include it in full as an appendix,
labelled a reference solver, and keep the numbered steps as the explanation of what it does. The
reader should be able to run either one.

## Screenshots

Every meaningful step gets a screenshot. Text alone is not evidence — it is a claim about evidence,
and it is trivially retypeable. Graders, maintainers, and clients all read images first.

### Screenshots must be real

Capture them from the actual session against the actual target. This is an integrity rule, not a
presentation one, and it is the one rule here with no exceptions.

- **Never generate, mock up, draw, or synthesise a screenshot** — not to illustrate, not as a
  placeholder, not "to show what it would look like".
- **Never re-stage a capture you did not take.** Re-running the command later and capturing that is
  still real. Typing the expected output into a terminal and capturing *that* is fabricated evidence.
- **Never edit the content of a capture.** Cropping and redaction are fine; changing a value, a
  hostname, a timestamp, or an output line is not.
- **If you do not have it, say so.** Write "not captured" in the evidence manifest and include the
  raw text output instead. A missing screenshot is a small gap. A fabricated one invalidates the
  whole report, and on an exam or engagement it is a fraud finding rather than a formatting one.

An agent assembling a writeup must not produce images at all. Ask the user for the captures, or
state plainly which steps have none.

**Capture at each step, while it is true.** Reconstructing screenshots after the fact costs more
time than taking them did, and on a timed exam that time comes out of the report. Capture when the
step succeeds, not at the end.

**Embed them inline, at the step they belong to** — not collected in an appendix where the reader
has to match them back up:

```markdown
![gobuster revealing the /admin-portal directory](evidence/02-gobuster-admin-portal.png)
```

The alt text becomes the figure caption in the rendered PDF and is numbered automatically, so write
it as a caption: state what the image proves, not "screenshot 2".

**What has to be visible in the frame:**

- The command that was run, and its output, in the same image where possible.
- The target host or IP, so the image is tied to a specific system.
- For exams, whatever framing the exam mandates — commonly the proof file contents and an
  IP-visible terminal in one frame. Check the required format and capture it that way the first
  time; the session will be gone later.
- For privilege escalation, the identity before and after (`id`, `whoami`).

**Name files so they sort into reading order** — `evidence/01-nmap.png`, `evidence/02-upload.png` —
and keep them in a directory beside the Markdown. Paths in the writeup are resolved relative to the
Markdown file, so the same folder renders correctly for anyone who receives it.

**Redact in the image, not in the caption.** Passwords, tokens, personal data, and client-identifying
detail must be masked in the pixels before the file is saved. A caption saying "password redacted"
under a screenshot showing the password is a disclosure.

If a step genuinely cannot be captured — output too long, a non-interactive pipeline — say so and
include the raw output as a fenced block plus a file in the evidence manifest instead.

## Style rules

- Separate fact, inference, and hypothesis explicitly.
- Prefer exact requests, offsets, RVAs, response fragments, and observed outputs over adjectives such as “obviously” or “simply”.
- Introduce acronyms once; define any custom oracle or primitive before using it.
- Keep code blocks minimal and runnable. Explain non-obvious lines immediately before or after the block.
- For CTFs, include the final verification/flag only when the event permits it. For exams, include exactly the proof material the grader asks for and nothing more. For pentests, bounties, and disclosures, never include raw secrets in the report body.

## Quality gate

Before publishing, verify that every destructive action is tied to its authorized scope and that the report explains both the discovery phase and the final execution phase.

Then run the reproduction section against itself, from a clean directory, following only what is written — no memory, no improvisation, no "obviously you also need to". Each of these must hold:

- Every tool used is installed by a command that appears in the writeup.
- Every file needed is either created by a listed command or its origin is stated.
- No step requires a decision the text does not make for the reader.
- Every substituted value is defined once, at the top.
- Every step has a screenshot, or a stated reason it cannot have one.
- The final verification command produces the shown output.

If any check fails, the reproduction is not finished. This is the section readers actually use, and it is the one most often written from memory and quietly broken.

## Publication PDF

For a final, shareable CTF report, retain the Markdown source and render it with `scripts/render_academic_writeup.py <input.md> <output.pdf>`. The expected layout is A4, with a full-width title, author/team/event line, abstract and keywords above a divider, then compact two-column technical prose.

The renderer requires `reportlab`; install it with `pip install reportlab`. Screenshots are embedded automatically: a line containing only `![caption](path.png)` becomes a numbered, captioned figure scaled to the column. Paths resolve relative to the Markdown file, so keep `evidence/` beside it. A path that does not resolve renders as a visible `[missing figure: ...]` marker rather than failing the build — treat any such marker in the output as a defect to fix before sharing.

If `reportlab` cannot be installed in the current environment, do not silently skip the PDF. Deliver the Markdown source with its `evidence/` directory intact, state that the PDF was not rendered and why, and give the user the exact command to run it themselves. Keep evidence tables narrow, label the final solver as a reference solver, and include a concise evidence manifest. Keep the code background light and use the built-in muted syntax colours (blue keywords, purple strings, red numbers, green comments) for quick scanning. Render the final PDF to images and inspect every page for clipped code, table overflow, or missing glyphs before sharing it — `pdftoppm -png -r 110 out.pdf page`, or `pypdfium2`/`pdf2image` from Python. **If no rasterizer is available, do not claim the layout was verified**: say the PDF is rendered but unverified and name what you could not check.

Use `../assets/omnictf-0day-3-publication-reference.pdf` as the retained visual benchmark. Match its clarity, density, technical reasoning, and restrained academic presentation, while keeping each report's evidence and wording original.
