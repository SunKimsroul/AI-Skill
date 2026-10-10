# Constraints

Evidence tells you a domain controller is on `10.10.1.5`. It does not tell you that this exam forbids automated exploitation, that the report has to follow a supplied template, or that you have four hours left. Those facts change what you should do, and none of them are observable.

So they are declared once, at intake, and enforced from the state file for the rest of the exam. This is what replaces knowing which certification you are sitting.

## Intake

Asked only when `exam-state.md` does not exist. Six short questions, once, in one message. Keep it brief — the user wants to start.

1. **Scope.** Which targets are in scope, and is anything explicitly out? Networks, hostnames, IP ranges, a domain.
2. **Clock.** When does the window close, and is report time inside it or separate? Convert the answer to an **absolute deadline** and record that, not a duration — "10 days" cannot be compared against the current time, and the whole time trigger in `phase-map.md` reads this field.
3. **Objectives.** What has to be achieved to pass, and what proves it? How many flags, targets, or objectives, what is the pass threshold, and which proof artifacts are required. Write one row per objective into the state file's Objectives and proof table immediately, with Captured set to no.
4. **Tool restrictions.** Anything you are not permitted to use? Prompt with the classes below, since candidates usually remember a restriction once they hear the category.
5. **Start condition.** How does the exam hand you the target? Blackbox network, **assumed breach** (credentials issued, no exploitation needed), **whitebox** (application source supplied), a single host with no network, or a shell already provided. This selects the entry phase in `phase-map.md` and stops an hour being spent scanning a perimeter that was never part of the task. Record it, and for whitebox record the source tree path too.
6. **Report.** Is there a supplied template to follow, or is it free-form? Are specific proof artifacts or screenshot framings mandated? Does it require working proof-of-concept code and source-level remediation per finding, as the whitebox web exams do?

Question 3 is the one candidates skip and the one that costs most. Without it the Objectives table
stays empty, "every objective is met" becomes unevaluable, and the pass threshold surfaces at report
time when it should have been steering the whole run. If the user does not know the threshold yet,
record what they do know and mark it to be confirmed from the exam guide — do not leave the table blank.

Then always ask: **is evasion or detection graded?** It is one line, and gating it on the scope answer fails the ordinary case — a domain usually becomes visible an hour into recon, long after the only moment the question was going to be asked, and nothing reopens it. That single answer decides whether the evasion overlay in `phase-map.md` is on for the whole exam, and it is worth the extra line.

Write every answer into the Scope and constraints block of `exam-state.md` before doing anything else.

## Restricted tool classes

Read these out as prompts in question 4. Record each as `allowed`, `forbidden`, `limited`, or `UNDECLARED`.

| Class | Examples | Typical restriction |
|---|---|---|
| Automated exploitation frameworks | Metasploit, `msfconsole`, `msfvenom` payload chains | Often limited to a single target, or forbidden outright |
| Automated exploitation tools | `sqlmap`, `commix`, automatic RCE chains | Frequently forbidden where manual skill is the graded thing |
| Vulnerability scanners | Nessus, OpenVAS, Nexpose, `nikto` | Commonly forbidden |
| Automated recon suites | AutoRecon, `nmap` scripted exploitation categories | Sometimes forbidden; plain port and service scans usually fine |
| Commercial tooling | Burp Suite Professional, Cobalt Strike | Depends entirely on the exam; some require it, some ban it |
| AI assistance | This library, and any model-driven help | Varies by provider, and by exam within a provider |
| Denial of service | Stress, flood, resource exhaustion | Essentially always forbidden |

The AI row is about **this session itself**, so treat it as a live question rather than a checkbox. If it comes back `UNDECLARED`, say once that the policy is unconfirmed, record that the user chose to proceed, and continue — do not silently assume either answer, and do not keep re-raising it.

It is also the row most often assumed wrong in both directions. Policies genuinely differ — some exams permit model assistance outright, others forbid it entirely, and the same provider can differ between two of its own certifications.

The useful heuristic is **proctoring**. A proctored exam generally treats an interactive model as third-party assistance and bans it. An unproctored, objective-based exam graded on what you compromised and how you documented it generally does not restrict helper software, because doing so would be neither enforceable nor the point. That is a heuristic for knowing what to expect, not a substitute for the answer — ask, record it, and do not generalize one provider's rule onto another.

## Enforcement points

A recorded constraint is worth nothing unless it is checked at the moment it would be violated. Check at these four points.

**Before naming a tool.** Every time a command is about to be suggested, check its class against the constraints block. If it is forbidden, do not suggest it and then caveat it — suggest the permitted route instead, and say in one line why. If it is `limited`, say how much of the allowance is already spent.

**Before touching a host.** Confirm the host is inside the declared scope. A host discovered mid-exam is not automatically in scope just because it is reachable — reachability is not authorization, and on most of these exams scope discipline is graded directly. Ask.

**On every invocation, against the clock.** State the remaining window when it drops under 40%. Enter REPORT under 20%. If no system clock is reachable in this session, ask the user for the current time as the first line of the turn and recompute from that — a time trigger that silently never fires is worse than no trigger, because it is relied on.

**At report time.** Check the output against the declared report format and the mandated proof artifacts. A perfect chain in the wrong template still loses marks.

## Handling UNDECLARED

`UNDECLARED` means unknown, and unknown is not permission.

When an action needs a constraint that was never declared, stop and ask before taking it — one short question naming the specific tool and what it is for. Record the answer so it is asked once and not again.

Do not treat a tool as permitted because it is standard, because it is installed, because it is the obvious route, or because the user seemed relaxed at intake. On the exams this library targets, an unauthorized tool in a report is a scoring problem that no amount of technical quality compensates for.

## Changing a constraint mid-exam

The user can change any of these at any time, and it is their call. Record the change with the time it happened rather than editing the original line — if a tool became permitted at hour six, the report needs to show it was not used before then.

## Scope is the boundary that is actually graded

Working inside the declared target list is part of the craft, not paperwork around it. An exam scope, a rules-of-engagement document, and a bounty policy are the same object in different clothes: the line that separates an assessment from an incident.

Stop and ask on any ambiguity. Do not expand the target list because a path looks promising, do not pivot to a host merely because it became reachable, and if something has unexpected impact — a service down, a host unresponsive — say so immediately rather than working around it quietly. A hung target usually needs a revert, and on a timed exam an unreported one costs the objective outright.
