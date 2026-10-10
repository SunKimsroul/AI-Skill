# Red Team - EDR & Defense Evasion (orientation)

## Table of Contents
- [Scope of this file](#scope-of-this-file)
- [Observation-first](#observation-first)
- [How EDR sees you](#how-edr-sees-you)
- [Evasion technique families — map](#evasion-technique-families--map)
- [The honest exam-relevant point](#the-honest-exam-relevant-point)
- [Where to learn the implementations](#where-to-learn-the-implementations)

For AMSI/CLM/AppLocker at the PowerShell layer see the `ctf-ad` pack (`evasion.md`). For the loaders these techniques protect see [payloads-and-execution.md](payloads-and-execution.md). For telemetry from the defender's side see [opsec-and-lifecycle.md](opsec-and-lifecycle.md) and the `ctf-ad` pack (`opsec-and-detection.md`).

---

## Scope of this file

This is an **orientation and detection-awareness map**, not an implementation guide. It explains how modern EDR observes an operator and names the evasion technique families you must recognize for CRTO/CRTL and authorized engagements — with the public tooling/research that implements each and, importantly, what still catches it. Building working evasion belongs in your own authorized lab, from the canonical sources below. For exams you operate an existing C2's evasion features and reason about detection; that understanding is what is tested.

## Observation-first

There is no universal bypass. What evades one EDR is caught by the next, and behavioral/telemetry detection often fires regardless of any single usermode trick. Determine what the target product actually flags by **testing small** in a matching lab or against a throwaway, read the result, and choose accordingly — do not assume a technique works because it once did.

## How EDR sees you

Understand the sensors before the evasions; each technique below targets one of these:

| Sensor | What it observes | ATT&CK-adjacent |
|---|---|---|
| Usermode API hooks | Inline hooks in `ntdll`/`kernel32` redirect Native API calls to the EDR for inspection | Defensive baseline |
| Kernel callbacks | `PsSetCreateProcessNotifyRoutine`, thread- and image-load callbacks fire in kernel on every process/thread/module | Hard to evade from usermode |
| ETW / ETW-TI | Event Tracing for Windows, incl. Threat-Intelligence provider (memory-alloc, remote-thread, etc.) | T1562.006 (target of tampering) |
| Minifilter / registry | File and registry telemetry via filter drivers | — |
| AMSI | Scans script / .NET content at execution | T1562.001 |
| Signed-image / memory scanning | Unbacked executable memory, RWX pages, private pages in signed modules | Behavioral |

## Evasion technique families — map

Each: what it is (one line), the sensor it targets, and how EDRs still catch it. Concept only — implement in your lab.

| Family | Targets | One-line | How it's still caught |
|---|---|---|---|
| Userland unhooking | API hooks | Restore clean `ntdll` .text from disk/KnownDlls/a fresh copy | Kernel callbacks + ETW-TI still fire; unhooking itself is detectable |
| Direct syscalls | API hooks | Invoke `syscall` directly, skipping hooked `ntdll` stubs (e.g. SysWhispers-style) | Call-stack origin outside `ntdll` is anomalous; kernel telemetry unaffected |
| Indirect syscalls | API hooks + stack | Jump through a real `ntdll` `syscall` gadget so the return address looks legitimate | Sensor stack-walking and syscall-number heuristics |
| ETW patching | ETW/ETW-TI | Neutralize ETW emission in-process (T1562.006) | The patch itself is a known IOC; kernel-side unaffected |
| AMSI bypass | AMSI | Neutralize the in-process scan interface (T1562.001) | Public one-liners are signatured; some content scanned pre-interface |
| Call-stack spoofing | Memory/behavior | Make a thread's call stack look benign during sensitive calls | Advanced sensors validate stack frames |
| Sleep-mask / memory encryption | Memory scanning | Encrypt beacon memory during sleep, restore to run (Ekko/Foliage/Cronos family — concept) | Scanning during the unmasked execute window; timing heuristics |
| Module stomping / unbacked-memory hygiene | Memory scanning | Execute from backing that looks image-backed | Private/modified pages in signed modules |
| BYOVD | Kernel | Load a signed-but-vulnerable driver to reach kernel (T1068 / T1562.001) | Microsoft vulnerable-driver blocklist; high risk and noisy — often out of ROE |
| Parent/child + command-line hygiene | Behavior | Plausible process lineage and arguments (see PPID spoofing in payloads file) | Lineage analytics, argument anomalies |

## The honest exam-relevant point

Modern EDR is layered and increasingly behavior- and telemetry-driven. A single usermode bypass rarely makes an operator invisible; correlation across process lineage, memory, network cadence, and kernel events frequently still fires. For CRTO/CRTL the graded skill is **reasoning about the sensor and choosing an approach whose detection profile the target does not cover**, plus the OPSEC discipline to test before committing — not memorizing one bypass. Most AD-focused exams (CRTP/CRTE) do **not** require evasion at all; correct technique and a clear report matter more (see [opsec-and-lifecycle.md](opsec-and-lifecycle.md)).

## Where to learn the implementations

Study and build in an authorized lab from canonical sources, not copied snippets (which are signatured):

- **CRTO / CRTL** (Zero-Point Security) — exam-aligned treatment of Cobalt Strike's evasion features, malleable profiles, and OPSEC.
- **MITRE ATT&CK** — T1562 (Impair Defenses) and sub-techniques, T1055 (Process Injection), T1620 (Reflective Code Loading): taxonomy and detection guidance.
- **Vendor/defensive research** — EDR-internals and detection write-ups (e.g. Elastic, SpecterOps, MDSec public research) explain both the technique and its telemetry; these are indexed in the local writeup index: `python scripts\search_writeup_index.py edr evasion` or `syscalls`.
- **Public C2 documentation** — how your framework implements sleep masks, syscall methods, and profile-driven behavior.
