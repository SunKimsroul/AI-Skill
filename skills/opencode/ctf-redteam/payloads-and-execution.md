# Red Team - Payloads & Execution (orientation)

## Table of Contents
- [Scope of this file](#scope-of-this-file)
- [Observation-first](#observation-first)
- [Execution primitives — technique map](#execution-primitives--technique-map)
- [Loader shape decisions](#loader-shape-decisions)
- [Beacon Object Files vs fork&run](#beacon-object-files-vs-forkrun)
- [.NET in-memory execution](#net-in-memory-execution)
- [Guardrails and environmental keying](#guardrails-and-environmental-keying)
- [Sleep, jitter, and in-memory footprint](#sleep-jitter-and-in-memory-footprint)
- [Where to learn the implementations](#where-to-learn-the-implementations)

For how these run inside a C2 see [c2-frameworks.md](c2-frameworks.md); for defeating the sensor that watches them see [edr-evasion.md](edr-evasion.md); for AMSI/CLM/AppLocker at the PowerShell layer see the `ctf-ad` pack (`evasion.md`).

---

## Scope of this file

This is an **orientation and detection-awareness map**, not an implementation guide. It names the execution techniques a red-team operator must recognize and choose between, maps each to its MITRE ATT&CK ID, points at the public tooling/courseware that implements it, and states what a defender sees. Writing novel loaders or working injection code is out of scope here by design — for exams (CRTO/CRTL) you operate an existing C2 and its published capabilities, and understanding + OPSEC + detection-awareness is what is actually tested. Build and test real loaders only in your own authorized lab, from the canonical sources below.

## Observation-first

The loader and execution method are dictated by the target's EDR and telemetry, discovered by *testing small* in your lab or against a throwaway, not by a fixed template. Public loader code is signatured quickly; the concept and the detection profile matter more than any one artifact. Pick the technique whose detection profile the target's sensor does not cover, confirm with a canary, then commit.

## Execution primitives — technique map

Each row: what it is (one line), its ATT&CK ID, and its typical detection profile. Choose by what the target's sensor does *not* watch.

| Technique | ATT&CK | One-line | Typical detection surface |
|---|---|---|---|
| Remote thread injection | T1055.002 | Allocate + write + `CreateRemoteThread` into another process | RWX alloc + cross-process write + thread create; heavily signatured |
| APC injection / early-bird | T1055.004 | Queue an APC to a (often suspended) thread | Suspended-process create + `QueueUserAPC`; watched |
| Thread execution hijacking | T1055.003 | `SetThreadContext` to redirect an existing thread | Context manipulation on a remote thread |
| Process hollowing | T1055.012 | Create suspended, unmap, replace image, resume | Image/section mismatch, suspended create; well-known |
| Process doppelgänging / herpaderping | T1055.013 | Image-name vs mapped-content mismatch via TxF / write races | Sensor image-load vs backing-file checks |
| Module stomping / overloading | T1055 | Overwrite a legitimately-loaded module's code section | Private/modified image pages in a signed module |
| Section-mapping injection | T1055 | `NtCreateSection` + `NtMapViewOfSection` into target | Cross-process section map; quieter than WriteProcessMemory |
| Reflective / manual DLL loading | T1620 | Load a DLL from memory with no `LoadLibrary` / disk | Unbacked executable memory; "reflective loading" heuristics |
| PPID spoofing | T1134.004 | Set a chosen parent for a spawned process | Parent/child lineage anomalies (e.g. Office→cmd) |
| Blockdlls / ACG | — | Restrict non-Microsoft DLLs in a sacrificial child | Mitigation-policy flags on child processes |

Cross-process ("remote") variants are noisier than self-injection; a sacrificial *spawn-and-inject* with a believable parent and command line trades a process-create for a cleaner injection target. The right choice is whichever the target sensor's telemetry does not cover — determine that by testing.

## Loader shape decisions

- **Staged vs stageless.** Staged fetches the final payload at runtime (smaller initial, extra network fetch, egg-hunt telemetry); stageless is self-contained (larger, one artifact). Choose on delivery constraints and network monitoring.
- **Self-injection vs remote.** Running in your own process is quieter but ties Beacon to a process you do not control the lifetime of; remote injection into a long-lived process is more stable but noisier.
- **Sacrificial process.** Spawn a benign-looking host (`spawnto`) with a plausible parent (PPID spoof) and inject — standard for fork&run post-ex.

## Beacon Object Files vs fork&run

BOFs (T1620 in spirit) run compiled C **inside the Beacon process**, no new process, no fork&run injection — dramatically lower footprint for short post-ex actions. Prefer a BOF over fork&run tooling (`execute-assembly`, injected DLLs) when a suitable BOF exists, because it avoids the process-create and injection telemetry entirely. Reserve fork&run for larger/managed tooling. Operating detail lives in [c2-frameworks.md](c2-frameworks.md).

## .NET in-memory execution

Running managed assemblies from memory (Cobalt Strike `execute-assembly`, in-process variants) avoids touching disk but crosses two sensors: **AMSI** (scans the assembly at load) and **ETW** (the CLR emits assembly-load and other events). Operators reason about both — patching/bypassing AMSI and reducing ETW visibility is covered conceptually in [edr-evasion.md](edr-evasion.md) and, for PowerShell-layer AMSI/CLM, in the `ctf-ad` pack (`evasion.md`). In-process ("patchless") execution reduces the fork&run footprint but does not remove the AMSI/ETW touchpoints.

## Guardrails and environmental keying

ATT&CK T1480 / T1480.001 (Execution Guardrails / Environmental Keying). Constrain a payload to run **only** on the intended target — key decryption of the real payload to the target domain, hostname, username, or a domain-joined check — so a payload pulled into a sandbox or the blue team's analysis box fails to detonate. This is both an OPSEC control and a scope-safety control. Concept only here; implement in your lab.

## Sleep, jitter, and in-memory footprint

Long sleep with jitter reduces call-home cadence and blends with normal traffic. While sleeping, Beacon's in-memory pages are a detection target; **sleep-mask / memory-encryption** concepts (encrypt the beacon's memory during sleep, restore to execute) are named and mapped in [edr-evasion.md](edr-evasion.md). Match sleep to the engagement's OPSEC posture (see [opsec-and-lifecycle.md](opsec-and-lifecycle.md)).

## Where to learn the implementations

Study and build these in an authorized lab from canonical sources, not from copied snippets:

- **CRTO / CRTL** (Zero-Point Security) course material — the exam-aligned, authoritative treatment of loaders, BOFs, and post-ex in Cobalt Strike.
- **MITRE ATT&CK** T1055 (Process Injection) sub-techniques and T1620 (Reflective Code Loading) — the taxonomy and detection guidance.
- **Public C2 documentation** — Cobalt Strike, Sliver, Havoc, Mythic docs describe their own supported execution methods and profile controls.
- The local writeup index — `python scripts\search_writeup_index.py process injection` or `execute-assembly` — to see how techniques were applied and detected in published research. Read, then adapt in your lab.
