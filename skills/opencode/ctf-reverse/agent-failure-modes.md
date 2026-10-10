# Agent failure modes in reverse engineering

Reversing is the category where an automated solver most often *looks* productive while getting nowhere — running tool after tool, producing fluent explanations, never producing a flag. The failures are not random. Research through 2025–2026 has characterised them, and each one has a specific countermeasure.

Read this when analysis has stalled, before running another tool. Every remedy below is something to do *instead of* one more command.

Sources are listed at the end; this file is an original summary of their findings, not a reproduction.

## The four root causes

Failure logs across agents solving CTF reversing challenges cluster into four causes, and they compound:

1. **Training bias** — pulled toward familiar patterns, so an unusual construction is read as the common one it superficially resembles.
2. **Over-trust in observations** — tool output is treated as fact rather than as a claim needing corroboration.
3. **Context limitation** — evidence established early is lost during long analysis, so later reasoning runs on a partial picture.
4. **Plan persistence** — a failed plan is continued rather than abandoned.

A useful frame is **Observe → Comprehend → Plan**. Anti-analysis techniques attack *Observe* first, and once the observation is wrong, a perfectly sound plan built on it still goes nowhere.

## Failure: analysing code that never runs

The most expensive failure, because everything downstream inherits it. Packing, runtime string decryption, and anti-debugging all mean the bytes on disk are not the instructions that execute.

The question a competent human asks first, and an automated solver almost always skips:

> **Am I looking at the code that actually executes?**

Ask it before interpreting any decompiled function, not after a hypothesis fails. The tell is interpreting the *meaning* of a plausible-looking function before establishing that the function is ever called.

**Remedy.** Corroborate static reading with dynamic evidence before building on it. Confirm the function is reached — breakpoint, xref, or trace. Dump memory after any suspected unpacking or decryption and compare it against the on-disk bytes. Where the two disagree, the runtime image wins.

## Failure: over-trusting the decompiler

Pseudocode is easier to read than assembly, which is exactly why it is over-relied on. It is a *reference for analysis*, not a reproduction of the original source or of actual behaviour. Optimisation and obfuscation distort it further, and it routinely invents wrong control structures and types.

**Remedy.** Treat pseudocode as a hypothesis about the assembly. When it matters — a comparison, an offset, a loop bound, a type — read the instructions. Where a decompiled function can be recompiled and run, compilation errors and execution results are strong feedback for correcting it; iterating on that feedback recovers a large share of output that would not compile on the first pass.

## Failure: context loss across functions

An agent explains one function correctly and still cannot say where the input is transformed or where it is finally compared. Real validation logic is distributed: `main` takes the input, a helper checks length, a global initialiser builds the key, and the comparison happens inside a VM interpreter. For a crypto binary the constant table, key schedule, IV, padding, and output encoding may each live somewhere different.

**Remedy — build the flow, not a pile of summaries.** "This function appears to validate the input" is not a result. The target is a single connected statement, for example: *this function compares bytes 4–12 of `argv[1]` against a global table that the initialiser decrypts with XOR at startup.*

Two structuring habits that measurably help:

- **Work bottom-up.** Analyse small leaf functions first, record what each establishes, then expand outward. Whole-program summarisation at the top loses exactly the detail the answer depends on.
- **Extract clues before summarising.** Pull the high-value anchors first — imports and API calls, strings, exported and named functions, distinctive constants — and let those select what to read. A larger context window is not a substitute; the constraint is which evidence gets connected, not how much fits.

Keep the call graph, xrefs, data flow, and any runtime trace in view together. Dispersed clues only become a validation flow when they are looked at as one thing.

## Failure: hypothesis fixation

The single most recognisable stall: commands keep executing, and no new understanding arrives. The agent reinterprets the same output in different words, or issues small variations of a command around an initial guess that was wrong.

Once "this is AES" is decided, evidence gets sought that *fits* AES rather than evidence that would disprove it. Every later step is pulled in the same direction. When GDB commands keep coming but the hypothesis never changes, the problem is not command syntax — it is the absence of a rule for stopping.

**Remedy — falsify on purpose, and give yourself stopping conditions.** Models default to supporting the current hypothesis rather than attacking it, and explicitly directing the search toward counterexamples measurably improves how often the true rule is found. So:

- Write the current hypothesis as one plain sentence. If it cannot be stated plainly, it cannot be tested — only elaborated.
- Name the observation that would **disprove** it, then go get that observation. Not the one that would confirm it.
- Set the stopping condition *before* starting a line of analysis: what result, or how many attempts without a new observable, ends it.
- When it ends, switch to a **different kind** of hypothesis — a different algorithm family, a different entry point, a different assumption about which artifact is the real target. A refined version of the same guess is not an alternative.

Recording facts, assumptions, and open questions separately (below) is what makes this possible: fixation is hard to see when confirmed evidence and speculation are written in the same voice.

## Failure: a correct explanation and no answer

A CTF asks for a flag, not an analysis. "The structure resembles AES" and "the program transforms and compares the input" can both be accurate and worth nothing.

Benchmarks built for this grade externally verifiable artifacts — a password the program accepts, a working keygen, a recovered flag — rather than prose. Identifying an algorithm and recovering the key are separately measured for good reason: recognition rates stay high when familiar S-boxes and round constants are visible, while recovery collapses once constants are XOR-concealed, the key is split across several places, and a PRNG state has to be tracked as well.

**Remedy.** End every line of analysis in something executable — a solver, a keygen, a patch, or an emulator — and run it against the real binary. A keygen must *generalise*: it is validated against inputs you have not seen, so hardcoding the one value you recovered does not pass. Turn a recovered value into a small validation script immediately; fast, cheap rejection of wrong candidates is most of the advantage an agent has.

## Failure: expensive to check

An analysis a human has to re-derive to trust has negative value. LLM assistance measurably helps novices comprehend programs while doing little for experts — and wrong suggestions actively slow experts down, because a plausible false lead costs more to rule out than it did to produce.

**Remedy — separate the three kinds of statement, always.**

| Record | Meaning | Example |
|---|---|---|
| **Fact** | Confirmed by a tool or observed at runtime | `strcmp` at `0x401A20` is reached with `argv[1]` |
| **Assumption** | Believed, not yet verified | the global at `0x4C1000` is the comparison table |
| **Clue** | Worth investigating, not yet interpreted | an unreferenced 256-byte block of high-entropy data |

Keep the reproduction command beside each fact. This is what lets a human check one link instead of re-running the whole analysis, and it is the mechanism that makes the expert-plus-agent combination outperform either alone.

## Conditions that predict success

Where these hold, hand it to the agent and let it iterate:

- Static analysis matches the executed path — strings, constants, and comparison routines are visible as-is.
- Validation logic is concentrated in one or two functions with simple call relationships.
- Candidate answers can be tested against the binary immediately.
- Familiar structures are present — XOR, Base64, standard cryptographic constants.
- The output can be made executable and externally checked.
- Call graph, data flow, xrefs, and traces are available together.

Where they fail — the executed code differs from what is on disk, the needed values are scattered, or intermediate results cannot be validated — more attempts will not help. Change the approach instead, and get a human to look.

## When to bring in a human

Automation is strongest at speed and repetition, and weakest at deciding that the current direction is wrong. Escalate when analysis has stalled twice on different hypotheses, when the decompiler and the runtime behaviour disagree and it is unclear which to believe, or when the challenge needs direct observation of a screen or live interaction — see `ctf-misc/interactive-and-ui-challenges.md`.

Hand over the fact/assumption/clue record, not a request for ideas. An expert redirects in seconds given the state; given "I'm stuck", they have to rebuild it first.

## Sources

Summarised from TeamH4C, "Why Your AI Agent Can't Solve CTF Challenges: Reverse Engineering" (<https://h4c.team/posts/49>), and the work it surveys:

- Nishizaka et al., "Towards LLM-Resistant Software Protection: Agent Failure Patterns in CTF Reverse Engineering", NDSS BAR 2026 — the four failure causes and the Observe/Comprehend/Plan frame.
- David & Gervais, "CrackMeBench: Binary Reverse Engineering for Agents" — externally validated artifacts over explanations.
- "CREBench" — algorithm identification measured separately from flag recovery.
- Chen et al., "ReCopilot" — call graph and variable data flow as analysis context.
- "Kong" — bottom-up accumulation of function-level results.
- "Clue-Driven Reverse Engineering" and Celebi-POC — clue extraction before summarisation, and grounding checks on model suggestions.
- "DecLLM" — compilation and execution feedback to repair decompiler output.
- "Failing to Falsify" — models favour confirming over refuting; prompting for counterexamples improves discovery.
- "Decompiling the Synergy" — LLM assistance helps novices more than experts; wrong suggestions cost expert time.
