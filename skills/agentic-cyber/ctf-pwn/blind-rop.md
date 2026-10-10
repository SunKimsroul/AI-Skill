# Blind ROP for a Supplied CTF Service

**Scope:** Use only against the explicitly supplied CTF service or an identical local container. BROP is a fallback when no executable is available and each connection provides a reliable crash/continue observation. Do not apply this workflow to an unapproved host.

## Recognize the Pattern

A reachable native service crashes or disconnects on an overlong input, no binary is supplied, and a fresh connection can be opened for every probe. First establish a binary oracle such as `continue`, `clean close`, or `crash`; an ambiguous timeout is not enough.

## CTF-Local Workflow

1. **Calibrate the observation.** Send a small normal request and a deliberately overlong request several times. Record the exact per-connection behavior, timeout, and any write-half-close quirk. Abort the blind approach if the observations are not repeatable.
2. **Find the overwrite boundary.** Vary only the padding length. Keep a probe log containing input length, appended word, and normalized outcome. Confirm the candidate offset on independent connections.
3. **Find a stop gadget.** Search only after the offset is stable. A candidate that returns cleanly without consuming unexpected stack words is a control-flow checkpoint; test it with the expected number of filler words.
4. **Identify a multi-register ROP sequence.** Use the stop gadget as the return target to distinguish a plausible pop sequence from a random executable address. Infer the required stack-word count from the outcomes, never from a single success.
5. **Search for an output primitive and its call site.** In a CTF service, use only challenge-provided behavior to test whether a candidate returns bytes from a chosen readable address. Treat output format, descriptor choice, and return behavior as part of the hypothesis.
6. **Recover and validate.** Reconstruct enough of the supplied binary image to identify its load layout and functions. Move to a local copy/container as soon as challenge artifacts make that possible, then reproduce every assumed gadget and calling convention before forming a final chain.

## Guardrails and Validation

- Normalize observations into a small set; network jitter is not evidence of a gadget.
- Repeat each positive result and include negative controls (wrong offset, wrong stack depth, unreadable address).
- Keep a resumable probe ledger: target identity, payload layout, outcome counts, and inference. Never treat a scan result as a final address without replay validation.
- Prefer a challenge-provided local deployment for the final chain. If none exists, report the validated primitive and the remaining uncertainty rather than guessing about libc, PIE, or file descriptors.

**Source pattern:** UTCTF 2019, `ECHO` ([writeup](https://thekidofarcrania.gitlab.io/2019/03/11/utctf/); [challenge metadata](https://ctftime.org/writeup/13822)).
