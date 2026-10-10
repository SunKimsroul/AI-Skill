# CTF Reverse - Turing-machine virtual machines

Use this workflow for a supplied CTF Turing-machine description, VM program, or local checker. Treat it as a table-driven state machine first; do not attempt to reason from an unbounded raw trace alone.

## Normalize the machine

Represent every transition in a uniform table:

```text
(state, read_symbol) -> (write_symbol, head_move, next_state)
```

Also record the blank symbol, tape initialization, start state, halting/accept/reject states, input encoding, and any side channel that exposes tape or state. Do not assume the head is bounded, the tape is byte-oriented, or a final state means success without checking the verifier.

## Controlled analysis workflow

1. Build a tiny emulator for the provided transition format with a step limit, trace mode, and a sparse tape representation. Keep input/output framing separate from transitions.
2. Run minimal controlled inputs and compare state/head/tape snapshots at repeatable checkpoints. Look for sweeps, delimiters, counters, pairing, rotations, copying, and phase changes.
3. Group repeated transition regions into a macro operation before expanding to full input. For example, a long left/right sweep may implement a permutation or a bit-level transform rather than a unique per-character rule.
4. Detect non-termination deliberately: record the first repeated `(state, head, local tape window)` condition and determine whether it is an intended reject loop, a format guard, or an emulator mistake.
5. Derive an inverse or constrained model only after identifying the machine's macro transformation. Validate it against the local checker with a fresh run.

## Crypto boundary

Some Turing-machine CTFs implement a recognizable primitive after an unusual tape transformation. Keep the layers separate:

- reverse the input encoding/permutation and machine control flow first;
- identify the primitive and exact state/round deviations second;
- load `/ctf-crypto` only when the remaining problem is genuinely AES, a cipher, or key recovery rather than VM semantics.

## Common traps

- Treating a bit tape as independent ASCII characters.
- Missing a one-bit rotation, pair swap, delimiter, or final cleanup pass before matching known output.
- Confusing a verifier's infinite loop with a successful halt.
- Optimizing or symbolically executing the full machine before first identifying its repeated high-level phases.

## Source-backed pattern

UMassCTF 2024's *Primitive Reversing* tasks used custom Turing machines: one performed tape-level bit transformations, while its sequel implemented an AES-like construction. They illustrate the need to model the transition system and the crypto interface as distinct layers: [CTFtime entry](https://ctftime.org/writeup/39081).
