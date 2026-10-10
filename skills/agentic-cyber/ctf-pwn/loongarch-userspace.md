# LoongArch Userspace Pwn Triage

Use this note for a supplied LoongArch ELF, local emulator image, or challenge service with a confirmed native memory-safety primitive. Establish the architecture and local runtime before interpreting a crash or constructing a challenge-local proof.

## Establish the executable model

1. Verify the ELF machine, class, endianness, interpreter, static/dynamic linkage, load base, and supplied libc/sysroot. Preserve the exact QEMU or container version used for the local run.
2. Start with static control flow. Record the stack-frame allocation, saved-register locations, input sink, and return sequence before assuming an x86-like calling pattern.
3. In the standard LoongArch calling convention, track argument registers `a0` onward, stack pointer `sp`, and return address `ra`. A branch-and-link records a return in `ra`; common returns jump through that register. Confirm the target's ABI from the supplied toolchain or binary rather than assuming a custom runtime follows Linux conventions.
4. Do not import MIPS delay-slot assumptions: LoongArch control-flow decoding has its own semantics. Use a matching LoongArch-capable disassembler/debugger for every control-flow conclusion.

## Reconstruct a confirmed local primitive

1. For an overflow or malformed-input condition, calculate the distance from the controlled object to every saved register and the saved `ra` from the actual frame layout. Validate offsets with a harmless recognizable marker in the local copy.
2. For a statically linked challenge, separately inventory executable code, writable memory, imported stubs, and mitigation settings. A large binary may expose many instruction sequences, but each candidate must be proven to restore `sp` and `ra` in the expected order.
3. Treat each potential chain element as a state transition: input registers, stack reads/writes, changed callee-saved registers, new `sp`, and next `ra`. Reject sequences whose side effects cannot be satisfied by the supplied local process.
4. Prefer the intended local success path or a non-sensitive marker function when validating control flow. Do not reuse an architecture-specific result against an unrelated host or service.

## Local verification

1. Run the supplied binary under the documented local emulator or guest and save the architecture, load mapping, crash/exit state, and relevant register values.
2. Cross-check every instruction/offset with a second local tool when possible. If the static tool and emulator disagree, treat the emulator trace and raw instruction bytes as primary evidence.
3. Re-run from a clean challenge copy and preserve the script, tool versions, ABI facts, and constraints that make the result reproducible.

## Source-derived pattern

UTCTF 2023's *Bing Chilling* demonstrates the reusable order: first obtain a LoongArch-capable local emulator/toolchain, identify the stack frame and `ra` restoration, then model any confirmed primitive using LoongArch state rather than x86 assumptions. The note intentionally omits the challenge's offsets and chain.

Source: <https://ctftime.org/writeup/36285>
