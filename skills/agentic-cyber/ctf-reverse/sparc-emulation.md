# SPARC CTF Binary Triage

Use this workflow only for supplied CTF files in a local emulator, container, or guest. Do not assume x86 calling conventions or control-flow behavior.

## Establish the exact target

1. Record `file`, `readelf -h`, `readelf -l`, and `readelf -d` output. Preserve the ELF class (often 32-bit in CTFs), endianness, interpreter, and dynamic-library list.
2. Use a SPARC-aware disassembler and decompiler. Cross-check decoded instructions with raw bytes at branch boundaries and around every apparent return.
3. Treat register windows and delay slots as first-class facts: a call/return may rotate a register window, and the instruction after a control-transfer instruction can still execute. Model those effects before assigning variables or simplifying a branch.

## Reproduce behavior locally

1. Prefer the challenge's supplied container, image, loader, and libraries. Otherwise construct a disposable matching sysroot and run the binary only with local test input under the matching QEMU SPARC user-mode emulator.
2. When the supplied setup exposes a local emulator-side debugger, use a multi-architecture debugger and save the guest architecture, executable, symbols, and transcript with the result.
3. Compare every behavior observation—input length, branch, message, exit status, and memory address—with an instruction or data reference in the static model. Resolve contradictions before using an observation as proof.

## Validate the model

- Track stack, frame, and return state in the target ABI rather than naming them after host registers.
- Re-check byte order for serialized integers, checksums, and protocol fields.
- Keep the binary, exact sysroot/container digest, command line, local input, and output together for teammate replay.
- If reversing reveals a vulnerability, transfer only the documented local execution model to `ctf-pwn`; do not turn it into an external-service workflow.

## Source

- Hack.lu CTF 2020 SPARC challenge writeup, including a locally emulated container plus multi-architecture debugging setup: <https://ctftime.org/writeup/24338>
