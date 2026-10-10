# RISC-V Userspace Pwn Triage

Use this note for a supplied CTF RISC-V binary, emulator image, or local QEMU service where the program is a userspace target. Keep testing inside the challenge image or local harness.

## Establish the execution model first

1. Read the challenge README and launcher before reverse engineering. Record the binary load address, memory permissions, word size, endianness, emulator, and the challenge-specific syscall table.
2. Import the file at the declared load base. A raw image loaded at address zero produces misleading references and stack-relative offsets.
3. Identify the ABI from the file and startup code. In the standard integer ABI, `a0`–`a7` carry arguments and syscall selection; `ecall` enters the challenge kernel or runtime. Treat non-Linux syscall numbers as challenge-defined until verified from the supplied material.
4. Map startup explicitly: memory map → stack setup → entry → dispatcher. Record whether the program text is writable/executable and whether a guest write can ever reach it.

## Decompile defensively

RISC-V disassemblers can lose type information around `ecall` and compressed instructions. Reconstruct behavior from register setup and memory accesses instead of trusting every decompiler signature.

- `sp` is the stack pointer; `ra` is the return address.
- Array addressing commonly appears as `base + index * element_size`; preserve the signedness of the parsed index.
- A comparison such as `index < count` is not a lower-bound check. Test whether negative values survive parsing and reach the address calculation in the supplied challenge.
- Check 32-bit versus 64-bit loads/stores separately. A 32-bit write on RV64 can be enough for a local code/data target but does not automatically control a full pointer.

## Convert a confirmed primitive into a local plan

When a challenge-local OOB read/write is real, make the arithmetic auditable:

```text
target = array_base + index * element_size
index  = (target - array_base) / element_size
```

Verify alignment, signed parsing, integer width, and the direction of the write with a harmless marker in the local copy before changing a control-flow target. Prefer the intended local win path or challenge syscall over assumptions about a normal Linux environment.

## Validation checklist

- Re-run under the supplied emulator and prove the chosen load base and stack address.
- Log each observed read/write address and compare it to the calculated address.
- Confirm instruction encoding with a local RISC-V assembler/disassembler that matches the target ISA extensions, especially when compressed (`C`) instructions are present.
- Preserve a script or interaction transcript that reproduces the result from a clean challenge instance.

## Source-derived pattern

CyberSecurityRumble's `riscy-stack: Userspace` illustrates the order of work: a custom userspace image and syscall table, manual load-base selection, an upper-bound-only signed index check, then target-address arithmetic inside the supplied RWX challenge mapping. The reusable lesson is the model-and-verify workflow above, not the challenge-specific offsets or payload.

Source: <https://ctftime.org/writeup/37449>
