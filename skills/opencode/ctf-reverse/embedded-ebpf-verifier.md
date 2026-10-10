# Reverse - Embedded eBPF objects and nested verifier payloads

## Embedded eBPF object inside a PE, with a nested position-keyed verifier payload

**Trigger:** A Windows PE's `.rdata` contains a run of bytes starting `7f 45 4c 46 02 01 01 00` (a 64-bit little-endian ELF) and the surrounding code feeds a user-derived buffer into a small interpreter loop with eleven 64-bit registers.

Carve the ELF out of `.rdata` by magic and length, and treat it as a separate target: `llvm-objdump -d` its `.text`, and dump `.rodata` independently — in these challenges `.rodata` is not string data but a descriptor (type, skip, length, start offset) followed by a second, encrypted instruction stream. Decode that nested payload with a per-position keystream rather than a single XOR key: each 4-byte instruction at file offset `off` typically has each of its bytes XORed with a distinct affine function of `off` (`raw[j] ^ ((off*a_j + b_j) & 0xff)`), so recover the four (a,b) pairs from a few known-shape instructions and apply them across the whole range. Once decoded, histogram the opcode byte before reading any semantics: a handful of marker opcodes, a block of direct byte-equality opcodes, two large equal-sized blocks of generator opcodes, and one terminal opcode tells you the program's structure immediately. Exploit the cheap constraints first — the direct equality checks pin specific input bytes for free, and only the remaining positions need to be solved against the outer parser's aggregate state words, lane sums and coverage masks. Keep the layers strictly separate in your solver: PE parser gives structural constraints, the eBPF object gives the compare function, the nested payload gives the direct checks. Where the outer PE contains a bespoke byte-mixing hash used to derive the final key, emulate it with Unicorn over the recovered inputs instead of porting it — custom mixers resist hand-transcription and a wrong port is indistinguishable from a wrong input.

```bash
llvm-objdump -d embedded.o
```

Source: https://cybersecurityelite.com/ctf-writeups/sekai-ctf-2026-writeup/
