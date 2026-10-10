# CTF Reverse - 6502 and retro runtime targets

Use this only for a supplied CTF runtime, emulator, ROM/program image, or local sandbox. A host executable that loads a `.prg`/ROM can contain both a native launcher and a guest 6502 program; establish which side owns the challenge logic before changing anything.

## First-pass map

1. Identify the loader: program-image size limit, destination/load base, reset state, and entry program counter.
2. Find the execution loop in the host runtime. A fetch/decode/dispatch loop or opcode-indexed handler table identifies the VM boundary and shows whether the instruction set is standard 6502, a variant, or a custom emulator.
3. Record guest architectural state separately from host variables: `A`, `X`, `Y`, status flags, stack pointer, program counter, zero page, guest RAM/ROM, and any I/O or ROM-call hooks.
4. Build or adapt a disassembler only after confirming opcode widths, operand/addressing modes, endianness, and the load base. Raw image offsets are not necessarily guest addresses.

## Reverse the guest program

- Treat an initial jump as a likely code/data split; follow reachable control flow before treating skipped bytes as instructions.
- Track 16-bit addresses as little-endian and distinguish zero-page indirect addressing from absolute addressing.
- Follow input, output, and comparison routines rather than beginning at an arbitrary byte. ROM/KERNAL-like call sites, error strings, and keyboard/input helpers are useful anchors in CTF runtimes.
- Translate small byte transforms into a short reference script only after documenting the relevant flag/register behavior. Check shifts/rotates, carry, flag-dependent branches, byte wraparound, and index-dependent operations explicitly.

## Guest vs host boundary

When a challenge combines 6502 code with a native runtime, first decide whether the intended solve is:

- **reverse:** recover a flag checker or encoded data from the guest program;
- **guest pwn:** reason about the supplied emulator's guest stack/memory and control flow within the CTF; or
- **host pwn:** a native parsing/emulation bug in the runtime itself.

Do not assume guest addresses map directly to host pointers. For a supplied local pwnable, preserve the runtime/version, program load base, stack direction, return-address representation, and endianness before moving to `/ctf-pwn`.

## Validation

- Keep the program image hash, load base, and decoded guest address beside every disassembly annotation.
- Re-run candidate input in a clean local runtime and confirm through the program's intended success path.
- If a decoder works only at raw file offsets, verify whether it must be rebased to guest memory first.

## Source-backed pattern

1337UP LIVE CTF 2023's *Impossible Mission* used a native runtime that loaded a 6502 program into guest memory. Its writeup demonstrates recovering the loader and opcode dispatch, rebasing a program image, separating data from code, and modeling the guest transformation: [CTFtime writeup](https://ctftime.org/writeup/38228).
