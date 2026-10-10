# CTF Pwn - TEE and TrustZone targets

Use this note only for a provided CTF/local-lab TrustZone or OP-TEE image. Treat the supplied QEMU snapshot, kernel, Trusted Application (TA), and host client as the complete target; do not apply these steps to a real device or production TEE.

## Recognition and boundary map

Suspect this family when an archive contains `tee.elf`, `optee_os`, a QEMU launch script, a Linux host client, or TA source / `.ta` binaries. Draw the path before testing anything:

```text
normal-world host client -> libteec / shared memory -> TA command handler
    -> OP-TEE syscall / secure kernel object -> SMC service or challenge flag path
```

Do not assume the host process, TA, and secure kernel share an address space or allocator. Label every buffer as host, shared, TA-private, or secure-kernel memory and record every copy/translation boundary.

## Deterministic triage

1. Preserve the exact supplied QEMU image, build revision, and launch arguments; collect a baseline run before changing code.
2. Identify the host command IDs, TA UUID, TA entrypoints, parameter types, shared-memory allocation, and error handling.
3. Load matching symbols for `tee.elf` in the provided debugger setup. Break at the challenge-specific syscall/handler, the TA command dispatcher, allocation/free paths, and the intended privileged-operation gate.
4. Compare decompiled secure-kernel additions with ordinary OP-TEE code. Challenge changes often stand out by naming, command numbers, custom tables, or unusual lifetime management.
5. Build a small TA or host harness that makes one controlled operation per run. Log return code, object index/handle, requested length, and whether the data crosses a world boundary.

## Primitive-oriented review

For each allocate/read/write/free operation, test only inside the supplied lab for:

- stale handles or indexes after free;
- length, offset, and integer-conversion mismatches;
- cross-world pointer or shared-memory validation mistakes;
- object-type confusion between allocator size classes;
- callbacks, operation tables, or state objects reclaimed into a stale allocation;
- a privileged SMC or flag handler reached only after a specific secure-kernel state transition.

When a memory bug is present, first prove the smallest reliable primitive: object reuse, controlled field change, read, or write. Only then map the affected structure to a legitimate invocation path already exercised by the TA. This prevents confusing a TA panic, a normal-world crash, and a secure-world exception.

## Validation checklist

- Reproduce the result after a clean emulator restart.
- Keep symbols, image hash, offsets, and the TA/host build versions together.
- Verify the final output crosses back through the expected TA/host buffer; do not treat console noise or decoy strings as a flag.
- If the hard part is identifying a custom syscall or ARM64 code path, load `/ctf-reverse`; if the hard part is heap/object lifetime, load the kernel and heap references in `/ctf-pwn`.

## Source-backed patterns

The SAS CTF 2025 *Broken Trust* writeup illustrates a QEMU OP-TEE bundle with a host client, TA, secure-kernel syscall, and a use-after-free/object-table investigation. It is a useful model for boundary mapping and reproducible debugger setup, not a template to replay outside the supplied challenge: [CTFtime writeup](https://ctftime.org/writeup/40255). Google CTF 2025's *unicornel trustzone* is another public TrustZone/emulator example: [CTFtime entry](https://ctftime.org/writeup/40333).
