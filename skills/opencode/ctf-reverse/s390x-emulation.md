# s390x / zArchitecture CTF Binary Triage

Use this workflow only for supplied CTF artifacts and a local emulator or guest. Do not infer x86 ABI, byte order, register names, or syscall conventions from an IBM System Z target.

## Recognize and preserve the target facts

1. Record `file`, `readelf -h`, `readelf -l`, and `readelf -d` output before changing anything. An s390x sample is commonly reported as `ELF 64-bit MSB IBM S/390`; `MSB` means big-endian.
2. Save the ELF interpreter path, `DT_NEEDED` libraries, and every supplied loader/library alongside the binary. Treat that collection as the execution environment.
3. Start static analysis with an s390x-aware disassembler, for example `s390x-linux-gnu-objdump -drwC target`, and cross-check control flow against strings, relocations, and data references. Do not trust an analysis tool that identifies the architecture incorrectly.

## Run only in a matching local environment

1. Build a disposable local sysroot from matching supplied or distribution s390x libraries. Use QEMU user mode with that sysroot, for example `qemu-s390x -L ./s390x-sysroot ./target`, and give it only local test input.
2. If QEMU user-mode tracing or debugger attachment is incomplete, switch to a Hercules guest with an s390x Linux image and its native tools. Keep the guest image, kernel, libraries, and command transcript with the evidence.
3. Compare static conclusions with observed local behavior: exit status, accepted/rejected test input, emitted messages, and file accesses. Record a mismatch instead of silently adjusting the model.

## Recover embedded data carefully

1. Inspect sections and high-entropy regions for format magic and size fields; do not label bytes as encrypted merely because they look random.
2. If a decompressor or checksum routine appears in the control flow, reproduce that transform in a small local script and validate the output by magic, length, and a second independent parser or hash where available.
3. Trace each recovered blob back to its referenced function and input condition. This separates a decoy resource from the bytes that influence validation.

## Validation checklist

- Confirm endianness at each multi-byte field and comparison.
- Confirm each dynamic observation against an address or function in the static model.
- Keep all inputs, sysroot contents, emulator version, and outputs so another teammate can replay the result.
- If the challenge later exposes a vulnerability, hand the understood local execution model to `ctf-pwn`; do not turn emulator observations into an external-service workflow.

## Sources

- Olympic CTF 2014 `zpwn` and its s390x execution notes: <https://blog.dragonsector.pl/2014/02/olympic-ctf-2014-zpwn-200.html>
- Olympic CTF 2014 `zbin` static-analysis and compressed-data notes: <https://blog.dragonsector.pl/2014/02/olympic-ctf-2014-zbin-re-500.html>
