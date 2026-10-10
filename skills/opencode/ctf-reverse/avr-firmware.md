# AVR Firmware and Intel HEX CTF Workflow

## Scope

Use this for a supplied AVR firmware image or Intel HEX file, optionally with a local emulator or CTF service. Keep all interaction confined to the supplied challenge endpoint or offline harness.

## Establish the Artifact and Memory Model

1. Confirm the format before treating it as raw bytes. Intel HEX records carry an address, record type, data, and checksum; preserve sparse addresses and extended-address records when converting.
2. Identify the AVR family from the challenge, vector table, or disassembler output. AVR code memory, SRAM, and EEPROM are distinct spaces; do not assume a RAM-looking address is an instruction address.
3. Disassemble with AVR-aware tooling and retain word-address vs byte-address conventions in your notes. In particular, branch/call targets, `Z` pointers, and `LPM` program-memory loads are common sources of an off-by-two error.

```bash
# Local artifact triage; select the MCU only when supplied or supported by evidence.
avr-objdump -D -m avr firmware.elf
avr-objcopy -I ihex -O binary firmware.hex firmware.bin
strings -a firmware.bin
```

## Reconstruct Input Handling Before Validation Logic

1. Locate reset/vector code, then trace UART or socket-adapter reads to the top-level parser.
2. Label parser dispatch decisions with a compact input table: accepted type, required delimiter, output, and next state. A JSON-like parser may distinguish strings, arrays, and object keys long before it reaches the secret check.
3. Follow validation data from flash reads (`LPM`) through registers to the first mismatch branch. Record whether the output is a boolean, index, signed difference, or modulo-256 difference.
4. Reproduce only that state transition in a short local script. Test at least one accepted and one rejected input before inferring secret bytes.

## Difference-Oracle Pattern

If the supplied challenge returns a first-mismatch value equivalent to `(probe_byte - secret_byte) mod 256`, recover a candidate byte algebraically and verify it against the local emulator/service. Confirm the direction using one controlled input; some implementations return the opposite subtraction.

```python
def candidate_from_difference(probe_byte: int, observed_delta: int) -> int:
    # Valid only after confirming: delta == (probe - secret) mod 256.
    return (probe_byte - observed_delta) & 0xff

# Do not advance after a mismatch until the previous prefix is confirmed.
# A zero delta usually means the tested byte matched; an index/length field may
# still be needed to distinguish success from a later mismatch.
```

**Validate:** Feed the recovered prefix back to the supplied local harness and check that the mismatch moves by exactly one position. Finish with the challenge's normal success condition, not merely printable output.

## Common AVR-Specific Pitfalls

- Treat `r0`/`r1` and the status register as live state around arithmetic; a decompiler may hide carry-dependent behavior.
- Check whether bytes in flash are loaded through `LPM`, rather than interpreted as adjacent RAM data.
- Model byte arithmetic modulo 256 before converting a displayed value to signed decimal.
- Keep the parser's maximum-length and terminator behavior. A correct secret prefix can still be rejected by a length cap.

**Source pattern:** Midnight Sun CTF 2020 Quals, `avr-rev` ([writeup metadata](https://ctftime.org/writeup/19396)).
