# White-Box Cryptography Triage

Use this note for a supplied binary, table set, HDL/netlist, simulator, or local oracle that embeds a cipher implementation and key material. The goal is to reconstruct and verify the local transformation. Do not apply this workflow to third-party protected applications or live devices.

## Classify the supplied implementation

1. Preserve the artifact, toolchain/simulator version, and every supplied plaintext/output pair. Build a small local input/output corpus with non-sensitive test vectors before modifying anything.
2. Decide which representation is present: explicit rounds and constants, lookup tables, encoded affine transforms, a synthesized hardware netlist, or a custom cipher-shaped transformation. Do not label a table as AES solely because it has 256 entries.
3. Map data flow at byte/word granularity: input ordering, round boundaries, table/register grouping, key-like constants, output ordering, and any display/transport transformation. Keep raw byte order separate from the human-visible hex order.
4. For HDL/simulation challenges, start from the testbench or wrapper. Trace keypad/API stimulus -> internal state -> display/output buffer, and make one controlled local marker input to establish direction and endianness.

## Form a key/transformation hypothesis

1. Use static topology first: identify repeated round-shaped regions, S-box-like tables, mix/linear layers, and key-schedule or round-key injection points. Document what is observed rather than assuming a standard construction.
2. If a local white-box analysis result yields a candidate round key or equivalent internal value, independently test its position and direction. A last-round AES key, for example, is not automatically the master key.
3. Reverse an applicable key schedule only after confirming the cipher variant, key size, and round numbering from the artifact. For a custom implementation, prefer reconstructing the observed function over forcing it into a familiar algorithm.
4. Account for affine encodings, byte permutations, bit order, and reversed block display. These representation layers often explain why an otherwise plausible candidate fails.

## Validate locally

1. Reimplement the smallest observed transform or use the supplied simulator with fixed vectors. A valid reconstruction must reproduce multiple independent supplied outputs, not just one flag-shaped candidate.
2. If the candidate is a key, encrypt/decrypt at least two local known pairs in the verified direction and representation. Preserve the input, expected output, actual output, and any normalization applied.
3. For multi-block data, verify each block boundary and all display-order conversions before joining text. Record the final decoding chain as: raw bytes -> representation transform -> cipher operation -> plaintext representation.

## Source-derived patterns

RHme3's *White Box Unboxing* illustrates a table-based embedded cipher where a recovered intermediate key required a separate schedule-reversal and local validation step. Alfa CTF 2026's *Покой* adds a hardware/netlist form: trace the simulator's I/O representation, recover embedded AES material from the supplied logic, and independently validate byte ordering over every block.

Sources: <https://ctftime.org/writeup/7281> and <https://ctftime.org/writeup/40705>
