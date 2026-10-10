# Huffman and Prefix-Code Recovery

Use this workflow for supplied CTF encoders, custom compressed blobs, or local decoders. Establish the exact bitstream convention before treating output bytes as ordinary text or attempting candidate-symbol search.

## Recover the encoder model

1. Locate the symbol lookup. A table indexed by input byte commonly contains a code value and code length; record table stride, endianness, and which bytes are actually consumed by the encoder.
2. Trace the packing state: current accumulator, number of occupied bits, shift direction, condition for writing a full byte, and how leftover bits carry into the next output byte.
3. Determine whether code bits are emitted MSB-first or LSB-first. Check a one-symbol local test and a two-symbol boundary-crossing test; either convention can produce plausible output for short samples.
4. Distinguish a literal code table, a serialized binary tree, and a canonical-Huffman length table. For canonical coding, reconstruct codes from lengths before decoding payload symbols.

## Build a local decoder only after validation

1. Start with a small map or tree generated from the recovered table. Reject a path only when it cannot reach a leaf under the established bit order.
2. Preserve decoder state across byte boundaries. If the encoder flushes a partial final byte, record its padding rule and expected output length separately.
3. For a non-bijective custom encoder, model the state transition and use only supplied output bytes to prune candidate symbols. Keep every candidate path until a full local encode reproduces the target.

## Prove the result

1. Encode a supplied prefix or other known local input through the reconstructed model and require byte-for-byte agreement with the reference encoder/output.
2. Decode, then re-encode the proposed plaintext and compare the complete byte stream, including trailing partial-byte behavior.
3. Save table extraction offsets, bit order, symbol lengths, final-bit count, and the local validation hash with the solve evidence.

## Sources

- Newark Academy CTF 2020 `Encoder`: table extraction, shift/OR packing state, and local output comparison: <https://ctftime.org/writeup/24805>
- Google CTF 2021 `DAVID AND THE TREE`: compressed-data/Huffman-tree context: <https://ctftime.org/writeup/29459>
