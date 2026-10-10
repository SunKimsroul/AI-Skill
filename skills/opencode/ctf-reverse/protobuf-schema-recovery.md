# Protocol Buffers CTF Schema Recovery

Use this workflow for supplied `.proto` files, descriptor sets, binaries, byte streams, or passive captures. Decode and reproduce messages locally; do not send speculative messages to systems outside the supplied CTF environment.

## Establish what is available

1. Preserve the original bytes and identify framing separately from the protobuf message: a file or socket stream can add a length prefix, record envelope, compression layer, or transport header.
2. Search supplied source, archives, binaries, and generated-code metadata for `.proto` files, `FileDescriptorProto`, service/method names, field names, package names, and generated-message symbols.
3. If a schema or descriptor set exists, use that exact version. Record syntax/edition, package, imports, and compiler/runtime version before generating code or decoding data.

## Decode an unknown message without inventing a schema

1. Use `protoc --decode_raw < message.bin` or an equivalent local wire-format viewer to make a field-number and wire-type ledger. This is an observation aid, not a type declaration.
2. Decode every key as `(field_number << 3) | wire_type`. Treat wire types as constraints: varint, 32-bit, 64-bit, or length-delimited; a length-delimited value can be bytes, UTF-8 text, a packed scalar sequence, or a nested message.
3. Compare multiple supplied messages and controlled local round trips. Field number, repetition, value range, string plausibility, nested-field structure, and byte-length changes reveal likely semantics.
4. Account for protobuf behavior before trusting a differential: absent fields may be omitted, repeated numeric values may be packed, maps are repeated entry messages, and duplicate singular scalar fields use the last value observed by the parser.

## Reconcile generated code and wire data

1. In generated Java, Go, Python, C++, Rust, or JavaScript code, map parser/getter/setter names back to field numbers and verify them against serialized samples.
2. If only a binary is supplied, locate descriptor data or generated parser routines, then use the recovered mapping to annotate the reverse-engineering model. Keep field names separate from values until evidence joins them.
3. Build a minimal local schema only after the wire ledger and generated-code facts agree. Serialize a known benign message and require byte-for-byte equality (or a documented reason why serialization differs) before using it in a challenge model.

## Validation checklist

- Preserve message framing as well as protobuf bytes.
- Validate nested messages, packed fields, and duplicate-field behavior independently.
- Keep the exact local decoder/compiler version, schema/descriptor hash, sample hash, and decoded output with the solve evidence.
- Hand a discovered memory-safety or race issue to `ctf-pwn` only after the local protobuf parser and message boundary are understood.

## Sources

- Protocol Buffers official wire-format reference: <https://protobuf.dev/programming-guides/encoding/>
- Google CTF 2020 `namespacefs` metadata: <https://ctftime.org/writeup/23897>
- Nuit du Hack CTF Quals 2017 `LetsEnchiffre` metadata: <https://ctftime.org/writeup/6159>
