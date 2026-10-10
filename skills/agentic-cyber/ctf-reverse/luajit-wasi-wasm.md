# LuaJIT-Wrapped WASM / WASI Triage

Use this note for a supplied Lua/LuaJIT script that embeds, generates, or loads a WebAssembly module together with a small WASI-like shim. Treat it as three separate layers: the Lua wrapper, the module, and the host-import bridge.

## Separate wrapper from module

1. Preserve the supplied script and record whether it is Lua source, LuaJIT bytecode, or a launcher for another runtime. Locate the exact bytes that form the WASM module; an embedded module begins with the WebAssembly magic bytes, not with a decompiler's guessed text.
2. Extract the module losslessly into a copied local artifact. Record offset, length, hash, and the code path that creates/loads it, so later analysis can distinguish an original module from a generated buffer.
3. Map the wrapper's responsibility: argument/input collection, memory allocation, module instantiation, imported functions, exported entry point, return/print handling, and any final comparison. Do not spend time fully deobfuscating generated Lua runtime plumbing until it affects one of those edges.

## Reconstruct the WASM boundary

1. Inventory imports, exports, memories, tables, globals, data segments, and the entry function. Classify host imports as runtime/WASI support, logging/I/O, or challenge-specific behavior.
2. Trace input through the wrapper into linear memory: pointer, length, encoding, alignment, and ownership. Then trace output/result back from the module into Lua. Keep little-endian loads/stores and 32-bit versus 64-bit values explicit.
3. Find the verifier loop or state transform inside the module and translate only the relevant functions into a small reference model. Use the module's own data segments/constants as evidence and ignore adjacent runtime strings.
4. If control flow is flattened into a Lua dispatch table or a WASM branch structure, name blocks by observable role (length gate, transform, target table, result) before reducing it to equations.

## Local validation

1. Run the unchanged supplied wrapper with a harmless marker input and save the module entry, input bytes, result code, and output path.
2. Check the reference model against at least two local observations, including a failing and a passing-format candidate. A flag-shaped string alone is not proof if the checker accepts multiple encodings.
3. Preserve the extracted module, wrapper-to-module map, and a minimal solver/validator so the result can be reproduced without depending on the original interactive shell.

## Source-derived pattern

SekaiCTF 2025's *Gondola* used a LuaJIT script containing an embedded WASM module plus a minimal WASI shim. The key reusable step is to isolate the module and its input/output bridge first, then model the checker rather than treating the generated Lua/WASI scaffolding as the challenge logic.

Source: <https://ctftime.org/writeup/40380>
