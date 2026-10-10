# Browser and managed-runtime CTF pwn workflow

Use this note only for supplied browser-engine builds, challenge shells, local containers, or an explicitly authorized lab. Browser and runtime challenges combine reverse engineering, allocator behavior, JIT assumptions, and sandbox boundaries; prove each primitive in the supplied build before attempting a chain.

## Scope the target

1. Identify the engine, revision/build flags, architecture, challenge wrapper, exposed JavaScript/bytecode API, and the exact solved condition.
2. Decide whether the task is a logic/trust-boundary challenge, a managed-runtime bug, a renderer-only primitive, or a full sandbox escape. Do not assume “browser” implies a memory-corruption exploit.
3. Reproduce the normal input path and save the crashes, output, and engine flags. Use the supplied debugger symbols and harness first.

## Primitive ladder

Document each rung separately and stop if a rung is unproven:

| Rung | Question |
|---|---|
| Reachability | Can the supplied input reach the interesting parser, cache, JIT tier, or native binding? |
| Confusion / corruption | Is there a controlled type, bounds, lifetime, integer, or serialization mismatch? |
| Managed primitive | Can it produce a stable object/address leak, forged reference, or bounded read/write in this build? |
| Native boundary | Does the primitive cross pointer compression, a heap cage, wasm code protection, or an embedder boundary? |
| Goal | Is the actual CTF goal a file read, a flag-service call, a process action, or a sandbox transition? |

Keep an invariant table for object maps/types, element kinds, length/capacity, backing stores, GC/lifetime assumptions, and JIT guards. A crash that changes after garbage collection or warm-up is not a stable exploit primitive.

## High-value challenge patterns

- **Trusted serialized cache/bytecode:** treat code cache, snapshot, deserialization, and custom bytecode input as a trust-boundary problem first. Verify whether the engine authenticates or structurally validates the data before looking for a raw memory bug.
- **JIT speculation mismatch:** compare optimized assumptions with the deoptimization/slow path; vary type, shape, length, prototype, and warm-up history one variable at a time.
- **Wasm boundary:** distinguish linear-memory bounds bugs from code-generation/control-flow bugs. Record module bytes, imports, memory/table configuration, and the engine revision.
- **Embedder API bug:** audit native bindings for argument conversion, persistent handles, backing-store lifetime, and externally allocated buffers.
- **Sandbox/cage boundary:** record which pointers are compressed, tagged, caged, indirect, or protected. Do not equate a managed-heap read/write with arbitrary native code execution.

## SpiderMonkey / Firefox Engine Targets

1. Establish whether the artifact is the standalone `js` shell, a Firefox process, or a custom embedder; exposed shell helpers and the process sandbox are different targets.
2. Record the exact Mozilla revision, build mode, enabled JIT tiers, assertions, GC/zeal flags, and any custom patches before comparing behavior with another write-up.
3. Model SpiderMonkey-specific object state separately from V8: object shape/group, slots, elements, typed arrays, wrappers, and nursery/tenured lifetime. Do not reuse a V8 map, hidden-class, pointer-compression, or array-layout assumption.
4. For a suspected JIT issue, make a small local reproducer and vary warm-up count, type specialization, shape transition, and GC timing one dimension at a time. Preserve the first deterministic mismatch before attempting any native-boundary step.
5. Treat a renderer/js-shell primitive and a Firefox sandbox escape as separate proof obligations. The supplied CTF harness determines the actual goal.

**Validation:** State the engine revision and wrapper, reproduce the behavior under the same flags twice, then verify the primitive survives a deliberate GC or JIT deoptimization test. If it does not, keep it classified as a crash rather than a stable primitive.

## MuJS Typed Arrays and Detached Buffers (Zh3r0 CTF 2021)

Use only with a supplied MuJS build/challenge shell or a local lab. MuJS is much smaller than major browser engines, but CTF wrappers often add their own `ArrayBuffer`/typed-array support and allocator choices; do not assume stock MuJS object layouts or browser APIs.

1. Record the MuJS revision, wrapper patches, whether `ArrayBuffer` and typed arrays are native or challenge-added, and the allocator in use (`jemalloc` versus libc).
2. Audit typed-array construction and indexing for width changes: requested element count, element width, byte length, allocation size, bounds check, and stored length must use compatible integer types. A multiplication or truncation mismatch can create a logical-size versus backing-store-size divergence.
3. Audit buffer-detach and garbage-collection paths. After detachment, enumerate every remaining JS reference, host pointer, finalizer, and backing-store ownership field. A stale typed-array view that survives collection is a lifetime bug, not merely a JavaScript exception.
4. With jemalloc, map only the local challenge's allocation sizes to size classes and observe reuse by allocating harmless sentinel buffers. Keep allocation count, size, GC trigger, and object lifetime in an experiment table; heap behavior is build-specific.
5. Prove the smallest stable primitive first: controlled index/length mismatch, deterministic stale-view access, or a local sentinel change. Re-run after an explicit GC and under the same allocator configuration before attempting any native-boundary reasoning.

**Validation table:** engine revision; wrapper commit; allocator and build flags; typed-array metadata before/after each operation; GC event; observed sentinel/result; repeat count. A single post-GC crash is not proof of usable OOB or UAF behavior.

**Key insight:** Small embedded engines reduce browser complexity, but custom typed-array support creates a separate native memory model. Keep the JavaScript-visible length, C allocation size, detached-buffer ownership, and allocator reuse model as four independent invariants.

**Source inspiration:** Zh3r0 CTF V2 *Javascript-for-Dummies* task metadata and the [2021 challenge analysis](https://ptr-yudai.hatenablog.com/entry/2021/12/06/001931).

## Differential method

1. Build a minimal test that has one observable property: a changed field, a controlled exception, a one-byte leak, or a deterministic crash.
2. Run it with and without optimization/GC triggers; preserve a matrix of behavior by build flag and iteration count.
3. Use debug printing, heap/object inspection, and source-level assertions in the local challenge build to explain the result.
4. Only then reduce the test into a repeatable primitive and evaluate whether the solve condition requires another boundary.

## Pivots

- Start with `ctf-reverse` for an unknown engine binary, custom VM, snapshot format, or native binding.
- Use `ctf-web` if the hard boundary is a browser origin, postMessage, extension, or server-side endpoint rather than managed memory.
- Use `ctf-crypto` if a challenge cache/bytecode blob is protected by a real cryptographic construction.

## Source technique example

[Google CTF 2022 d8 write-up](https://gist.github.com/Riatre/83d5fdb970946c8e185c5e1b2b842b1b) illustrates the important initial distinction between a trusted serialized code-cache boundary and a conventional memory-corruption path.

## V8 Bootstrap Primitives: addrOf, fakeobj, and the Sandbox

Every V8 exploit passes through the same two primitives before anything else is possible. Build them
first; the specific bug only matters insofar as it yields them.

**`addrOf(obj)`** — leak the in-heap address of a JS object. The standard construction is a type
confusion between a `PACKED_DOUBLE_ELEMENTS` array and a `PACKED_ELEMENTS` array: store the object
in the array, read the slot back as a double, and the raw pointer arrives as its bit pattern.

**`fakeobj(addr)`** — the inverse. Write a chosen address as a double, read the slot back as an
object reference, and V8 treats those bytes as a live pointer.

```javascript
// with a bug that lets the same backing store be read as both kinds
let f64 = new Float64Array(1);
let u64 = new BigUint64Array(f64.buffer);
function d2i(d) { f64[0] = d; return u64[0]; }
function i2d(i) { u64[0] = i; return f64[0]; }
// %DebugPrint(obj) in d8 --allow-natives-syntax shows the Map and element kind
```

From there the usual escalation is to corrupt a `TypedArray`'s **backing-store pointer and length**,
which turns into arbitrary read/write without needing the original bug again. Keep one corrupted
array as the R/W primitive and leave everything else intact — a stable primitive is worth more than
a clever one.

**Element kinds are a lattice and transitions are one-way.** `SMI → DOUBLE → ELEMENTS`, and a
`HOLEY` variant of each. Writing a float into a SMI array transitions it and can change the backing
store layout underneath you, which is both how many bugs are reached and how a working exploit
silently breaks. `%DebugPrint` after every step while developing.

**Pointer compression** means in-heap references are 32-bit offsets into a 4 GB cage, not full
pointers. A leaked "address" is a compressed one, and forging a raw native pointer from inside the
heap is not possible by construction.

### The sandbox changed what "arbitrary R/W" buys you

On a modern V8, **arbitrary read/write inside the cage is a step, not the finish**. The sandbox bounds
in-heap pointers to that 4 GB region, so corrupting objects within it can no longer reach arbitrary
process memory, and the old "overwrite a function pointer, call it" ending does not apply.

Escapes pivot to objects holding **external pointers** — `ArrayBuffer` backing stores, WASM instance
data, `FILE` handles, and anything else referencing memory outside the cage. Those are held in a
separate pointer table with type tags, so the target is a confusion or an index corruption in that
table rather than a raw pointer overwrite. A WASM instance's RWX code region has historically been
the shortest route from in-cage R/W to native execution; check whether the build still has one.

For a CTF challenge, read the patch you were given before assuming any of this: teaching bugs are
frequently on a build with the sandbox disabled, in which case in-cage R/W really is the finish.
