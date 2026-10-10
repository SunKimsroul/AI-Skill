# CTF Reverse - Rust ECS game targets

Use this workflow for a provided CTF game binary and its supplied assets/save files. Treat the game executable and offline save format as the target; do not use it to alter online games or third-party services.

## Recognize the shape

Common clues are Rust panic output, `RUST_BACKTRACE`, mangled Rust symbols, `bevy_ecs` strings, a large native binary, and a separate save/world file. An ECS (entity-component-system) game distributes behavior across systems that operate on matching entity components, so an obvious UI action may not have a neatly named standalone handler.

## Triage in a reproducible order

1. Run the supplied binary normally and record command-line loading/saving behavior, logs, assets, and a clean baseline save.
2. Trigger harmless, observable actions one at a time: movement, selection, interaction, save, and load. Use the resulting log strings and state changes as anchors.
3. Compare a baseline save with a save after one controlled change. Locate headers, counts, lengths, compressed regions, serialized resource names, and the changed state before trying to infer the whole format.
4. Demangle Rust names where possible. Panic paths, drop glue, type names, and generic instantiations often expose crate/module names even when the application functions were inlined.
5. In Bevy specifically, search for `FunctionSystem`, `drop_in_place`, and the application crate name. A system's monomorphized type/vtable context can reveal the original system function and its query/resource/event parameters.
6. Build an input-to-system-to-state map. For example, a mouse/input anchor may lead to a component or event, then to the world/save system that controls the intended challenge condition.

## How to stay oriented in an optimized Rust binary

- Rust monomorphization produces many similar generic functions. Do not assume every `run_unsafe` or iterator helper is application logic; prefer instances whose type information includes the game crate or a relevant component/resource.
- ECS systems may be inlined into framework wrappers. Follow vtables, destructor/type strings, and event/query parameter names rather than relying only on a function's outer framework name.
- Keep binary analysis and save-file analysis independent until both point to the same state field or rule.
- If the challenge uses a serialized or encrypted save, first test for known plaintext, controlled diffs, framing, and truncation behavior; pivot to `/ctf-crypto` only after proving that a cryptographic layer is the actual blocker.

## Validation

- Reproduce the observation from a fresh copy of the provided save.
- Confirm any inferred state change through the game's own load/UI/log path, not merely a guessed byte offset.
- Record binary hash, command line, save-file hash, changed offsets, and the exact action that caused them for the writeup.

## Source-backed pattern

corCTF 2024's *corMine* paired a Rust/Bevy executable with a world-save file. The public writeup shows how panic/log clues, Bevy system type information, and save-state tracing can reduce a large optimized game binary to a meaningful action path: [original writeup](https://nnub.es/blog/en/ctf/corctf/2024/cormine/) and [CTFtime entry](https://ctftime.org/writeup/39394).
