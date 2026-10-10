# CTF Misc - Build-system and Make jails

Use this only for a supplied CTF service, source bundle, or local sandbox that intentionally executes user-controlled build input. Do not test these patterns against CI, build servers, source repositories, or infrastructure outside the stated challenge scope.

## Recognize the boundary

A build-system jail commonly accepts a target name, dependency/prerequisite, variable, or recipe body; filters it; then writes a generated Makefile and invokes GNU Make with a chosen shell. The important boundary is layered:

```text
application input validation -> Makefile parsing/expansion -> recipe text -> shell parsing -> challenge artifact
```

Map the actual generated Makefile before trying to solve it. A filter that understands shell tokens may not reason about Make expansion, and a filter on one input field may leave another field semantically significant.

## Source-first workflow

1. Read the wrapper/source and reconstruct the exact generated file, invocation, working directory, shell, environment, allowed characters, and stdout/stderr handling.
2. Identify target, prerequisites, recipe lines, variable assignments, included files, `.PHONY`, and whether each submitted value is parsed by Make, the shell, or both.
3. Classify expansion timing: Make has immediate/deferred variable evaluation and recipe expansion before the shell sees the line. Keep a table showing what each layer receives.
4. Review Make's automatic variables (`$@`, `$<`, `$^`, and related forms) in the context of the generated target/prerequisite graph. They can carry semantic strings that do not appear literally in a restricted recipe field.
5. Use the smallest harmless observation in the provided sandbox to verify a hypothesis, then confirm a result through the challenge's intended output. Keep the reconstructed Makefile and layer-by-layer explanation for the writeup.

## Common traps

- Treating it as only a Bash jail: the Make layer may be the key parser, while the shell receives already-expanded text.
- Testing against the displayed UI rather than the source-generated Makefile.
- Ignoring target/prerequisite names, automatic variables, built-in variables, or error output as data paths.
- Forgetting that a missing `PATH` changes external-command availability but does not remove shell builtins or Make's own semantics.
- Assuming a denied literal implies the same semantic value cannot be constructed by a later expansion phase.

## Pivot rules

- Use [bashjails.md](bashjails.md) only after the Make expansion result is known and the remaining limitation is shell behavior.
- Use `/ctf-web` when the wrapper's input parsing, template construction, or request state is the main weakness rather than the build language.
- Use `/ctf-reverse` for a custom build interpreter or binary validator.

## Source-backed pattern

WolvCTF 2024's *Made* series generated Makefiles from constrained user input. The series demonstrates why target/prerequisite context, automatic variables, Make expansion, and shell behavior must be analyzed as separate layers in a CTF-only sandbox: [CTFtime writeup](https://ctftime.org/writeup/38837).
