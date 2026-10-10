# CTF Reverse - REXX and legacy scripting targets

Use this for a supplied REXX script, CTF interpreter service, or local reproduction. Keep testing inside the stated challenge environment; legacy interpreter features and file APIs are not a reason to probe other systems.

## Recognize REXX semantics before translating

REXX can look opaque because identifiers can use punctuation, stem variables act like associative arrays, and string/byte functions are central to ordinary logic. Before converting anything to Python or another language, record the interpreter and version, character encoding, argument parsing, variable names, and which operations evaluate dynamically.

## Triage workflow

1. Identify whether the challenge supplies a script, a REPL/interpreter banner, or both. Preserve the exact interpreter/version and the intended input framing.
2. Normalize the script without changing semantics: expand symbolic variable names, label stem/array accesses, and separate `PARSE` operations from ordinary assignments.
3. Map control flow around `IF`, `DO`, `CALL`, `SIGNAL`, and especially `INTERPRET`, which evaluates a string as REXX code at runtime.
4. Treat string helpers as byte operations when appropriate. Check `X2C`, `C2X`, `D2C`, `BITXOR`, `COPIES`, `OVERLAY`, `SUBSTR`, padding, and modulo/division behavior with the target interpreter's documentation.
5. Verify the encoding before decoding constants. A modern local interpreter may differ from a mainframe/EBCDIC-oriented challenge; reproduce the expected code page and pad byte before trusting a translated XOR or conversion.
6. Use a small local reference implementation to validate each decoded stage. Keep generated code and static checks separate until the first stage is understood.

## Common traps

- Misreading a punctuated variable name or a stem variable as a syntax error.
- Assuming ASCII when the challenge's byte conversion reflects EBCDIC or a specific interpreter implementation.
- Forgetting that bytewise XOR may pad the shorter input, which changes the tail of a decoded string.
- Treating dynamic `INTERPRET` output as plain text instead of a next-stage program.
- Copying a result from a different REXX implementation without confirming its conversion semantics.

## Pivot rules

- Load `/ctf-crypto` only when the REXX layer is completely reduced and the remaining transformation is cryptographic.
- Load `/ctf-misc` for an intentionally exposed CTF interpreter service after identifying its language/runtime; keep the scope limited to the service provided by the challenge.

## Source-backed pattern

BraekerCTF 2024's *The mainframe speaks* used obfuscated REXX with dynamic evaluation, bytewise operations, and an EBCDIC-sensitive conversion difference. It demonstrates why interpreter/version and code-page fidelity matter when reversing legacy scripts: [CTFtime writeup](https://ctftime.org/writeup/38692).
