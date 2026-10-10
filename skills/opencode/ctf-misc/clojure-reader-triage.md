# Clojure Reader and Graal CTF Triage

Use this workflow for supplied Clojure source, JARs, Graal native images, or local CTF services. Do not submit reader forms to systems outside the supplied challenge environment.

## Identify the parser boundary

1. Search supplied source and decompiled classes for `read`, `read-string`, `clojure.edn/read-string`, `load-string`, `eval`, reader conditionals, tagged literals, and bindings of `*read-eval*`.
2. Separate the ordinary Clojure reader from the EDN reader. EDN is intended for data; general reader APIs can accept reader forms whose behavior depends on runtime settings and custom readers.
3. Record the input's exact path: socket or file -> line/token split -> reader API -> resulting object -> later evaluation or dispatch. A parenthesis checker can still be a reader invocation rather than a syntax-only check.

## Reproduce harmlessly and locally

1. Pin the supplied Clojure/Graal version and launch arguments. For a native image, preserve native-image configuration, resource files, reflection configuration, and the original source/JAR if supplied.
2. Use a disposable local copy and a benign arithmetic reader form such as `#=(+ 1 2)` only when source evidence shows reader evaluation is enabled. Record the returned value or logged side effect; do not use an operating-system command as the proof.
3. If only data is expected, compare `clojure.edn/read-string` and the application's reader behavior on the same supplied sample. A difference is evidence of a trust-boundary mismatch, not yet a solution.

## Reconcile source and runtime behavior

1. Check exception handling: a broad `try/catch` can hide reader errors while preserving a side effect or altered state.
2. Map custom tagged readers and dynamic bindings before assuming built-in behavior. Generated native-image code may remove or change reflection-based paths, so validate against the provided build where possible.
3. Keep the minimal local input, exact version, configuration, observed result, and source location together. Hand off to `ctf-pwn` or `ctf-web` only after the parser/evaluation boundary is proven in the supplied environment.

## Source

- Hackover CTF 2018 `Holy graal`: supplied Clojure source, a reader-based input boundary, and Graal native-image context: <https://ctftime.org/writeup/11536>
