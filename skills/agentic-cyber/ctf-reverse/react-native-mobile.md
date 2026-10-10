# React Native Mobile Artifact Analysis (CTF / Offline)

## Scope

Use for a supplied APK/IPA that contains React Native code. Treat the native Android/iOS layer as a loader and bridge first; the challenge logic may live in a JavaScript bundle or Hermes bytecode.

## Triage

1. Preserve the original package and list the manifest, assets, native libraries, resources, and DEX/Mach-O metadata.
2. Look for `index.android.bundle`, `main.jsbundle`, Hermes bytecode, Metro module IDs, source maps, and React Native bridge registrations.
3. Decompile the native wrapper only far enough to identify the bundle path, asset loading, device checks, and JavaScript-to-native methods.
4. Make a separate offline copy of the bundle. Search UI strings, action handlers, API-route construction, feature gates, validation functions, and hard-coded test fixtures.

## Bundle Reconstruction

- For readable JavaScript bundles, split Metro modules with a compatible offline tool or parser; retain module IDs and dependency edges because names may be stripped.
- For Hermes bytecode, use a version-matched local disassembler/decompiler where possible, then corroborate every recovered function with string references and call sites.
- Start from a visible UI message or button handler and trace backwards to the state predicate, then forwards to the local result/rendering path.
- Distinguish local validation from a remote request. An embedded URL, token, or API key is evidence for source review, not permission to contact a service.

## Dynamic Confirmation

Run only the supplied app in an isolated emulator or local CTF environment. Hook the React Native bridge or selected native methods to observe arguments and return values, then reproduce the intended path using a local fixture. Keep certificate bypasses, account changes, and network access outside this workflow unless the challenge explicitly supplies that environment.

## Validation

- Rebuild the relevant input/state transition locally and confirm the same UI branch or output.
- Verify that any extracted secret comes from the challenge artifact rather than stale cache, analytics, or an unrelated third-party package.
- Record package hash, bundle path, bundle/runtime version, module/function location, and the exact local check that proves the conclusion.
