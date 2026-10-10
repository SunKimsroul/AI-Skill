# CTF Web - HTML parser differentials and mutation XSS

Use this only against a supplied CTF application or an explicitly authorized local reproduction. Do not test sanitizer bypasses against third-party sites.

## Recognize mXSS

Mutation XSS occurs when an input sanitizer and the browser do not agree on the final DOM. The sanitizer may accept a string according to one parse/serialization model, while later insertion with `innerHTML`, templating, DOMParser, or another parse/serialize pass changes element nesting, namespaces, or attributes.

Look for user-authored HTML/notes, sanitizer libraries with custom allowed tags/attributes, a rich-text preview, MathML/SVG support, custom elements, or a server that sanitizes then sends HTML to a browser.

## Local differential workflow

1. Reproduce the exact supplied sanitizer version, policy, and browser context locally. Record whether the application uses server-side sanitization, client-side sanitization, or both.
2. Capture four separate artifacts for each harmless test case: submitted source, sanitizer output string, DOM immediately after parsing, and DOM after the application's actual insertion/serialization path.
3. Compare tag names, attributes, text nodes, namespace URI, parent/child structure, and any elements that were dropped, moved, reopened, or reinterpreted.
4. Focus on parser-boundary features: HTML versus SVG/MathML namespaces, integration points, foreign-content parsing, table/select/template context, and parse-then-serialize-then-parse cycles.
5. Reduce any difference to the smallest local proof that demonstrates a changed DOM/security property. Only then evaluate the CTF's intended sink and flag path.

## What to audit in source

- custom `allowed_tags`, `allowed_attributes`, or added namespace-capable elements;
- sanitizer output passed to `innerHTML`, `insertAdjacentHTML`, a template renderer, or a second sanitizer;
- DOM reserialization (`outerHTML`, framework hydration, markdown/rich-text conversion) between sanitization and display;
- browsers/frameworks used by an admin bot versus the local preview;
- CSP and Trusted Types configuration, which may change whether a DOM mutation becomes executable.

## Common mistakes

- Comparing raw strings instead of the parsed DOM.
- Testing only the sanitizer's own output viewer and not the application's actual insertion context.
- Assuming HTML-only parsing rules apply inside SVG or MathML.
- Treating a DOM difference as executable XSS without proving the relevant script/event/URL sink in the supplied CTF.

## Source-backed pattern

Hack.lu CTF 2023's *Awesomenotes II* used a sanitizer configuration with custom extra tags and a namespace-context confusion. The transferable lesson is to compare sanitizer and browser DOM behavior under the exact application context, rather than relying on a static allowlist reading: [CTFtime writeup](https://ctftime.org/writeup/38012).
