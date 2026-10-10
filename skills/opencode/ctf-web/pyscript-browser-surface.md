# PyScript Browser-Surface CTFs

Use this note for a CTF that executes attacker-controlled Python in the browser through PyScript or Pyodide. Work against the supplied local challenge/browser profile or organizer endpoint only.

## Map the two interpreters

1. Separate server processing from browser execution. Record what the server stores/filters and what code the browser actually interprets.
2. Inspect the page for PyScript/Pyodide bootstrapping, the code container, imported packages, DOM IDs, CSP, and any admin-bot route.
3. Treat a Python-specific blacklist as only one layer. Determine whether it filters raw source, rendered HTML, or runtime output, and whether the browser-side bridge has different capabilities.

## Build a local capability inventory

- Use harmless expressions to identify available builtins, classes, and documented PyScript APIs in the provided environment.
- Check whether the runtime can reference existing DOM elements, set text/content, register events, or make same-origin requests.
- Compare Python-object exposure with JavaScript/DOM exposure. The important boundary is often the bridge from sandboxed-looking Python to a real page element.
- Reproduce one benign DOM change locally, then verify its resulting HTML and CSP behavior in browser developer tools.

## Validation discipline

1. Prefer a local non-sensitive test element and a visible marker over using a real user/admin session.
2. Confirm that code execution happens in the browser that renders the challenge page, not merely on the server or in an isolated worker.
3. Record the exact PyScript/Pyodide version and API method used; class ordering and exposed bridges can change across versions.
4. Treat any bot interaction as the final CTF validation step, after a harmless local proof establishes the boundary.

## Source-derived pattern

GPN CTF 2023's `cross-site-python` accepted user Python and relied on server-side keyword filtering. The decisive CTF analysis was browser-side: PyScript exposed a DOM element bridge, so the relevant question became which page capability the supplied runtime could reach—not whether the server saw a conventional JavaScript tag.

Source: <https://ctftime.org/writeup/37172>
