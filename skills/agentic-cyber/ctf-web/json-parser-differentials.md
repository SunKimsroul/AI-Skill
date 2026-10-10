# CTF Web - JSON Parser Differentials

Use this note when a supplied CTF service parses, validates, stores, or reparses JSON across different runtimes. The issue is the mismatch between representations, not JSON syntax alone. Keep experiments inside the provided challenge or a local reproduction.

## Triage workflow

1. Trace every conversion boundary: raw HTTP/query string, string construction, regex/WAF validation, JSON parser, object merge, serializer, and downstream language or package.
2. Record each parser and exact version. Do not assume `JSON.parse`, `ujson`, a database JSON column, and an application validator agree.
3. Build a local behavior matrix using harmless markers. Compare accepted/rejected input, resulting object keys, serialized output, and which value a policy check reads.
4. Focus on semantic disagreement: duplicate keys, escaped control or surrogate code points, Unicode normalization, numbers outside precise integer range, and prototype-shaped keys.
5. Confirm the smallest difference changes a CTF-visible authorization or data-flow decision. Keep a saved normal request and a local unit test as evidence.

## Minimal local harness

Run parser checks against local copies of the supplied stack; do not send fuzzing payloads to systems outside the challenge.

```python
import json

samples = {
    "duplicate_key": '{"role":"viewer","role":"admin"}',
    "lone_surrogate": '{"name":"x\\ud800"}',
    "large_integer": '{"id":9007199254740993}',
    "prototype_shape": '{"constructor":{"prototype":{"marker":"local"}}}',
}

for name, raw in samples.items():
    try:
        value = json.loads(raw)
        print(name, "parsed", repr(value), "roundtrip", json.dumps(value, ensure_ascii=True))
    except Exception as exc:
        print(name, "rejected", type(exc).__name__, str(exc))
```

For a second runtime, parse the exact same raw bytes and compare the object graph and round-trip JSON. Reject a finding if the suspected difference disappears before the policy-sensitive sink.

## Common CTF pattern: validation before parsing

Treat any hand-built JSON string or regex that runs before the final parser as a separate interpreter. A filter can inspect one textual field while the parser retains a different duplicate-key value or truncates/normalizes a malformed Unicode sequence. Review these questions:

- Does a regex see the same field occurrence the parser ultimately uses?
- Does the parser choose first-key or last-key precedence for duplicates?
- Is raw input decoded once, twice, or not at all before validation?
- Is a JSON object merged into a JavaScript object or configuration library after parsing?

Prototype-shaped keys (`__proto__`, `constructor`, `prototype`) deserve a separate dependency and merge audit; see [node-and-prototype.md](node-and-prototype.md). Do not infer a prototype-pollution sink solely from the presence of those keys.

## Validation standard

Document the raw local test value, parser versions, each intermediate representation, and the exact challenge endpoint or source-code branch affected. Prefer a harmless role/feature marker or a local assertion over command execution. If no cross-boundary semantic difference survives, return to ordinary input validation rather than forcing a parser-differential theory.

**Source pattern:** InCTF 2021 `Json Analyser` combined a Unicode/duplicate-key interoperability mismatch with a separate prototype-pollution path ([official writeup](https://ctftime.org/writeup/29827), [source analysis](https://blog.bi0s.in/2021/08/15/Web/inCTFi21-JsonAnalyser/)).
