# Graph Query / Cypher Injection

Use this only against a supplied CTF service or an explicitly authorized test environment. Prefer a local copy of the application or challenge container whenever available. Keep testing in-band; do not use third-party callback services or alter graph data.

## Cypher String-Context Reconstruction (BSidesTLV 2022)

**Recognition:** A search or filter field produces graph-database errors mentioning Neo4j, Cypher, `MATCH`, labels, relationships, or regex operators such as `=~`. A punctuation change may alter the server error because untrusted input is concatenated into a Cypher expression.

### 1. Reconstruct the likely query context

Start with the supplied source code if available. Otherwise, send harmless syntax probes to the CTF/authorized endpoint and record only status, error class, result count, and response shape. The aim is to distinguish:

- quoted string vs numeric context;
- literal equality vs regex (`=~`) vs property lookup;
- a query that ends after the input vs one that appends a fixed clause;
- whether the application returns selected fields directly.

For example, a case-insensitive search often resembles:

```cypher
MATCH (p:Thing)
WHERE p.name =~ '.*' + toLower($input) + '.*'
RETURN p
```

The injection point and the trailing syntax determine whether a candidate closes a string, parentheses, or a comment boundary. Do not assume SQL quoting rules apply to Cypher.

### 2. Use the smallest in-band proof

First prove a syntax-boundary change with an input that only changes the result set or causes a predictable parser error. Then test a minimal projected value that the challenge response can display. Preserve the baseline request and every response used to support the inferred query model.

Avoid destructive clauses (`CREATE`, `MERGE`, `SET`, `DELETE`, `DETACH DELETE`) and avoid out-of-band procedures. The solving objective is read-only recovery from the supplied challenge graph.

### 3. Enumerate only the challenge graph needed for the flag path

Once the context is proven, reason from the application's domain model. A Pokédex-style challenge may have labels for the visible objects plus a hidden flag object; a social graph may expose relationships and properties. Prefer narrow queries that project one label/property at a time, then validate each value through the normal response.

Useful Cypher concepts to recognize in source or error traces:

```cypher
MATCH (n)                 // graph pattern
MATCH (n:Label)           // label restriction
n.property                // property projection
labels(n), keys(n)        // metadata helpers
WHERE n.name =~ '...'     // regex comparison
WITH value AS alias       // pipeline an expression forward
RETURN alias              // in-band result projection
```

Keep an evidence table: request purpose, inferred grammar boundary, selected field, response fingerprint, and conclusion. Do not treat one verbose error as proof of the final query shape.

### 4. Validate and report

- Reproduce the successful read from a clean session or local container.
- Confirm the recovered text belongs to the expected challenge object, not an accidental error reflection.
- Record the vulnerable concatenation pattern and the safe remediation: parameterize values, allow-list dynamic labels/properties, restrict dangerous procedures, and apply least-privilege database roles.

**Key insight:** Cypher is a separate language with its own grammar and graph operators. Treat it as a query-language injection problem, not a SQL payload-translation exercise: derive the exact concatenation context first, then use a narrow, read-only in-band projection.

**Source inspiration:** BSidesTLV 2022, *Pokedex*: <https://ctftime.org/writeup/34480>.
