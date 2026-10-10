# PHP Restricted-Expression Construction

Use this for a supplied CTF PHP interpreter/service that accepts only a tiny punctuation alphabet or bans letters, digits, whitespace, quotes, warnings, or common function names. Work against the supplied local container whenever possible; begin with pure expressions and preserve every accepted/rejected parser result.

## Character-Closure and Identifier Synthesis (idekCTF 2022)

**Recognition:** The challenge permits fragments such as parentheses, brackets, dots, commas, or XOR but blocks normal PHP source. It may reject warnings, so common coercion tricks are unusable. The problem is not ordinary input filtering: it is a language-construction search under an exact character grammar.

### 1. Model the allowed alphabet exactly

Record permitted bytes, tokenization rules, PHP version, warning/error behavior, and length limits. Build a small offline table of characters derivable from bytewise XOR of permitted one-byte strings.

```python
from itertools import combinations

allowed = "[(,.^)]"  # replace with the challenge's actual permitted bytes
derived = {}
for left, right in combinations(allowed, 2):
    out = chr(ord(left) ^ ord(right))
    derived.setdefault(out, (left, right))

for ch in sorted(derived):
    print(repr(ch), "<-", derived[ch])
```

This is only a character-closure model. It does not prove that a PHP expression using each pair parses or has the intended type.

### 2. Find a no-warning seed value

Search the PHP built-ins available in the supplied version for a pure expression whose name can already be synthesized and whose result unlocks new characters (often a digit or a useful string). Test candidates locally one at a time.

Good first proofs are deterministic and side-effect free: length, substring, case conversion, or numeric functions. Capture stdout, stderr, and exit status; a warning can invalidate an otherwise correct construction in strict challenges.

### 3. Expand the closure iteratively

After deriving a seed character, add it to the offline alphabet and repeat the XOR table. At each generation, track:

- expression text;
- resulting byte and PHP type;
- whether it parses under the challenge version;
- dependency expressions and total length.

Use dynamic programming to retain the shortest valid construction per byte. Do not concatenate strings before proving PHP's precedence and coercion behavior on a local toy expression.

```python
# Keep only the shortest construction for each byte.
best = {ch: ch for ch in allowed}
for _ in range(12):
    changed = False
    for a, expr_a in list(best.items()):
        for b, expr_b in list(best.items()):
            c = chr(ord(a) ^ ord(b))
            candidate = f"({expr_a}^{expr_b})"
            if c not in best or len(candidate) < len(best[c]):
                best[c] = candidate
                changed = True
    if not changed:
        break
```

The offline optimizer supplies candidates; the supplied local PHP runtime remains the authority.

### 4. Validate with a pure-function checkpoint

Before attempting a challenge-specific objective, synthesize a harmless identifier and invoke it with a harmless literal/value. Require an exact expected result and no warning. Only then document the construction path and use the challenge's intended local verification route.

**Key insight:** Restricted PHP challenges are graph searches over bytes, expression types, and parser rules. The important breakthrough is often a no-warning seed that expands the character closure—not a single memorized punctuation payload.

**Source inspiration:** idekCTF 2022, *PHPFu...n*: <https://ctftime.org/writeup/36079>.
