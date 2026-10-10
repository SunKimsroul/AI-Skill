# Enigma Cipher Analysis

Use this workflow for a supplied Enigma ciphertext, machine variant, rotor set, or a custom implementation. Work locally: model the exact machine before searching settings.

## Ciphertext-Only Recovery with Known Ring Settings (404 CTF 2022)

**Recognition:** The challenge names Enigma or provides rotor wiring, a reflector, ciphertext in a 26-letter alphabet, and some configuration constraints. The crucial details are rotor stepping order, whether a keypress steps before encryption, the double-step rule, ring settings, rotor order, starting positions, and plugboard policy.

### 1. Build a faithful local oracle

1. Normalize the ciphertext exactly as the challenge does (usually uppercase `A`-`Z` only).
2. Implement forward and reverse rotor traversal, including each rotor's current position and ring offset.
3. Step rotors at the same time as the target. For a three-rotor Wehrmacht-style machine, the middle rotor steps both when the right rotor reaches its notch and when the middle rotor is at its own notch (the double-step).
4. Prove the model against any supplied known plaintext/ciphertext pair before scoring unknown text. Enigma is reciprocal only when the full state evolution is identical.

Keep the model small and deterministic: a one-character stepping error makes language scores meaningless.

### 2. Search the core machine before the plugboard

When ring settings are supplied and the plugboard is empty or unknown, enumerate each rotor order and its initial positions first. A three-rotor search is normally only `6 * 26^3 = 105,456` candidates.

Use a language score, not a visual guess. Index of coincidence is a fast first pass; tetragram/log-likelihood scoring is a better tie-breaker.

```python
from itertools import permutations, product

best = []
for order in permutations(available_rotors, 3):
    for pos in product(range(26), repeat=3):
        plain = enigma_decrypt(ciphertext, order=order, positions=pos,
                               rings=known_rings, plugboard={})
        score = quadgram_score(plain)  # or IOC for an inexpensive first pass
        best.append((score, order, pos, plain[:80]))

for item in sorted(best, reverse=True)[:20]:
    print(item)
```

Do not mix candidate state between attempts. Create a new machine (or reset every rotor position) for each trial.

### 3. Refine plugboard pairs only after the core settings rank well

For each high-scoring core setting, test one candidate plugboard pair at a time, keeping the best improving pair. Enforce Enigma's constraints: a letter maps to at most one other letter and mappings are symmetric.

```python
def add_pair(board, a, b):
    if a == b or a in board or b in board:
        return None
    candidate = dict(board)
    candidate[a], candidate[b] = b, a
    return candidate

board = {}
while True:
    options = []
    for a in alphabet:
        for b in alphabet:
            candidate = add_pair(board, a, b)
            if candidate is None:
                continue
            text = enigma_decrypt(ciphertext, order, positions, known_rings, candidate)
            options.append((quadgram_score(text), candidate, text))
    if not options or max(options)[0] <= current_score:
        break
    current_score, board, plaintext = max(options)
```

Use beam search rather than a greedy loop if several one-pair choices score similarly. Reject apparent improvements that only create a short accidental word while lowering the full-text score.

### 4. Validate the whole configuration

- Re-encrypt the recovered plaintext from the identical initial state and require an exact ciphertext match.
- Confirm the flag format, separators, and all non-letter handling from the supplied challenge.
- Record rotor order, ring settings, initial positions, reflector, plugboard pairs, and stepping convention in the solve notes so the result is reproducible.

**Why this works:** With a fixed machine, wrong rotor/position choices behave close to random text. The correct settings consistently raise global language statistics; once the main state is correct, plugboard-pair experiments become distinguishable rather than noise.

**Source inspiration:** 404 CTF 2022, *Enigma*, public writeup metadata and method summary: <https://ctftime.org/writeup/34447>.
