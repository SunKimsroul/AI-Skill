# Modular Square-Root Recovery

Use this for supplied CTF values that reduce to `x^2 = a mod p` or `x^2 = a mod n` after factoring `n`. Keep every mathematical candidate until an independent property of the supplied plaintext selects one.

## Prime-modulus workflow

1. Verify that `p` is an odd prime and test whether a root can exist with `pow(a, (p - 1) // 2, p) in (0, 1)`.
2. Use the shortcut `pow(a, (p + 1) // 4, p)` only when `p % 4 == 3`. For any other odd prime, use a local Tonelli-Shanks implementation or a tested library routine.
3. Validate every returned root before further decoding: `pow(root, 2, p) == a % p`. A nonzero quadratic residue has two roots, `r` and `p - r`.

## Composite-modulus workflow

When a factored modulus is a product of distinct primes, recover roots modulo each prime and CRT-combine their Cartesian product. Do not assume there are exactly four candidates without checking the factorization and special cases.

```python
from sympy.ntheory.residue_ntheory import sqrt_mod
from sympy.ntheory.modular import crt

def roots_mod_semiprime(a, p, q):
    roots_p = list(sqrt_mod(a % p, p, all_roots=True) or [])
    roots_q = list(sqrt_mod(a % q, q, all_roots=True) or [])
    candidates = set()
    for root_p in roots_p:
        for root_q in roots_q:
            candidate, _ = crt([p, q], [root_p, root_q])
            candidate = int(candidate)
            assert pow(candidate, 2, p * q) == a % (p * q)
            candidates.add(candidate)
    return sorted(candidates)
```

## Select and validate a message

1. Preserve the complete root set before converting integers to bytes.
2. Use only independent supplied evidence—expected length, known framing, magic bytes, checksum, padding syntax, or a verifier—to select a candidate.
3. Re-encrypt or square the selected value and require it to reproduce the challenge value exactly.

## Sources

- 0x41414141 CTF 2020 `eazy RSA`: <https://ctftime.org/writeup/25862>
- SuSeC CTF 2020 `Inaction`: <https://ctftime.org/writeup/18875>
