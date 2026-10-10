# Okamoto-Uchiyama CTF Workflow

Use this for supplied crypto parameters only. Recognize Okamoto-Uchiyama (OU) by a modulus of the form `n = p^2 * q`, a public base `g`, and ciphertexts modulo `n`.

## Confirm the structure before decrypting

1. Do not confuse an OU modulus with ordinary RSA. After recovering a candidate `p`, require `n % (p * p) == 0`, then set `q = n // (p * p)` and validate the expected primality/size assumptions from the supplied challenge.
2. Inspect the key generator for relations between `p` and `q`. A CTF may make `q` a polynomial in `p` plus a small unknown delta; solve that algebraic relation locally and validate the resulting factorization before interpreting ciphertext.
3. For the common relation `q = p^2 + B`, set `x = p^2`; then `n = x * (x + B)`. The discriminant `B^2 + 4*n` must be a square and `x = (-B + sqrt(discriminant)) / 2` must itself be a square. If `B` includes a bounded delta, iterate only that supplied local bound.

## Decrypt after factor recovery

For OU encryption `c = g^m * h^r mod n` with `h = g^n mod n`, the plaintext lies modulo `p`. Use the L function on values modulo `p^2`:

```python
from math import gcd

def invmod(a, modulus):
    return pow(a, -1, modulus)

def ou_decrypt(ciphertext, g, p):
    p2 = p * p
    def L(value):
        assert (value - 1) % p == 0
        return ((value - 1) // p) % p
    numerator = L(pow(ciphertext, p - 1, p2))
    denominator = L(pow(g, p - 1, p2))
    assert gcd(denominator, p) == 1
    return numerator * invmod(denominator, p) % p
```

## Validate the result

1. Check the public-base condition locally: `L(g^(p-1) mod p^2)` must be invertible modulo `p`.
2. Decode `m` only using supplied message framing, byte length, or a documented encoding. OU plaintext is an integer modulo `p`, not automatically a byte string.
3. Re-encrypt a recovered plaintext with the supplied public key and locally chosen valid randomness, or verify the challenge's provided relation, before accepting the result.

## Source

- PoseidonCTF 2020 `discrete log`: OU recognition plus a structured relation between `p` and `q`: <https://ctftime.org/writeup/22916>
