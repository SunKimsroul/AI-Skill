# Matrix-Conjugation Oracle Reconstruction

## Recognize the Linear Map

Use this when a challenge encrypts matrices over a finite field by a fixed secret conjugation, `E(X) = U X U⁻¹`, and permits encryption or decryption of chosen matrices under the same session key. Although `U` is unknown, `E` is a linear transformation on the `n²` entries of `X`. Recover that transformation rather than solving for `U` directly.

## Recover and Invert the Transformation

1. Keep the field modulus/session fixed; a regenerated modulus or key invalidates all prior oracle samples.
2. Query the oracle on every elementary matrix `Eᵢⱼ` (one at position `(i, j)`, zero elsewhere), respecting any supplied input bounds.
3. Flatten each returned matrix in one documented order, such as row-major. Those `n²` result vectors are the columns of a linear map `T`.
4. Flatten the target ciphertext the same way and solve `T · x = c` over `GF(p)`. Reshape `x` into the candidate plaintext matrix.
5. Re-encrypt the candidate locally or through the supplied CTF oracle and require byte-for-byte equality with the target ciphertext.

```python
# SageMath; oracle(M) returns the challenge's encryption of M over GF(p).
F = GF(p)

def flat(M):
    return [M[i, j] for i in range(n) for j in range(n)]

cols = []
for i in range(n):
    for j in range(n):
        B = matrix(F, n, n, 0)
        B[i, j] = 1
        cols.append(vector(F, flat(oracle(B))))

T = matrix(F, n*n, n*n, lambda row, col: cols[col][row])
plain_vector = T.solve_right(vector(F, flat(ciphertext)))
plaintext = matrix(F, n, n, list(plain_vector))
```

## Failure Checks

- A singular `T` usually means a changed session, inconsistent row/column flattening, or an oracle that transformed a different representation than assumed.
- Do not mix integer arithmetic with field arithmetic: perform every solve modulo the supplied prime.
- If the oracle only accepts a restricted encoding, first prove that the elementary matrices survive its parser; otherwise derive an equivalent spanning set that does.

**Source pattern:** zer0pts CTF 2020, `nibelung` ([writeup](https://hackmd.io/30-fhA4DSvqZ8MuMfEwO_A)).
