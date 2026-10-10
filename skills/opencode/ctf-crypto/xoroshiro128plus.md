# xoroshiro128+ State Recovery

## Recognize the Generator

Use this for a supplied challenge implementation with two 64-bit state words, addition output, XOR mixing, and rotations characteristic of xoroshiro128+. First reproduce any wrapper around the output—bit reversal, truncation, modular reduction, or a discrete-log-derived value—before modeling the generator itself.

## Transition Model

```python
MASK = (1 << 64) - 1

def rotl(x: int, amount: int) -> int:
    return ((x << amount) | (x >> (64 - amount))) & MASK

def xoroshiro128plus_next(s0: int, s1: int) -> tuple[int, int, int]:
    output = (s0 + s1) & MASK
    s1 ^= s0
    next_s0 = rotl(s0, 55) ^ s1 ^ ((s1 << 14) & MASK)
    next_s1 = rotl(s1, 36)
    return output, next_s0 & MASK, next_s1 & MASK
```

## Recover State from Observations

1. Derive raw generator outputs from the challenge protocol. If outputs are hidden behind a finite-group operation, solve the supplied local/CTF discrete-log relation first; do not feed the transformed value into the PRNG model.
2. Preserve exactly which bits are observed. Full 64-bit outputs make direct state reconstruction straightforward; partial outputs need a bit-vector/SMT model with constraints only on the revealed bits.
3. Encode several consecutive transitions over 64-bit bit-vectors. Constrain each modeled output to the reconstructed observation and solve for the two initial state words.
4. Replay all observed values and at least one future challenge output before using a predicted key, nonce, or random value.

```python
# Z3 outline: use BitVec(64), RotateLeft, and modulo-2^64 arithmetic.
# solver.add((s0 + s1) & observed_mask == observed_value & observed_mask)
# Then update s0/s1 with the exact challenge rotation constants each round.
```

**Failure checks:** `xoroshiro` has several variants. Confirm the output function (`+`, `**`, `++`), rotation constants, state-word ordering, and whether the challenge emits values before or after state advancement. A satisfying state that fails a complete replay is the wrong variant or wrapper inversion.

**Source pattern:** InCTF 2019, `PRetty stroNG` ([writeup](https://v3ct0r719.github.io/posts/inctf/)).
