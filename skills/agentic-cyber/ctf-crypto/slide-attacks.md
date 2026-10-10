# Slide Attacks on Repeated-Round CTF Ciphers

Use this note for a custom CTF block cipher with many structurally identical or periodically keyed rounds, especially when an encryption/decryption oracle is supplied. Work only with the challenge oracle or source.

## Recognize the prerequisite

1. Normalize one round into a state transition and record the key schedule period.
2. Look for a repeated transformation, a fixed/alternating subkey pattern, or a very large round count with unusually small key/block state.
3. Check whether a second challenge function acts as an inverse oracle. A pair of related encrypt/decrypt interfaces may let you build plaintext/ciphertext samples even when each interface is presented differently.
4. Do not infer a slide attack from the number of rounds alone; prove which round boundary repeats.

## Build and test candidate slid pairs

- Generate samples that preserve the state coordinates left unchanged by a round (for example, a Feistel half or selected lanes). This concentrates the chance of a useful alignment.
- Index samples by the equality relations implied by the repeated transition, rather than comparing every pair blindly.
- For each candidate pair, derive a small set of round-key or differential constraints from the local cipher model.
- Reject false pairs by re-encrypting independent challenge samples. One matching relation is not sufficient evidence.

## Adapt to non-ideal schedules

Alternating subkeys or generalized Feistel layouts can require an advanced slide variant. First separate the cipher into its smallest repeating sub-rounds, identify which positions are preserved, and write the alignment equations symbolically. Only then choose a complementary/twisted/related-key construction suited to the supplied schedule.

## Verification checklist

1. Confirm the reconstructed key/state against several fresh oracle pairs.
2. Measure whether the candidate search is consistent with the intended query budget.
3. Record the exact round period, state layout, and candidate-pair predicate in the solver notes.
4. Keep the method tied to the custom CTF construction; do not assume standard ciphers have the required self-similarity.

## Source-derived pattern

PlaidCTF 2022's `choreography` used a generalized Feistel construction with an enormous number of alternating sub-rounds. The key insight was that attack cost depended on the repeated sub-round structure, not the total round count; fixed preserved lanes allowed efficient candidate-pair filtering inside the challenge query limit.

Source: <https://ctftime.org/writeup/33163>
