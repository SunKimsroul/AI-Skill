# CSIDH and Class-Group Action CTFs

Use this note for a supplied CSIDH-style challenge implementation in Sage/Python. Treat it as a custom algebraic protocol: audit the exact action code and validate every observation on a reduced local instance before scaling it.

## Establish the action model

1. Record the base prime, small odd-prime list, curve representation, public-key encoding, and allowed private-exponent range.
2. Identify how a private action is walked: positive/negative passes, kernel construction, twists, point selection, and retry/failure paths.
3. Confirm whether the challenge gives a shared-action oracle, a public key, related curves, or only an encrypted value derived from the secret vector.
4. Reproduce a tiny parameter version locally and test that the intended commutative action and encoding match the supplied implementation.

## Audit implementation behavior before solving the hard problem

- Look for probabilistic branches in isogeny walks, point lifting, order tests, exceptional curves, or retry limits.
- Determine whether a prime-degree step can be skipped or fail with a probability that depends on the corresponding secret exponent.
- If queries must be distinct, derive a family of related public curves that can be mapped back to a common comparison neighborhood using known group actions.
- Turn each response into a canonical curve/public-key representation before frequency counting or graph search.

## Recover and validate hypotheses

1. Use repeated, related challenge queries to collect a distribution of mapped outputs.
2. Separate the most likely error-free public state from perturbed states only after verifying the expected distribution on the small local model.
3. Model perturbations as short paths in the relevant isogeny/action graph; use bounded meet-in-the-middle only when the parameter constraints justify it.
4. Verify a candidate exponent vector by regenerating the public action and checking independent oracle responses or the supplied ciphertext relation.

## Source-derived pattern

hxp CTF 2021's `infinity` implemented a faulty CSIDH action where individual isogeny steps could fail with probabilities tied to small secret exponents. The transferable lesson is not a fixed solver: it is to characterize implementation-dependent failures locally, map related outputs into one neighborhood, and validate frequency/graph inferences against the published action.

Source: <https://ctftime.org/writeup/31902>
