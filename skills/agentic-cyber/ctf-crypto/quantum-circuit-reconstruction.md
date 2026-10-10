# Quantum-Circuit State Reconstruction (CTF / Offline)

## Scope

Use for supplied Qiskit/QASM source, a circuit diagram, or a saved state vector in a CTF. Treat it as deterministic program reconstruction unless the challenge genuinely includes measurement noise or quantum-key-distribution assumptions.

## Triage

1. Record the qubit count, state-vector ordering, endianness, and whether the artifact is a basis state, amplitudes, counts, or a rendered bit string.
2. Separate reversible gates (`X`, `CX`, `CCX`, swaps, controlled permutations) from non-reversible operations (measurement, reset, post-selection, random sampling).
3. Confirm the challenge's Qiskit version or reproduce the ordering with a two- or three-qubit local test; do not rely on intuitive control/target bit order.
4. Check whether every stage maps one basis vector to one basis vector. If yes, avoid a full `2^n` simulator and model each stage as a bit permutation.

## Reversible Basis-State Workflow

For a basis-state-only pipeline, reverse stages in reverse order. `X`, `CX`, `CCX`, and `SWAP` are self-inverse, so applying the same gate again undoes it. A state vector with exactly one `1` encodes the corresponding basis-index bit string.

```python
def require_basis_state(vector):
    ones = [i for i, value in enumerate(vector) if value == 1]
    if len(ones) != 1 or any(value not in (0, 1) for value in vector):
        raise ValueError('not a deterministic basis state')
    return ones[0]

def bits(index, width):
    return format(index, f'0{width}b')

# First prove indexing on a tiny local circuit. Then implement the inverse
# stage-by-stage and collapse each one-hot vector back to its basis index.
```

## General State-Vector Workflow

When amplitudes are not one-hot, use a local simulator matching the supplied runtime. Build each gate matrix/unitary, apply conjugate-transposes in reverse order, and validate by re-running the forward circuit. Preserve complex values until the final comparison; casting amplitudes to integers is valid only for a proven basis-state challenge.

## Validation

- Reapply the original forward circuit to the reconstructed input and require an exact match for deterministic vectors.
- Check padding and byte grouping before decoding an alleged plaintext.
- If measurements occur, distinguish a challenge-specific deterministic seed/count constraint from probabilistic output; do not claim a single recovered input without an observable that supports it.

## Common Failure Modes

- Reversing gate order but not gate direction.
- Assuming textbook wire order matches the framework's basis-index convention.
- Treating `measure` or `reset` as reversible.
- Losing information by converting non-binary amplitudes to `int`.

**Boundary:** Run only against supplied challenge files or a local simulator. This is an analysis workflow, not access to a quantum service.
