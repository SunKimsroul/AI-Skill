# Lamport One-Time Signature Recovery

## Recognize the Construction

Lamport signatures publish one secret preimage for each message bit and hash the corresponding secret pairs into the public key. Use this note when a CTF artifact exposes a Lamport signer/verifier, repeated signatures under one key, or a local binary flaw that lets you obtain a signature for a controlled message.

## Controlled-Message Comparison

For a fixed key, a signature on an all-zero bit string reveals the `0` secret value at every position. Compare it position-by-position with a signature on the target message: equality means that target bit used the zero branch; inequality means it used the one branch.

```python
def recover_bits_from_zero_signature(target_sig: list[bytes],
                                     zero_sig: list[bytes]) -> str:
    if len(target_sig) != len(zero_sig):
        raise ValueError('signature lengths differ')
    return ''.join('0' if a == b else '1'
                   for a, b in zip(target_sig, zero_sig))

def bits_to_bytes(bits: str) -> bytes:
    if len(bits) % 8:
        raise ValueError('bit length must be byte aligned')
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))
```

## CTF Workflow

1. Reverse the supplied verifier and establish message length, bit order, signature element size, hash, and whether the key remains fixed across runs.
2. Identify the local challenge flaw that redirects a comparison, message pointer, or signing input. Prove it on a local binary/harness before relying on signature data.
3. Request or derive a signature of the controlled all-zero message, then compare it with the existing target signature using the exact element ordering.
4. Validate recovered bytes against flag syntax and, where possible, by verifying with the supplied public key.

## Reused OTS Leaf Under a Merkle Root

A Merkle authentication path proves that a Lamport leaf belongs to a public root; it does not repair reuse of that leaf. For a supplied signature log, group records by identity and leaf/authentication path, then look for a supposedly one-time Lamport key signing multiple distinct message hashes. Collect the branch material disclosed for each bit across the records. Once both required values for every target-hash bit are available, construct a candidate signature in the challenge's exact field order and verify it locally against the supplied root/path.

**Validate:** Keep message-hash bit order, checksum/length fields, and sibling-node ordering exact. A candidate that has the right Lamport branch values but fails the Merkle-root reconstruction is not a valid signature.

**Boundary:** A normal Lamport system does not disclose both branches. This method requires a CTF-supplied implementation flaw or intentionally exposed controlled-message signature; do not treat it as a generic attack on correctly deployed one-time signatures.

**Source patterns:** Hack.lu CTF 2019, `Lamport Verify` ([writeup](https://sectt.github.io/writeups/Hacklu19/crypto_lamport/README)); Facebook CTF 2019, `postquantumsig` ([writeup metadata](https://ctftime.org/writeup/15491)).
