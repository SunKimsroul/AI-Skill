# Winternitz One-Time Signature Triage

Use this workflow only with a supplied CTF verifier, source tree, transcript, or local fixture. Winternitz/WOTS is not Lamport: each signature element sits on a hash chain, and a correctly implemented one-time scheme with a checksum is not generically reusable.

## Reconstruct the Exact Scheme

1. Read the local signer and verifier before interpreting a signature. Record the digest expansion, number of chains, base `w`, chain length, serialization, public-key compression, and whether a checksum is included.
2. Derive the direction and count of every chain from the code. For the common form, signing digit `d_i` emits `H^(w - 1 - d_i)(sk_i)` and verification applies `H^d_i`; variants can reverse the convention.
3. Confirm that checksum digits bind the full message-digit vector. Treat a missing or incorrectly generated checksum as a challenge-specific implementation flaw, not a property of normal WOTS/WOTS+.

## Audit a Supplied Reused Signature Locally

1. Decode the original message digest into exactly the verifier's digits. Build a per-chain table containing the original digit, the proposed digit, emitted hash depth, and verification hash depth.
2. Derive the feasibility condition from the local chain direction. A known chain element can only move forward through the hash function; do not copy an inequality from another WOTS variant without replaying it in the supplied verifier.
3. If the local implementation lacks a binding checksum, search only the supplied message-format space for a benign fixture satisfying all chain constraints. If the checksum is correct or no locally valid candidate exists, stop and report that the observed signature is not reusable under this model.
4. Keep original artifacts immutable and perform every comparison against an offline local verifier. Do not query external signing or verification services.

## Validate

1. Run two harmless local messages through the verifier and confirm chain direction, digit order, and checksum placement.
2. Recompute every public-chain endpoint from the candidate signature and compare it with the supplied public key/root.
3. Preserve the source revision, original digest digits, candidate digits, and chain-step table as evidence. A plausible-looking message is not proof unless the supplied verifier accepts it locally.

**Boundary:** This note covers intentionally flawed or reused CTF one-time-signature artifacts. Do not apply it to production signature services or infer that a standard WOTS+/XMSS deployment is breakable.

**Source pattern:** DiceCTF 2024 Quals, `winter` ([writeup metadata](https://ctftime.org/writeup/38952)); the toy verifier omitted the usual WOTS checksum, making its reused hash-chain behavior auditable from local source.
