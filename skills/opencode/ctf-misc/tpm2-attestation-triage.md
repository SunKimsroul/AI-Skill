# TPM2 Attestation Lab Triage

Use this note for a supplied CTF VM, kernel module, source bundle, TPM state directory, memory image, or local TPM simulator. Treat TPM-backed challenges as a protocol-and-state reconstruction problem. Work only inside the supplied guest/emulator and never issue commands to a real TPM or an external attestation service.

## Draw the trust map before testing

1. Inventory the supplied components: guest OS/image, TPM emulator/state store, kernel module or service, client/attester/verifier source, certificates, and configuration. Hash preserved artifacts before changing the local copy.
2. Classify every key/object by role: endorsement identity, attestation identity, long-lived signer, sealed secret, or ephemeral session key. Record only labels/handles from the supplied lab and the expected authorization/policy for each object.
3. Reconstruct the verifier's acceptance claims as a table: identity binding, public area/name binding, PCR selection and digest, policy digest, certification object, transcript fields, signature source, freshness challenge, and session lifecycle.
4. Keep a separate map of mutable state: persistent objects, transient objects, sessions, PCR values, emulator backing files, service restarts, and guest reboots. A reboot, a TPM reset, and a process restart are different state transitions.

## Analyze PCR policy provenance

1. Find where the supplied module/service reads, extends, resets, or compares PCRs. Record order, hash bank, selected indices, input bytes, and error handling.
2. Recompute policy and transcript digests locally from non-secret fixture data or supplied test vectors. Compare byte-for-byte against the verifier's serialization; field order and names matter.
3. Trace cleanup paths for sessions and transient objects. If initialization fails, document the observed state in the local emulator rather than assuming cleanup or measurement occurred.
4. Treat authorization as a property of each object and command path. An attestation key, sealed object, or signing key that lacks the expected policy/auth binding is a local audit finding to prove with supplied source/state evidence.

## Validate a conclusion in the supplied lab

1. Use a copied VM/emulator state and harmless test material. Capture module/service logs, verifier decision, relevant PCR/object metadata, and state before/after one controlled transition.
2. Compare a successful path and a deliberately invalid non-secret fixture to determine exactly which verifier condition rejects it. Do not substitute live credentials, flags, or external endpoints.
3. For a memory-forensics intended path, preserve acquisition timing and the relationship between guest RAM, emulator persistence, and protocol stage before carving candidate material.
4. Produce a final evidence graph linking provisioning -> attestation -> verifier checks -> protected operation, plus the exact trust-boundary mismatch or recovery observation.

## Source-derived pattern

R3CTF 2026's *trustedhash* combined a supplied QEMU VM, a software TPM, a kernel module, and an external verifier. Its reusable lesson is to model identities, PCR-policy lifecycle, verifier transcript binding, and persistence separately; a cryptographically sound transcript can still be undermined by a state/authorization lifecycle mismatch in the supplied lab.

Source: <https://ctftime.org/writeup/40961>
