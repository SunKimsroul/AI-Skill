# Move, Sui, and object-capability CTF workflow

Use this note for Move/Sui/aptos-style challenge packages. Model the challenge as an object and capability state machine. The important question is normally who can create, receive, mutate, destroy, or transfer which object—not whether a value is merely hidden in source.

## First pass

1. Identify the chain/framework, package ID, module, entry functions, test harness, object IDs, and the solved predicate.
2. List every resource/struct with its abilities (`key`, `store`, `copy`, `drop`), fields, initializer, and transfer/receive path.
3. For each public or entry function, write the required signer/capability/object inputs and the precise state delta.
4. Trace generic type parameters and dynamic fields. A type or object that looks interchangeable at the client layer may have an ownership or ability constraint in the VM.

## Invariants to check

- privileged capabilities are created once and cannot be leaked, copied, or reinitialized;
- object ownership (address-owned, shared, immutable, wrapped) matches the intended caller and transition;
- a passed object has the expected type, package/module origin, and relation to the target state;
- transfer, receive, freeze, delete, and unwrap paths do not bypass an authorization check;
- version/upgrade/migration logic cannot revive an old capability or bypass a new invariant;
- balances, supply, counters, and timestamps are updated in the same transaction state that the solve predicate reads;
- shared-object transactions do not rely on client-side ordering assumptions.

## Common CTF shapes

- **Capability leak:** a constructor, return value, dynamic field, or event exposes an authority object.
- **Object substitution:** an entry function accepts a same-shaped or user-owned object without proving its origin/relation.
- **Initialization replay:** module setup, test-only path, or upgrade migration creates a second privileged state.
- **Transfer/receive mismatch:** an object becomes reachable by an unintended owner because wrapping/unwrapping or shared-state handling is incomplete.
- **Arithmetic/state split:** a reward, pool, or claim computes from stale, user-controlled, or differently rounded object fields.

## Differential solve method

1. Run the supplied normal transaction and record every created/mutated/deleted object.
2. Modify one invariant at a time in the local test framework: object identity, owner, generic type, capability, transaction order, or lifecycle path.
3. Reduce any unexpected acceptance to the smallest entry-call sequence.
4. Verify the official solved predicate and preserve the exact before/after object state.

Use only the supplied local network, CTF RPC, or test accounts. Do not submit transactions to unrelated public packages.

## Source technique examples

- [Move CTF write-up](https://dantheman8300.gitbook.io/move-ctf-writeup)
- [MetaTrust Web3 Security CTF Sui challenges](https://leoq7.com/2023/09/MetaTrust-CTF-Sui/)
