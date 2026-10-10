# Solana and account-model CTF workflow

Use this note for Solana/Anchor challenge bundles. These are often presented as “crypto” or “blockchain” challenges, but the core bug is usually authorization, account ownership, serialization, or cross-program invocation rather than discrete-log cryptanalysis.

## First pass

1. Identify the framework and files: Anchor `lib.rs`, account structs, instruction handlers, test harness, solver scaffold, and deployment/configuration code.
2. Write the solve condition precisely: which account field, token balance, authority, or `is_solved` predicate must change?
3. Build a table for every account accepted by each instruction: expected owner, signer requirement, writable requirement, PDA seeds/bump, discriminator/layout, and relation to the caller.
4. Trace all CPIs (cross-program invocations), including token-program calls, system-program transfers, and any forwarded account list.

## High-value invariants

For every instruction, verify that the program—not the client—establishes these facts:

- the account is owned by the expected program before deserialization;
- a privileged authority is a signer or is a correctly derived PDA;
- a PDA uses the exact intended seeds, program ID, and bump;
- account relationships are checked (`pool.mint == mint.key()`, `vault.authority == pool.key()`, etc.);
- mutable accounts cannot be substituted with an equivalent-layout attacker account;
- initialization cannot be repeated to reset authority, counters, or discriminator state;
- close/reallocate paths cannot resurrect stale authority or leave rent/value in an unintended account;
- token mint, token-account owner, decimals, and transfer authority match the challenge’s intended asset;
- CPI account metas preserve signer and writable expectations rather than forwarding attacker-selected privilege.

## Common CTF primitives

- **Unchecked account substitution:** a handler deserializes a supplied account but misses owner, PDA, or cross-account relation checks.
- **PDA seed confusion:** a client-controlled seed, wrong program ID, inconsistent bump, or domain collision yields an account accepted as privileged.
- **Signer confusion in CPI:** an instruction forwards accounts to another program without proving the authority relationship first.
- **Reinitialization / close-reopen:** `init_if_needed`, custom initialization, close, or realloc logic resets a state machine or leaves a usable stale field.
- **Arithmetic/state mismatch:** share, fee, liquidity, or oracle calculations update one state variable but validate another; inspect rounding direction and all pre/post-transfer balances.
- **Token program ambiguity:** classic SPL Token versus Token-2022, mint extensions, delegate authority, and associated-token assumptions alter the real invariant.

## Differential solve method

1. Make the normal client path succeed once and capture the account list and state deltas.
2. Change one relation at a time in a local framework instance: signer, writable bit, account owner, PDA seed, mint, or instruction order.
3. When a check fails, record the program line that enforces it; when it succeeds unexpectedly, reduce the request to the smallest substituted account set.
4. Verify the solve by the official predicate, not merely by a successful transaction.

Do not import production private keys or probe public programs. Use the CTF RPC, local validator, and accounts supplied with the challenge.

## Reference solve shape

```text
read instruction handler
  -> list expected account invariants
  -> compare against framework/server setup
  -> create only the missing valid-looking account or instruction sequence
  -> invoke the intended entry point
  -> assert the challenge's official solved condition
```

## Source technique example

[DiceCTF 2023 Solana Challenges write-up](https://lkmidas.github.io/posts/20230304-dicectf2023-writeups/) is a useful CTF-oriented example of tracing Anchor program state, instructions, and the provided solver framework.
