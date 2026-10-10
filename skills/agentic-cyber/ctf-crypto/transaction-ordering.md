# Transaction-Ordering and Oracle-State CTFs

Use this note for a supplied chain, local fork, or organizer-provided testnet CTF where the result depends on transaction order. Do not apply it to production contracts or public third-party systems.

## Model the state transitions, not just the contract functions

1. Draw the sequence: user input → randomness/request event → oracle fulfillment → settlement/claim.
2. Record which values are fixed at each stage: caller, request ID, seed, block number, nonce, and any streak/round state.
3. Identify whether an input is still accepted after the contract has requested randomness but before fulfillment. That interval is the core CTF condition to test.
4. Recompute the settlement value from the contract's exact encoding and state snapshot. Treat address packing, block fields, and integer truncation as part of the calculation.

## Validate in a controlled challenge environment

- Use the supplied local chain/fork or explicit organizer testnet. Capture transaction receipts, block numbers, and emitted events for each phase.
- Start with a single round. Prove that the state machine accepts or rejects each ordering before automating repeated rounds.
- Compare the code's expected ordering against actual inclusion ordering from the local/testnet receipts. Do not assume a nominal block time or a particular fee market.
- Keep a replay log containing the initial state, transaction inputs, receipts, and final contract state.

## Common red flags

- A random result is computed only after a request, but bets/guesses remain mutable until fulfillment.
- A later action overwrites a stored guess without invalidating the prior request.
- Settlement combines a newly revealed seed with caller-controlled or order-dependent fields.
- A multi-round score/streak is reset on only some failure paths.

## Source-derived pattern

GPN CTF 2023's `gambling` challenge accepted a new guess after requesting randomness but before the challenge oracle delivered it. The reusable lesson is to map the request-to-fulfillment window and verify state transitions on the provided challenge chain; it is not merely a weak-randomness problem.

Source: <https://ctftime.org/writeup/37193>
