# Incident-Response Evidence Chains (CTF / Offline)

## Goal

Use when a CTF provides logs, endpoint artifacts, PCAPs, service exports, or a multi-stage blue-team storyline. Recover an evidence-backed sequence rather than solving each clue in isolation.

## Build an Evidence Graph

Create nodes for identities, IPs, hosts, services, processes, files, sessions, tunnels, and C2-like destinations. Add an edge only when an artifact supplies both sides and a time/context: authentication log, process lineage, DNS/flow record, EDR event, shell history, Git/server audit event, or file metadata.

Typical chain:

`source service -> user -> source IP -> endpoint -> initial access -> discovery -> tunnel/pivot -> C2`

The order is a hypothesis, not proof. Preserve each edge's source artifact, timestamp, timezone, and confidence.

## Offline Workflow

1. Inventory every artifact and normalize timestamps to one timezone without overwriting originals.
2. Start with the strongest pivot: a service audit record, authentication/session ID, process hash, or network 5-tuple.
3. Join evidence using stable identifiers—host ID, user/SID, PID/PPID, session ID, file hash, connection tuple—not display names alone.
4. For each proposed stage, record what happened, where, when, the evidence path/offset, and the next pivot it justifies.
5. Correlate tunnel/proxy behavior with both endpoint process lineage and network flow timing; do not label encrypted or uncommon traffic as C2 without corroboration.
6. Produce a compact timeline and a separate fact table. Keep unknowns as unknowns rather than filling gaps from challenge naming.

## Validation

- Require two independent artifacts for high-confidence claims where possible.
- Reconcile timestamp skew, log rotation, NAT, shared users, and reused IPs before joining events.
- Test that every claimed edge can be traced back to a local artifact and that the final answer is supported by the requested evidence, not merely a plausible chain.

**Boundary:** Analyze supplied CTF artifacts or authorized evidence copies only. This workflow is for reconstruction and reporting; it does not authorize active investigation of external systems.
