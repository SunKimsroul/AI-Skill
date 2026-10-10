# Operation routes

## Knowledge and category routing

| Command | Knowledge pack | First question |
|---|---|---|
| `/web` | `ctf-web` | What is the input, trust boundary, and observable effect? |
| `/ad` | `ctf-ad` | What foothold do I hold, and what is the shortest graph edge from it? |
| `/redteam` | `ctf-redteam` | What does the target's detection posture allow, and what does a small test confirm? |
| `/recon` | `ctf-pentest` | Have I enumerated every service and mapped version→known-exploit before attacking? |
| `/privesc` | `ctf-privesc` | Have I enumerated fully before reaching for an exploit? |
| `/pivot` | `ctf-pivoting` | What must reach what, and in which direction? |
| `/pwn` | `ctf-pwn` | Is the bug and controllable primitive established? |
| `/rev` | `ctf-reverse` | What does the target do, and which static evidence supports that? |
| `/foren` | `ctf-forensics` | Which artifact, timeline, or provenance question is unanswered? |
| `/crypto` | `ctf-crypto` | Is the weakness implementation, protocol, or mathematics? |
| `/misc` | `ctf-misc` | Is this a VM, encoding, sandbox, protocol, or automation problem? |
| `/osint` | `ctf-osint` | What public fact is needed, and how can it be corroborated? |

Use `ctf_playbook.search_ctf_skills` before loading a broad skill file. Keep reverse and pwn primary for binary work.

## Git workflow

### `/pull`

1. Inspect repository status, current branch, remotes, and uncommitted changes.
2. State the intended remote and branch.
3. Ask before changing a dirty worktree or resolving conflicts.
4. Fetch and fast-forward only when the user confirms the target and the worktree is safe.
5. Record the resulting commit in the handoff or writeup notes.

### `/push`

1. Show the staged diff, destination remote, and branch.
2. Check for flags, passwords, session cookies, API keys, customer data, and private target details.
3. Ask the user to explicitly confirm the exact remote and branch.
4. Push only the reviewed commit; never force-push without a separate explicit instruction.

## Authorized real-infrastructure workflow

1. Read the active engagement record and stop if it is pending, expired, absent, or does not cover the proposed target/action.
2. Prefer the least disruptive validation that proves or disproves a finding.
3. Preserve request/response evidence, timestamps, and affected assets without retaining secrets in writeups.
4. Stop on scope ambiguity, unexpected production impact, or a target outside the declared boundary.
5. Report impact, reproduction, and remediation separately from raw credentials or exploit payloads.
