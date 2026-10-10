# The challenge notebook

Keep one running record per challenge. It costs a line per observation and it is what stops the two failures that waste the most time: repeating work you already did, and forgetting the detail that turns out to be the answer.

The rule behind it: **in a CTF, almost everything you notice is placed there on purpose.** Challenge authors build a path and leave the pieces along it. A detail that looks like scenery at minute three is very often the key at minute forty — you just did not yet have the second piece that gave it meaning. So the notebook is not documentation. It is the working set you solve from.

## The ledger

One table. Add a row the moment you observe something, before deciding whether it matters.

```markdown
| #  | Observation                                   | Where from        | Kind       | Status  |
|----|-----------------------------------------------|-------------------|------------|---------|
| 1  | Server: Werkzeug/2.2.2 Python/3.9.2           | HTTP headers      | fact       | unused  |
| 2  | /admin returns 403, /admin/ returns 500       | dirb              | fact       | unused  |
| 3  | comment "TODO remove debug pin"               | page source       | clue       | unused  |
| 4  | 500 page leaks a traceback path /app/main.py  | manual request    | fact       | used    |
| 5  | maybe SSTI in the name field                  | guess             | assumption | ruled-out |
```

**Kind** — keep the three apart, because mixing them is how a guess quietly becomes a premise:

- **fact** — you observed it. A tool printed it, the server returned it, the file contains it.
- **assumption** — you believe it, you have not shown it.
- **clue** — something is off about it and you do not yet know why.

**Status** — `unused`, `used`, or `ruled-out`.

- `unused` — logged, not yet part of any working step. **This column is the point of the whole file.**
- `used` — it contributed to something that worked.
- `ruled-out` — tested and disproved. Write *why*, in the row. "Not SSTI — `{{7*7}}` renders literally" is worth ten times "no".

## Rules

**Log before you judge.** The filter that decides "this is irrelevant" is the same one that has already committed to a wrong reading. Write the row first; decide later.

**Never delete a row.** Status changes; entries do not disappear. A ruled-out path is a result — it is what stops you re-running it at hour two, and on a hard challenge the ruled-out list is most of what you know.

**"Seems irrelevant" is the most common shape of the key detail.** A version number, a strange port, an odd filename, a charset, a timestamp that does not fit, a field that is accepted but ignored — these are the things that mean nothing alone and everything in pairs.

**An error that is shaped differently is a fact.** Two rejections are not the same rejection. Different status code, different timing, different wording, different length — log the difference. A large share of CTF challenges are solved by noticing that one input failed *differently*.

**Log what you tried, not only what you found.** A command that returned nothing still tells you something is not there.

## When stuck, read the unused rows first

This is the mechanism. Before generating new hypotheses, before loading another pack, before running another tool:

**Read every `unused` row and ask of each one: what would have to be true for this to matter?**

Then look for pairs. Most intended paths are two or three observations combined, and each is inert on its own — a version number plus a leaked path, a debug comment plus a differently-shaped error. The reason a solve stalls is rarely a missing observation. It is usually two observations you already have, never put side by side.

Do this *before* inventing a new direction. A new guess is unconstrained; an unused observation is a constraint the author put there deliberately, and it is far more likely to be on the intended path.

If every row is `used` or `ruled-out` and you are still stuck, that is real information: you are missing an observation, so go back to the artifacts and enumerate rather than reason. Re-read the challenge description and re-run recon on what you have not touched.

## Scale it to the challenge

This should never feel like paperwork.

- **Easy challenge** — four or five rows, and you will barely consult it. Keep it anyway; the cost is seconds and you do not know it is easy until it is solved.
- **Hard or multi-stage** — the ledger *is* the solve. Expect twenty to fifty rows, and expect the winning move to come from pairing two `unused` entries rather than from a new idea.
- **Multi-day or team** — this is also the handoff. Someone picking it up reads the ledger and is current in a minute, and it becomes the raw material for the writeup. See `ctf-writeup`.

## Handing to a human

When escalating, send the ledger. An expert reading twenty rows of observations, and specifically the `unused` ones, will often redirect immediately — that is exactly the judgement call automation is worst at and a human is fastest at. Sending "I'm stuck" instead throws away everything you gathered and makes them rebuild it before they can help.
