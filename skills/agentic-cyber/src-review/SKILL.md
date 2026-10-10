---
name: src-review
description: Five-pass deep source-code review to find NEW, provable vulnerabilities in real software (PHP/Go/JS/C). Use when the user asks to find a 0-day, review source for unreported flaws, patch-diff a security fix, or prove a bug locally with a PoC. Covers surface mapping, sink hunting per language, incomplete-fix diffing, minimal reproducer building, and regression bounding.
---

# src-review — five-pass vulnerability hunt in real source

The unit of work is one **candidate**. A candidate becomes a finding only when it
reproduces locally on a build you control. No exceptions, no "it should work".

## Preconditions (state them before starting)

- Target repo at a known commit, locally cloned, **full git history** (`git fetch --unshallow` if shallow).
- Legal basis: open source / authorized. Local proof only — never test against third-party live systems.
- Runtime available locally (php/node/go/python/gcc) or a base container (`docker run --rm`) matching the target's real-world deployment.

## Pass 1 — SURFACE (30 min max)

Answer four things in notes before touching code details:

1. **Entry points** — what accepts untrusted input? (file parsers, HTTP handlers, CLI args, deserializers)
2. **Trust boundary** — the exact line where untrusted bytes become "data the code trusts".
3. **Privilege** — what user does the code run as in production (web user? root? sandboxed?)
4. **Reachable surface size** — `ls` the module list; parsers/archives/codecs are where bugs live.

Libraries: the public API IS the entry point. For a media-metadata library, every
`analyze(file)` call is an attacker-controlled input channel.

## Pass 2 — SINK HUNT

Grep per bug class, then walk **backwards** from sink to entry (taint tracking).
Never report a sink before proving the path from untrusted input.

PHP sinks:
```
exec( shell_exec( system( passthru( proc_open( popen(
eval( unserialize( include/require with variable
preg.*\/e  assert(  create_function(  file_get_contents/php://
simplexml_load / DOMDocument->load*      (XXE: check for LIBXML_NOENT!)
fopen/file_put_contents with variable    (path traversal, LFI)
iconv_substr / mb_  with huge lengths     (DoS)
imagecreatefrom*                          (decoder bugs)
```
Go: `os/exec.Command`, `unsafe`, `cgo`, `syscall`, `text/template` in handlers, `sql` + Sprintf.
JS: `child_process`, `eval`/`Function`, `vm`, `JSON.parse` on prototypes, `Buffer` math.
C/C++: `strcpy/memcpy/sprintf/alloca`, all `malloc` + index arithmetic, integer truncation.

XXE specifics people get wrong: `LIBXML_NOENT` **enables** entity substitution (the opposite
of what the name suggests). `LIBXML_NONET` blocks network but NOT `file://`. On libxml ≥2.9
external entities are off *by default* — any code that adds `NOENT` re-arms them.

## Pass 3 — PATCH DIFF (highest-yield pass)

```bash
git log --oneline --grep="security\|CVE\|vuln\|XXE\|inject\|overflow\|fix" -i | head -30
git diff <fix-commit>^ <fix-commit>            # what changed
```

Read every security fix for four things:
1. What was the bug (reconstruct from the fix shape)?
2. **Is the fix complete** — every path, or just the reported one?
3. Same pattern elsewhere in the codebase (grep the fixed pattern's signature)?
4. **Does the fix itself introduce a new danger?** (added flags, loosened checks,
   new code paths). Fixes written under pressure regularly regress — verify the
   fix commit's parents against the fixed version with the same PoC.

## Pass 4 — DEEP READ

Take the 1–2 most promising candidates from passes 2–3 and read the full function
plus every caller. Build the exact input that reaches the sink: correct container
format, correct field offsets, correct encoding. 90% of "false" candidates die here
because a sanitizer sits between source and sink — that's the pass working.

## Pass 5 — PROVE

1. Craft the input programmatically (python struct.pack for binary formats — reproducible, byte-exact).
2. Run against the **current** version → capture the evidence (leaked data, crash, RCE output).
3. Run the identical input against the **pre-fix / parent** commit → bounds the affected range.
4. Minimize until removing any single byte breaks it.
5. Record: affected versions, CWE class, attacker prerequisites, what the attacker gains.

Proof template (PHP example):
```bash
php -r 'require "repo/lib.php"; $r = (new Lib())->analyze("evil.bin");
        var_export($r["leaked"]);'
```

## Writing it up

Lead with: one-line impact, affected versions, minimal repro steps, expected vs actual.
Report privately per the project's SECURITY.md. Attach a patch if you can.
Severity honest: local-file-read via file upload processing is usually High, not Critical.

## Red flags that predict findings (from real hunts)

- A security fix that *adds* a parsing feature/flag — verify it against the parent.
- Comments citing CVEs/blog posts near guards — the guard was bolted on, check its branches.
- `escapeshellarg` present at call site but the *argument construction* above it builds the command.
- One caller left unpatched after a class-wide fix.
- Version checks guarding deprecated functions where the "safe" fallback branch is the weak one.
