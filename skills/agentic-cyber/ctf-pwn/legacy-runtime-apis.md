# Legacy Language Runtime API Auditing

Use this for supplied CTF binaries, source trees, or containers built around legacy-language runtimes. A high-level language artifact can reach native library APIs with independent allocation, conversion, and ownership rules; trace the native runtime before assuming the source language itself is the vulnerability.

## GnuCOBOL `CBL_*` File API Ownership Audit (PlaidCTF 2021)

**Recognition:** A challenge ships COBOL source or a binary linked with `libcob`, exposes operations such as create/open/read/write/copy, or references `CBL_COPY_FILE`, `cob_str_from_fld`, `cob_current_module`, or generated COBOL call frames.

### 1. Identify the real implementation boundary

1. Record the supplied GnuCOBOL/libcob build, compiler mode, generated C source (if present), and the C runtime symbols used by the wrapper.
2. Map each high-level field to its native representation: byte length, encoding, NUL termination, allocation helper, lifetime owner, and whether a filename buffer is reused as a data buffer.
3. Read the matching source revision of the supplied runtime. A `CBL_*` call can look safe in COBOL while its native helper owns and frees temporary buffers.

### 2. Audit allocation-to-use transitions

For every file operation, draw this small timeline:

```text
COBOL argument -> native string conversion -> allocation -> file syscall
             -> free/realloc/close -> later read/write/copy -> cleanup
```

Look for a pointer freed before a subsequent read/write, size derived from a different field than the backing allocation, or a destination/source alias that is not rejected. Keep filename length and file-content length as separate variables in the model.

### 3. Reproduce only in the supplied local challenge

Compile/run the provided source under AddressSanitizer where feasible, or set breakpoints on the conversion helper, `free`, and the relevant `read`/`write` call. Use an inert local fixture to prove the ownership bug and record the allocation size and use site.

```bash
# Supplied challenge source only.
grep -RniE 'CBL_COPY_FILE|cob_str_from_fld|cob_current_module' ./challenge-source 2>/dev/null
nm -D ./challenge-binary 2>/dev/null | grep -iE 'cob|CBL_'
```

Do not use a local UAF observation as proof of a stable primitive. First demonstrate repeatability under the same runtime/allocator build, then return to the general heap workflow for allocator-specific reasoning.

### 4. Validate the root cause

- Preserve the exact runtime revision and the native source line/function responsible for the lifetime error.
- Re-run the minimal trigger in a clean local container and capture the same sanitizer/debugger evidence.
- State whether the CTF wrapper gives a read, write, lifetime, or only crash primitive; do not infer control from the bug class alone.

**Key insight:** In legacy runtime challenges, the source language is often an input grammar over a C ABI. The decisive evidence is native buffer ownership and size flow, not the apparent safety of the high-level file statement.

**Source inspiration:** PlaidCTF 2021, *The Cobol Job*: <https://ctftime.org/writeup/27590>.
