# Linux Rootkit Memory-Dump Triage

## Scope

Use this for a supplied Linux memory image where a kernel module, process, file, or network activity may be hidden. Keep analysis offline; use the profile or kernel symbols supplied with the CTF artifact.

## Reconcile Independent Kernel Views

1. Confirm kernel/banner and select the matching profile or symbol table. Record tool and profile versions so plugin output remains reproducible.
2. Inventory processes, shell history, loaded modules, files, network interfaces, and connections. Treat a single view as incomplete: a rootkit can unlink itself from the normal module list or filter directory/process results.
3. Compare the ordinary module listing with a cross-view/module-integrity check. A module address present only in the integrity view is a high-value candidate for an unlinked `.ko`.
4. Use the candidate module address to dump the loaded module, then analyze it as a kernel object. Trace its initialization path, parameter handling, syscall/file-operation hooks, and persistent global buffers.
5. Correlate process history or command-line fragments with module parameters. Encoded module arguments often identify a ciphertext, hidden PID, file name, or initial key material.

```bash
# Volatility 2-style names vary by supplied Linux profile/plugin pack.
vol.py -f memory.vmem --profile=<profile> linux_banner
vol.py -f memory.vmem --profile=<profile> linux_pslist
vol.py -f memory.vmem --profile=<profile> linux_lsmod
vol.py -f memory.vmem --profile=<profile> linux_check_modules
vol.py -f memory.vmem --profile=<profile> linux_bash
# Dump only the module address identified in the supplied memory image.
vol.py -f memory.vmem --profile=<profile> linux_moddump -b <module_base> -D modules
```

## Recover Runtime State and Validate

Kernel modules frequently derive a runtime key from a static constant plus external input, then leave the derived buffer in the loaded image's writable region. Locate the buffer from the initialization/transform code, extract only the demonstrated length, and reproduce the exact decode locally.

```python
def xor_repeating(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError('empty key')
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
```

**Validate:** Confirm the extracted module base appears in the cross-view result, not just in one plugin. Check that the recovered plaintext or configuration satisfies the artifact's expected format, and retain provenance: memory offset → module dump → code/data offset → transform output.

**Source pattern:** Insomni'hack Teaser 2020, `getdents` ([writeup](https://ctftime.org/writeup/17984)).
