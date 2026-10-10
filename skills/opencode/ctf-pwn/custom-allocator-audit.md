# Custom Allocator and Heap-Canary Audit

## Scope

Use this for a supplied CTF binary whose allocator is application-defined rather than glibc, particularly when allocations carry a custom canary, footer, free-list link, or bookkeeping table. Reconstruct the allocator before applying any generic heap technique.

## Build an Allocator Map

1. Identify allocation, free, edit, display, and error paths. Record every user-controlled length and whether it is rounded, truncated, or independently stored.
2. Draw the exact chunk layout from the code and local debugger: header fields, requested size, capacity, canary position, payload boundary, footer, next/previous links, and global slot references.
3. Build a lifecycle table for each menu action: allocation source, metadata initialized, fields left stale, canary checked, links changed, and whether the user pointer remains reachable after free.
4. Use only harmless local fixtures to compare adjacent allocations of different sizes. A leak/print path may expose allocator metadata or the canary; distinguish a genuine disclosure from uninitialized padding.
5. If a write boundary reaches metadata, first prove locally which field changes and what check detects it. Preserve any required canary before reasoning about the next allocator operation.

## Validation Checklist

- Reproduce allocation and free order on the supplied local binary, recording addresses and chunk contents after every action.
- Confirm every claimed offset against the allocator's own size/rounding rule, not a libc assumption.
- Trigger the canary check with a minimal local mutation to establish its coverage and failure behavior; then restore the normal fixture.
- Treat a stale-pointer or overlap claim as valid only when the local program visibly returns the same region through two distinct logical objects.

**Source pattern:** Byte Bandits CTF 2019, `hardmalloc` ([writeup index](https://ctftime.org/writeup/14933)).
