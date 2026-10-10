# Mimalloc Heap Triage

Use this note for a supplied CTF binary/container that links Mimalloc or exposes Mimalloc symbols/configuration. Build an allocator model from the supplied version and local behavior before applying any heap hypothesis. Do not assume glibc chunks, tcache, or safe-linking rules apply.

## Identify the exact allocator model

1. Record the Mimalloc library/build, architecture, security-mode configuration, thread model, and all supplied allocator options. Keep allocator version facts separate from generic heap folklore.
2. Inspect local mappings while exercising the provided binary. Mimalloc-managed regions can be distinct from the conventional `[heap]` mapping, so debugger heap helpers may not describe the target allocations.
3. For each relevant requested size, determine the supplied build's page/bin behavior, user-data start, metadata placement, and alignment empirically. Do not carry offsets between versions or challenges.
4. Check whether secure mode is enabled. Pointer encoding, randomized allocation order, guard pages, and double-free checks are build-dependent; record observed behavior rather than inferring it from the library name.

## Model allocation state locally

1. Make a table for one size class: allocation order, returned address, page, and state after free. Mimalloc distinguishes allocation-ready free blocks from locally freed and cross-thread-freed blocks in the supplied design.
2. Determine the state transition that makes a recently freed block reusable. A same-size allocation need not immediately return it if an allocation-ready list still has untouched blocks.
3. Use harmless marker bytes in a copied challenge to prove UAF/read/write reachability and list ordering. Keep page metadata and user data separate in notes.
4. If a local pointer leak exists, derive base candidates from the actual mapping/page model and validate them against a second independent local pointer. Do not treat a leak as a universal fixed offset.

## Validate a confirmed primitive

1. For an overwritten free-list or application pointer, first redirect only to a non-sensitive, mapped local marker and document expected versus observed allocation order.
2. Restore/repair the copied local allocator state between experiments. An allocator crash proves only that an invariant was violated; it is not evidence of controlled allocation.
3. Preserve allocator build information, the size-class schedule, mapping evidence, state transitions, and a clean local replay script before expanding beyond the minimal challenge proof.

## Source-derived pattern

UIUCTF 2025's *do re mi* illustrates the key difference: a non-secure Mimalloc build used per-size pages, separate allocation-ready/local-free lists, and mappings outside the normal heap. The reusable lesson is to empty/model the relevant list state locally, then validate every claimed reuse or pointer interpretation against the supplied build.

Source: <https://ctftime.org/writeup/40356>
