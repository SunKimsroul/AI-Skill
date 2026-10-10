# TempleOS / HolyC CTF Triage

Use this note for a supplied TempleOS/TinkerOS QEMU image, HolyC source archive, or local serial-backed challenge guest. Treat the guest as its own runtime model; do not apply normal Linux privilege, ELF, or memory-protection assumptions without verifying them in the supplied image.

## Establish the guest and source path

1. Preserve the disk image, QEMU launcher, serial configuration, and guest version. Work from a copied image and record all guest resets/reboots because runtime-compiled addresses and memory state can change.
2. Locate the challenge source, including compressed HolyC files and startup/include scripts. Map boot/autostart -> source include -> compiled function -> serial/menu dispatcher.
3. Determine the actual memory/privilege model in the supplied build. TempleOS-like images may execute application, compiler, and kernel code in one broadly writable/executable address space, but document the observed image rather than treating this as a universal fact.
4. Treat the local serial bridge as I/O only. Keep guest source, guest memory, and host-side QEMU plumbing as separate trust boundaries.

## Analyze HolyC control flow precisely

1. Identify HolyC-specific syntax and lower it to observed machine behavior. In particular, distinguish a normal `switch (...)` from bracketed dispatch constructs such as `switch [...]`; do not assume a `default` branch implies an automatically bounded table.
2. For a computed dispatch, record selector width/signedness, table element width, table base, entry interpretation, and target-base addition. A signed relative offset table has different reachability than an absolute pointer table.
3. Use the supplied guest's local disassembler/debugger or QEMU inspection to verify the compiled instruction sequence and table bounds. Source syntax alone is insufficient proof of the compiled dispatch.
4. Reduce any out-of-range or arithmetic condition to an auditable local index equation before testing it. Validate with a harmless target/control marker in the copied guest first.

## Validate in the supplied image

1. Run an unchanged baseline over the documented local serial path and save the exact output/state.
2. Make one reversible source or input change in a copy, reboot or reload through the documented guest path, and confirm which function/address/state changed.
3. Preserve the guest version, QEMU command, source-to-code mapping, table model, and local replay steps. Do not reuse fixed addresses, memory layout, or any guest result outside the supplied CTF image.

## Source-derived pattern

m0leCon CTF 2025's *HolyM0le* combined a supplied QEMU image, HolyC source, serial I/O, and a TempleOS-specific bracketed switch dispatch. The reusable lesson is to derive the compiled dispatch/table semantics and the guest's actual memory model locally before classifying a control-flow condition.

Source: <https://ctftime.org/writeup/40348>
