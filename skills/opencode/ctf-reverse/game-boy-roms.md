# Game Boy ROM and Tile-Memory Reversing

Use this note for a supplied Game Boy or Game Boy Color ROM in a CTF. Work on the provided ROM and an emulator; do not treat it as a workflow for modifying commercial games.

## Triage the cartridge before code analysis

1. Run `file` and preserve the original ROM hash. A Game Boy header identifies the title, cartridge type, ROM/RAM capacity, and whether a memory-bank controller (MBC) is involved.
2. Record the target generation and cartridge mapper. Banked ROM means a CPU address can refer to different physical data after a bank-register write; annotate bank state in every code/data reference.
3. Start with an emulator that has a debugger and graphics viewers. Set breakpoints on the entry point, input handling, and display-update routines rather than assuming that a string is stored as normal ASCII text.

## Separate the three useful views

| View | Question to answer |
|---|---|
| CPU execution | Which LR35902 routine calculates or copies the value? |
| ROM/RAM banks | Which cartridge bank supplies the code or asset? |
| Video memory | Is the answer already present as tiles, a tile map, or a palette? |

For graphics-oriented challenges, inspect tile data and the background/window tile maps before reversing the entire game loop. A visible phrase may be encoded by tile indices, reordered tiles, or a map populated after an NPC/action event.

## Reproduce, then decode

1. Trigger the in-game condition and capture the relevant graphics-memory view or emulator dump.
2. Determine whether the interesting bytes are character tiles, tile-map indices, a permutation, or a simple palette/bitplane transformation.
3. Make a small offline decoder that takes the captured bytes and emits a candidate image or text. Keep the input dump and expected output together so the conclusion is reproducible.
4. If a tile is scrambled, test ordering and map-index hypotheses before assuming encryption. Confirm by reconstructing multiple characters, not just one flag-like fragment.

## Debugging notes

- LR35902 is Game Boy's CPU, not 6502; use its register/flag semantics and the ROM's bank state in your analysis.
- Graphics updates are often DMA/copy loops. Break on writes to the video-memory region or on the routine that runs after the relevant dialogue/action.
- Treat save RAM and battery-backed data as separate from the immutable ROM. Reset to a clean save when validating a finding.

## Source-derived pattern

1337UP LIVE CTF 2023's `Virtual RAM` distributed a Game Boy ROM and used an in-game hint to direct solvers to video memory. The reusable lesson is to inspect the supplied cartridge's graphics state and tile arrangement before spending time decompiling the full program.

Source: <https://ctftime.org/writeup/38229>
