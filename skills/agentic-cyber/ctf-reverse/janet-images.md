# Janet Image and Runtime Reversing

Use this note when a CTF gives you a Janet runtime plus a `.jimage`/compiled image, or an ELF that embeds Janet code. Keep experiments local to the supplied interpreter and challenge files.

## Confirm the artifact boundary

1. Separate the interpreter from the challenge program. Check whether the executable is a stock Janet runtime and whether the real logic is in a `.jimage` image.
2. Record the exact runtime version and launch arguments from the challenge instructions. Image formats and bytecode details can vary by version.
3. Run the image locally with safe, known inputs and save the full transcript. The runtime's error messages, help output, and evaluation mode can reveal how it loads the image and which modules are available.

## Prefer behavioral reconstruction first

- Search the image and runtime output for source filenames, symbols, constants, prompts, and format strings.
- Identify externally visible state: input grammar, attempt counters, time, random-number generation, and output rounding/formatting.
- Reproduce only the small state transition that determines the answer. If the program seeds a PRNG from time, process state, or supplied input, verify the seed timing and call order in the same runtime before trying a remote/local challenge instance.
- Use a bytecode/image disassembler only when behavior and constants do not explain the condition. Treat its output as a hypothesis until it matches a local run.

## Validation checklist

1. Run your reproduction against the same Janet version.
2. Check that PRNG construction happens once at the same point in execution; creating a fresh generator per value can change the sequence.
3. Match number formatting, parsing, and rounding exactly.
4. Preserve a minimal local script and expected output so another solver can validate the observation without the original interactive session.

## Source-derived pattern

UIUCTF 2023's `geoguesser` paired a Janet runtime with `program.jimage`. The decisive observation was challenge-visible behavior: coordinates came from a time-seeded Janet RNG. Reproducing the seed and call sequence was simpler and more reliable than fully decoding the image bytecode.

Sources: <https://ctftime.org/writeup/37385>, <https://ctftime.org/writeup/37400>
