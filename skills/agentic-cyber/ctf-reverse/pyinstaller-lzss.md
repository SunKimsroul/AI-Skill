# PyInstaller and LZSS-Wrapped Artifact Recovery

## Scope

Use this when a supplied executable is primarily a Python bundle and the meaningful artifact is hidden behind a compression step such as LZSS. Work from local challenge files; identify the wrapper before spending time decompiling an embedded interpreter.

## Workflow

1. Classify the outer file with `file`, `strings`, and a section/overlay view. Look for PyInstaller markers (`PYZ`, `PYI`, Python module names) and compression signatures.
2. Extract candidate modules with a PyInstaller-aware extractor. If the main module is missing, carve zlib/PYZ streams from the supplied file and search the recovered material for `__main__`, usage strings, or a file-processing function name.
3. Identify the exact transform from the recovered code. Treat `lzss`, `encode_file`, or a similar import as a direction clue, not proof that every LZSS implementation uses the same flags, window, or byte order.
4. Reproduce the decoder locally using the same library/version or a small format-matched implementation. Write the result to a new file; never overwrite the original artifact.
5. Classify the result by magic bytes. If it is Intel HEX, preserve record addresses before converting; if it is ELF, PE, archive, image, or text, pivot to the corresponding analysis workflow.

```bash
file supplied
strings -a supplied | grep -Ei 'pyi|pyz|python|lzss|encode|decode'
binwalk -e supplied
# Run a PyInstaller extractor only against the supplied CTF binary.
```

## Validation

- Compare output size and magic bytes with the decoder's expected format.
- Check that a round trip with the recovered encoder/decoder, when both are supplied, preserves a small fixture.
- For an Intel HEX result, validate record checksums and reconstruct bytes by address; do not mistake the printable hexadecimal records for the program itself.
- Keep a short provenance note: outer artifact → recovered module → transform → decoded artifact.

**Source pattern:** Aero CTF 2020, `Elderly File` ([writeup metadata](https://ctftime.org/writeup/18761)).
