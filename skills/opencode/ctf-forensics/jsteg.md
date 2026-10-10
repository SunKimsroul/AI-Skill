# CTF Forensics - JSteg JPEG Coefficient Extraction

Use this procedure only on a supplied JPEG challenge file. JSteg embeds bits in the parity of quantized nonzero AC DCT coefficients, so RGB-pixel LSB extraction will usually miss it.

## Triage

1. Preserve the original JPEG; do not recompress it before extraction because recompression changes DCT coefficients.
2. Check the supplied file locally with `file`, `exiftool`, and `binwalk`, then inspect quantized coefficients with a JPEG-aware parser.
3. Treat ordinary metadata or an F5-style coefficient-distribution signal as a separate hypothesis. JSteg extraction needs a bit-order and coefficient-selection check.
4. Test the conventional exclusion of `-1`, `0`, and `1`, then only the conventions justified by the supplied challenge/source. Score output by magic bytes, flag prefix, or entropy—not by accidental printable fragments.

## Local coefficient extractor

Install `jpegio` locally if needed: `pip install jpegio`. The array order and channel handling are format-dependent; retain all components unless the challenge states otherwise.

```python
import jpegio as jio

def pack_bits(bits):
    return bytes(sum(bit << (7 - offset) for offset, bit in enumerate(bits[i:i + 8]))
                 for i in range(0, len(bits) - 7, 8))

def jsteg_candidates(path):
    image = jio.read(path)
    for skip_small in (True, False):
        bits = []
        for component in image.coef_arrays:
            height, width = component.shape
            for top in range(0, height, 8):
                for left in range(0, width, 8):
                    block = component[top:top + 8, left:left + 8].reshape(-1)
                    for index, value in enumerate(block):
                        if index == 0:        # JPEG block DC coefficient
                            continue
                        value = int(value)
                        if value == 0 or (skip_small and abs(value) == 1):
                            continue
                        bits.append(value & 1)
        yield skip_small, pack_bits(bits)

for skip_small, data in jsteg_candidates('challenge.jpg'):
    print('skip ±1:', skip_small, 'head:', data[:64])
    open(f'jsteg-{int(skip_small)}.bin', 'wb').write(data)
```

## Validation

Run `file` and a local hexdump over each candidate. If a candidate begins with a known header (ZIP, PNG, gzip, text/flag prefix), carve only that locally supplied result and verify its length/checksum where available. If both variants are noise, return to metadata, F5 detection, steghide/outguess, or pixel-domain analysis rather than forcing JSteg.

**Source pattern:** Zh3r0 CTF, `LSB fun` ([writeup metadata](https://ctftime.org/writeup/21809)).
