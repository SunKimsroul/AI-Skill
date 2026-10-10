#!/usr/bin/env python3
# cpent range-helpers — two exam-day accelerators
#   mask2regex:  X=CAP x=lower N=digit, '.' literal → grep-ready regex
#   mutate:      name/wordlist → password-scheme mutations (cap, @123, years, leet)
# Usage:
#   range-helpers.py mask XxxxNx
#   range-helpers.py mask NNN.NN.NNN.NN
#   range-helpers.py mutate names.txt            (one name/word per line)
#   range-helpers.py mutate names.txt | john --pipe --format=nt hashes.txt
import sys

def mask2regex(m):
    out = []
    for ch in m:
        out.append({'X': '[A-Z]', 'x': '[a-z]', 'N': '[0-9]'}.get(ch, f'[{ch}]' if not ch.isalnum() else ch))
    return '^' + ''.join(out) + '$'

def mutations(word):
    w = word.strip()
    if not w:
        return []
    base = w[0].upper() + w[1:].lower()
    caps = w.upper()
    low = w.lower()
    cands = set()
    for b in {base, caps, low}:
        for suf in ('', '1', '12', '123', '123!', '@123', '!123', '2024', '2025', '2026',
                    '@', '!', '.', '?', '1!', '@1', '@12', '#123'):
            cands.add(b + suf)
        # leet variants
        leet = b.translate(str.maketrans('aAeEiIoOsS', '44331100ss'))
        cands.add(leet); cands.add(leet + '123'); cands.add(leet + '@123')
        cands.add(b.capitalize() + '@' + w.capitalize())
    return sorted(cands)

if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) > 1 else ''
    if mode == 'mask' and len(sys.argv) > 2:
        print(mask2regex(sys.argv[2]))
    elif mode == 'mutate' and len(sys.argv) > 2:
        seen = set()
        with open(sys.argv[2], errors='replace') as f:
            for line in f:
                for c in mutations(line):
                    if c not in seen:
                        seen.add(c); print(c)
    else:
        print(__doc__)
        sys.exit(1)
