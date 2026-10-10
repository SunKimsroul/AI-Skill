# Forensics Field Notes

Distilled post-solve lessons. Read after SKILL.md when the challenge matches
this category. Newest entries at the bottom of each section.

## Archive & Crypto Recovery

### GalleryVault Encrypted-Zip Recovery via bkcrack (Protected, HTB 2026)
**Pattern:** Android GalleryVault app ships an AES/ZipCrypto-encrypted vault zip (`mobile_protected.zip`). Known-plaintext attack works because inner files are zlib streams with predictable headers: extract ~12+ known plaintext bytes (cipher0/1/2.bin vs plain.bin from the APK's bundled assets), run bkcrack to recover the internal keys, then `bkcrack -C vault.zip -c <entry> -k <keys> -d decrypted.zip`.
**Key moves:** `java -jadx apk` to locate crypto + asset paths; `bkcrack -C enc.zip -p plain.bin -x 0 <hex>`; unzip decrypted vault, pull `galleryvault.db` + thumbs for the flag image.
**Gotchas:** bkcrack needs contiguous known plaintext at the right offset — brute-force the offset only after confirming the compression method (stored vs deflate). Decrypted inner zip can still be large (1G+) — extract selectively.
See: solve artifacts at ~/Documents/HackTheBox/HTB-CTF/mobile/Protected/ (solve.py, exploit.py, bkcrack.log).


### NimPlant C2 PCAP + minidump, two-part flag (The Art of Capture, HTB 2026)
**Tags:** #forensics #network #c2 #nimplant #rc4 #shellcode
**Env:** NimPlant v1.2 (Nim, puppy HTTP client); pcapng + user minidump of implant; MSVC dropper exe
**Pattern:** pcap = encrypted NimPlant C2 over plain HTTP (`/api/v2/login|ping|query`): server reply `{"id":..,"k":<b64>}` carries the session key XOR-masked by a build-time 32-bit `xor_key`; traffic is `b64(16 printable IV || AES-128-CTR)`. Build key brute-force collapses to 65536 candidates (k0 = key&0xFF, C = b1^b2^b3 of key) — validate by first POST decrypting to JSON. Operator `upload` task drops a dropper exe whose `main` RC4-decrypts an embedded shellcode (`VirtualProtect` + in-place RC4 + `call`) — decrypt statically with the odd 12-byte .rdata string (length proven by `i%12` magic-div in KSA). Flag split: exfil screenshot's FIGlet banner = part 1 WITHOUT `}`; shellcode plaintext = part 2 ending in `}`.
**Key moves:** decrypt ping/query `data` fields; screenshot result = b64→gzip→PNG; banner via pyfiglet beam-search (`big_money-ne`); shellcode: `pe.get_data(VA-of-blob, size)` + plain RC4, read strings — flag part 2 verbatim after final `ret`.
**Gotchas:** minidump is from a DIFFERENT later session (identification only, its screenshot has no flag); don't "fix" a flagless banner by inferring `}` when the description says two parts — the second artifact supplies it.
See: solve at ~/Documents/HackTheBox/HTB-CTF/Forensic/The Art of Capture/ (solve.py, solve_rev.py, writeup.md).

## Archived printer spool + stencil transposition (SCC "SQ_NOTICE9", 2026-09)
- Raw ESC/P spool: evidence hidden in-band. Bold runs `ESC E <char> ESC F` in print order = XOR key (read with `re.findall(rb'\x1bE(.*?)\x1bF', data)`).
- Stencil puzzle: 12x12 letter block + 12x12 '#'/'.' mask grids in a "maintenance doc"; a roster's "cut authority" number selects the mask by its '#' count.
- Orientation twist: "filed notch-up, prints notch-right" = rotate the mask 90° CW before applying; holes read row-major spell the instruction (here: "KEY IS THE EMPHASIS RUN IN PRINT ORDER").
- Sealed payload: repeating-key XOR; verification = CHK hex string printed in the spool appears verbatim inside the decrypted plaintext (not a CRC of it).
- Analysis hygiene: `od -A d -t x1z` + Python binary reads only; never open in an editor (CRLF/eol-rewriting would silently destroy in-band evidence).
