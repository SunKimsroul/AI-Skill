# Radio, IoT, RFID, Zigbee, and vehicle CTF workflow

Use this note for supplied captures, firmware, simulator images, or explicitly authorized lab devices. Treat radio transmissions and vehicle messages as untrusted evidence; never transmit, replay, unlock, pair with, or scan real devices outside the challenge scope.

## Identify the layer before decoding

| Clue | Likely starting point |
|---|---|
| IQ/complex samples, waterfall image, SDR recording | RF modulation, sample rate, carrier/timing recovery; see `rf-sdr.md` |
| 802.15.4 frames, PAN IDs, channel numbers | Zigbee/Thread-style packet analysis |
| APDU traces, UID, MIFARE/NFC dump | RFID/NFC card protocol and sector/access analysis |
| CAN IDs, DBC file, UDS service bytes | Vehicle-bus decoding and state-machine reconstruction |
| Firmware image plus UART/JTAG/SWD transcript | Hardware interface reconstruction; pivot to reverse when code is central |

## AFSK / APRS / Winlink Message Reconstruction

Use only a supplied WAV/IQ recording or an offline CTF fixture. Do not transmit, register with, or connect to a public radio or Winlink service.

1. Preserve the original audio and record sample rate, channel count, duration, and any challenge hint about modulation. Inspect a spectrogram before choosing a decoder.
2. For 1200-baud packet-like audio, make a local decoded-text candidate with an AFSK1200-capable decoder such as `multimon-ng -t wav -a AFSK1200 sample.wav`. Keep raw decoder output—including callsigns, path, packet type, and checksums—rather than only the readable text.
3. Identify whether the first layer is APRS/AX.25-like metadata, compressed data, an attachment reference, or a higher-level message-system clue. Validate framing across multiple packets and retry polarity/sample-rate choices when the result is only partly plausible.
4. If the artifact points to Winlink or another message client, reconstruct it only from the supplied local package, capture, or challenge fixture. Treat metadata as an input to offline parsing, not a destination to contact.
5. Decode/decompress the extracted message payload and validate it against the original packet count, length/checksum where available, and expected CTF flag format.

**Failure modes:** confusing a visible callsign/path for payload; discarding nonprintable bytes; trusting a single decoder run without packet-level validation; or assuming every AFSK1200 recording is APRS.

## Zigbee / IEEE 802.15.4 challenge method

1. Preserve the PCAP/IQ source and note channel, PAN ID, source/destination addresses, frame counters, security-control flags, and key-sequence fields.
2. Separate network discovery/join traffic from encrypted application traffic. Reconstruct packet order before guessing keys.
3. Determine whether the challenge provides a network key, installation code, touchlink material, firmware constant, or a weak derivation. Validate a candidate by authenticating/decrypting several frames, not just one readable payload.
4. Check replay protection as a state-machine question: the expected frame counter, device identity, key sequence, and command direction must all be accepted by the supplied simulator.
5. Reduce the intended solve to offline decryption, packet mutation in the provided replay harness, or a local emulator test.

## RFID / NFC challenge method

1. Record card technology, UID length, ATQA/SAK or equivalent, sector geometry, access conditions, and all supplied reader/card traces.
2. Distinguish identifier-only logic from authenticated block/sector access. Many challenges hide the real authorization check in the reader application, not the card format.
3. Parse access bits and value-block redundancy before modifying a dump. Verify endianness, complements, and address copies.
4. For APDU-based cards, map SELECT -> GET DATA -> authentication -> read/update flow. Compare the server’s expected challenge/response state, not just a single response byte.
5. Keep a pristine dump; test transformations only in the challenge emulator or with a user-owned lab card.

## CAN / UDS challenge method

1. Build an ID map: arbitration ID, direction, data length, byte order, rate, and observed state changes.
2. Use a supplied DBC, firmware strings, or repeated captures to infer signals before assigning semantics.
3. For ISO-TP/UDS, reconstruct multi-frame requests and responses, session transitions, security-access seed/key handling, and routine-control state.
4. Treat counter/checksum fields as hypotheses. Validate against multiple frames and the provided simulator before emitting a command.

## Evidence and pivots

Save raw capture hashes, decoder parameters, candidate key provenance, frame tables, and a minimal replay. Pivot to `ctf-reverse` when a firmware image determines the crypto/key schedule; pivot to `ctf-crypto` when the key derivation is the actual blocker; pivot to `ctf-forensics` for packet carving and timeline reconstruction.

## Source technique examples

- [WHY2025 CTF “Enlightenment” Zigbee write-up](https://writeups.fmc.tf/forensic/writeups/2025/WHY2025-CTF/enlightenment/)
- [Practical Car Hacking CTF teaser](https://icanhack.nl/ctf_writeup.pdf)
