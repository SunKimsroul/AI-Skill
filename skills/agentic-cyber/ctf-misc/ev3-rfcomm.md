# LEGO EV3 RFCOMM Capture Reconstruction

**Scope:** Analyze only a supplied CTF Bluetooth capture, EV3 image, or local emulator. This is an offline protocol-reconstruction workflow, not a procedure for interacting with real devices.

## Recognize the Pattern

A challenge provides a `.pklg` Bluetooth HCI log plus an EV3 screen/photo or sensor context. EV3 traffic is carried in Bluetooth RFCOMM, while the useful information may be a repeated direct-command field, a display coordinate, or sensor values—not printable text.

## Workflow

1. Open the supplied log in Wireshark and isolate the EV3 conversation by Bluetooth address, direction, and RFCOMM layer. Preserve the original capture.
2. Group packets by length, opcode prefix, and direction. Compare adjacent packets with an identical prefix; record only changing offsets and their byte order.
3. Correlate a small controlled sequence with the visual clue. For display output, test whether changing fields act as coordinates or character codes. For scanner data, decode candidate byte groups as integers and IEEE-754 floats, then compare against the observed black/white or color pattern.
4. Reconstruct the message in capture order. Keep framing and repeated commands separate from payload fields, and preserve unknown bytes rather than deleting them.
5. Validate against the supplied screen/image and a second packet group. A candidate must explain both the static clue and every changing field, not merely yield flag-like text once.

## Failure Modes

- Filtering only by packet length can mix request and response directions.
- Treating every changed byte as ASCII misses coordinates, endian integers, and float sensor values.
- Bluetooth reassembly can change visible packet boundaries; compare RFCOMM payloads, not raw HCI offsets alone.

**Source patterns:** HITCON CTF 2018, `EV3 Basic` ([writeup metadata](https://ctftime.org/writeup/11942)) and `EV3 Scanner` ([writeup metadata](https://ctftime.org/writeup/11943)).
