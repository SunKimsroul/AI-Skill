# CTF Forensics - Industrial-protocol captures

Use this note only to analyze a supplied PCAP/PCAPNG or an explicitly authorized offline lab capture. Do not replay packets, write registers, scan industrial networks, or connect to a live controller. For CTFs, the capture is the evidence and the goal is reconstruction.

## Recognize the capture

Industrial CTF packets may mention Modbus, PLC, HMI, SCADA, a plant/pool/thermal system, port 502, or a fieldbus-looking TCP conversation. Start with Wireshark protocol statistics and endpoint conversations, then let the available dissector identify the protocol rather than assuming every TCP payload is raw text.

## Modbus/TCP reconstruction workflow

1. Work from a copy of the capture. Record the relevant device IPs, TCP streams, unit IDs, and time window.
2. Filter the supplied capture with the Modbus dissector (for example, `modbus`) and separate client requests from server responses by direction.
3. For each request, identify the MBAP framing fields: transaction ID, protocol ID, length, unit ID, then the Modbus PDU/function code. Treat function semantics and byte layout as evidence, not as a string format.
4. Group suspected writes by `(source device, destination, unit ID, function, register/coils)` and preserve both packet time and transaction ID. A challenge may encode data in register address, value, ordering, or the change between writes.
5. Remove acknowledgements/duplicate writes only after confirming they do not carry state. Compare repeated positions: some traces use a marker or control value followed by the meaningful value.
6. Reconstruct a candidate byte sequence, then validate it against expected text/flag structure and the original packet ordering. Keep the extraction script and filter with the solve.

## Common traps

- A TCP stream can mix request and response directions; do not concatenate them blindly.
- Transaction IDs associate a response with a request but are not always the intended data order.
- A register number, a value, and a function-code payload have different offsets. Decode the protocol first instead of slicing every TCP payload at a fixed arbitrary position.
- Device address and unit ID can distinguish several simulated controllers in the same capture.

## Siemens S7comm passive reconstruction

1. Keep the capture offline. Use protocol hierarchy/conversations to isolate the candidate TCP stream, then use the installed S7comm dissector when it recognizes the traffic. Preserve raw packet bytes alongside every displayed field.
2. Separate transport framing from S7 semantics. Record the TCP stream, packet direction, request/response role, and S7 job/acknowledgement relationship before interpreting payload data.
3. If the task concerns PLC time or another typed value, identify the exact S7 data type and field boundaries from the packet/dissector. Decode packed decimal/date-time components independently from the raw bytes; do not treat a byte slice as ASCII.
4. Compare repeated packets or a supplied reference capture by field boundary, not whole-stream text. A one-field difference can be the intended timestamp, register value, or state change.
5. Validate the reconstructed value with the challenge's stated format or a local deterministic check such as a hash. Preserve the filter, packet numbers, raw field, decoded candidate, and validation result.

## Pivot rules

- Load `/ctf-reverse` if the PCAP accompanies PLC firmware, a custom protocol implementation, or a simulator binary.
- Load `/ctf-crypto` if the reconstructed payload is encrypted/encoded and the network reconstruction is complete.
- Keep real-infrastructure work within the engagement scope; this note intentionally contains no live-control workflow.

## Source-backed pattern

JerseyCTF IV's *vibrations* used an offline Modbus capture in which register position/value and repeated control writes needed to be separated before reconstructing the message. It demonstrates protocol-statistics-first triage and reproducible PCAP extraction: [CTFtime writeup](https://ctftime.org/writeup/38964).

Mapna CTF 2024's *PLC II ?* adds an S7comm pattern: isolate the supplied capture, compare field boundaries with a reference protocol representation, decode the typed PLC time value, and verify the resulting challenge-format value locally: [CTFtime writeup](https://ctftime.org/writeup/38540).
