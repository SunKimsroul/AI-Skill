# CTF Forensics - VoIP/SIP/RTP captures

Use this only for a supplied CTF PCAP/PCAPNG, disk image, or explicitly authorized offline lab capture. Do not capture, replay, register against, or listen to real VoIP traffic.

## Recognition

Look for SIP signaling, RTP media, telephony-related hints, phone numbers/extensions, UDP stream pairs, or a disk image that contains/deleted a capture. A normal file listing may not show the relevant PCAP; verify unallocated/deleted artifacts before assuming the image is empty.

## Offline workflow

1. Preserve the image/capture hash and recover the candidate PCAP from the supplied artifact using normal forensic tooling.
2. In Wireshark, identify signaling separately from media. SIP/SDP typically describes calls/codecs/endpoints; RTP carries the audio payload.
3. Use the Telephony/VoIP call view to group related streams rather than following a single arbitrary UDP stream. Note call duration, participant direction, codec, packet loss, and timestamps.
4. Reconstruct or export the audio from the supplied capture. Compare both directions and prioritize unusually long, repeated, or late calls, then listen/spectrogram only after preserving the stream mapping.
5. If speech is ambiguous, validate candidate words against the expected flag format and retain the selected call/stream identifiers as evidence.

## Common traps

- Treating SIP signaling text as the audio itself.
- Exporting packets in capture order without RTP sequence/timestamp reconstruction.
- Missing a second media direction or a later call with the relevant payload.
- Stopping at the mounted filesystem when the PCAP is deleted or carved.
- Assuming a codec problem means encryption; first confirm the RTP payload type and stream reconstruction.

## Pivot rules

- Load `/ctf-forensics` disk/recovery notes when the PCAP must be carved from an image.
- Load `/ctf-crypto` only after the media/capture reconstruction is complete and a genuine encrypted/encoded layer remains.
- Load signal/stego notes if the exported audio contains tones, modem data, or a spectrogram clue instead of spoken text.

## Source-backed pattern

Cyber Heroines CTF's *Marian Croak* hid a relevant PCAP inside a supplied ext4 image and used SIP/RTP call reconstruction to recover spoken flag evidence. It illustrates the disk-image-to-VoIP-call workflow: [CTFtime writeup](https://ctftime.org/writeup/37891).
