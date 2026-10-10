# IPv6 CTF and Capture Triage

Use this workflow for supplied PCAPs, logs, container/lab configurations, or organizer-provided local environments. Do not scan or connect to unrelated IPv6 hosts.

## Preserve address meaning

1. Record each address with its scope: `fe80::/10` link-local, `fc00::/7` unique-local, `ff00::/8` multicast, or globally routable. Do not treat a link-local address as globally reachable.
2. Preserve the interface or zone for link-local evidence. In a supplied local lab, a link-local endpoint needs an interface zone to identify the link; record it as part of the endpoint fact rather than dropping it during normalization.
3. Keep IPv6 literals bracketed when they appear with a port in a URI or connection record so the address/port split remains unambiguous.

## Reconstruct supplied traffic passively

1. Filter the capture with `ipv6`, then group by source/destination, next-header chain, flow label, and transport tuple. Confirm a decoder's interpretation against raw packet bytes for unusual traffic.
2. Walk extension headers in their declared order. Record Hop-by-Hop, Routing, Fragment, Destination Options, and Authentication/ESP boundaries before interpreting the final transport protocol.
3. Reassemble only supplied fragments. Preserve fragment identification, offset, and more-fragments state; do not infer application payload from a single noninitial fragment.
4. Treat ICMPv6 Neighbor Solicitation/Advertisement and Router Advertisement packets as topology evidence. Reconcile MAC, interface, link-local address, prefix, and timestamp before placing a host in the local-lab graph.

## Validate a local model

1. Compare at least two passive decoders such as Wireshark/tshark fields and a raw-byte or Scapy interpretation. Resolve discrepancies in extension-header or fragment handling before extracting data.
2. If a supplied challenge is IPv6-only, reproduce only within its supplied local lab/container. Confirm scope, interface zone, and service binding from local configuration or capture evidence first.
3. Save the original capture hash, packet numbers, address scope/zone, decoded header chain, and recovered payload artifacts with the solve evidence.

## Source

- RCTS CERT 2021 `The lost Jetson`: IPv6-only and link-local interface-zone context in a CTF environment: <https://ctftime.org/writeup/29894>
