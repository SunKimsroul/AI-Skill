# Public CTF technique intake

Use this as a source ledger for additions to the local skill library. Extract only concise, original technique summaries and verification workflows; do not copy full public writeups or assume a technique transfers unchanged to a different challenge.

## Intake rules

1. Prefer organizer material, challenge source, author writeups, or well-maintained technical references.
2. Record the challenge, category, source URL, observed primitive, and the existing skill that should own the technique.
3. Search the current library before adding content. Extend a focused note when possible; add a new note only for a distinct workflow.
4. Preserve the boundary: CTF/local-lab actions stay in CTF skills; real-infrastructure testing requires the active engagement workflow.
5. Rebuild the Claude ZIPs with `scripts/package_claude_skills.py` after any local skill change. This step, and the coverage review below, are maintainer tasks that need the repository checkout — those scripts are deliberately not shipped inside the uploaded skill package.

## Local source index

Two collectors feed a local, metadata-only index. Neither downloads writeup bodies.

- `scripts/collect_public_writeup_catalog.py --resume --pages <count>` covers the CTFtime writeup index (use `--start-page <first>` only to choose a range deliberately). CTFtime is finite: it ends at roughly page 1306, and the local catalog already holds every entry.
- `scripts/collect_writeup_index.py --with-ctftime` builds the unified index at `sources/writeup-index.jsonl`. It aggregates ~100 public sources — CTF events and team blogs, HackTheBox/VulnHub/TryHackMe machine writeups, IppSec videos, Active Directory and web-security research, bug-bounty writeups, malware/DFIR/crypto/OSINT blogs, and curated collections. Use `--list-sources` to see the configured sites, `--only <name>` for one source, and `--refresh` to drop and re-harvest a source whose filter you changed.
  - Source `kind`s: `sitemap` (XML sitemap or sitemap-index; relative `<loc>` paths are resolved), `markdown` (a README of links; set `base` for repo-relative targets), `html` (a page whose links may be relative; set `pages` with a `{page}` template for paginated indexes), `regex` (named-group extraction from arbitrary text such as a JS bundle), `feed` (RSS or Atom — usually recent items only), and `json` (per-source schema handler). Sites that 403 a non-browser agent are retried once with a browser User-Agent.
  - The index is metadata-only (URL + title + source + platform). It never stores writeup bodies. A few high-value sources deliberately excluded: aggregators that redistribute full third-party article text, and sites that hard-block automated access.

Query the index with `scripts/search_writeup_index.py`:

```powershell
python scripts\search_writeup_index.py --stats
python scripts\search_writeup_index.py heap tcache
python scripts\search_writeup_index.py --source 0xdf --limit 20
python scripts\search_writeup_index.py --regex "oscp|proving ground"
```

Then, from the repository checkout, run `scripts/review_public_writeup_coverage.py` to produce a repeated-tag review queue. Review index entries against current coverage before extracting an original, short technique summary.

The index is a finding aid, not a library. It records where a technique was published; it does not reproduce the author's text. Read the source, then write your own note and credit it.

To add a site, append an entry to `SOURCES` in `collect_writeup_index.py`: `sitemap` for a site with an XML sitemap, `markdown` for a curated README of links, `html` for a page whose links are relative to a repository base. Give each one an `include` regular expression narrow enough to keep tag pages, author pages, and navigation out of the index.

## Current additions

| Technique family | Evidence source | Owning skill | Added note |
|---|---|---|---|
| Trusted V8 serialized code cache vs conventional memory corruption | [Google CTF 2022 d8](https://gist.github.com/Riatre/83d5fdb970946c8e185c5e1b2b842b1b) | `ctf-pwn` | `browser-and-managed-runtimes.md` |
| WebAuthn ceremony binding and passkey validation | [MDN passkeys guide](https://developer.mozilla.org/en-US/docs/Web/Security/Authentication/Passkeys) | `ctf-web` | `modern-identity-and-cloud.md` |
| Cloud CI/IaC trust graph | [Hacking the Cloud CI/CDon't CTF](https://hackingthe.cloud/aws/capture_the_flag/cicdont/) | `ctf-web`, `ctf-forensics` | `modern-identity-and-cloud.md`, `cloud-and-endpoint-telemetry.md` |
| Terraform state race/poisoning challenge reasoning | [Wiz State of Affairs write-up](https://kabinet.gitbook.io/ctf-writeup/2026/wiz-cloud-security-challenge/state-of-affairs) | `ctf-forensics` | `cloud-and-endpoint-telemetry.md` |
| Solana/Anchor account relation and state analysis | [DiceCTF 2023 Solana challenges](https://lkmidas.github.io/posts/20230304-dicectf2023-writeups/) | `ctf-crypto` | `solana-and-chain-state.md` |
| Move/Sui object and capability state analysis | [Move CTF write-up](https://dantheman8300.gitbook.io/move-ctf-writeup) | `ctf-crypto` | `move-and-object-state.md` |
| Zigbee capture and protocol reconstruction | [WHY2025 Enlightenment](https://writeups.fmc.tf/forensic/writeups/2025/WHY2025-CTF/enlightenment/) | `ctf-misc` | `radio-iot-and-vehicle.md` |
| HDL simulation, reset, width, and state-machine reasoning | [Google CTF 2020 “basics”](https://ctftime.org/writeup/23026) | `ctf-reverse` | `hardware-logic-and-fpga.md` |
| Agent/MCP prompt and tool-boundary challenges | [MCP CTF Challenge Server](https://github.com/aganita/mcp-ctf-challenge) | `ctf-ai-ml` | `agentic-tools-and-mcp.md` |
| Tool-authority and agentic workflow reasoning | [Snyk CTF 2026 AI write-ups](https://adragos.ro/snyk-ctf-2026/) | `ctf-ai-ml` | `agentic-tools-and-mcp.md` |
| TrustZone / OP-TEE secure-world boundary triage | [SAS CTF 2025 Broken Trust](https://ctftime.org/writeup/40255) | `ctf-pwn` | `tee-and-trustzone.md` |
| Managed backend / direct client API authorization triage | [ImaginaryCTF 2025 imaginary-notes](https://ctftime.org/writeup/40428) | `ctf-web` | `managed-backends.md` |
| Rust/Bevy ECS game and save-state reversing | [corCTF 2024 corMine](https://ctftime.org/writeup/39394) | `ctf-reverse` | `rust-ecs-games.md` |
| Offline industrial/Modbus packet reconstruction | [JerseyCTF IV vibrations](https://ctftime.org/writeup/38964) | `ctf-forensics` | `industrial-protocol-captures.md` |
| Makefile/build-system jail boundary analysis | [WolvCTF 2024 Made Harder](https://ctftime.org/writeup/38837) | `ctf-misc` | `build-system-jails.md` |
| Table-driven Turing-machine / VM reconstruction | [UMassCTF 2024 Primitive Reversing 2](https://ctftime.org/writeup/39081) | `ctf-reverse` | `turing-machine-vms.md` |
| 6502 program image and retro-runtime analysis | [1337UP LIVE CTF 2023 Impossible Mission](https://ctftime.org/writeup/38228) | `ctf-reverse` | `retro-6502-vms.md` |
| Offline SIP/RTP/VoIP call reconstruction | [Cyber Heroines CTF Marian Croak](https://ctftime.org/writeup/37891) | `ctf-forensics` | `voip-pcap.md` |
| Sanitizer/browser HTML mutation differential (mXSS) | [Hack.lu CTF 2023 Awesomenotes II](https://ctftime.org/writeup/38012) | `ctf-web` | `html-parser-differentials.md` |
| CUDA host/device and GPU-kernel reconstruction | [VolgaCTF 2024 cuCRACKME](https://ctftime.org/writeup/39400) | `ctf-reverse` | `cuda-gpu-kernels.md` |
| REXX interpreter and EBCDIC-sensitive legacy-script analysis | [BraekerCTF 2024 The mainframe speaks](https://ctftime.org/writeup/38692) | `ctf-reverse` | `rexx-and-legacy-scripts.md` |
| RISC-V userspace memory-map and ABI-aware pwn triage | [CyberSecurityRumble Quals riscy-stack: Userspace](https://ctftime.org/writeup/37449) | `ctf-pwn` | `riscv-userspace.md` |
| Game Boy ROM banking and tile-memory reconstruction | [1337UP LIVE CTF 2023 Virtual RAM](https://ctftime.org/writeup/38229) | `ctf-reverse` | `game-boy-roms.md` |
| Janet runtime/image separation and deterministic state reconstruction | [UIUCTF 2023 geoguesser](https://ctftime.org/writeup/37385) | `ctf-reverse` | `janet-images.md` |
| CTF-chain transaction-ordering and oracle-fulfillment state analysis | [GPN CTF 2023 gambling](https://ctftime.org/writeup/37193) | `ctf-crypto` | `transaction-ordering.md` |
| Version-aware Log4j configuration/pattern expansion and oracle reasoning | [Google CTF 2022 Log4J](https://ctftime.org/writeup/34511) | `ctf-web` | `log4j-configuration.md` |
| PyScript/Pyodide browser-runtime and DOM-bridge boundary analysis | [GPN CTF 2023 cross-site-python](https://ctftime.org/writeup/37172) | `ctf-web` | `pyscript-browser-surface.md` |
| Repeated-round custom-cipher slide-pair analysis | [PlaidCTF 2022 choreography](https://ctftime.org/writeup/33163) | `ctf-crypto` | `slide-attacks.md` |
| CSIDH class-group action and implementation-failure analysis | [hxp CTF 2021 infinity](https://ctftime.org/writeup/31902) | `ctf-crypto` | `csidh-isogenies.md` |
| Recursive fixed-point CRC with a restricted hexadecimal alphabet | [Dragon CTF 2021 CRC Recursive Challenge](https://gist.github.com/mkow/b43883ef4c3e25d6001e8c5f4f63430d) | `ctf-crypto` | `advanced-math.md` |
| Supplied Qiskit/QASM circuit and state-vector reconstruction | [GDG Algiers CTF 2022 Kvant](https://ctftime.org/writeup/35880) | `ctf-crypto` | `quantum-circuit-reconstruction.md` |
| SpiderMonkey/Firefox local-build and JIT-primitive triage | [GPN CTF 2023 icefox](https://ctftime.org/writeup/37396) | `ctf-pwn` | `browser-and-managed-runtimes.md` |
| React Native APK/IPA bundle and bridge analysis | [NahamCon CTF 2022 OTP Vault](https://ctftime.org/writeup/33429) | `ctf-reverse` | `react-native-mobile.md` |
| Root-of-unity polynomial projection and CRT reconstruction | [LIT CTF 2022 crypto/SUSSS](https://ctftime.org/writeup/34678) | `ctf-crypto` | `advanced-math.md` |
| VBScript/Windows Script Host staged static deobfuscation | [HeroCTF v5 Give My Money Back](https://ctftime.org/writeup/37012) | `ctf-malware` | `scripts-and-obfuscation.md` |
| Multi-stage blue-team evidence-chain reconstruction | [Cyberconférence CTF 2023 Blue's Clues series](https://ctftime.org/event/1968/tasks/) | `ctf-forensics` | `incident-response-evidence-chain.md` |
| Hill matrix cipher with custom alphabet and composite modulus | [LIT CTF 2022 Running Up That Hill](https://ctftime.org/writeup/34645) | `ctf-crypto` | `classic-ciphers.md` |
| Repository-triggered CI and mutable build-artifact trust analysis | [NahamCon CTF 2023 Supplier](https://gist.github.com/mlashley/224a91cff0b1712e161121817b1e24b3) | `ctf-web` | `modern-identity-and-cloud.md` |
| AFSK/APRS/Winlink supplied-recording message reconstruction | [pbctf 2021 Is that your packet?](https://ctftime.org/writeup/30872) | `ctf-misc` | `radio-iot-and-vehicle.md` |
| Local encrypted-PDF and nested-archive password recovery | [n00bzCTF 2023 Crack & Crack](https://ctftime.org/writeup/37218) | `ctf-forensics` | `disk-recovery.md` |
| Enigma ciphertext-only rotor, ring, and plugboard recovery | [404 CTF 2022 Enigma](https://ctftime.org/writeup/34447) | `ctf-crypto` | `enigma.md` |
| Supplied public-GCS bucket object inventory and generation-aware evidence triage | [UofTCTF 2024 Out of the Bucket](https://ctftime.org/writeup/38449) | `ctf-forensics` | `disk-and-memory.md` |
| Neo4j/Cypher graph-query context reconstruction and in-band read-only validation | [BSidesTLV 2022 Pokedex](https://ctftime.org/writeup/34480) | `ctf-web` | `graph-query-injection.md` |
| Local sudoedit argument-escape parser/allocator reproduction for CVE-2021-3156 | [HTB Business CTF 2021 Rocket](https://ctftime.org/task/16960) | `ctf-misc` | `linux-privesc.md` |
| Restricted-PHP punctuation alphabet closure and no-warning identifier construction | [idekCTF 2022 PHPFu...n](https://ctftime.org/writeup/36079) | `ctf-web` | `php-expression-constraints.md` |
| Apache Flink JobManager management-surface and local file-read provenance triage | [HTB Business CTF 2021 Level](https://ctftime.org/writeup/29625) | `ctf-web` | `flink-jobmanager-triage.md` |
| MuJS typed-array size/OOB and detached-buffer lifetime analysis under jemalloc | [Zh3r0 CTF V2 Javascript-for-Dummies](https://ctftime.org/event/1285/tasks/) | `ctf-pwn` | `browser-and-managed-runtimes.md` |
| GnuCOBOL/libcob `CBL_*` native ownership and file-API lifetime audit | [PlaidCTF 2021 The Cobol Job](https://ctftime.org/writeup/27590) | `ctf-pwn` | `legacy-runtime-apis.md` |
| Printable-ASCII ROT47 recognition and reversible decode validation | [UrchinSec Tanzania National CTF MMXXIV 47](https://ctftime.org/writeup/39134) | `ctf-crypto` | `classic-ciphers.md` |
| JSON cross-parser semantic-differential triage | [InCTF 2021 Json Analyser](https://ctftime.org/writeup/29827) | `ctf-web` | `json-parser-differentials.md` |
| FCSR/F-FCSR carry-state recognition and local transition reconstruction | [m0leCon CTF 2021 Obscurity-fixed](https://ctftime.org/writeup/28423) | `ctf-crypto` | `stream-ciphers.md` |
| Rail Fence zigzag reconstruction and punctuation-aware round-trip validation | [DEADFACE CTF 2023 Off the Rails](https://ctftime.org/writeup/38041) | `ctf-crypto` | `classic-ciphers.md` |
| Bifid coordinate fractionation with explicit square and period validation | [Cryptoverse CTF 2023 Crypto/Warmup 2](https://ctftime.org/writeup/36979) | `ctf-crypto` | `classic-ciphers.md` |
| Boneh-Durfee small-private-exponent RSA lattice triage and local candidate validation | [HacktivityCon CTF Bon Appetit](https://ctftime.org/writeup/22738) | `ctf-crypto` | `rsa-attacks.md` |
| JSteg JPEG AC-DCT coefficient parity extraction and local candidate validation | [Zh3r0 CTF LSB fun](https://ctftime.org/writeup/21809) | `ctf-forensics` | `jsteg.md` |
| Passive port-knocking sequence reconstruction from a supplied PCAP | [Zh3r0 CTF Knock knock](https://ctftime.org/writeup/21664) | `ctf-forensics` | `network.md` |
| Bacon biliteral carrier extraction and five-bit-group validation | [Houseplant CTF 2020 Sizzle](https://ctftime.org/writeup/20354) | `ctf-crypto` | `classic-ciphers.md` |
| Playfair keyed-square digraph reconstruction and filler-aware round-trip validation | [TG:HACK 2020 The Message](https://ctftime.org/writeup/19967) | `ctf-crypto` | `classic-ciphers.md` |
| AVR/Intel HEX firmware parser and byte-difference-oracle reconstruction | [Midnight Sun CTF 2020 Quals avr-rev](https://ctftime.org/writeup/19396) | `ctf-reverse` | `avr-firmware.md` |
| PyInstaller wrapper recovery with format-matched LZSS decompression and artifact reclassification | [Aero CTF 2020 Elderly File](https://ctftime.org/writeup/18761) | `ctf-reverse` | `pyinstaller-lzss.md` |
| Fixed-key finite-field matrix-conjugation oracle reconstruction via an elementary-matrix basis | [zer0pts CTF 2020 nibelung](https://hackmd.io/30-fhA4DSvqZ8MuMfEwO_A) | `ctf-crypto` | `matrix-conjugation.md` |
| Linux memory-dump rootkit detection through module cross-view reconciliation and runtime-buffer recovery | [Insomni'hack Teaser 2020 getdents](https://ctftime.org/writeup/17984) | `ctf-forensics` | `linux-rootkit-memory.md` |
| xoroshiro128+ state reconstruction after protocol/output-wrapper inversion | [InCTF 2019 PRetty stroNG](https://v3ct0r719.github.io/posts/inctf/) | `ctf-crypto` | `xoroshiro128plus.md` |
| Lamport controlled-message signature comparison after local verifier-flaw reconstruction | [Hack.lu CTF 2019 Lamport Verify](https://sectt.github.io/writeups/Hacklu19/crypto_lamport/README) | `ctf-crypto` | `lamport-signatures.md` |
| Reused Lamport OTS leaf reconstruction despite a Merkle authentication path | [Facebook CTF 2019 postquantumsig](https://ctftime.org/writeup/15491) | `ctf-crypto` | `lamport-signatures.md` |
| 8051 firmware and I²C peripheral-model state-machine reconstruction | [Google CTF 2019 flagrom](https://blog.atx.name/google-ctf-2019/) | `ctf-reverse` | `8051-i2c-firmware.md` |

| Application-defined allocator and heap-canary layout/lifecycle reconstruction | [Byte Bandits CTF 2019 hardmalloc](https://ctftime.org/writeup/14933) | `ctf-pwn` | `custom-allocator-audit.md` |
| Blind ROP crash-oracle calibration, stop-gadget validation, and supplied-service binary recovery | [UTCTF 2019 ECHO](https://thekidofarcrania.gitlab.io/2019/03/11/utctf/) | `ctf-pwn` | `blind-rop.md` |
| ADFGVX six-by-six coordinate decoding after stable columnar-transposition reversal | [SunshineCTF 2019 CB3](https://ctftime.org/writeup/14243) | `ctf-crypto` | `classic-ciphers.md` |
| Bash CGI environment-import mapping and harmless local Shellshock proof | [Inferno CTF 2019 We will we will Shock You](https://ctftime.org/writeup/17790) | `ctf-web` | `shellshock-cgi-triage.md` |
| LEGO EV3 RFCOMM capture field differencing and display/sensor reconstruction | [HITCON CTF 2018 EV3 Basic](https://ctftime.org/writeup/11942) | `ctf-misc` | `ev3-rfcomm.md` |
| IBM s390x/zArchitecture ELF static-and-emulator triage | [Olympic CTF 2014 zpwn](https://ctftime.org/writeup/943) | `ctf-reverse` | `s390x-emulation.md` |
| SPARC ELF local-emulation and ABI-aware static triage | [Hack.lu CTF 2020 Secret Pwnhub Academy Rewards Club](https://ctftime.org/writeup/24338) | `ctf-reverse` | `sparc-emulation.md` |
| Supplied Tomcat/WAR, connector, manager, and proxy-boundary reconstruction | [Insomni'hack 2024 Jumper](https://ctftime.org/writeup/39110) and [VolgaCTF 2020 Netcorp](https://ctftime.org/writeup/19248) | `ctf-web` | `tomcat-local-triage.md` |
| Protocol Buffers unknown-schema, descriptor, and wire-format recovery | [Google CTF 2020 namespacefs](https://ctftime.org/writeup/23897) and [Nuit du Hack 2017 LetsEnchiffre](https://ctftime.org/writeup/6159) | `ctf-reverse` | `protobuf-schema-recovery.md` |
| General modular square-root candidate recovery with Tonelli-Shanks and CRT | [0x41414141 CTF 2020 eazy RSA](https://ctftime.org/writeup/25862) and [SuSeC CTF 2020 Inaction](https://ctftime.org/writeup/18875) | `ctf-crypto` | `modular-square-roots.md` |
| Clojure/Graal reader-evaluation and EDN-vs-code parser triage | [Hackover CTF 2018 Holy graal](https://ctftime.org/writeup/11536) | `ctf-misc` | `clojure-reader-triage.md` |
| IPv6 address scope, extension-header, and passive neighbor-evidence triage | [RCTS CERT 2021 The lost Jetson](https://ctftime.org/writeup/29894) | `ctf-forensics` | `ipv6-passive-triage.md` |
| Huffman/prefix-code table, bit-order, and carry-state reconstruction | [Newark Academy CTF 2020 Encoder](https://ctftime.org/writeup/24805) and [Google CTF 2021 DAVID AND THE TREE](https://ctftime.org/writeup/29459) | `ctf-reverse` | `huffman-code-recovery.md` |
| Okamoto-Uchiyama `p^2*q` structure recovery and L-function decryption | [PoseidonCTF 2020 discrete log](https://ctftime.org/writeup/22916) | `ctf-crypto` | `okamoto-uchiyama.md` |
| Symfony configuration/debug/profiler and environment-provenance reconstruction | [Securinets CTF 2019 Custom Location](https://ctftime.org/writeup/14077) | `ctf-web` | `symfony-local-triage.md` |
| PHP-FPM/FastCGI listener, pool-configuration, and path-resolution boundary reconstruction | [hxp CTF 2020 resonator](https://ctftime.org/writeup/25660) and [hxp CTF 2020 heiko](https://ctftime.org/writeup/25659) | `ctf-web` | `php-fpm-fastcgi-local-triage.md` |
| LoongArch ELF/emulator, ABI, and userspace primitive reconstruction | [UTCTF 2023 Bing Chilling](https://ctftime.org/writeup/36285) | `ctf-pwn` | `loongarch-userspace.md` |
| Siemens S7comm passive framing and typed PLC-value reconstruction from an offline capture | [Mapna CTF 2024 PLC II ?](https://ctftime.org/writeup/38540) | `ctf-forensics` | `industrial-protocol-captures.md` |
| TPM2 attestation trust-map, PCR-policy provenance, and local-emulator state lifecycle reconstruction | [R3CTF 2026 trustedhash](https://ctftime.org/writeup/40961) | `ctf-misc` | `tpm2-attestation-triage.md` |
| White-box cipher table/netlist, representation-layer, and local key/transformation validation | [RHme3 White Box Unboxing](https://ctftime.org/writeup/7281) and [Alfa CTF 2026 Покoй](https://ctftime.org/writeup/40705) | `ctf-crypto` | `white-box-crypto.md` |
| WebGPU/WGSL shader pipeline, local parameter enumeration, texture readback, and UV/model reconstruction | [SAS CTF 2025 Quals Washing Machine](https://ctftime.org/writeup/40286) | `ctf-reverse` | `webgpu-wgsl-triage.md` |
| LuaJIT wrapper, embedded WebAssembly module, and minimal WASI host-bridge reconstruction | [SekaiCTF 2025 Gondola](https://ctftime.org/writeup/40380) | `ctf-reverse` | `luajit-wasi-wasm.md` |
| Mimalloc build, per-size page/list state, mapping, and local primitive reconstruction | [UIUCTF 2025 do re mi](https://ctftime.org/writeup/40356) | `ctf-pwn` | `mimalloc-heap-triage.md` |
| TempleOS/TinkerOS QEMU guest, HolyC source, bracketed dispatch, and local memory-model reconstruction | [m0leCon CTF 2025 HolyM0le](https://ctftime.org/writeup/40348) | `ctf-pwn` | `templeos-holyc-triage.md` |
| Winternitz/WOTS hash-chain signature, checksum, digit-order, and local monotonicity audit | [DiceCTF 2024 Quals winter](https://ctftime.org/writeup/38952) | `ctf-crypto` | `winternitz-signatures.md` |

## Coverage review prompts

- Does a new writeup identify a different trust boundary, parser, protocol state machine, algebraic assumption, or memory-lifetime rule?
- Is the technique absent from the owning skill, or only described with an obsolete version/toolchain?
- Can it be written as a reproducible triage and validation procedure without reproducing the author’s full writeup?
- Does it belong to a cross-category route that should also be added to `solve-challenge`?
