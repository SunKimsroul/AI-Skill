# Skill Learning Journal

Master log of every lesson captured into the ctf-* skill library by the
`loophole` loop. One line per capture. Newest at the bottom.

Format: `- <date> <event> <challenge> (<category>) → <skill>: <lesson>`

---

<!-- seed: the field-notes.md files in ctf-pwn, ctf-reverse, ctf-web already
     contain decades of accumulated entries from past solves; this journal
     starts fresh from 2026-09-09 -->
- 2026-09-09 HTB Protected (mobile/forensics) → ctf-forensics: bkcrack known-plaintext on GalleryVault zip vault; jadx to find plaintext assets
- 2026-09-12 Encrypted NimPlant C2 in pcap: XOR-mask key brute-force -> AES-CTR session; uploaded dropper's RC4 shellcode holds flag part 2; banner in exfil screenshot lacks } on purpose.
2026-09-13 HTB Sherlock Brutus (forensics/SSH brute force): attacker IP = dominant Failed-password source in auth.log; wtmp (utmp 384B records) cross-validates sessions BUT stores local time (UTC+7 here) vs auth.log UTC — always diff TZ before calling timestamps inconsistent.
- 2026-09-15 Listeners started with sudo outlive the solve and freeze agent sessions: always timeout them, prefer ports >1024, and kill by port the moment the flag lands.
- 2026-09-15 Unauth MDT Monitor SOAP/OData endpoints parse attacker XML: XXE reads CustomSettings.ini/Bootstrap.ini and leaks deployment domain creds.
- 2026-09-15 GenericWrite/WriteProperty on group lets you flip groupType to distribution (-2147483646), edit membership, flip back to security (-2147483644) — sidesteps 'no add to security group' DACLs.
- 2026-09-25 glibc 2.39 tcache_get enforces 16-align (abort: malloc(): unaligned tcache chunk detected) but does NOT size-check; free(fake) needs size exactly 0x70/0x71 and key slot != tcache_key
- 2026-09-25 CSCV Message System: invalid-priority seeds PIE leak pre-validation; size|priority globals qword = plantable tcache fake chunk; .bss write-chain to hijack fn-pointer table dodges canary entirely; binary-embedded prompt injection treated as data.
