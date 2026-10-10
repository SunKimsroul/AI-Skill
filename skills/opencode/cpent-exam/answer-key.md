# CPENT prior-attempt answer key (CPENTv2025 form, 52/53)

Complete memory of the 2026-08-24 attempt. **WARNING: exam forms rotate IPs,
hostnames, and sometimes credentials between attempts.** Treat every answer here
as a *pattern to verify against the live target*, never as a submit-blind value.
The reusable parts are: the techniques, the credential patterns (`Name@123`),
the hash constants (unchanged if the same user/password ships again), and the
question archetypes. Full reports: `~/Documents/CPENT/Notes/review_notes/`.

## Global insights (highest reuse value)

- **Password pattern: `Name@123`** — Stewart `H3l3nn@123`, Jade `Distasio@123`,
  client admin `Pott3r@123`, Joshua `c3ll0@123`. When a crack stalls, mutate
  range wordlist entries with `@123`, capitalization, and leetspeak first.
- `Pa$$w0rd` was BOTH the writable-DC DSRM local Administrator AND the domain
  Administrator password (reuse across tiers).
- Every range has a given-credential foothold host; the range wordlist (prior:
  `~/CPENT/AD2/Passwords.txt`, 201 entries) lived on the attacker-side exam
  files or foothold box — find it before touching rockyou.
- Answer masks (X/x/N) validated every answer; the NT-hash-fragment questions
  masked the HASH HEX, not the password.

## Zone 1 — AD (172.25.170.0/24, CPENTv2025.com) — 12 Q

| # | Answer | Technique to reproduce |
|---|--------|------------------------|
| 1 | `Pott3r` | PTH domain Admin → secretsdump client (.140); real admin = `Admin` RID 1002, pw `Pott3r@123`, NT `3dedf452f612c78c21685d2696614848` |
| 2 | `H3l3nn` | AS-REP roast Stewart (UAC DONT_REQ_PREAUTH) → john + range wordlist |
| 3 | `172.25.170.12` | LDAP computer query: RODC managedBy George (CN George = sAM `Larry`) |
| 4 | `c3ll0` | DCSync → NT `8973ec6636a1f0757e99bd4713234566` cracked to `c3ll0@123` |
| 5 | `Distasio` | RODC PRP `msDS-AuthenticatedToAccountList` shows Jade cached → spray `Mustain` → `Distasio@123` |
| 6 | `004c` | Jade NT `746e12d158e767e95d8502d99050004c` → last 4 |
| 7 | `RANGEADSERVER19` | null-session user list `krbtgt_32374` ↔ `msDS-KrbTgtLink` |
| 8 | `Stewart` | DCC2 (MsCacheV2) computed per DCSync'd account; suffix `262e11` = stewart |
| 9 | `Windows11.CPENTv2025.com` | `dNSHostName` of client computer object |
| 10 | `Joshua` | LDAP `managedBy` on AD-WIN (.50) |
| 11 | `3` | `msDS-RevealOnDemandGroup` entry count on .12 |
| 12 | `Pa$` *(unsubmitted)* | Key List attack with `krbtgt_32374` AES256 → DC Admin NT `fff5da224d7d3f6a0ccb79b988baa75c` = `Pa$$w0rd`. Next time: EXECUTE the named method, then submit |

Domain creds: `Stewart:H3l3nn@123` (foothold) · `Jason:qwerty` **local admin on
both RODCs + writable DC** · `Jade(Mustain):Distasio@123` · DSRM `Administrator:Pa$$w0rd`.
krbtgt_32374: NT `c139db903791f017a93b199a474322c0`, AES256
`f575aa686c7e48d9a36a8aedb991159e6b43e3f731cf264d448269fee7642a90`.
Chain: null enum → AS-REP → spray (lockout=0) → Jason → secretsdump RODC +
DCSync DC → DCC2/Key List.

## Zone 4 — IoT (172.25.120.0/24) — 13 Q

Hosts: `.110` `ubuntu/toor` (IOT.bin, IOT2–6.bin) · `.100` `cpent/cpentpw`
(FileOne/Two/Three.bin).

| # | Answer | # | Answer |
|---|--------|---|--------|
| 13 | `65536` (SquashFS block size) | 20 | `4.3.1` (GCC in kernel banner @464A28) |
| 14 | `Blackfin` (uImage CPU) | 21 | `JFFS2` (FS signature) |
| 15 | `Linux 2.6.26.5` (uImage name) | 22 | `7753728` (TRX image size, FileOne==IOT) |
| 16 | `ELF` (carved 813682, ARM) | 23 | `0xE0080` (SquashFS start, FileTwo) |
| 17 | `0xD8232C` (xz carve offset) | 24 | `passwd` (root cred in `usr/etc/passwd`) |
| 18 | `192.168.0.60` (DSP-W215 in config.sqlite) | 25 | `WNDR3800` (router-info.asp DeviceID) |
| 19 | `v1.21.1` (BusyBox strings) | | |

Embedded creds: WNDR3800 root `admin:$1$$iC.dUsGpxNNJGeOm1dFio/` (empty-salt MD5-crypt).
All answers fell out of `binwalk` / `binwalk -e` + `file`/`strings`/`sqlite3`.

## Zone 5 — Binary (172.25.65.0/24) — 9 Q

Foothold: `.103` `ubuntu/Cr@ckMeD0wn` (also: root cron → world-writable
`/home/thomas/youstc.sh` local privesc). Services on `.165`/`.105` TCP/1337
via socat; egress filtered by `.250`.

| # | Answer | Note |
|---|--------|------|
| 26 | `0x64413764` | EIP value, pattern_create 200 |
| 27 | `112` | pattern_offset; buf[100] at ebp-0x6c |
| 28 | `G4t3w4y` | flag `CTF{G4t3w4y_0v3rfl0w_PWN3D}` on .165 |
| 29 | `72` | x64 length oracle (71 normal, 72 breaks) |
| 30 | `win` | hidden ret2win fn on .105 |
| 31 | `0x0000000000401186` | brute-forced entry; win+1 also works, +3 does not |
| 32 | `37` | flag{B0_0v3rfl0w_W4s_T00_3asy_f0r_y0u!} minus braces |
| 33 | `Luhn Algorithm` | challenge3.exe UPX → radare2, digit-doubling validator |
| 34 | `0x0A` | `imul 0x66666667` = division by ten |

## Zone 2 — CTF (192.168.200.0/24) — 13 Q

| # | Answer | Technique |
|---|--------|-----------|
| 35 | `Networking` | SQLi UNION on `/ticketing` search → agents table (Alice Smith) |
| 36 | `uG0tm3b4ck` | users table `ctfplayer:dUcwdG0zYjRjaw==` → base64 -d |
| 37 | `b7oql50ih` | `/var/www/local.txt` after upload-bypass RCE (`allow_all=1` + include()) |
| 38 | `1396520` | `stat -c %s /var/www/suid_bash` |
| 39 | `kcn86hln90` | `/usr/bin/Admin.txt` via `suid_bash -p` |
| 40 | `b3Blbn` | root id_rsa body first 6 |
| 41 | `Joomla 4.1.0` | administrator/manifests/files/joomla.xml |
| 42 | `Whit3lin3` | james shadow crack: mask-regex candidates scraped on-box |
| 43 | `fa6775` | root.txt `18c355b2521328b7e942c841d4fa6775` last 6 (cap_setuid php) |
| 44 | `2.4.41` | nmap Apache banner (.232) |
| 45 | `slideshow-gallery` | wp-content readme.txt, v1.4.6 (CVE-2014-5460) |
| 46 | `brent3` *(alt `admhc1`)* | henry SSH/WP pw; later notes win |
| 47 | `M5qmm` | root.txt `M5qmmqOT7EDPoz7c0hYS` first 5, root via CVE-2021-3156 |

Creds: `ctfplayer:uG0tm3b4ck` · Joomla super-admin `admin:Wx21@iKl29001`
(CVE-2023-23752 leak) · `james:Whit3lin3` · `henry:brent3` ·
james user.txt `054c2f07868de253c61e39564d0bf224`. Joomla RCE: prepend webshell
to cassiopeia `error.php` before the `_JEXEC` guard.

## Zone 3 — Web (10.10.1.0/24) — 6 Q

| # | Answer | Note |
|---|--------|------|
| 48 | *(unanswered)* | Maria's Region, TKT-TKT-004_Emergency_Staging.md — admin dashboard gated |
| 49 | *(unanswered)* | kwame SSH passphrase last 5 — same gate |
| 50 | *(unanswered)* | incident_rep_master.zip MASTER OVERRIDE KEY first 5 — same gate |
| 51 | `tony@synixon.com` | Socket.IO bot leaks supervisor to any client |
| 52 | `legacy_dev_keys.log` | supervisor bug-reports page |
| 53 | `A1EL2L8P` | flag{A1EL2L8P} via LFI `/syni_dev/debug-view.php?file=../../../../../../home/flag.txt` |

Takeover chain: register technician → bot `reset-password:supervisor123` with
`user: tony@synixon.com` → supervisor login → bug reports → LFI.
syncvibe (.9, Next.js 16.2.7): registered `neopent1:Passw0rd!23`; the 48–50 gate
is a signed HS256 JWT (`is_admin`) — secrets likely on the OTHER host; untried
lead for next attempt.
