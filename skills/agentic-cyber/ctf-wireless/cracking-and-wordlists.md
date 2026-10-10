# Wireless - Cracking depth and wordlist strategy

Extends the cracking notes in `wpa2-psk-handshake-and-pmkid.md` with the wider offline-attack
toolkit: candidate generation, rule and mask strategy, WPA-specific tooling, and distribution.

## Mode 22000 attack modes and when each pays

**Trigger:** You hold a WPA hash (22000) and need to choose an attack mode rather than run rockyou and hope.

Hashcat's attack modes trade coverage against cost, and WPA's slow PBKDF2 (4096 iterations) makes that choice matter more than raw hardware. A straight **wordlist** (`-a 0`) catches genuinely weak keys and should always run first. **Rules** (`-a 0 -r`) multiply a curated list by transformations and are the highest-yield next step — a good list plus a strong rule set beats a bigger raw list. **Combinator** (`-a 1`) joins two wordlists, which fits passphrases built from two words. **Mask/brute** (`-a 3`) is only viable when the pattern is known, because the eight-character minimum already makes blind brute force hopeless against WPA. **Hybrid** (`-a 6`/`-a 7`) appends or prepends a mask to wordlist words — the mode that cracks `Password2024!` and the whole corporate `Word + digits + symbol` family. Order them by expected value for the target: wordlist, then rules, then targeted hybrid/mask once the client's pattern is visible, and remember `--increment` walks mask lengths so a single mask covers a range.

```bash
hashcat -m 22000 hash.22000 rockyou.txt                                   # -a 0 wordlist
hashcat -m 22000 hash.22000 curated.txt -r rules/best64.rule              # -a 0 + rules
hashcat -m 22000 -a 1 hash.22000 words-a.txt words-b.txt                  # combinator
hashcat -m 22000 -a 6 hash.22000 base.txt '?d?d?d?d'                      # word + 4 digits
hashcat -m 22000 -a 7 hash.22000 '?u?l?l?l' base.txt                      # cap-word prefix
hashcat -m 22000 -a 3 hash.22000 '?u?l?l?l?l?l?d?d?d?d' --increment       # masked, min len 8
```

Source: Operator practice; hashcat

## WPA-specific candidate generation with hcxpsktool

**Trigger:** You want candidates derived from the capture itself — the ESSID, BSSID, and observed device data — not a generic list.

`hcxpsktool` (part of hcxtools) generates WPA candidate passwords tailored to a specific capture, which is far more efficient than a generic wordlist because a large share of real PSKs are derived from exactly the values in the beacon: the ESSID, the BSSID/MAC, phone numbers, and common vendor default patterns. Feed it the pcapng and it emits candidates built from the network's own identifiers — router-default schemes (some ISPs derive the default key from the BSSID or serial), MAC-based keys, digit strings, and dates — which cracks the "left it on the sticker default" and "named after the network" cases that a wordlist misses. Pipe its output straight into hashcat so nothing large hits disk. Pair it with `hcxpcapngtool -E` (which dumps every string seen on the air — SSIDs, hostnames, identities) to build a capture-derived wordlist as well; those observed strings are frequently components of the passphrase.

```bash
# Candidates from the capture's own identifiers
hcxpsktool -c dump.pcapng --hex --digit --weakpass | sort -u > candidates.txt
hcxpsktool -c dump.pcapng --mac --essid --netgear --spectrum | sort -u >> candidates.txt

# Strings actually seen on the air (SSIDs, hostnames, identities) -> often key components
hcxpcapngtool -o hash.22000 -E aired-strings.txt dump.pcapng

# Stream candidates into hashcat without writing a giant file
hcxpsktool -c dump.pcapng --weakpass | hashcat -m 22000 hash.22000
```

Source: Operator practice; hcxtools (ZerBea)

## Keyboard walks and pattern generators

**Trigger:** The passphrase resists wordlists and looks like a keyboard pattern (`Qwerty123!`, `1qaz2wsx`, `Zaq12wsx`).

A large class of "complex-looking" passwords are keyboard walks — adjacent-key sequences that satisfy a complexity policy while being trivial to enumerate. `kwprocessor` generates them exhaustively from keyboard geometry (rows, columns, diagonals, with configurable length and character sets), producing the `1qaz2wsx`, `qwertyuiop`, `1q2w3e4r` family that no dictionary contains but users pick constantly. This matters for WPA specifically because an eight-plus-character keyboard walk meets the minimum-length rule and looks strong to an auditor. Generate a walk list once and keep it; feed it directly or as the base for hybrid attacks. Combine with the org-name candidates from the previous file — a corporate PSK is very often `[keyboard walk]` or `[org name][keyboard symbols]`, and the two generators together cover most of the "passed the policy, still weak" space.

```bash
git clone https://github.com/hashcat/kwprocessor && cd kwprocessor && make
./kwp basechars/full.base keymaps/en-us.keymap routes/2-to-16-max-3-direction-changes.route \
  > walks.txt
hashcat -m 22000 hash.22000 walks.txt
hashcat -m 22000 -a 6 hash.22000 walks.txt '?d?s'      # walk + trailing digit/symbol
```

Source: Operator practice; kwprocessor (hashcat)

## Wordlists worth keeping, and building a target list

**Trigger:** You are assembling a WPA cracking corpus, or building a list specific to one client.

The general-purpose lists earn their place by different strengths: **rockyou** is the fast first pass; **weakpass** and **hashesorg** aggregate real breached passwords at scale (the best raw-volume WPA lists); **crackstation** and **probable-wordlists** add breadth; and a **WPA-filtered** list (eight-plus characters only) avoids wasting the slow WPA kernel on candidates the length rule rejects. But for a corporate engagement the highest-yield list is the one you build for the target: the company and site names, product names, the SSID and its variants, the address, local sports teams, and the year, run through a rule set — because a corporate PSK is disproportionately a compound of those. `cewl` scrapes the org's own website into a themed wordlist, which is a strong base for that. Filter any list to WPA's length rule before spending GPU time on it.

```bash
# Curated general lists (SecLists ships several)
#   rockyou.txt · weakpass_3 · hashesorg · probable-v2-wpa-length.txt
# WPA length filter — drop < 8 chars up front
awk 'length>=8 && length<=63' rockyou.txt > rockyou-wpa.txt

# Scrape the client's own site into a themed base list
cewl -d 3 -m 5 --with-numbers https://www.corp.example -w corp-cewl.txt
# then org-derived hybrids (see wpa2-psk-handshake-and-pmkid.md and hcxpsktool above)
hashcat -m 22000 -a 6 hash.22000 corp-cewl.txt '?d?d?d?d!'
```

Source: Operator practice; SecLists, weakpass, cewl

## Distributed and cloud GPU cracking

**Trigger:** A hash resists CPU/single-GPU cracking and the engagement authorises off-site cracking, or an NTDS/large corpus needs real horsepower.

WPA's slow hash makes serious cracking a hardware problem, and two approaches scale it. **Cloud GPU** — a spot instance with modern GPUs runs hashcat orders of magnitude faster than a laptop and is rented for the hours a crack needs; upload the hash (never the raw capture with client data beyond what is needed) and the wordlists, run, and tear down. **Distributed cracking** — `hashtopolis` coordinates many agents against one job, splitting keyspace across a cracking rig or a set of cloud nodes, which is how a team shares hardware and how a large NTDS dump is cracked in reasonable time. Both require the authorisation that moving hashes off-site needs — a WPA hash or an NTDS dump leaving the client environment is a data transfer that belongs in the engagement's written scope. Manage results with the potfile so re-runs skip solved hashes, and use `--left`/`--show` to track what remains and what cracked.

```bash
# Cloud: provision a GPU instance, install hashcat, run, destroy
hashcat -m 22000 hash.22000 wordlist.txt -r rules/dive.rule -w 4 -O
hashcat -m 22000 hash.22000 --show                # solved (from the potfile)
hashcat -m 22000 hash.22000 wordlist.txt --left   # still unsolved

# Distributed: hashtopolis server + agents on the cracking nodes
git clone https://github.com/hashtopolis/server
git clone https://github.com/hashtopolis/agent-python
```

Source: Operator practice; hashtopolis
