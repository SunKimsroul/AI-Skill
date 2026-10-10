# Wireless - Reconnaissance and survey

## The airodump survey read as a routing table

**Trigger:** You are in range of the in-scope networks and need to decide which of a dozen 802.11 attacks actually applies before burning time on one that cannot work.

The survey output is a decision table, not a listing, and reading it correctly is what separates a fast engagement from a stalled one. Sweep all channels first to inventory what exists, then relock to a single channel and BSSID to write a clean capture — an unlocked capture hops away and misses the exact frames you need. Route on four fields. `ENC` separates WEP from WPA/WPA2 from WPA3. `AUTH` is the most decisive: `PSK` means there is a passphrase to recover, `SAE` means WPA3 and the passphrase attacks change completely, `MGT` means enterprise and there is no shared passphrase to crack at all, so anyone still trying to capture a handshake there is wasting the engagement. The station list decides client-dependent versus clientless variants. `#Data` climbing tells you an IV or traffic engine is actually running. Then check two things the default view hides: whether WPS is advertised and unlocked, which is usually faster than any passphrase attack, and whether management frame protection is enabled, which decides whether every deauthentication-driven attack below is even possible. Run this per in-scope ESSID rather than staring at the unfiltered sweep — a corporate site will show fifty neighbouring networks and the filter is what keeps you inside scope.

```bash
sudo airodump-ng wlan0mon                                    # sweep all channels
sudo airodump-ng wlan0mon --essid "CorpWiFi"                 # filter to one in-scope name
sudo airodump-ng wlan0mon --essid "CorpWiFi" --wps           # add the WPS column
sudo airodump-ng wlan0mon --essid "CorpWiFi" --wps -c 1 --bssid 10:7B:EF:08:A3:B4
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF wlan0mon -w capture   # lock + write

# Routing from the columns:
#   ENC=WEP  + clients      -> ARP replay                     wep-and-legacy.md
#   ENC=WEP  + no clients   -> fragmentation / ChopChop       wep-and-legacy.md
#   AUTH=SKA                -> shared-key bypass via XOR      wep-and-legacy.md
#   ENC=WPA2 + WPS unlocked -> WPS PIN first, always          wps-attacks.md
#   ENC=WPA2 + clients      -> deauth, catch the 4-way        wpa2-psk-handshake-and-pmkid.md
#   ENC=WPA2 + no clients   -> PMKID                          wpa2-psk-handshake-and-pmkid.md
#   ENC=WPA3 + transition   -> downgrade to half-handshake    wpa3-sae-attacks.md
#   ENC=WPA3 + SAE only     -> online brute / collider twin   wpa3-sae-attacks.md
#   AUTH=MGT                -> enterprise evil twin; no PSK exists
#                                                             wpa-enterprise-evil-twin.md
#   ENC=OPN                 -> portal, isolation, MiTM        open-and-guest-networks.md
```

Source: offsecexams.com OSWP cheatsheet; HTB Academy, Attacking Corporate Wi-Fi Networks — Initial Reconnaissance

## Reading RSN in Wireshark: the AKM list is the ground truth

**Trigger:** `airodump-ng` shows WPA3, or shows WPA2, and you need to know precisely which key-management suites the AP will actually accept.

The `ENC`/`AUTH` columns are a summary and they collapse distinctions that decide your entire attack path — most importantly, a transition-mode AP advertising both WPA2-PSK and WPA3-SAE may render as `WPA3 / SAE` in the sweep, hiding the downgrade opportunity that is the single easiest way into a WPA3 network. Save the capture with `-w`, open a beacon frame from the target BSSID in Wireshark, and read the RSN Information element directly: the **AKM Suite List** enumerates every key-management method the AP will negotiate, and the **RSN Capabilities** field carries the two management-frame-protection bits. Seeing both `PSK` and `SAE` in the AKM list is transition mode and means a WPA2 half-handshake attack is available. Seeing only `SAE` means the downgrade path is closed. Seeing `802.1X`/`FT-802.1X` confirms enterprise regardless of what the SSID name suggests. Seeing `OWE` means Opportunistic Wireless Encryption — an "open" network that is actually encrypted, so the traditional open-network sniffing attacks do not apply. Beacons from different BSSIDs of the *same* ESSID frequently differ; in a real deployment one AP will be misconfigured and it will be the one that lets you in, which is why you check per-BSSID rather than per-network.

```text
Wireshark display filters:

  wlan.fc.type_subtype == 0x08                 beacons
  wlan.fc.type_subtype == 0x04                 probe requests (client PNL leakage)
  wlan.fc.type_subtype == 0x05                 probe responses
  wlan.ssid == "CorpWiFi"                      one network
  eapol                                        the 4-way handshake
  wlan.rsn.akms.type                            AKM suites offered

Beacon -> Tagged parameters -> RSN Information:
  AKM Suite List
     00-0F-AC:2  PSK              WPA2 personal
     00-0F-AC:8  SAE              WPA3 personal
     00-0F-AC:2 + 00-0F-AC:8      TRANSITION MODE -> downgrade available
     00-0F-AC:1  802.1X           enterprise
     00-0F-AC:5  802.1X-SHA256    enterprise, PMF-capable
     00-0F-AC:18 OWE              enhanced open
  RSN Capabilities
     MFPC (bit 7)  management frame protection capable
     MFPR (bit 6)  management frame protection REQUIRED -> deauth is dead
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Initial Reconnaissance, Reconnaissance and Enumeration

## Detecting PMF/802.11w before planning anything that needs a deauthentication

**Trigger:** Your attack plan involves deauthentication — handshake capture, evil twin, karma client-steering — on a WPA2 or WPA3 network.

Management frame protection is the single control that invalidates most of the classic wireless toolkit, and checking for it early saves you from an afternoon of attacks that cannot work. Unprotected management frames let anyone forge a deauthentication from the AP's address, which is the enabling primitive for handshake capture, for pushing clients onto an evil twin, and for denial of service. With PMF required, those frames are cryptographically protected and rejected, so handshake capture becomes a waiting game for natural reassociation, evil twins have to win on signal strength alone, and DoS via deauth is off the table. WPA3 mandates PMF; WPA2 makes it optional and most enterprise deployments still leave it off, which is why a WPA2 network in a corporate estate is usually the softest target. Read it from the RSN Capabilities bits in the beacon rather than by trying a deauth and inferring from failure. Check it per BSSID: in a fleet advertising one ESSID it is common for a single AP to have PMF off while its siblings have it on, and that AP is where every deauthentication-driven attack belongs.

```bash
sudo airodump-ng -c 1 --bssid AA:BB:CC:DD:EE:FF wlan0mon -w pmfcheck
# then in Wireshark: beacon -> RSN Information -> RSN Capabilities

# tshark equivalent, faster for a sweep across many BSSIDs
tshark -r pmfcheck-01.cap -Y "wlan.fc.type_subtype == 0x08" \
  -T fields -e wlan.bssid -e wlan.ssid \
  -e wlan.rsn.capabilities.mfpc -e wlan.rsn.capabilities.mfpr | sort -u

# MFPR=1  -> PMF required; deauth-based attacks are dead. See client-side-and-dos.md
# MFPC=1, MFPR=0 -> optional; PMF-capable clients protected, legacy clients not
# both 0 -> PMF disabled; deauth-driven attacks all available
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Reconnaissance and Enumeration

## Kismet as the cross-check for noisy multi-AP environments

**Trigger:** A corporate site with many APs sharing an ESSID, heavy neighbouring noise, or a client you believe exists but `airodump-ng` never shows.

A large corporate WLAN broadcasts one ESSID from many radios and surrounds it with dozens of neighbouring networks, and in that environment `airodump-ng`'s single scrolling table is easy to misread and genuinely does miss things — a station associated to one AP of a multi-AP deployment can fail to appear while Kismet catches it immediately. Kismet hops channels several times a second, keeps persistent per-device state instead of a live-refreshing table, and gives you a filterable web UI where you can pin one SSID and see every BSSID advertising it along with each one's security posture and connected clients side by side. That side-by-side view is exactly what finds the one misconfigured AP in a fleet — the one still in transition mode, the one with WPS enabled, the one on an older firmware. Use both tools rather than choosing: `airodump-ng` for the fast routing read and clean per-BSSID captures, Kismet for inventory and for confidence that you have seen everything. Kismet's own logs are also better engagement evidence than a screenshot of a scrolling terminal, since they retain device first-seen and last-seen timestamps.

```bash
sudo airmon-ng check kill
sudo kismet -c wlan0mon
# UI at http://localhost:2501 — set credentials on first launch

# Running as root, Chrome needs --no-sandbox to open the UI
sudo google-chrome --no-sandbox http://localhost:2501

# In the UI:
#   Settings -> Data Sources -> wlan0mon : channel "hop" is the default, ~5 hops/sec
#   Devices tab : filter by SSID -> every BSSID advertising it, with crypto per AP
#   SSID tab    : "Advertising 0 / Responding 0" with probing clients means the AP is down
#   Click an AP : connected clients with MAC, manufacturer, last-seen
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Initial Reconnaissance

## Probe requests: harvesting the preferred-network list

**Trigger:** You need targets for a karma attack, want to find a network whose AP is offline, or are looking for client-side findings.

Client devices carry a preferred-network list of everything they have ever joined, and many of them actively shout for those names rather than waiting to hear a beacon. That leaks the device's network history to anyone listening, which is both an attack input and a finding on its own. Two situations make it immediately actionable. If a client probes for an ESSID that no AP in range is advertising, the real AP is offline or out of range and you can impersonate it with no competition — this is the highest-yield karma setup because there is no legitimate AP to lose a signal-strength contest against. And if a client probes for a *hidden* network by name, it has just told you the SSID the AP declines to broadcast. Read the PROBE column in `airodump-ng` for the quick view, and use `airgraph-ng` to render the client-to-network probe relationships as a graph when there are enough devices that the text becomes unreadable — the graph makes roaming behaviour and orphaned clients obvious at a glance and is a good report figure. Note that modern iOS and Android randomise MAC addresses and have largely stopped broadcast-probing for known networks, so a thin PNL harvest reflects modern client hygiene rather than a failed capture; older laptops, printers, scanners and medical devices are where the leakage still lives.

```bash
sudo airodump-ng wlan0mon -w survey --output-format pcap,csv
# read the PROBE column: names clients are asking for

sudo airgraph-ng -i survey-01.csv -g CPG -o probe-graph.png   # client -> probed AP
sudo airgraph-ng -i survey-01.csv -g CAPR -o assoc-graph.png  # client -> associated AP

# Extract the probed-for names directly
tshark -r survey-01.cap -Y "wlan.fc.type_subtype == 0x04 && wlan.ssid != \"\"" \
  -T fields -e wlan.sa -e wlan.ssid | sort -u
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Initial Reconnaissance; offsecexams.com OSWP cheatsheet

## Hidden SSIDs and the multi-BSSID deployment pattern

**Trigger:** A beacon with a blank or zero-length ESSID, or one in-scope name advertised by ten or more BSSIDs.

A hidden network suppresses the SSID in its beacons but cannot suppress it everywhere: the name still appears in probe requests from clients that know it, in probe responses, and in association requests. So the disclosure is free the moment any client interacts with the AP, and if you do not want to wait, a deauthentication forces one to reassociate and reveal it. Hiding an SSID is therefore a finding to note as ineffective rather than an obstacle. The multi-BSSID pattern is more operationally important. Enterprise deployments broadcast one ESSID from many APs for roaming, and each radio is separately configured, which means the fleet is only as strong as its weakest member — the whole point of surveying per-BSSID is to find the one AP running an older firmware with WPS enabled, or the one still in WPA3 transition mode while its siblings are SAE-only. Sort the survey by BSSID and compare the security columns across the fleet; a single outlier row is usually the way in. Watch also for BSSIDs that differ only in the last octet, which indicates multiple SSIDs on one physical radio — often a guest network and a corporate network sharing hardware, which makes segmentation testing between them a priority.

```bash
# Reveal a hidden ESSID: wait for a client, or force one to reassociate
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF wlan0mon
sudo aireplay-ng -0 1 -a AA:BB:CC:DD:EE:FF -c CLIENT_MAC wlan0mon

# Compare the fleet — the outlier row is the target
sudo airodump-ng wlan0mon --essid "CorpWiFi" --wps -w fleet
awk -F', ' 'NR>2 && $1 ~ /:/ {print $1, $6, $7, $8, $9}' fleet-01.csv | sort -u

# BSSIDs differing only in the last octet = several SSIDs on one radio;
# test guest-to-corporate segmentation. See open-and-guest-networks.md
```

Source: offsecexams.com OSWP cheatsheet; HTB Academy, Attacking Corporate Wi-Fi Networks — Initial Reconnaissance

## Vendor identification from the BSSID prefix

**Trigger:** You have a target BSSID and want to know the hardware before choosing an attack.

The first three octets of a BSSID are the organisationally unique identifier and map to the manufacturer, which is worth two minutes because it narrows several later decisions. It tells you which default-PIN and default-credential lists apply if WPS is enabled or you reach the management interface; it tells you which vendor's known CVEs to check when you get to the gateway or controller; and it tells you whether the fleet is homogeneous or whether someone has bolted a consumer access point onto a corporate network, which is itself a finding. Look it up locally from the IEEE OUI database that ships with most distributions rather than pasting client BSSIDs into a web service during an engagement. Cross-check against Kismet, which resolves manufacturers automatically. Be aware that many APs randomise or offset the BSSID per-SSID from a base hardware address, so a lookup that returns nothing is often a virtual BSSID rather than an unknown vendor — try the physical address from a neighbouring BSSID in the same fleet.

```bash
grep -i "107BEF" /var/lib/ieee-data/oui.txt
grep -i "$(echo AA:BB:CC:DD:EE:FF | tr -d ':' | cut -c1-6)" /var/lib/ieee-data/oui.txt

# Refresh the local database
sudo update-ieee-data

# Feeds into:
#   default WPS PIN lists            -> wps-attacks.md
#   default admin credentials, CVEs  -> wireless-infrastructure.md
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Compromising WPA2 Wi-Fi Network
