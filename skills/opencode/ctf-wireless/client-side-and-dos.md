# Wireless - Client-side attacks and availability testing

## Deauthentication and disassociation mechanics

**Trigger:** You need to force reassociation, or you are testing whether management-frame forgery is possible.

Deauthentication and disassociation are management frames, and on a network without PMF they are unauthenticated — anyone can forge one claiming to come from the access point, and the client obeys. That single property enables handshake capture, evil-twin client steering and denial of service alike, which is why PMF is the control that matters most on a WPA2 network. Two variants behave differently. Addressed to a specific client with `-c`, the frame is a targeted disconnection and is both far more reliable and far less disruptive. Addressed to the broadcast address, it disconnects every station on the AP at once and is noticeably less effective per frame because some clients ignore broadcast deauthentication entirely. Frame count matters more than people expect: a few frames force a reconnection, while a continuous flood prevents the reconnection you were trying to cause, so a capture that yields no EAPOL after a large deauth count is usually over-attacking rather than under-attacking. Reason codes carry semantic meaning to the client — code 7 (class 3 frame from nonassociated station) is the aireplay default and is widely obeyed, while code 1 is generic — and some supplicants respond differently to different codes, which is worth varying if a specific client will not move.

```bash
sudo aireplay-ng --deauth 3 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon  # targeted
sudo aireplay-ng --deauth 3 -a AA:BB:CC:DD:EE:FF wlan0mon                        # broadcast
sudo aireplay-ng --deauth 0 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon   # continuous

# mdk4 equivalents, with more control over the frame
sudo mdk4 wlan0mon d -B AA:BB:CC:DD:EE:FF -c 6         # deauth
sudo mdk4 wlan0mon d -w whitelist.txt -c 6             # spare listed stations

# Disassociation rather than deauthentication — some clients treat them differently
sudo mdk4 wlan0mon d -B AA:BB:CC:DD:EE:FF -c 6 -s 100

# Confirm the effect from the capture rather than assuming
tshark -r cap-01.cap -Y "wlan.fc.type_subtype == 0x0c" \
  -T fields -e wlan.sa -e wlan.da -e wlan.fixed.reason_code
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Attacking WPA2 Wi-Fi Network; offsecexams.com OSWP cheatsheet

## Confirming PMF and working around it

**Trigger:** Deauthentication produces no effect, or the beacon shows MFPR set.

When PMF is required, management frames are protected with a BIP integrity check and a forged deauthentication is silently discarded, so the attack fails without any error and looks identical to being out of range. Confirm which it is from the beacon's RSN Capabilities rather than inferring from silence — MFPR set means required, MFPC without MFPR means capable but optional. The optional case is the interesting one in practice: on a mixed network, PMF-capable clients negotiate protection while legacy clients do not, so deauthentication still works against the older devices, and in a corporate estate those older devices are frequently the printers, scanners and handhelds that matter operationally. When PMF is genuinely enforced, three approaches remain. PMKID needs no client at all and is unaffected. An evil twin can still win a client by being stronger than the real AP, which is a positioning problem rather than a protocol one. And the SA Query timeout and channel-switch mechanisms have historically had implementation weaknesses in some vendors' firmware, though these are unreliable and vendor-specific.

```bash
sudo airodump-ng -c 1 --bssid AA:BB:CC:DD:EE:FF wlan0mon -w pmfcheck
tshark -r pmfcheck-01.cap -Y "wlan.fc.type_subtype == 0x08" \
  -T fields -e wlan.bssid -e wlan.rsn.capabilities.mfpc -e wlan.rsn.capabilities.mfpr

# MFPR=1              deauth is dead        -> PMKID, or win on signal strength
# MFPC=1, MFPR=0      mixed                 -> legacy clients still deauthable
# both 0              unprotected           -> everything in this file works

# Which clients negotiated protection? Compare per-station association requests.
tshark -r pmfcheck-01.cap -Y "wlan.fc.type_subtype == 0x00" \
  -T fields -e wlan.sa -e wlan.rsn.capabilities.mfpc
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Reconnaissance and Enumeration

## Channel switch announcement and beacon-based client steering

**Trigger:** You need to move clients off a channel without a deauthentication, or PMF blocks the direct approach.

A channel switch announcement is an information element in a beacon telling associated stations that the AP is moving to a different channel, and clients follow it because that is the mechanism legitimate APs use for DFS radar avoidance. Forging one moves clients to a channel where the real AP is not, which produces a disconnection without a single deauthentication frame — useful when PMF blocks the direct route, since the CSA travels in the beacon rather than in a protected management frame on some implementations. The same family includes beacon flooding, which fills the client's scan results with fabricated networks and degrades its ability to find the real one, and authentication flooding, which exhausts the AP's association table so genuine clients cannot join. All three are availability attacks rather than access attacks: they do not get you onto the network, they take it away from its users. They are also the noisiest thing in this pack and the most likely to cause an incident, so they belong at the end of a test plan rather than the start.

```bash
sudo mdk4 wlan0mon d -B AA:BB:CC:DD:EE:FF -c 6         # deauth/disassoc
sudo mdk4 wlan0mon b -n "CorpWiFi" -c 6                # beacon flood
sudo mdk4 wlan0mon a -a AA:BB:CC:DD:EE:FF              # authentication flood
sudo mdk4 wlan0mon m -t AA:BB:CC:DD:EE:FF              # Michael countermeasures (TKIP only)

# Channel switch announcement
sudo mdk4 wlan0mon f -t AA:BB:CC:DD:EE:FF

# Verify the effect on the client side rather than assuming
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF wlan0mon      # station list emptying?
```

Source: Operator practice

## Client PNL leakage and MAC randomisation

**Trigger:** You are assessing client-side exposure rather than the network's configuration.

The client half of a wireless assessment is about what devices reveal and what they will connect to, independent of how well the network is configured. Two behaviours dominate. Preferred-network-list leakage means a device broadcasts the names of networks it has joined, which discloses where its owner has been — hotel chains, airports, other employers, home networks — and hands an attacker a karma target list. Modern iOS and Android have largely stopped broadcast-probing for saved networks and randomise their MAC per network, which closes both problems, so a thin harvest reflects good client hygiene rather than a failed capture; the leakage now lives in older laptops, printers, handheld scanners and embedded devices. The second behaviour is auto-join: a device configured to automatically connect to an open network by name will join an impersonation of it without any user interaction, which is what makes a karma attack against a corporate guest SSID effective. Test both by capturing probes over a realistic period and by standing up a karma AP and observing what joins unprompted. Randomised MACs are visible in the capture — the locally-administered bit set in the second nibble of the address is the tell.

```bash
# Harvest over a realistic window
sudo airodump-ng wlan0mon -w clients --output-format pcap,csv

# Which devices are probing, and for what
tshark -r clients-01.cap -Y "wlan.fc.type_subtype == 0x04 && wlan.ssid != \"\"" \
  -T fields -e wlan.sa -e wlan.ssid | sort -u

# Randomised vs real MAC: locally-administered bit (second nibble is 2/6/A/E)
tshark -r clients-01.cap -Y "wlan.fc.type_subtype == 0x04" \
  -T fields -e wlan.sa | sort -u | awk '{print $1, (substr($1,2,1) ~ /[26aeAE]/ ? "randomised" : "real")}'

# Auto-join test: stand up the probed-for name and see what joins unprompted
#   -> rogue-ap-and-karma.md
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Initial Reconnaissance; operator practice

## KRACK, kr00k and the residual protocol weaknesses

**Trigger:** An estate with old client devices or old access-point firmware, where you want to know whether the historical protocol attacks still apply.

Two well-known post-2017 weaknesses occasionally still matter. **KRACK** attacks the four-way handshake by replaying message three, which causes a vulnerable client to reinstall an already-in-use key and reset its nonce counter, allowing replay and in some configurations decryption or forgery. It is a client-side vulnerability, not a network one, so patching state on the endpoints is what determines exposure — and the wpa_supplicant variant that reinstalled an all-zero key was devastating on older Android and Linux devices. **kr00k** is an implementation flaw in certain Broadcom and Cypress chips where the transmit buffer is flushed after a disassociation using an all-zero temporal key, so the attacker deauthenticates a client and reads the few kilobytes it emits encrypted with a known key. Both are largely closed by firmware from 2018-2020 onward, which makes them checks to perform rather than attacks to rely on — their value in a modern estate is finding the neglected device, typically an embedded controller or a handheld that has not been updated since deployment. Both are also client-side, which means the network can be perfectly configured and still have exposed devices on it.

```bash
# KRACK test scripts (Vanhoef) — run against a client under test
git clone https://github.com/vanhoefm/krackattacks-scripts
#   krack-test-client.py runs a rogue AP that probes for key reinstallation

# kr00k: deauthenticate, then capture what the client flushes
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF wlan0mon -w kr00k
sudo aireplay-ng --deauth 5 -a AA:BB:CC:DD:EE:FF -c CLIENT_MAC wlan0mon
#   frames after the disassociation encrypted with an all-zero TK are decryptable
#   https://github.com/hexway/r00kie-kr00kie

# Both are client-side: identify the device generation first
#   OUI lookup -> recon-and-survey.md
```

Source: Operator practice; Vanhoef & Piessens, KRACK (2017); ESET, kr00k (2020)

## FragAttacks — aggregation and fragmentation design flaws

**Trigger:** A thorough client-side assessment, especially an estate with devices of any age, where the aggregation/fragmentation flaws that affect nearly all Wi-Fi devices are in scope.

FragAttacks (Vanhoef, 2021) are a family of vulnerabilities in the 802.11 standard itself plus widespread implementation bugs, and their significance is breadth: because several are design flaws in how frames are aggregated and fragmented, essentially every Wi-Fi device ever made was affected at disclosure, across WEP through WPA3. Three classes matter. The **aggregation** flaw lets an attacker set the A-MSDU flag so a crafted frame is parsed as containing attacker-chosen packets — a route to injecting traffic (for example, a malicious ICMPv6 router advertisement to redirect a victim's DNS). The **mixed-key** and **fragment-cache** flaws abuse how devices reassemble fragments encrypted under different keys or leave fragments in a cache across reconnections, allowing exfiltration or injection. And a cluster of **implementation** bugs — accepting plaintext frames, accepting fragmented frames as full frames — are trivially exploitable on the devices that have them. Like KRACK and kr00k these are largely closed by post-2021 firmware, so the assessment value is identifying the unpatched device rather than expecting a universal win, but the class is worth testing precisely because the neglected embedded device is exactly what remains vulnerable. Vanhoef's test tool enumerates which specific flaws a given client or AP exhibits.

```bash
# Vanhoef's official test suite — tests a specific client or AP for each FragAttack
git clone https://github.com/vanhoefm/fragattacks
cd fragattacks && ./build.sh
# run a specific test against a target (many sub-tests; see TESTING.md)
sudo python3 fragattack.py wlan0 ping I,E        # plaintext-injection class
sudo python3 fragattack.py wlan0 ping-frag-sep   # fragment handling
sudo python3 fragattack.py wlan0 amsdu-inject    # A-MSDU aggregation flaw

# Result is per-flaw pass/fail -> which CVEs the device is exposed to; feed the report.
# Identify device generation first (OUI) -> recon-and-survey.md
```

Source: Vanhoef, FragAttacks (2021, CVE-2020-24586/24587/24588 and others)

## Detecting the wireless IDS that is watching you

**Trigger:** Attacks that worked briefly stop working, your rogue AP disappears from the air, or clients associate and are immediately disconnected.

Managed enterprise wireless usually includes a wireless intrusion prevention capability, and in containment mode it will actively fight you: it detects a rogue AP advertising a corporate SSID and floods it with deauthentication frames, which produces exactly the symptom of clients associating to you and immediately dropping. Recognising this matters because the natural response — increasing power, retrying, adding more clients — makes the detection stronger rather than weaker. The tell is directional: capture on the channel your rogue AP is using and look for deauthentication frames addressed to *your* BSSID from an address you do not control. Sensor-driven containment usually also implies the client is receiving alerts about your activity in real time. Reducing your footprint is the practical response — `mana_loud=0` to stop retransmitting every beacon, a randomised rather than cloned BSSID, lower transmit power, and shorter attack windows — but recognise that against a properly configured WIPS in containment mode, a rogue AP attack is being actively suppressed and the useful result is knowing that the control works.

```bash
# Are you being contained? Capture on your own rogue AP's channel.
sudo airodump-ng -c 1 wlan2mon -w wips
tshark -r wips-01.cap -Y "wlan.fc.type_subtype == 0x0c" \
  -T fields -e wlan.sa -e wlan.da -e wlan.bssid | sort | uniq -c | sort -rn
#   deauth frames aimed at YOUR BSSID from an address you do not control = containment

# Reduce footprint
#   mana_loud=0                      stop retransmitting every known beacon
#   sudo macchanger -r wlan1         random BSSID rather than a clone
#   sudo iw dev wlan1 set txpower fixed 1000    lower power, smaller radius
```

Source: Operator practice
