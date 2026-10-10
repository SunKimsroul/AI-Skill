# Wireless - Automation frameworks

## Choosing a framework, and when manual still wins

**Trigger:** A fleet of targets and limited time, or a repeatable attack you would rather not hand-drive.

The automation frameworks each wrap the same underlying aircrack/hostapd/hcx toolchain, and they differ in *what* they automate rather than in capability, so choose by the shape of the job. `wifite2` orchestrates the full break-a-network flow (survey, WPS, PMKID, handshake, crack) across many targets in sequence — the right tool for sweeping a fleet. `airgeddon` is a menu-driven wrapper over the whole toolchain including evil twin and WPS, good for working quickly and interactively but it hides what it runs. `bettercap` is a scriptable framework with a live `wifi` module (recon, deauth, handshake capture, and its own caplet scripts) plus Bluetooth and network MITM in one tool. `wifipumpkin3` is the rogue-AP-as-a-platform choice, with a plugin architecture for sniffers, proxies and credential capture. `Fluxion` does one thing — the handshake-validated captive-portal attack — well. The rule that keeps you out of trouble: every framework decides *for you* when to deauthenticate and how hard, which is exactly the judgement call that matters on a production network, so constrain each one to authorised BSSIDs and permitted attacks, and hand-build at least once so the framework's silent failures are diagnosable. Frameworks are a speed and breadth tool, not a substitute for understanding the layer beneath them.

```bash
# Decision:
#   sweep many targets, break WPA2         -> wifite2
#   interactive menu over everything       -> airgeddon
#   scriptable recon + MITM + BLE          -> bettercap
#   rogue AP as a MITM/capture platform    -> wifipumpkin3
#   handshake-validated captive portal     -> fluxion
#   enterprise (802.1X)                    -> eaphammer / hostapd-wpe (enterprise-eap-advanced.md)

sudo apt install -y wifite bettercap
git clone https://github.com/v1s1t0r1sh3r3/airgeddon /opt/airgeddon
git clone https://github.com/P0cL4bs/wifipumpkin3 /opt/wifipumpkin3
git clone https://github.com/FluxionNetwork/fluxion /opt/fluxion
```

Source: Operator practice

## wifite2 for a full-fleet WPA2/WPA3 sweep

**Trigger:** Many authorised BSSIDs to work through, and a mechanical break-everything pass is wanted.

`wifite2` chains survey, WPS (pixie + PIN), PMKID, handshake-via-deauth, conversion and cracking, iterating over every target it can see, and it is genuinely useful as both a fast first pass and an end-of-engagement completeness check — running it after a manual pass and finding it caught a PMKID you missed on one AP is cheap insurance. The discipline is to bound it: pin it to your authorised BSSIDs and channels, disable the attacks you do not have sign-off for, and never point it at an open scan on a client site because its defaults will attack whatever it sees. Its captured handshakes land already converted, and its cracked-key output is a clean summary. Treat a `wifite2` run as a scripted operator, not as fire-and-forget — watch what it deauthenticates.

```bash
# Bound to one authorised target, only the attacks you have sign-off for
sudo wifite --bssid AA:BB:CC:DD:EE:FF --channel 6 --wpa --no-wps --dict wordlist.txt
sudo wifite --essid "CorpWiFi" --pmkid --no-deauths        # passive-only variant
sudo wifite --kill --wpa --wps --crack --dict rockyou.txt  # full, scoped fleet pass

# Results
ls ~/hs/               # captured handshakes, already 22000-converted
cat cracked.txt        # recovered keys
```

Source: Operator practice; wifite2 (derv82)

## bettercap wifi module and caplets

**Trigger:** You want scriptable, live recon and attack in one tool, or you are already using bettercap for network MITM.

`bettercap`'s `wifi` module turns the adapter into an interactive console: it surveys continuously, tracks APs and clients as live objects, deauthenticates by target, captures handshakes and PMKIDs, and can stand up an evil twin — all driven by typed commands or by caplet scripts that replay a sequence. Its advantage over the aircrack CLI is state and scriptability: you can express "watch this BSSID, deauth its clients, capture the handshake, write it out" as a caplet and rerun it, and its events feed a web UI. It also carries a Bluetooth LE module in the same tool, which is convenient when a wireless assessment spans both. The handshake output is a pcap that `hcxpcapngtool` converts as usual. Keep the same scoping discipline — its `wifi.deauth` targets a BSSID or broadcast, and broadcast on a production network is disruptive.

```bash
sudo bettercap -iface wlan0mon
#   > wifi.recon on
#   > wifi.recon.channel 6
#   > wifi.show
#   > set wifi.handshakes.file /root/hs.pcap
#   > wifi.deauth AA:BB:CC:DD:EE:FF          # targeted; capture the handshake
#   > wifi.assoc AA:BB:CC:DD:EE:FF           # PMKID association attack

# Scripted via a caplet
sudo bettercap -iface wlan0mon -caplet handshake-hunt.cap
hcxpcapngtool -o hash.22000 /root/hs.pcap
```

Source: Operator practice; bettercap

## airgeddon and wifipumpkin3 as interactive platforms

**Trigger:** You want a menu you can drive quickly (airgeddon), or a rogue AP you can extend with plugins (wifipumpkin3).

`airgeddon` presents the whole toolchain as a numbered menu — interface into monitor mode, scan, WPS, handshake, evil twin, WPA3, DoS — which makes it fast for moving through a fleet and forgiving when you do not remember a tool's flags, at the cost of obscuring what it actually executes, so it is a poor tool to learn on and an awkward one to debug when a step fails silently. `wifipumpkin3` is the opposite emphasis: it is a rogue-AP *framework* where the AP is a platform you extend with plugins — DNS spoofers, sniffers, credential capturers, proxy modules, a captive portal engine — driven from its own shell. Use airgeddon to work quickly through standard attacks and wifipumpkin3 when the rogue AP is the point and you want to script what happens to clients after they join. Both need the same authorisation as any deauth or rogue-AP activity.

```bash
sudo bash /opt/airgeddon/airgeddon.sh          # numbered menu over the toolchain

cd /opt/wifipumpkin3 && sudo python3 setup.py install
sudo wifipumpkin3
#   > set interface wlan1
#   > set ssid CorpWiFi
#   > use spoof.dns_spoof
#   > use sniffkin3
#   > start
```

Source: Operator practice; airgeddon, wifipumpkin3
