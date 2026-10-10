# Wireless - Rig, adapters and monitor mode

## Choosing an adapter that can actually inject

**Trigger:** You are assembling a wireless testing rig, or a laptop's built-in card produces empty captures and silent injection failures.

Every attack in this pack depends on two driver capabilities that most consumer Wi-Fi hardware does not expose: raw monitor-mode capture and arbitrary frame injection. Built-in Intel and Broadcom cards typically do the first badly and the second not at all, which is why a beginner's first engagement produces a capture that never completes a handshake and an `aireplay-ng` that prints no error while doing nothing. Buy the chipset, not the brand name on the box — vendors silently change chipsets between hardware revisions of the same model, so verify with `lsusb` after purchase rather than trusting the listing. The Atheros **AR9271** is the most reliable 2.4 GHz-only option and works with in-kernel drivers on any modern distribution; the **MT7612U** is the best current dual-band choice because `mt76` is in-tree and needs no out-of-tree driver maintenance; the Realtek **RTL8812AU** is common and capable but depends on an out-of-tree driver that breaks on kernel upgrades, which is a bad property in the middle of an engagement. You want at least two radios and preferably three, because the core attacks run concurrently on separate interfaces — one scanning in monitor mode, one hosting the rogue AP, one deauthenticating — and trying to time-share a single card between those roles is the second most common reason an evil twin fails to catch anything.

```bash
lsusb                          # confirm the chipset actually present
lsusb -t                       # driver bound per device
iw list | grep -A 10 "Supported interface modes"   # must include: monitor, AP
iw list | grep -A 6 "Supported Ciphers"

# Capability check that matters most: does the driver expose AP mode as well as monitor?
# hostapd-based attacks (evil twin, karma, enterprise) fail without AP mode.
```

Source: Operator practice

## Windows host to Linux tooling — USB passthrough is the whole problem

**Trigger:** Your workstation is Windows and every tool in this pack is Linux-only.

None of the 802.11 attack tooling runs natively on Windows: monitor mode and injection are driver capabilities that the Windows NDIS stack does not expose to userland, and no amount of Npcap configuration changes that. You need Linux with the *physical adapter* attached to it, and the word "physical" is the trap — a Linux VM will happily run `aircrack-ng` against a capture file while having no radio at all. There are three routes and they are not equally good. A full hypervisor VM (VMware Workstation or VirtualBox) with the USB adapter passed through to the guest is the most reliable: the guest kernel binds its own driver and everything behaves like bare metal. WSL2 can work but needs `usbipd-win` to attach the device, and the default WSL2 kernel is built without most wireless drivers and without `CONFIG_CFG80211`, so you will be compiling a custom kernel — workable, but not something to discover the night before an engagement. Bare-metal Linux on a USB stick is the fallback that always works and is worth having ready regardless, because a hypervisor USB stack that drops the adapter mid-capture is a real failure mode. Whichever route, verify the radio appears with `iw dev` inside Linux *before* you rely on it, and re-verify after any host reboot, because passthrough bindings do not always persist.

```powershell
# Windows host, WSL2 route: attach the USB radio to the Linux guest
winget install --interactive --exact dorssel.usbipd-win
usbipd list                                  # find the BUSID of the adapter
usbipd bind --busid 2-4
usbipd attach --wsl --busid 2-4
```

```bash
# Inside Linux, confirm the radio actually arrived before trusting it
lsusb
iw dev                       # must list a phy and an interface
ip link show
# If `iw dev` is empty, the driver did not bind — passthrough succeeded but the
# kernel lacks the module. This is the normal WSL2 default-kernel outcome.
```

Source: Operator practice

## Monitor mode brought up correctly, with the interference killed first

**Trigger:** Captures come back empty, the card drifts off the channel you set, or the interface flips back to managed mode on its own.

Nothing works until the card is in monitor mode, pinned to the target channel, and free of the userland daemons that fight you for the radio. NetworkManager and `wpa_supplicant` periodically re-scan, which yanks the card off your channel mid-capture and shows up much later as a capture that mysteriously never completed a handshake; kill them before starting, and if the channel starts drifting again mid-run, assume a service came back rather than restarting the whole capture. Bring monitor mode up with the channel already specified so there is no window in which the card wanders. There are two mechanisms and they are not interchangeable: `airmon-ng start` renames the interface to `wlan0mon` and is the right default, while `iw dev ... interface add` creates a second virtual interface alongside the managed one and leaves the original in place. Prefer the `iw` route when you will use `reaver`, because a long-standing interaction between `airmon-ng`'s renaming and reaver's interface handling makes reaver associate and then silently fail. Some drivers also need the interface down before the mode change and up afterwards; if `iw set monitor` returns busy, that is what it is telling you.

```bash
sudo airmon-ng                        # enumerate wireless interfaces and drivers
sudo airmon-ng check kill             # stop NetworkManager / wpa_supplicant / avahi
sudo airmon-ng start wlan0 6          # monitor mode, locked to channel 6

# Driver-level alternative — required for reaver, keeps the managed interface
sudo iw dev wlan0 interface add mon0 type monitor
sudo ifconfig mon0 up

# Manual route when the above fights you
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
sudo iw dev wlan0 set channel 6

# Restore afterwards
sudo airmon-ng stop wlan0mon && sudo systemctl restart NetworkManager
```

Source: offsecexams.com OSWP cheatsheet; HTB Academy, Attacking Corporate Wi-Fi Networks — Compromising WPA2 Wi-Fi Network

## Prove injection before trusting any replay attack

**Trigger:** Before the first replay, deauthentication or evil-twin attempt on a new rig.

An adapter that captures perfectly may be unable to transmit, and no tool in the aircrack suite reports this clearly — `aireplay-ng` will sit there sending frames into a void and the attack simply never works. Run the injection test explicitly and read both numbers it gives you: it reports whether the card can inject at all, and it reports per-AP ping success, which is really a link-quality measurement. Zero responding APs means the driver or chipset cannot inject and every replay attack in this pack will fail without printing an error. A low percentage against a specific AP means the AP is too far away or on a congested channel, and the correct response is to move or to raise transmit power within your regulatory domain rather than to keep replaying. Re-run this test whenever you change adapter, channel, or physical position, because it is a two-second check that prevents an hour of debugging the wrong layer.

```bash
sudo aireplay-ng -9 wlan0mon                          # generic injection test
sudo aireplay-ng -9 -e CorpWiFi -a AA:BB:CC:DD:EE:FF wlan0mon   # against one AP

# Expect: "Injection is working!" and a non-zero percentage per AP.
# 0 responding APs  -> driver/chipset cannot inject; change adapter
# Low percentage    -> distance/congestion; move or change channel
```

Source: offsecexams.com OSWP cheatsheet

## Regulatory domain, transmit power, and the missing 5 GHz channels

**Trigger:** The target AP is on a 5 GHz channel your card never shows, or your rogue AP will not start on the channel you chose.

The kernel enforces a regulatory domain that restricts which channels may be used and at what power, and the default on many systems is the most conservative setting rather than your actual country's. The visible symptom is a target that other tools can see but yours cannot, or a `hostapd` that refuses to start on channel 100 with a country-code complaint. Set the regulatory domain to the country you are physically testing in — this is a legal constraint, not a bypass, and setting it to a country you are not in is both illegal and a good way to interfere with radar systems. Understand also that the 5 GHz band splits into channels that require Dynamic Frequency Selection: on DFS channels an AP must listen for radar before transmitting, and most cards will not let you start an AP there at all, so an evil twin against a target on a DFS channel typically has to run on a different channel and rely on the client roaming to you. 6 GHz (Wi-Fi 6E) is a separate problem entirely — very little attack tooling supports it, WPA3 is mandatory there, and open and WPA2 modes are prohibited by the standard, so a 6E-only network is largely out of reach of the classic toolchain.

```bash
iw reg get                            # current regulatory domain
sudo iw reg set GB                    # set to the country you are testing in
sudo iw dev wlan0 set txpower fixed 2000    # 20 dBm, in mBm

iw list | grep -E "MHz|DFS|no IR"     # channels available and their restrictions
#   "no IR"          -> no initiating radiation; cannot start an AP here
#   "radar detection" -> DFS channel; hostapd will usually refuse

# 2.4 GHz channel/frequency map for tools that want MHz (wacker, hostapd)
#   ch1=2412  ch6=2437  ch11=2462  ch13=2472
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Compromising WPA3 Wi-Fi Network; operator practice

## Splitting radios across roles, and MAC identity per role

**Trigger:** An evil-twin or enterprise attack needs to scan, host an AP, and deauthenticate at the same time.

The standard corporate attack shape needs three simultaneous radio behaviours and a single card cannot provide them: `wlan0mon` stays in monitor mode capturing and confirming what happened, `wlan1` runs `hostapd`/`eaphammer` as the rogue AP, and a third interface sends deauthentication frames to push clients across. Attempting this on one card produces the confusing failure where the AP appears to start but no client ever completes association, because the radio is being retuned underneath it. Assign MAC identity per role deliberately as well. The rogue AP's MAC is the lever: cloning the target BSSID makes clients treat you as the same network, which is what a WPA3 downgrade or a collision attack needs, while a random MAC is right for karma, where you are impersonating a *name* and a duplicate BSSID would collide with the real AP. Two rules follow from that. If you clone the target's BSSID, put your AP on a different channel or the two radios will collide and you will DoS the network you are supposed to be quietly assessing. And randomise the MAC again before the next attack — a card still carrying the previous target's BSSID is the cause of a whole class of "the attack worked yesterday" failures.

```bash
# Role assignment
#   wlan0mon : monitor  — survey, handshake capture, verification
#   wlan1    : AP       — hostapd / hostapd-mana / eaphammer
#   wlan2    : injection — aireplay-ng deauth

sudo ip link set wlan1 down
sudo macchanger -m 9C:9A:03:39:BD:7A wlan1   # clone the target BSSID (downgrade/collider)
sudo ip link set wlan1 up

sudo macchanger -r wlan1                      # random (karma, and reset between attacks)
sudo macchanger -p wlan1                      # restore permanent hardware MAC

iwconfig                                      # confirm each interface's mode and frequency
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Attacking WPA3 Wi-Fi Network, Performing Karma & Mana Attack

## Toolchain install and the version divergences that break commands

**Trigger:** Setting up a testing box, or a command copied from a cheatsheet fails with an unrecognised option.

The wireless toolchain has drifted enough between releases that published commands routinely do not run, and the two that bite hardest are `hcxdumptool` and `reaver`. `hcxdumptool` changed its command-line surface between the 6.2.x generation and 6.3/7.x: options such as `--enable_status`, `--filterlist_ap` and `-o` were renamed or removed, and newer builds refuse to run against an interface you have already put into monitor mode because the tool now manages the interface itself. Check your version first and use the matching syntax rather than assuming the older cheatsheet is wrong. `hcxpcapngtool` replaced the older `hcxpcaptool`, and both replaced the long-dead `cap2hccapx` — anything producing `.hccapx` is targeting hashcat mode 2500, which is deprecated in favour of 22000. On the cracking side, hashcat mode 22000 covers both PMKID and EAPOL and is what you want in every current case. Install `hostapd-mana` and `eaphammer` from source rather than distribution packages, because stock `hostapd` lacks the credential-capture hooks entirely and using it is exactly why a mana output file never appears.

```bash
sudo apt update && sudo apt install -y \
  aircrack-ng kismet hcxtools hcxdumptool reaver bully pixiewps \
  hostapd wpasupplicant macchanger wireshark tshark hashcat john \
  hydra nmap ettercap-graphical dnsmasq

hcxdumptool --version         # decides which flag syntax applies below
hcxpcapngtool --version

# hostapd-mana (karma + enterprise credential capture) — not the stock hostapd
git clone https://github.com/sensepost/hostapd-mana /opt/hostapd-mana

# eaphammer (enterprise evil twin)
git clone https://github.com/s0lst1c3/eaphammer /opt/eaphammer
cd /opt/eaphammer && sudo ./kali-setup

# wacker (WPA3 SAE online brute force)
git clone https://github.com/blunderbuss-wctf/wacker /opt/wacker

# wifiphisher (captive-portal / phishing rogue AP)
git clone https://github.com/wifiphisher/wifiphisher /opt/wifiphisher
cd /opt/wifiphisher && sudo python3 setup.py install
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks (multiple sections); offsecexams.com OSWP cheatsheet
