# Wireless - Adjacent wireless (Bluetooth, and pointers)

A wireless assessment often scopes more than 802.11. This file covers Bluetooth and Bluetooth
Low Energy — the adjacent radio most likely to be in a Wi-Fi engagement's scope — and points
to the rest of the library for the other bands. Confirm each band is in scope before testing;
Bluetooth touches phones, wearables, medical and access-control devices.

## Bluetooth Classic and BLE reconnaissance

**Trigger:** The scope includes Bluetooth, or devices (headsets, wearables, beacons, locks, medical/IoT) are present that speak it.

Bluetooth splits into two stacks with different discovery, and the first job is inventory. **Classic** (BR/EDR) devices are found by inquiry scanning, which returns address, class-of-device (hinting at the device type), and name; non-discoverable devices are missed by a plain scan and need either a known address or a brute over the address space. **BLE** advertises continuously, so a passive scan of advertisement packets enumerates every advertiser in range along with its service UUIDs, manufacturer data and, often, a static or resolvable address — much richer than Classic discovery and entirely passive. Build the device inventory first with the standard tooling, then enumerate each device's services: Classic via SDP (which services and channels it exposes) and BLE via GATT (the attribute database of services and characteristics), because that service map is what tells you whether there is anything worth attacking — an unauthenticated characteristic that unlocks a door, a debug service, a credential.

```bash
sudo systemctl start bluetooth
bluetoothctl                     # scan on ; devices ; info <MAC>
hcitool dev                      # local adapters
sudo hcitool lescan              # BLE advertisement scan (passive-ish)
sudo hcitool scan                # Classic inquiry
sudo sdptool browse <MAC>        # Classic service/channel enumeration

# BLE GATT enumeration
sudo bettercap -eval "ble.recon on"          # live BLE recon
gatttool -b <MAC> --primary                  # services
gatttool -b <MAC> --characteristics          # characteristics
sudo btmgmt find                             # LE + BR/EDR discovery
```

Source: Operator practice

## BLE GATT interaction and characteristic abuse

**Trigger:** BLE recon found a device with a readable/writable GATT database and no or weak authentication.

Most BLE security failures are not cryptographic — they are missing authorisation on the GATT characteristics. A device that exposes a writable characteristic controlling a physical function (a lock, a relay, an actuator) without requiring pairing or authentication can be driven directly by writing the right value, and a device that exposes sensor data, credentials or configuration on a readable characteristic leaks it to anyone in range. So after enumeration, read every readable characteristic (secrets and config hide there) and identify writable ones that map to a function, then test whether the device enforces authentication before honouring a write. The workflow is: map the GATT tree, read everything, correlate handles to functions (the vendor app's traffic or the characteristic UUIDs often reveal which handle does what), and attempt an unauthenticated write to a function characteristic. `nRF Connect` (mobile) is the fastest interactive explorer; `gatttool`/`bettercap` script it.

```bash
gatttool -b <MAC> -I                         # interactive
#   connect
#   char-desc                                 # full handle map
#   char-read-hnd 0x000e                       # read a characteristic by handle
#   char-write-req 0x0011 01                   # write (test unauthenticated control)

# bettercap scripted
sudo bettercap -eval "ble.recon on; ble.enum <MAC>; ble.write <MAC> <uuid> <hex>"
```

Source: Operator practice

## BLE sniffing, pairing capture and replay

**Trigger:** Two BLE devices communicate (a phone and a lock, a fob and a reader) and the goal is to capture, understand, or replay that exchange.

Interesting BLE traffic happens between a legitimate central and peripheral, and capturing it needs a sniffer that can follow the connection's channel-hopping. A dedicated sniffer — an **Ubertooth One**, or an **nRF52840** running a sniffer firmware feeding Wireshark, or **btlejack** on Micro:bits — locks onto a connection and captures the link, including the pairing exchange. Legacy BLE pairing (pre-4.2 "Just Works" and passkey) is weak: the temporary key is derived from a guessable or brute-forceable value, so a captured pairing can be cracked (`crackle`) to recover the long-term key and decrypt the session, after which the traffic is readable and often replayable. Even without breaking crypto, many devices accept a straight **replay** of a captured command (unlock, activate) because they implement no freshness — capture the command characteristic write and replay it. Secure Connections (4.2+) with proper authentication defeats the crypto attacks, so success here is also a device-generation finding.

```bash
# Capture with an nRF52840 sniffer (feeds Wireshark) or Ubertooth
ubertooth-btle -f -c capture.pcap            # follow connections
btlejack -f 0x<accessaddr> -c capture        # hijack/sniff an existing connection

# Crack legacy pairing to decrypt the session
crackle -i capture.pcap -o decrypted.pcap    # recovers TK/LTK for legacy pairing

# Replay a captured command (no-freshness devices)
#   re-issue the captured characteristic write with gatttool/bettercap
```

Source: Operator practice; btlejack, crackle, Ubertooth

## Where the rest of the wireless spectrum lives

**Trigger:** The scope extends past Wi-Fi and Bluetooth to other bands.

The library already covers the non-802.11, non-Bluetooth radio work, so use those files rather than duplicating them here. Zigbee/802.15.4, RFID/NFC, and CAN/vehicle work are in `ctf-misc/radio-iot-and-vehicle.md`. Software-defined-radio and raw IQ/signal processing (capturing and demodulating an arbitrary signal, sub-GHz, custom protocols) are in `ctf-misc/rf-sdr.md`. The wireless-assessment mindset carries across all of them: inventory what transmits, identify the protocol, enumerate the service or command surface, and test whether authentication and freshness are enforced — the same shape as Wi-Fi and BLE, on a different physical layer.

```text
Zigbee / 802.15.4, RFID / NFC, CAN / vehicle  ->  ctf-misc/radio-iot-and-vehicle.md
SDR / raw IQ / sub-GHz / arbitrary signals     ->  ctf-misc/rf-sdr.md
Wi-Fi (802.11)                                 ->  this pack
Bluetooth / BLE                                ->  this file
```

Source: Operator practice
