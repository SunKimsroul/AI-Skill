# Wireless - Wardriving, mapping and OSINT

## Wardriving with Kismet and GPS

**Trigger:** A large site or campus where the access points are spread across buildings and floors, or a pre-engagement mapping pass is wanted.

Wardriving is systematic wireless survey with location attached — every AP and client Kismet sees gets tagged with a GPS fix, which turns a flat device list into a map of where each radio physically is. This matters for a corporate assessment in three ways: it finds the full extent of a fleet that no single vantage point can see, it locates the physically neglected AP (the one in a far building running old firmware), and it produces coverage evidence showing where the network leaks beyond the building's walls into the car park or the street, which is a finding in its own right. Attach a GPS (a cheap USB puck or a phone running a GPSD bridge), start `gpsd`, and point Kismet at both the wireless interface and the GPS. Kismet logs everything to a `.kismet` SQLite database that carries per-device first/last-seen, signal, and location, which is far better engagement evidence than a terminal screenshot and can be replayed and filtered offline.

```bash
sudo apt install -y gpsd gpsd-clients kismet
sudo gpsd /dev/ttyUSB0 -F /var/run/gpsd.sock     # or a phone via GPSD-relay over TCP
cgps -s                                           # confirm a GPS fix

sudo kismet -c wlan0mon                            # Kismet auto-detects gpsd
# logs -> ~/.kismet/*.kismet  (SQLite: devices, packets, GPS, alerts)

# Offline analysis of the capture DB
kismetdb_dump_devices --in Kismet-*.kismet --out devices.json
kismetdb_to_wiglecsv   --in Kismet-*.kismet --out site.csv
```

Source: Operator practice; Kismet

## War-walking a building to map the fleet

**Trigger:** A multi-AP ESS indoors, where the goal is the per-AP posture map rather than a street-level survey.

Indoors, GPS is unreliable, so the map is built from signal strength and physical notes rather than coordinates — walk the coverage area methodically, floor by floor, and record which BSSID is strongest in each zone alongside its security posture. The point is the same outlier-hunt as any fleet survey, but on foot: a large deployment is only ever partly in RF range from one spot, so the misconfigured AP in a back office or a satellite floor is invisible from the lobby and only a walk finds it. Lock the survey to the target ESSID, watch the per-BSSID signal climb and fall as you move, and note the physical location where each BSSID peaks. The deliverable is a table of BSSID → location → posture (AKM, WPS, PMF, firmware hint), which both directs the attack (walk back to the weak AP) and evidences coverage for the report.

```bash
# Per-BSSID signal as you move — the strongest BSSID names the AP you are nearest
sudo airodump-ng wlan0mon --essid "CorpWiFi" -w walk
watch -n2 "awk -F', ' 'NR>2 && \$1~/:/ {print \$1, \$4, \$6, \$8, \$9}' walk-01.csv | sort -k5 -n"

# Kismet's live signal view is better for this — Devices -> sort by SSID -> RSSI column
# Record: BSSID | floor/room where signal peaks | AKM | WPS | PMF | vendor
```

Source: Operator practice

## WiGLE — BSSID geolocation and SSID history

**Trigger:** You have a BSSID or SSID and want to locate it, confirm ownership, or check whether it has been catalogued publicly.

WiGLE is a public database of wardriven wireless observations, and it turns a BSSID into a location and an SSID into a history of where it has been seen. Two uses in an authorised assessment. Reconnaissance: a target SSID or BSSID looked up in WiGLE reveals whether the network is already publicly mapped, where else it appears (a chain with the same SSID across sites, a device that has moved), and roughly where a given BSSID physically sits — useful for scoping a fleet before arriving. And exposure: finding a client's home or previous-employer SSIDs in its probe list (see below) and geolocating them via WiGLE demonstrates how much a leaked PNL discloses about a person. Use the API for scripted lookups. Treat WiGLE as OSINT on infrastructure — it only contains what others have already collected in public, but for a corporate SSID that is often more than the client expects.

```bash
# API lookup by BSSID (netid) or SSID
curl -s -u "$WIGLE_USER:$WIGLE_KEY" \
  "https://api.wigle.net/api/v2/network/search?netid=AA:BB:CC:DD:EE:FF"
curl -s -u "$WIGLE_USER:$WIGLE_KEY" \
  "https://api.wigle.net/api/v2/network/search?ssid=CorpWiFi"

# Upload a wardrive to WiGLE (contributes back; do not upload client data without permission)
#   -> kismetdb_to_wiglecsv output, or the WiGLE mobile app
```

Source: Operator practice; WiGLE

## Probe-request OSINT: reading a client's history

**Trigger:** A capture full of probe requests, where the goal is what the client devices disclose about their owners.

A device's preferred-network list is a travel history: the SSIDs it probes for are networks it has joined — home routers, past employers, hotels, airports, other clients' offices — and each name is a piece of OSINT about the person carrying the device. Harvest the probes, then enrich: geolocate the named SSIDs via WiGLE, recognise chain names (a hotel or airline SSID places the person there), and spot corporate SSIDs from other organisations that indicate where an employee has worked or visited. In a corporate assessment this is both a client-hygiene finding (staff devices leaking network history) and a social-engineering input (a spear-phish referencing a network the target trusts). Modern iOS and Android randomise MACs and have largely stopped broadcasting saved-network probes, so a rich harvest usually indicates older laptops, printers, or embedded devices — which is itself worth noting.

```bash
sudo airodump-ng wlan0mon -w probes --output-format pcap,csv
tshark -r probes-01.cap -Y "wlan.fc.type_subtype == 0x04 && wlan.ssid != \"\"" \
  -T fields -e wlan.sa -e wlan.ssid | sort -u

# Per-device PNL, then geolocate each SSID via WiGLE
tshark -r probes-01.cap -Y "wlan.fc.type_subtype == 0x04" \
  -T fields -e wlan.sa -e wlan.ssid | awk 'NF==2' | sort | awk '{print $1" -> "$2}'
```

Source: Operator practice

## SSID and BSSID OSINT for target identification

**Trigger:** During scoping, to identify which networks belong to the target and pull public intelligence on the hardware.

Before arriving on site, several public sources turn a company name or a captured BSSID into useful intelligence. The BSSID's OUI names the hardware vendor, which predicts default credentials, WPS behaviour and known CVEs. WiGLE places a BSSID and reveals sibling networks. FCC ID and vendor MAC databases confirm the device model. And the SSID naming convention itself — once one is known — predicts the others (a `Corp-Guest` implies a `Corp-Staff`, a `Corp-ENT` implies enterprise auth), which tells you what to look for in the survey and whether an enterprise SSID exists that changes the whole engagement. None of this touches the target; it is pre-engagement homework that makes the on-site time efficient and ensures the survey does not miss an SSID that OSINT already revealed.

```bash
# Vendor from a known BSSID
grep -i "$(echo AA:BB:CC:DD:EE:FF | tr -d ':' | cut -c1-6)" /var/lib/ieee-data/oui.txt

# Public catalogues (browser / API): WiGLE (location + siblings), FCC ID lookup (model),
# Shodan for any exposed management interface tied to the org's ranges.
# SSID convention: one known name predicts the family — note enterprise SSIDs especially.
```

Source: Operator practice
