# Wireless - Enterprise 802.1X, deep

Complements `wpa-enterprise-evil-twin.md` (the rogue-authenticator attack). This file covers
the wider 802.1X surface: the EAP method matrix, online credential spraying without a rogue
AP, passive identity harvesting, EAP-TLS, and RADIUS-side attacks.

## The EAP method matrix — which attack each method allows

**Trigger:** A survey shows `MGT`, and the specific EAP method in use decides which attack is even possible.

"Enterprise" is not one thing — it is whichever EAP method the deployment configured, and the method determines the attack completely, so identify it before choosing a tool. Capture one real authentication and read the EAP type. **PEAP** and **EAP-TTLS** wrap an inner password exchange (usually MSCHAPv2, sometimes PAP/GTC) in a TLS tunnel, so they fall to a rogue authenticator that harvests the inner challenge/response or the cleartext — the primary evil-twin path. **EAP-TLS** authenticates with a client certificate and has no password to steal; only certificate theft from an endpoint helps. **EAP-FAST** uses a PAC and can be attacked similarly to PEAP when anonymous provisioning is allowed. **EAP-PWD** and the legacy **LEAP** have their own cryptographic weaknesses (LEAP falls to `asleap` outright). **EAP-MD5** is unprotected and its hash is captured passively. The single most decisive read is TLS-tunnelled-password (attackable by evil twin) versus certificate-based (not), and it is a two-second check that saves setting up an attack that cannot work.

```bash
sudo airodump-ng wlan0mon -c 1 --essid "CorpWiFi-ENT" -w ent
tshark -r ent-01.cap -Y "eap" -T fields -e eap.type | sort -u
#   4  = MD5      -> passive hash capture
#   6  = GTC      -> cleartext inner (if downgraded to) 
#   13 = TLS      -> client cert; no password; endpoint cert theft only
#   17 = LEAP     -> asleap
#   21 = TTLS     -> tunnelled password; rogue authenticator
#   25 = PEAP     -> tunnelled MSCHAPv2; rogue authenticator (primary path)
#   43 = EAP-FAST -> PAC; attack anonymous provisioning
#   52 = EAP-PWD  -> dictionary/side-channel research
```

Source: Operator practice

## hostapd-wpe — the classic rogue RADIUS

**Trigger:** You want the original hostapd-wpe workflow, or eaphammer is unavailable, for PEAP/TTLS credential capture.

`hostapd-wpe` (Wireless Pwnage Edition) is the long-standing rogue-authenticator patch to `hostapd` that answers 802.1X, completes the inner exchange against a fake server, and logs the MSCHAPv2 challenge/response and any cleartext it can elicit — the tool `eaphammer` and `hostapd-mana` descend from. It is worth knowing directly because it is the reference implementation and it is what many older guides and exam labs assume. Configure it with a certificate (mimicking the real RADIUS server's issuer/subject raises acceptance against loosely-validating clients), point clients at it by matching the SSID and channel, and read its log for captured hashes. The output is a NetNTLM/MSCHAPv2 pair that `asleap` or `hashcat -m 5500` cracks offline. Everything about client-side certificate validation from `wpa-enterprise-evil-twin.md` applies identically: a supplicant that validates properly rejects it, and that rejection is a positive finding.

```bash
git clone https://github.com/OpenSecurityResearch/hostapd-wpe   # or the maintained fork
# hostapd-wpe.conf: interface, ssid, channel, eap_user_file, cert paths
sudo hostapd-wpe hostapd-wpe.conf
#   ...  username: CORP\jdorian
#        challenge: aa:f2:...   response: a936:...
tail -f hostapd-wpe.log
asleap -C <challenge> -R <response> -W /usr/share/wordlists/rockyou.txt
hashcat -m 5500 'jdorian::::<response>:<challenge>' /usr/share/wordlists/rockyou.txt
```

Source: OpenSecurityResearch hostapd-wpe

## air-hammer — online password spray against WPA-Enterprise

**Trigger:** You have a valid username list (from EAP identity capture or OSINT) and want credentials without standing up a rogue AP.

`air-hammer` attacks the real network rather than impersonating it: it performs an online horizontal password spray against a WPA-Enterprise SSID, trying one password across many usernames via the genuine RADIUS server, which frequently backs onto Active Directory. This is the enterprise analogue of a domain password spray and it is powerful precisely because it needs no rogue AP, no deauthentication, and no client interaction — just a username list and a candidate password. The username list is exactly what EAP identity disclosure (in the evil-twin file) hands you, or what OSINT and the `DOMAIN\user` convention provide. The critical operational constraint is lockout: spraying against a RADIUS-fronted AD applies to real domain accounts, so pace it to one password per account per lockout window and confirm the domain lockout policy first, or the finding becomes "the tester locked out the workforce." Horizontal (one password, many users) is the safe shape; vertical (many passwords, one user) trips lockout fast.

```bash
git clone https://github.com/Wh1t3Rh1n0/air-hammer
# one password across many users (horizontal spray) against the real SSID
sudo python3 air-hammer.py -i wlan0 -e "CorpWiFi-ENT" -P password.txt -u users.txt
#   -P single-password file, -u user list  -> horizontal, lockout-safe
# Confirm the AD lockout policy first; pace to stay under the threshold.
```

Source: Wh1t3Rh1n0 air-hammer

## Passive identity and credential harvesting with crEAP

**Trigger:** You want to enumerate enterprise users and catch weak-method credentials without transmitting anything.

Enterprise networks leak in the clear before the TLS tunnel forms. `crEAP` passively parses a monitor-mode capture and extracts the EAP identities (the `DOMAIN\username` sent in the Identity Response) and, where a weak method like MD5 or an unprotected inner exchange is in use, the credentials themselves — all without a rogue AP or a single injected frame. Even when only identities are recovered, that is a live roster of authenticating users and the domain naming convention, which feeds `air-hammer` spraying and the internal phase. Because it is entirely passive it is the safest enterprise recon step and a clean standalone finding (identity disclosure), and it belongs early in the engagement for the same reason the evil-twin file captures identities early: it costs nothing and makes everything after it faster.

```bash
sudo airodump-ng wlan0mon -c 1 --essid "CorpWiFi-ENT" -w entcap
git clone https://github.com/Shellntel/scripts    # crEAP.py
sudo python3 crEAP.py -i wlan0mon                  # live, or feed a pcap
# identities -> users.txt for air-hammer and the internal phase
tshark -r entcap-01.cap -Y "eap.code==2 && eap.type==1" -T fields -e eap.identity | sort -u
```

Source: Shellntel crEAP

## EAP-TLS: certificate theft rather than credential capture

**Trigger:** The method is EAP-TLS, so there is no password — the only path is a client certificate and key lifted from an endpoint.

EAP-TLS authenticates the device with a client certificate and private key, and there is nothing for a rogue authenticator to harvest, so an evil twin correctly fails and that failure is the finding to report. The realistic path is lateral: obtain the certificate and its private key from a compromised endpoint (Windows machine or user certificate store, a MDM profile, a mobile keychain, or a config file), export it, and authenticate as that device. This is why an EAP-TLS network is usually only reachable *after* an internal foothold obtained some other way, not from the wireless edge — worth stating plainly, because it is also the reason EAP-TLS is the control to recommend. If a certificate is exported without its private key, it is useless for authentication; capture both.

```bash
# On a compromised Windows endpoint — export machine/user cert WITH private key
#   certutil -store My     # enumerate
#   PowerShell: Export-PfxCertificate -Cert Cert:\LocalMachine\My\<thumb> -FilePath c.pfx -Password ...
openssl pkcs12 -in c.pfx -clcerts -nokeys -out client.pem
openssl pkcs12 -in c.pfx -nocerts -nodes  -out client.key

cat > tls.conf <<'EOF'
network={
    ssid="CorpWiFi-ENT"
    key_mgmt=WPA-EAP
    eap=TLS
    identity="host/WS01.corp.local"
    client_cert="client.pem"
    private_key="client.key"
}
EOF
sudo wpa_supplicant -B -i wlan0 -c tls.conf && sudo dhclient wlan0
```

Source: Operator practice

## RADIUS-side attacks: shared secret and freeradius-wpe

**Trigger:** You have reached the RADIUS server or its shared secret, or captured RADIUS traffic between an AP and the server.

The RADIUS layer behind 802.1X has its own weaknesses once reachable. The **shared secret** between an AP (NAS) and the RADIUS server protects the RADIUS exchange, and it is often weak and reused across every AP; capturing an Access-Request/Response pair allows an offline dictionary attack on that secret, and a recovered secret lets you impersonate an AP to the server or a server to an AP. A compromised or attacker-run **FreeRADIUS-WPE** server logs every inner MSCHAPv2 exchange it processes, so if you can insert a rogue RADIUS into the path (or you already run one for the evil twin) you harvest credentials server-side. And a RADIUS server reachable on the network with default or weak management credentials exposes the entire client and secret database. These are post-foothold or infrastructure findings rather than wireless-edge attacks, but they are where an enterprise wireless compromise becomes total — one RADIUS box authenticates the whole estate.

```bash
# Crack a captured RADIUS shared secret from an Access-Request/Response pair
# (e.g. with a purpose-built cracker over the Message-Authenticator/Response Authenticator)
git clone https://github.com/joswr1ght/radius-crack     # or equivalent

# FreeRADIUS-WPE logs inner MSCHAPv2 when in the auth path
#   /usr/local/var/log/radius/freeradius-server-wpe.log
grep -iE "username|challenge|response" /var/log/radius/*wpe*.log
```

Source: Operator practice; FreeRADIUS-WPE
