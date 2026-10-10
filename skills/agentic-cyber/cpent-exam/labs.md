# CPENT practice labs — weak-area drills (run before the exam window)

## Lab 1 — OT/Modbus pcap analysis (VERIFIED on this laptop, no root needed)

Generates a realistic master↔slave Modbus/TCP exchange as a pcap, then you
answer exam-style questions from it with tshark — the exact v1-form OT skill.

```bash
# 1. generate the drill pcap (scapy venv):
~/.local/share/pipx/venvs/scapy/bin/python \
  ~/.config/opencode/skills/cpent-exam/labs-ot-drill.py /tmp/opencode/ot.pcap

# 2. answer these BEFORE looking with tshark, then verify:
#    Q1 MAC+IP of the device ISSUING requests
#    Q2 which unit IDs answered
#    Q3 which register was WRITTEN, and its before/after value
#    Q4 function codes in order

# 3. verify (this tshark build ignores -T fields for modbus — use -V):
tshark -r /tmp/opencode/ot.pcap -Y mbtcp -V | grep -E "Frame [0-9]|Source Address|Function Code|Unit Identifier|Reference Number|Register [0-9]+ \(UINT16\):|Register Value"
```
Gotchas baked in on purpose: the display filter is **`mbtcp`** (not
"modbus"), and packets need proper TCP seq/ack progression or Wireshark
swallows the payloads (the generator handles it).
Exam-day live capture: `sudo tcpdump -i any port 502 -w ot.pcap` (type your
password interactively) → same tshark analysis. No traffic = proctor NOW.

## Lab 2 — Modbus server/client round-trip (active OT understanding)

```bash
V=~/.local/share/pipx/venvs/pymodbus/bin/python
$V - <<'EOF' &
from pymodbus.server import StartAsyncTcpServer
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext
import asyncio
ctx = ModbusServerContext(slaves=ModbusSlaveContext(hr=ModbusSequentialDataBlock(0,[100,200,300,400])), single=True)
asyncio.run(StartAsyncTcpServer(context=ctx, address=("127.0.0.1",15020)))
EOF
sleep 2 && $V - <<'EOF'
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient("127.0.0.1", port=15020); c.connect()
print("registers:", c.read_holding_registers(0,4).registers)
print("write:", c.write_register(2,1337))
print("after:", c.read_holding_registers(0,4).registers); c.close()
EOF
kill %1
```

## Lab 3 — Double pivot with chisel (docker, run when practicing)

Topology: attacker → edge (net1) → hop (net1+net2) → inner (net2).
```bash
docker network create p1; docker network create p2
docker run -d --rm --name edge --network p1 -v ~/tools:/x alpine sleep 1h
docker run -d --rm --name hop  --network p2 -v ~/tools:/x alpine sleep 1h
docker network connect p1 hop
docker run -d --rm --name inner --network p2 -v ~/tools:/x alpine sleep 1h
# inner hosts a "flag": docker exec inner sh -c 'echo flag{pivot-mastered} > /flag.txt'
# edge runs chisel SERVER (reverse mode); attacker connects, gets R:socks.
docker exec -d edge /x/chisel server -p 8000 --reverse
~/tools/../usr/bin/chisel client <edge-ip>:8000 R:socks      # attacker side (adjust path)
# HOP 2: through the socks proxy, run a SECOND chisel server on hop, connect
# again, chain proxychains (socks5 127.0.0.1:1080 → hop:1080), then:
proxychains4 -f chained.conf docker exec inner cat /flag.txt   # or nmap/smb via chain
docker rm -f edge hop inner; docker network rm p1 p2
```
Success = reading the inner flag through TWO hops in under 10 minutes.
(Docker daemon verified present; run this drill when images are pulled.
`docker run --rm` everywhere — nothing persists.)

## Lab 4 — Next.js gate battery (vs a local vulnerable app)

Pull a deliberately vulnerable Next.js middleware app (or build one with a
flagged version) and run web-nextjs.md §13 steps 1-7 against it locally.
Minimum set: the 5 CVE-2025-29927 header values from memory, `_next/image`
SSRF oracle, upload-field traversal, JWT forge/verify one-liner.

## Lab 5 — Report pipeline (5 minutes, do once)

```bash
CAP_ZONE=drill5 CAP_DIR=/tmp/opencode bash ~/.config/opencode/skills/cpent-exam/capture.sh 01 hostname
# write one Step S-1 from the four-block law into report-example.md's shape,
python3 ~/.config/opencode/skills/ctf-exam-report/scripts/validate_report.py --strict <your-file>
```
Goal: strict PASS on your own first attempt.
