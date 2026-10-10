#!/usr/bin/env python3
# CPENT OT drill — craft a realistic Modbus/TCP exchange and write a pcap
# (no capture privileges needed; analysis practice with tshark/wireshark).
# Usage: scapy-venv-python ot_drill.py /tmp/opencode/ot.pcap
import sys
from scapy.all import Ether, IP, TCP, wrpcap
from scapy.contrib.modbus import (
    ModbusADURequest, ModbusADUResponse,
    ModbusPDU03ReadHoldingRegistersRequest, ModbusPDU03ReadHoldingRegistersResponse,
    ModbusPDU06WriteSingleRegisterRequest, ModbusPDU06WriteSingleRegisterResponse,
    ModbusPDU01ReadCoilsRequest, ModbusPDU01ReadCoilsResponse,
)

MASTER, SLAVE = "10.10.99.100", "10.10.99.200"
OUT = sys.argv[1] if len(sys.argv) > 1 else "/tmp/opencode/ot.pcap"
pkts, t = [], 1000.0

def pair(req_pdu, resp_pdu, unit):
    global t, seq_m, seq_s
    req_bytes = bytes(ModbusADURequest(transId=TRANSACTION[0], unitId=unit)/req_pdu)
    resp_bytes = bytes(ModbusADUResponse(transId=TRANSACTION[0], unitId=unit)/resp_pdu)
    req = Ether(src=MASTER_MAC, dst=SLAVE_MAC)/IP(src=MASTER, dst=SLAVE)/ \
          TCP(sport=50200, dport=502, flags="PA", seq=seq_m, ack=seq_s)/req_bytes
    resp = Ether(src=SLAVE_MAC, dst=MASTER_MAC)/IP(src=SLAVE, dst=MASTER)/ \
           TCP(sport=502, dport=50200, flags="PA", seq=seq_s, ack=seq_m+len(req_bytes))/resp_bytes
    seq_m += len(req_bytes)
    seq_s += len(resp_bytes)
    req.time = t; resp.time = t + 0.01; t += 0.2; TRANSACTION[0] += 1
    pkts.extend([req, resp])

TRANSACTION = [1]
MASTER_MAC = "02:00:00:aa:00:64"
SLAVE_MAC  = "02:00:00:aa:00:c8"
seq_m, seq_s = 1, 1

pair(ModbusPDU03ReadHoldingRegistersRequest(startAddr=0, quantity=4),
     ModbusPDU03ReadHoldingRegistersResponse(registerVal=[300, 23, 4096, 7]), unit=1)
pair(ModbusPDU06WriteSingleRegisterRequest(registerAddr=2, registerValue=1337),
     ModbusPDU06WriteSingleRegisterResponse(registerAddr=2, registerValue=1337), unit=1)
pair(ModbusPDU01ReadCoilsRequest(startAddr=0, quantity=8),
     ModbusPDU01ReadCoilsResponse(coilStatus=0b10110001), unit=2)
pair(ModbusPDU03ReadHoldingRegistersRequest(startAddr=0, quantity=4),
     ModbusPDU03ReadHoldingRegistersResponse(registerVal=[300, 23, 1337, 7]), unit=1)

wrpcap(OUT, pkts)
print(f"wrote {len(pkts)} packets -> {OUT}")
print("Drill questions to answer from the pcap (verify with tshark):")
print("  1. MAC + IP of the device ISSUING Modbus requests")
print("  2. Unit IDs that answered, per exchange")
print("  3. Which register was WRITTEN, and to what value (before vs after)")
print("  4. Function codes used, in order")
