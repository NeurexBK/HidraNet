#!/usr/bin/env python3
"""A DNS server for the test network: answers every A query with one address
and prints who asked, so the test can prove the question left through the
node and not from the client. Not for anything else."""
import socket
import struct
import sys

answer_ip = sys.argv[1] if len(sys.argv) > 1 else "10.201.0.2"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 53))
print("dns-stub listening", flush=True)
while True:
    data, src = sock.recvfrom(4096)
    if len(data) < 12:
        continue
    tid, flags, qd = struct.unpack("!HHH", data[:6])
    # Parse the first question name.
    i = 12
    labels = []
    while i < len(data) and data[i] != 0:
        n = data[i]
        labels.append(data[i + 1 : i + 1 + n].decode("ascii", "replace"))
        i += 1 + n
    qname = ".".join(labels)
    qend = i + 5  # null byte + qtype + qclass
    qtype = struct.unpack("!H", data[i + 1 : i + 3])[0] if i + 3 <= len(data) else 0
    print(f"query from {src[0]} for {qname} type {qtype}", flush=True)
    header = struct.pack("!HHHHHH", tid, 0x8180, 1, 1 if qtype == 1 else 0, 0, 0)
    question = data[12:qend]
    resp = header + question
    if qtype == 1:
        resp += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton(answer_ip)
    sock.sendto(resp, src)
