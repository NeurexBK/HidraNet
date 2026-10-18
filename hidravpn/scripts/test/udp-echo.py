#!/usr/bin/env python3
"""A UDP echo server standing in for the node's WireGuard endpoint in the
kill-switch test: whatever it receives, it sends back. Not for anything else."""
import socket
import sys

addr = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 51820
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((addr, port))
print("udp-echo listening", flush=True)
while True:
    data, src = s.recvfrom(2048)
    s.sendto(data, src)
