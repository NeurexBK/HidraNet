#!/usr/bin/env python3
"""Send one UDP datagram and wait briefly for any reply. Exit 0 if a reply
comes, 1 if it times out. Used to tell whether the kill switch let a datagram
through. Payload is 16 bytes so a minimal DNS stub also answers."""
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
timeout = float(sys.argv[3]) if len(sys.argv) > 3 else 2.0
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(timeout)
try:
    s.sendto(b"\x00" * 16, (host, port))
    s.recvfrom(2048)
    sys.exit(0)
except Exception:
    sys.exit(1)
