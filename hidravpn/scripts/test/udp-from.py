#!/usr/bin/env python3
"""Datagrams from a socket with a source address of its own. Prints the
socket's source address ("from IP"), then one word for the datagrams:
"sent"; "blocked" when this machine's own firewall refused one (EPERM); or
"refused" when ICMP errors about earlier ones kept one from being sent.

  udp-from.py SOURCE HOST PORT SIZE COUNT
      bound to SOURCE (0.0.0.0: the address the routes give), sends COUNT
      datagrams of SIZE bytes to HOST:PORT
  udp-from.py --wait FILE SOURCE HOST PORT SIZE COUNT
      the same, but sends only once FILE appears; the source address is
      fixed by the routes of the moment it starts: a socket opened before
      the routes changed

For the tests of what enters the tunnel. Not for anything else."""
import os
import socket
import sys
import time

args = sys.argv[1:]
go = None
if args[0] == "--wait":
    go, args = args[1], args[2:]
src, host, port, size, count = args[0], args[1], int(args[2]), int(args[3]), int(args[4])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((src, 0))
# Connecting picks the source address now, and the socket keeps it.
s.connect((host, port))
print("from", s.getsockname()[0], flush=True)
if go:
    deadline = time.time() + 60
    while not os.path.exists(go) and time.time() < deadline:
        time.sleep(0.1)


def send():
    # A connected socket hands back the ICMP error an earlier datagram drew
    # (nothing listens there) on the next send, which then sends nothing:
    # that one is sent again.
    for _ in range(2):
        try:
            s.send(b"\x00" * size)
            return "sent"
        except PermissionError:
            return "blocked"
        except ConnectionRefusedError:
            pass
    return "refused"


words = set()
for _ in range(count):
    words.add(send())
    time.sleep(0.05)
print("blocked" if "blocked" in words else "refused" if "refused" in words else "sent", flush=True)
