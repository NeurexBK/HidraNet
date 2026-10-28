#!/usr/bin/env python3
"""What one probe gets back, printed as one word:

  probe.py tcp HOST PORT   open | refused | silent | blocked
  probe.py udp HOST PORT   answered | silent | blocked
  probe.py icmp HOST       answered | silent | blocked   (an echo; needs root)

"refused" is a TCP reset: nothing listens, but the address answered.
"blocked" is this machine's own firewall refusing to send (EPERM).
"silent" is nothing back within the timeout. Not for anything else."""
import errno
import os
import socket
import struct
import sys
import time

TIMEOUT = 2.0


def tcp(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    try:
        s.connect((host, port))
        return "open"
    except ConnectionRefusedError:
        return "refused"
    except PermissionError:
        return "blocked"
    except OSError as e:
        return "blocked" if e.errno == errno.EPERM else "silent"


def udp(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(TIMEOUT)
    try:
        # 16 bytes, so a minimal DNS stub answers too.
        s.sendto(b"\x00" * 16, (host, port))
    except PermissionError:
        return "blocked"
    try:
        s.recvfrom(2048)
        return "answered"
    except OSError:
        return "silent"


def checksum(b):
    if len(b) % 2:
        b += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def icmp(host):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.settimeout(TIMEOUT)
    ident = os.getpid() & 0xFFFF
    body = struct.pack("!BBHHH", 8, 0, 0, ident, 1) + b"hidravpn"
    body = body[:2] + struct.pack("!H", checksum(body)) + body[4:]
    try:
        s.sendto(body, (host, 0))
    except PermissionError:
        return "blocked"
    end = time.time() + TIMEOUT
    while time.time() < end:
        try:
            data, src = s.recvfrom(2048)
        except OSError:
            break
        hl = (data[0] & 0x0F) * 4
        kind, _, _, rid, _ = struct.unpack("!BBHHH", data[hl : hl + 8])
        if kind == 0 and rid == ident and src[0] == host:
            return "answered"
    return "silent"


kind = sys.argv[1]
if kind == "tcp":
    print(tcp(sys.argv[2], int(sys.argv[3])))
elif kind == "udp":
    print(udp(sys.argv[2], int(sys.argv[3])))
elif kind == "icmp":
    print(icmp(sys.argv[2]))
else:
    sys.exit("probe.py tcp|udp|icmp HOST [PORT]")
