#!/usr/bin/env python3
"""A UDP listener that answers nothing: one line per datagram it gets,
"from IP:PORT", appended to a file. For the kill-switch tests, where a reply
would go somewhere other than the sender. Not for anything else.

  udp-sink.py FILE PORT [PORT...]   (every address)"""
import selectors
import socket
import sys

log = sys.argv[1]
sel = selectors.DefaultSelector()
for port in sys.argv[2:]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", int(port)))
    sel.register(s, selectors.EVENT_READ)
while True:
    for key, _ in sel.select():
        _, src = key.fileobj.recvfrom(2048)
        with open(log, "a") as f:
            f.write("from %s:%d\n" % src)
