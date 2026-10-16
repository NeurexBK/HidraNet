#!/usr/bin/env python3
"""Opens one TCP connection to a keep-alive HTTP server, makes a request,
waits until a file appears, then makes a second request on the SAME
connection. Prints "first ok", then "second ok" or "second blocked".

Used to prove that a connection opened before the kill switch does not carry
on through it: being an established connection must open nothing. Exit 0
when the second request was blocked, 1 when it got through."""
import os
import socket
import sys
import time

host, port, go = sys.argv[1], int(sys.argv[2]), sys.argv[3]
s = socket.create_connection((host, port), timeout=5)


def get():
    s.sendall(b"GET / HTTP/1.1\r\nHost: test\r\nConnection: keep-alive\r\n\r\n")
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = s.recv(4096)
        if not chunk:
            raise ConnectionError("closed")
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1])
    while len(body) < length:
        chunk = s.recv(4096)
        if not chunk:
            break
        body += chunk
    return head.split(b"\r\n")[0]


print("first ok" if b" 200 " in get() else "first failed", flush=True)
deadline = time.time() + 30
while not os.path.exists(go) and time.time() < deadline:
    time.sleep(0.1)
s.settimeout(3)
try:
    print("second ok" if b" 200 " in get() else "second failed", flush=True)
    sys.exit(1)
except Exception as e:  # a timeout or a reset: the kill switch cut it off
    print(f"second blocked ({type(e).__name__})", flush=True)
    sys.exit(0)
