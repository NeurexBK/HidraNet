#!/usr/bin/env python3
"""Load for the test network only: many admissions, many redemptions, many
idle connections at once, against a node's admission service. Prints one JSON
line of what came back.

  load-http.py admit  H:P SOURCES PER_SOURCE      (SOURCES: a,b,c addresses to send from)
  load-http.py redeem H:P REDEMPTIONS.json COPIES SOURCES [UNTAKEN.json]
                      (every pass sent COPIES times at once, from the sources in turn;
                      the passes no copy of which was taken written to UNTAKEN.json)
  load-http.py idle   H:P SOURCES PER_SOURCE GET_SOURCE
                      (that many idle connections, then one GET / from GET_SOURCE)
  load-http.py wallet-to-redemptions WALLET OUT [NODE_KEY]
"""
import base64
import json
import os
import socket
import sys
import threading
import time


def hp(s):
    h, p = s.rsplit(":", 1)
    return (h, int(p))


def post(addr, path, body, source=None, timeout=30):
    data = (f"POST {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {len(body)}\r\n\r\n").encode() + body
    t0 = time.monotonic()
    try:
        s = socket.create_connection(addr, timeout=timeout, source_address=(source, 0) if source else None)
        s.sendall(data)
        buf = b""
        while True:
            c = s.recv(65536)
            if not c:
                break
            buf += c
        s.close()
    except OSError as e:
        return ("error:" + type(e).__name__, b"", time.monotonic() - t0)
    head, _, rest = buf.partition(b"\r\n\r\n")
    parts = head.split(b" ", 2)
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else "garbled"
    return (status, rest, time.monotonic() - t0)


def run_all(jobs):
    """Starts every job at the same moment; returns their results in order."""
    results = [None] * len(jobs)
    go = threading.Event()

    def worker(i, fn):
        go.wait()
        results[i] = fn()

    ts = [threading.Thread(target=worker, args=(i, fn)) for i, fn in enumerate(jobs)]
    for t in ts:
        t.start()
    time.sleep(0.2)
    t0 = time.monotonic()
    go.set()
    for t in ts:
        t.join()
    return results, time.monotonic() - t0


def tally(results):
    out = {}
    for st, _, _ in results:
        out[str(st)] = out.get(str(st), 0) + 1
    return out


def cmd_admit(addr, sources, per):
    jobs = []
    for src in sources:
        for _ in range(per):
            key = base64.b64encode(os.urandom(32)).decode()
            body = json.dumps({"public_key": key, "name": "load"}).encode()
            jobs.append(lambda src=src, body=body: post(addr, "/admit", body, src))
    results, wall = run_all(jobs)
    addrs = []
    for st, body, _ in results:
        if st == 200:
            addrs.append(json.loads(body)["client_address"])
    print(json.dumps({
        "sent": len(jobs), "statuses": tally(results), "wall_secs": round(wall, 2),
        "slowest_secs": round(max(r[2] for r in results), 2),
        "admitted": len(addrs), "distinct_addresses": len(set(addrs)),
    }))


def cmd_redeem(addr, path, copies, sources, untaken=None):
    reds = json.load(open(path))
    jobs, which = [], []
    for i, red in enumerate(reds):
        body = json.dumps(red).encode()
        for c in range(copies):
            src = sources[(i * copies + c) % len(sources)]
            jobs.append(lambda body=body, src=src: post(addr, "/redeem", body, src))
            which.append(i)
    results, wall = run_all(jobs)
    per_pass = {}
    for i, (st, body, _) in zip(which, results):
        per_pass.setdefault(i, []).append(st)
    taken_twice = sum(1 for v in per_pass.values() if v.count(200) > 1)
    taken = sum(1 for v in per_pass.values() if 200 in v)
    addrs = [json.loads(b)["client_address"] for st, b, _ in results if st == 200]
    if untaken:
        json.dump([reds[i] for i, v in sorted(per_pass.items()) if 200 not in v], open(untaken, "w"))
    print(json.dumps({
        "passes": len(reds), "sent": len(jobs), "statuses": tally(results),
        "wall_secs": round(wall, 2), "slowest_secs": round(max(r[2] for r in results), 2),
        "passes_taken": taken, "passes_taken_twice": taken_twice,
        "distinct_addresses": len(set(addrs)),
    }))


def cmd_idle(addr, sources, per, get_source):
    socks = []
    for src in sources:
        for _ in range(per):
            try:
                socks.append(socket.create_connection(addr, timeout=10, source_address=(src, 0)))
            except OSError:
                pass
    time.sleep(0.5)
    t0 = time.monotonic()
    try:
        s = socket.create_connection(addr, timeout=30, source_address=(get_source, 0))
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        buf = b""
        while True:
            c = s.recv(65536)
            if not c:
                break
            buf += c
        status = int(buf.split(b" ", 2)[1]) if buf else "closed"
    except OSError as e:
        status = "error:" + type(e).__name__
    dt = time.monotonic() - t0
    for s in socks:
        s.close()
    print(json.dumps({"idle_connections": len(socks), "get_status": status, "get_secs": round(dt, 2)}))


def cmd_wallet(wallet, out, node_key=None):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    reds = []
    for p in json.load(open(wallet))["passes"]:
        if node_key and p["node_public_key"] != node_key:
            continue
        sk = X25519PrivateKey.from_private_bytes(base64.b64decode(p["client_secret"]))
        pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        red = {k: p[k] for k in ("key_id", "node_public_key", "nonce", "randomizer", "signature")}
        red["client_public_key"] = base64.b64encode(pub).decode()
        reds.append(red)
    json.dump(reds, open(out, "w"))
    print(len(reds))


def main():
    c = sys.argv[1]
    if c == "admit":
        cmd_admit(hp(sys.argv[2]), sys.argv[3].split(","), int(sys.argv[4]))
    elif c == "redeem":
        cmd_redeem(hp(sys.argv[2]), sys.argv[3], int(sys.argv[4]), sys.argv[5].split(","),
                   sys.argv[6] if len(sys.argv) > 6 else None)
    elif c == "idle":
        cmd_idle(hp(sys.argv[2]), sys.argv[3].split(","), int(sys.argv[4]), sys.argv[5])
    elif c == "wallet-to-redemptions":
        cmd_wallet(sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else None)
    else:
        sys.exit("unknown command")


if __name__ == "__main__":
    main()
