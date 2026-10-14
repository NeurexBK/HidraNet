#!/usr/bin/env python3
"""Throws malformed and mutated requests at the three doors that take
requests from anyone: a node's POST /admit, a node's POST /redeem and the
issuer's POST /issue. For the test network only.

Every answer must be a well-formed HTTP answer with an expected status, or a
connection the server closed; never a 500, never a hang longer than the
server's own per-connection timeout. A redemption mutated in a way that keeps
it the same pass (case, spaces) may be taken once; the same pass must never
be taken twice. Prints one line per finding and a summary; exits 1 on any
finding.

  fuzz-http.py --open H:P --pass H:P --issuer H:P --redemption FILE
               --token-file FILE --key-id HEX --rounds N --seed S
"""
import argparse
import base64
import json
import os
import random
import socket
import sys
import time

TIMEOUT = 8.0  # the servers give up on a connection after 5 s
OK_STATUS = {200, 400, 403, 404, 405, 409, 413, 429, 503}

findings = []
counts = {}
statuses = {}


def finding(what):
    findings.append(what)
    print("FINDING " + what, flush=True)


def send(addr, data, half_close=True):
    """Sends raw bytes, returns (status or None, body, seconds)."""
    host, port = addr
    t0 = time.monotonic()
    s = socket.create_connection((host, port), timeout=TIMEOUT)
    try:
        try:
            s.sendall(data)
            if half_close:
                s.shutdown(socket.SHUT_WR)
        except OSError:
            # The server answered and closed before taking all of it.
            pass
        buf = b""
        while True:
            try:
                c = s.recv(65536)
            except socket.timeout:
                return None, b"<timeout>", time.monotonic() - t0
            except OSError:
                break
            if not c:
                break
            buf += c
            if len(buf) > 1 << 20:
                break
    finally:
        s.close()
    dt = time.monotonic() - t0
    if not buf:
        return None, b"", dt
    head, _, body = buf.partition(b"\r\n\r\n")
    first = head.split(b"\r\n", 1)[0].split()
    if len(first) < 2 or not first[0].startswith(b"HTTP/1.") or not first[1].isdigit():
        return -1, buf[:200], dt
    lens = [l for l in head.split(b"\r\n")[1:] if l.lower().startswith(b"content-length:")]
    if lens and int(lens[0].split(b":", 1)[1]) != len(body):
        return -2, buf[:200], dt
    return int(first[1]), body, dt


def http(method, path, body, extra=b""):
    if isinstance(body, str):
        body = body.encode("utf-8", "surrogatepass")
    return (
        method.encode() + b" " + path.encode() + b" HTTP/1.1\r\nHost: x\r\n"
        + extra + b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )


def check(name, addr, data, half_close=True, allowed=OK_STATUS):
    status, body, dt = send(addr, data, half_close)
    counts[name] = counts.get(name, 0) + 1
    statuses[status] = statuses.get(status, 0) + 1
    if status is None:
        print(f"closed without an answer: {name} after {dt:.1f}s, sent {data[:70]!r}", flush=True)
    if status == -1:
        finding(f"{name}: not an HTTP answer: {body[:80]!r}")
    elif status == -2:
        finding(f"{name}: Content-Length does not match the body")
    elif status is not None and status not in allowed:
        finding(f"{name}: status {status}: {body[:160]!r}")
    if dt > 6.5:
        finding(f"{name}: answered after {dt:.1f}s, past the server's own timeout")
    if status is not None and status != 200 and body:
        try:
            json.loads(body)
        except ValueError:
            finding(f"{name}: a refusal that is not JSON: {body[:80]!r}")
    return status, body


# ---- generators -----------------------------------------------------------

def rand_bytes(r, n):
    return bytes(r.getrandbits(8) for _ in range(n))


def rand_string(r):
    pick = r.randrange(9)
    if pick == 0:
        return ""
    if pick == 1:
        return "A" * r.choice([1, 43, 44, 45, 342, 343, 344, 1000, 20000])
    if pick == 2:
        return base64.b64encode(rand_bytes(r, r.choice([0, 1, 31, 32, 33, 255, 256, 257]))).decode()
    if pick == 3:
        return "".join(chr(r.randrange(0x20, 0x2FFF)) for _ in range(r.randrange(1, 60)))
    if pick == 4:
        return "\u0000\ud800" if r.random() < 0.5 else "\n\r\t‮"
    if pick == 5:
        return "../" * r.randrange(1, 20) + "etc/passwd"
    if pick == 6:
        return rand_bytes(r, 8).hex()
    if pick == 7:
        return "%s%n%x" * 5
    return str(r.randrange(-2**63, 2**63))


def rand_json(r, depth=0):
    pick = r.randrange(8 if depth < 4 else 5)
    if pick == 0:
        return None
    if pick == 1:
        return r.choice([True, False])
    if pick == 2:
        return r.choice([0, -1, 2**64, 1e308, -0.0, 3.5])
    if pick in (3, 4):
        return rand_string(r)
    if pick == 5:
        return [rand_json(r, depth + 1) for _ in range(r.randrange(0, 5))]
    return {rand_string(r)[:20]: rand_json(r, depth + 1) for _ in range(r.randrange(0, 5))}


def mutate_obj(r, obj):
    """A copy of a request with one field broken."""
    o = dict(obj)
    if not o:
        return {rand_string(r)[:16] or "x": rand_json(r)}
    keys = list(o.keys())
    k = r.choice(keys)
    pick = r.randrange(10)
    if pick == 0:
        del o[k]
    elif pick == 1:
        o[k] = rand_json(r)
    elif pick == 2 and isinstance(o[k], str):
        s = o[k]
        if s:
            i = r.randrange(len(s))
            o[k] = s[:i] + chr(r.randrange(32, 127)) + s[i + 1:]
    elif pick == 3 and isinstance(o[k], str):
        o[k] = o[k] * r.randrange(2, 50)
    elif pick == 4:
        o[rand_string(r)[:16] or "x"] = rand_json(r)
    elif pick == 5 and isinstance(o[k], str):
        o[k] = o[k][: r.randrange(len(o[k]) + 1)]
    elif pick == 6:
        o[k] = [o[k]]
    elif pick == 7 and isinstance(o[k], list):
        o[k] = o[k] + [rand_string(r) for _ in range(r.randrange(1, 40))]
    elif pick == 8 and isinstance(o[k], str):
        # Another value of about the same size, or the padding dropped.
        if r.random() < 0.5:
            o[k] = base64.b64encode(rand_bytes(r, max(1, len(o[k]) * 3 // 4))).decode()
        else:
            o[k] = o[k].replace("=", "")
    else:
        o[k] = None
    return o


def raw_garbage(r, method, path):
    """Broken HTTP: the request line, the headers, the length."""
    pick = r.randrange(14)
    body = json.dumps(rand_json(r)).encode()
    if pick == 0:
        return rand_bytes(r, r.randrange(1, 3000))
    if pick == 1:
        return b"\r\n" * r.randrange(1, 100)
    if pick == 2:
        return method.encode() + b" " + path.encode() + b" HTTP/1.1\r\nContent-Length: -5\r\n\r\n" + body
    if pick == 3:
        return method.encode() + b" " + path.encode() + b" HTTP/1.1\r\nContent-Length: 99999999999999999999999\r\n\r\n"
    if pick == 4:
        return method.encode() + b" " + path.encode() + b" HTTP/1.1\r\nContent-Length: 10\r\nContent-Length: 0\r\n\r\n" + body
    if pick == 5:
        return method.encode() + b" " + path.encode() + b" HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
    if pick == 6:
        return method.encode() + b" " + path.encode() + b" HTTP/1.1\r\n" + (b"X-A: " + b"a" * 100 + b"\r\n") * 200 + b"\r\n"
    if pick == 7:
        return method.encode() + b" " + path.encode() + b" HTTP/1.1\r\nContent-Length: 16385\r\n\r\n" + b"{" * 16385
    if pick == 8:
        return method.encode() + b" /" + b"a" * 30000 + b" HTTP/1.1\r\n\r\n"
    if pick == 9:
        return method.encode() + b" " + path.encode() + b" HTTP/1.1\r\nContent-Length: 16384\r\n\r\n" + b"[" * 16384
    if pick == 10:
        return b"\xff\xfe" + method.encode() + b" " + path.encode() + b"\r\n\r\n"
    if pick == 11:
        return r.choice([b"DELETE", b"PUT", b"get", b"POST\x00", b"OPTIONS"]) + b" " + path.encode() + b" HTTP/1.1\r\n\r\n"
    if pick == 12:
        return method.encode() + b" " + path.encode() + b"?" + b"&".join([b"a=b"] * 500) + b" HTTP/1.1\r\n\r\n"
    return method.encode() + b" " + path.encode() + b" HTTP/1.1\r\nContent-Length: 2\r\n\r\n" + b"\xc3\x28"


def same_pass_variants(red):
    """The same pass, written differently: may be taken once at most."""
    v = []
    v.append(dict(red, key_id=red["key_id"].upper()))
    v.append(dict(red, key_id=" " + red["key_id"] + "\n"))
    v.append(dict(red, nonce=" " + red["nonce"] + " "))
    v.append(dict(red, nonce=red["nonce"].rstrip("=")))
    v.append(dict(red, nonce=red["nonce"].replace("+", "-").replace("/", "_")))
    v.append(dict(red, client_public_key=" " + red["client_public_key"]))
    v.append(dict(red, node_public_key=red["node_public_key"] + " "))
    v.append(dict(red, signature=red["signature"] + "\n"))
    # The last base64 character of a 32-byte value carries 4 unused bits:
    # another letter there decodes to the same bytes in a lax decoder.
    n = red["nonce"]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    last = n[-2]
    i = alphabet.index(last)
    for j in range(i & ~0xF, (i & ~0xF) + 16):
        if alphabet[j] != last:
            v.append(dict(red, nonce=n[:-2] + alphabet[j] + "="))
            break
    return v


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--open", required=True)
    ap.add_argument("--pass", dest="passnode", required=True)
    ap.add_argument("--issuer", required=True)
    ap.add_argument("--redemption", required=True)
    ap.add_argument("--token-file", required=True)
    ap.add_argument("--key-id", required=True)
    ap.add_argument("--rounds", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()

    def hp(s):
        h, p = s.rsplit(":", 1)
        return (h, int(p))

    open_n, pass_n, iss = hp(a.open), hp(a.passnode), hp(a.issuer)
    red = json.load(open(a.redemption))
    token = open(a.token_file).read().strip()
    r = random.Random(a.seed)

    good_admit = {"public_key": base64.b64encode(rand_bytes(r, 32)).decode(), "name": "fuzz"}
    good_issue = {"token": token, "key_id": a.key_id, "blinded": [base64.b64encode(rand_bytes(r, 256)).decode()]}

    # 1. Broken HTTP and broken JSON at every door.
    for i in range(a.rounds):
        target = r.choice([("admit", open_n, "/admit", good_admit),
                           ("admit-on-pass-node", pass_n, "/admit", good_admit),
                           ("redeem", pass_n, "/redeem", red),
                           ("redeem-on-open-node", open_n, "/redeem", red),
                           ("issue", iss, "/issue", good_issue)])
        name, addr, path, good = target
        kind = r.randrange(4)
        if kind == 0:
            data = raw_garbage(r, "POST", path)
        elif kind == 1:
            data = http("POST", path, json.dumps(rand_json(r)))
        elif kind == 2:
            m = good
            for _ in range(r.randrange(1, 4)):
                m = mutate_obj(r, m)
            # A mutated pass that is still the same pass is tried below, on its own.
            if name == "redeem" and all(m.get(k) == red[k] for k in red):
                continue
            if name == "issue":
                # Never spend the account's quota on purpose; a broken token keeps it.
                m = dict(m, token="x" + str(m.get("token")))
            data = http("POST", path, json.dumps(m))
        else:
            # Other methods and paths; a GET of / or /keys is answered.
            data = http(r.choice(["POST", "GET"]), r.choice([path, "/", "/node", "/keys", "/x", "//", "/admit/", "/redeem?x"]),
                        rand_bytes(r, r.randrange(0, 200)))
        status, body = check(name, addr, data, half_close=r.random() < 0.8)
        if not data.startswith(b"POST " + path.encode() + b" "):
            continue
        if name == "redeem" and status == 200:
            finding("redeem: a broken pass was taken: " + json.dumps(m)[:200] if kind == 2 else "redeem: 200 on garbage")
        if name == "issue" and status == 200 and path == "/issue":
            finding("issue: signed for a request with a broken token")

    # 2. The issuer with the real token and broken blinded messages: nothing
    # that is not a blinded message is signed, and nothing is charged for it.
    for i in range(200):
        bl = [r.choice([rand_string(r), base64.b64encode(rand_bytes(r, r.choice([255, 257, 0, 512]))).decode(), "=" * 344])
              for _ in range(r.randrange(1, 20))]
        st, body = check("issue-real-token", iss, http("POST", "/issue", json.dumps(dict(good_issue, blinded=bl))))
        if st == 200:
            finding("issue: signed something that is not a blinded message: " + json.dumps(bl)[:120])
    for n in (17, 100, 400):
        st, body = check("issue-too-many", iss, http("POST", "/issue", json.dumps(dict(good_issue, blinded=good_issue["blinded"] * n))))
        if st == 200:
            finding(f"issue: signed {n} at once, past the per-request limit")

    # 3. The real pass, written differently. At most one variant is taken,
    # and then the pass itself is refused as spent.
    taken = []
    for v in same_pass_variants(red):
        st, body = check("redeem-variant", pass_n, http("POST", "/redeem", json.dumps(v)))
        if st == 200:
            taken.append(v)
    if len(taken) > 1:
        finding(f"redeem: the same pass was taken {len(taken)} times, written differently")
    st, body = check("redeem-real", pass_n, http("POST", "/redeem", json.dumps(red)))
    if taken and st == 200:
        finding("redeem: the pass was taken again after a variant of it")
    if not taken and st != 200:
        finding(f"redeem: the real pass was refused: {st} {body[:120]!r}")
    st, body = check("redeem-again", pass_n, http("POST", "/redeem", json.dumps(red)))
    if st == 200:
        finding("redeem: the same pass was taken twice")
    elif st != 409:
        finding(f"redeem: a spent pass got {st}, not 409: {body[:120]!r}")

    # 4. Half-open connections: sent nothing, sent half a request.
    socks = []
    for addr in (open_n, pass_n, iss):
        for data in (b"", b"POST /admit HTTP/1.1\r\nContent-Length: 100\r\n\r\n{\"a\":"):
            s = socket.create_connection(addr, timeout=TIMEOUT)
            s.sendall(data)
            socks.append((addr, s))
    for addr, s in socks:
        t0 = time.monotonic()
        try:
            s.recv(4096)
        except (socket.timeout, ConnectionResetError):
            pass
        dt = time.monotonic() - t0
        if dt > 7.0:
            finding(f"a half-open connection to port {addr[1]} was kept {dt:.1f}s")
        s.close()

    # 5. The doors still work.
    st, body = check("after:node", open_n, http("GET", "/", ""))
    if st != 200:
        finding(f"after the fuzzing the open node does not describe itself: {st}")
    st, body = check("after:pass-node", pass_n, http("GET", "/", ""))
    if st != 200:
        finding(f"after the fuzzing the pass node does not describe itself: {st}")
    st, body = check("after:issuer", iss, http("GET", "/keys", ""))
    if st != 200:
        finding(f"after the fuzzing the issuer does not answer /keys: {st}")

    total = sum(counts.values())
    print(f"sent {total} requests: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
    print("answers: " + ", ".join(f"{k if k is not None else 'closed'}: {v}" for k, v in sorted(statuses.items(), key=lambda x: str(x[0]))))
    print(f"{len(findings)} finding(s)")
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
