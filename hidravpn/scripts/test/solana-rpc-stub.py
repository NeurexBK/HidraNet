#!/usr/bin/env python3
"""Stands in for a Solana JSON-RPC node on the test network: answers
`getTransaction` for the signatures in the ledger file given, as a token
transfer of the amount there to the wallet there. Anything else is null, as
a transaction the chain never saw. The ledger is read on every request, so a
test "pays" by writing to it:

    {"<signature>": {"amount": 50004213, "time": 1700000000, "ok": true}}

`mint`, `owner`, `decimals` and `payer` may be given per entry to make a
transaction of the wrong token, to another wallet, of other decimals.
Not for anything else."""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

LEDGER, WALLET, MINT = sys.argv[1], sys.argv[2], sys.argv[3]
PAYER = "ExYv4idyqxmuodpoZtxyGxeTGi6oYrqFAshAgCsRissc"


def transaction(entry):
    amount = int(entry["amount"])
    owner = entry.get("owner", WALLET)
    mint = entry.get("mint", MINT)
    decimals = int(entry.get("decimals", 6))
    payer = entry.get("payer", PAYER)
    before = 900_000_000
    had = 1_000

    def bal(index, who, raw):
        return {"accountIndex": index, "owner": who, "mint": mint,
                "uiTokenAmount": {"amount": str(raw), "decimals": decimals,
                                  "uiAmount": raw / 10 ** decimals,
                                  "uiAmountString": str(raw / 10 ** decimals)}}

    return {
        "blockTime": int(entry["time"]),
        "slot": 1,
        "transaction": {"message": {}, "signatures": []},
        "meta": {
            "err": None if entry.get("ok", True) else {"InstructionError": [0, "Custom"]},
            "fee": 5000,
            "preTokenBalances": [bal(1, payer, before), bal(2, owner, had)],
            "postTokenBalances": [bal(1, payer, before - amount), bal(2, owner, had + amount)],
        },
    }


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        try:
            req = json.loads(self.rfile.read(n))
            sig = req["params"][0]
            method = req["method"]
        except (ValueError, KeyError, IndexError, TypeError):
            self.answer(400, {"jsonrpc": "2.0", "id": None,
                              "error": {"code": -32700, "message": "Parse error"}})
            return
        if method != "getTransaction":
            self.answer(200, {"jsonrpc": "2.0", "id": req.get("id"),
                              "error": {"code": -32601, "message": "Method not found"}})
            return
        try:
            with open(LEDGER) as f:
                ledger = json.load(f)
        except (OSError, ValueError):
            ledger = {}
        entry = ledger.get(sig)
        result = transaction(entry) if entry else None
        print("getTransaction", "known" if entry else "unknown", flush=True)
        self.answer(200, {"jsonrpc": "2.0", "id": req.get("id"), "result": result})

    def answer(self, status, body):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, fmt, *args):
        pass


HTTPServer(("0.0.0.0", 8899), Handler).serve_forever()
