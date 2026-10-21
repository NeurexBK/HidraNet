#!/usr/bin/env python3
"""Stands in for the price feed on the test network: answers any request
with one pair of the mint given, at the price in the file given (dollars for
one token), read on every request so a test moves the market by writing to
it. A file that says "down" makes the feed answer nonsense, as a feed that
broke. Not for anything else."""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PRICE_FILE, MINT = sys.argv[1], sys.argv[2]


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            price = open(PRICE_FILE).read().strip()
        except OSError:
            price = "down"
        if price == "down":
            raw = b"<html>maintenance</html>"
        else:
            raw = json.dumps([{
                "chainId": "solana", "dexId": "test",
                "baseToken": {"address": MINT, "symbol": "HNET"},
                "quoteToken": {"address": "So11111111111111111111111111111111111111112", "symbol": "SOL"},
                "priceUsd": price, "liquidity": {"usd": 5000.0},
            }]).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, fmt, *args):
        pass


HTTPServer(("0.0.0.0", 8898), Handler).serve_forever()
