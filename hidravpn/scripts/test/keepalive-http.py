#!/usr/bin/env python3
"""An HTTP/1.1 server that keeps the connection open between requests, so a
test can make two requests on one TCP connection: one before the kill switch
is armed and one after. Answers every GET with a short body."""
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


host = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 8082
HTTPServer((host, port), Handler).serve_forever()
