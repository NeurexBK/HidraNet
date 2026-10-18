#!/usr/bin/env python3
"""The IPv6 side of whoami-http.py: answers every request, on any address of
either family, with the address the request came from."""
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = (self.client_address[0].removeprefix("::ffff:") + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print("http request from", self.client_address[0], flush=True)


class DualStack(HTTPServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


DualStack(("::", 80), Handler).serve_forever()
