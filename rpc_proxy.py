#!/usr/bin/env python3
"""
HTTPS → HTTP proxy for Bitcoin Core RPC
- RPC user & password are **hard‑coded** (no need to embed in URL)
- Works with or without /wallet/…
"""

import http.server
import ssl
import urllib.request
import urllib.parse
import base64
from http import HTTPStatus

# ----------------------------------------------------------------------
# CONFIG – ONLY EDIT THESE LINES
# ----------------------------------------------------------------------
RPC_HOST      = "127.0.0.1"          # Bitcoin Core host
RPC_PORT      = 18443               # regtest (8332 for mainnet)
HTTPS_PORT    = 8443                # iOS connects here
CERT_FILE     = "bitcoin-proxy.crt" # self‑signed cert path
KEY_FILE      = "bitcoin-proxy.key"

# <<<=== HARD‑CODED RPC CREDENTIALS ===>>>
RPC_USER      = "user"
RPC_PASSWORD  = "password"
# ----------------------------------------------------------------------


# Pre‑compute the Authorization header once
_AUTH_HEADER = f"Basic {base64.b64encode(f'{RPC_USER}:{RPC_PASSWORD}'.encode()).decode()}"


class SimpleRPCProxy(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        # 1. Read body
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b""
        except Exception as e:
            self._send(400, f"Bad body: {e}")
            return

        # 2. Debug
        print("\n=== PROXY REQUEST ===")
        print(f"Path: {self.path}")
        print(f"Body: {body.decode(errors='replace')}")
        print(f"Authorization sent: {_AUTH_HEADER[:20]}…")
        print("=====================\n")

        # 3. Forward to Bitcoin Core
        target = f"http://{RPC_HOST}:{RPC_PORT}{self.path}"
        req = urllib.request.Request(target, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", _AUTH_HEADER)   # ALWAYS sent

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                resp_body = resp.read()
                self.send_response(resp.status)
                for k, v in resp.headers.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(resp_body)
                print(f"→ {resp.status} ({len(resp_body)} bytes)")

        except urllib.error.HTTPError as e:
            err_body = e.read()
            self.send_response(e.code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(err_body)
            print(f"← {e.code} {err_body.decode(errors='replace')}")

        except Exception as e:
            self._send(500, f"Proxy error: {e}")

    def do_GET(self):
        self._send(405, "POST only")

    def _send(self, code, msg):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(msg.encode())
        print(f"← {code} {msg}")

    def log_message(self, *args):
        pass   # silence default logs


# ----------------------------------------------------------------------
if __name__ == "__main__":
    httpd = http.server.HTTPServer(("0.0.0.0", HTTPS_PORT), SimpleRPCProxy)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    print(f"\nHTTPS RPC Proxy (hard‑coded auth)")
    print(f"   iOS → https://x.x.x.x:{HTTPS_PORT}/…")
    print(f"   Core ← http://{RPC_HOST}:{RPC_PORT}")
    print(f"   User: {RPC_USER}")
    print(f"   Auth header: {_AUTH_HEADER[:20]}…\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped")
