# tests/vulnerable_server.py
import http.server
import socketserver
import time
import json
import sys

# [!] VULNERABILITY: SINGLETON SHARED STATE
# In a threaded server, this global variable is shared across ALL requests.
# It effectively 'leaks' the identity of the user currently logging in to
# any other request occurring at the same time.
_SERVER_CONTEXT = {
    "current_identity": None,
    "is_admin": False
}

HOST = "127.0.0.1"
PORT = 8085

class VulnerableHandler(http.server.SimpleHTTPRequestHandler):
    def _send_json(self, status, data):
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def do_POST(self):
        """
        [ENDPOINT] /api/login
        The Trigger: Claims an identity, waits (opening the window), then denies it.
        """
        if self.path == "/api/login":
            length = int(self.headers.get('content-length', 0))
            body = self.rfile.read(length).decode('utf-8')
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                return self._send_json(400, {"error": "Bad JSON"})

            username = data.get("username")

            # [!] STATE POLLUTION START
            # The server sets the identity GLOBAL variable for logging/context
            # BEFORE validation is complete.
            _SERVER_CONTEXT["current_identity"] = username
            if username == "admin":
                _SERVER_CONTEXT["is_admin"] = True
            
            # [!] THE RACE WINDOW
            # Hashing passwords is slow (bcrypt/argon2). We simulate 300ms latency.
            # During this sleep, the server believes 'admin' is the active user.
            time.sleep(0.3)

            # [!] VALIDATION (Always fails for us)
            # We don't have the password, so we get rejected.
            # But the damage is done: the window was open for 0.3s.
            _SERVER_CONTEXT["current_identity"] = None
            _SERVER_CONTEXT["is_admin"] = False
            
            self._send_json(401, {"error": "Invalid Credentials"})
            return

    def do_GET(self):
        """
        [ENDPOINT] /api/dashboard
        The Target: Trusts the global state.
        """
        if self.path == "/api/dashboard":
            # [!] FLAW: Checks the shared global variable instead of a session token
            if _SERVER_CONTEXT["is_admin"]:
                self._send_json(200, {
                    "status": "ACCESS_GRANTED",
                    "msg": "Welcome, Administrator.",
                    "flag": "CIPHER{RACE_CONDITION_SINGLETON_STATE_WON}"
                })
            else:
                self._send_json(403, {"error": "Forbidden", "context": _SERVER_CONTEXT["current_identity"]})
            return

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Handle requests in separate threads to enable the race."""
    daemon_threads = True

if __name__ == "__main__":
    print(f"[*] Vulnerable Singleton Server running on http://{HOST}:{PORT}")
    print("[*] Target: Race the 'login' validation window.")
    server = ThreadedHTTPServer((HOST, PORT), VulnerableHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
