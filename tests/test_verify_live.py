import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis import verify
from aegis.models import Finding


class FixtureHandler(BaseHTTPRequestHandler):
    fixed = False  # flipped by the test class for the "patched" variant

    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/.env":
            if self.fixed:
                return self.send_error(404)
            body = b"DATABASE_URL=postgres://user:pass@db.internal:5432/app\nAPI_KEY=sk-test-123456\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return self.wfile.write(body)
        if self.path == "/.git/HEAD":
            if self.fixed:
                return self.send_error(404)
            body = b"ref: refs/heads/main\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return self.wfile.write(body)
        if self.path.startswith("/files"):
            if not self.fixed:
                body = b"<html><head><title>Index of /files/</title></head><body><h1>Index of /files/</h1><a href='backup.zip'>backup.zip</a></body></html>"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                return self.wfile.write(body)
        body = b"ok"
        self.send_response(200)
        if self.fixed:
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("Strict-Transport-Security", "max-age=31536000")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Access-Control-Allow-Origin", "https://app.example")
            self.send_header("Set-Cookie", "session=abc; Secure; HttpOnly; SameSite=Lax")
        else:
            origin = self.headers.get("Origin")
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Set-Cookie", "session=abc")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


FixtureHandlerFixed = type("FixedHandler", (FixtureHandler,), {"fixed": True, "server_version": "web", "sys_version": ""})


def serve(handler) -> tuple[ThreadingHTTPServer, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


class LiveVerifyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vuln_server, cls.vuln = serve(FixtureHandler)
        cls.fixed_server, cls.fixed = serve(FixtureHandlerFixed)

    @classmethod
    def tearDownClass(cls):
        cls.vuln_server.shutdown()
        cls.fixed_server.shutdown()

    def _finding(self, vuln_class, base, endpoint="/"):
        return Finding(title="t", vuln_class=vuln_class, severity="medium",
                       target=base, endpoint=base + endpoint)

    def test_vulnerable_target_verifies(self):
        cases = [
            ("security-headers", verify.verify_security_headers),
            ("cors", verify.verify_cors),
            ("cookie-flags", verify.verify_cookie_flags),
            ("info-disclosure", verify.verify_info_disclosure),
        ]
        for vuln_class, fn in cases:
            outcome = fn(self._finding(vuln_class, self.vuln))
            self.assertEqual(outcome["status"], "verified", f"{vuln_class}: {outcome}")

    def test_fixed_target_refutes(self):
        cases = [
            ("security-headers", verify.verify_security_headers),
            ("cors", verify.verify_cors),
            ("cookie-flags", verify.verify_cookie_flags),
            ("info-disclosure", verify.verify_info_disclosure),
        ]
        for vuln_class, fn in cases:
            outcome = fn(self._finding(vuln_class, self.fixed))
            self.assertEqual(outcome["status"], "refuted", f"{vuln_class}: {outcome}")


class JwtTests(unittest.TestCase):
    def _token(self, header: bytes, payload: bytes, sig: str) -> str:
        import base64

        enc = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
        return f"{enc(header)}.{enc(payload)}.{sig}"

    def test_alg_none_verified(self):
        token = self._token(b'{"alg":"none","typ":"JWT"}', b'{"sub":"1","exp":9999999999}', "")
        f = Finding(title="JWT", vuln_class="jwt", severity="high", target="https://a.example",
                    raw_evidence={"token": token})
        self.assertEqual(verify.verify_jwt(f)["status"], "verified")

    def test_signed_unexpired_refuted(self):
        token = self._token(b'{"alg":"HS256","typ":"JWT"}', b'{"sub":"1","exp":9999999999}', "abc123")
        f = Finding(title="JWT", vuln_class="jwt", severity="high", target="https://a.example",
                    raw_evidence={"token": token})
        self.assertEqual(verify.verify_jwt(f)["status"], "refuted")

    def test_no_token_inconclusive(self):
        f = Finding(title="JWT", vuln_class="jwt", severity="high", target="https://a.example")
        self.assertEqual(verify.verify_jwt(f)["status"], "inconclusive")


if __name__ == "__main__":
    unittest.main()
