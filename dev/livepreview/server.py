"""Imago localis ad probationem; non servitium productionis."""
import argparse
import hmac
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs

from probentium.contracts import ProbentiumError, strict_json
from probentium.screen import _integrity, safe_text
from probentium.workbench import Workbench

ASSETS = Path(__file__).parent


def build_server(case, port=5197):
    board = Workbench(case)
    if board.refresh().get("synthetic") is not True:
        raise ProbentiumError("preview_requires_synthetic_case")
    token = secrets.token_urlsafe(32)
    lock = threading.Lock()

    def safe_frame(width, height):
        frame = board.frame(width, height)
        if board.model.get("synthetic") is not True:
            raise ProbentiumError("preview_requires_synthetic_case")
        # Tituli breves eodem statu nituntur; fontes et viae non adduntur.
        frame["summary"] = {
            "case_name": safe_text(board.model.get("case_name"))[:160],
            "origin": "synthetic case",
            "integrity": _integrity(board.model),
            "version": safe_text(board.model.get("version"))[:32],
            "counts": {name: board.model.get("counts", {}).get(name)
                       for name in ("sources", "events", "controls", "filings")},
        }
        return frame

    class Handler(BaseHTTPRequestHandler):
        server_version = "LocalPreview"
        sys_version = ""

        def log_message(self, *_):
            pass

        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def respond(self, status, body, mime="application/json; charset=utf-8"):
            self.send_response(status)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
            self.end_headers()
            self.wfile.write(body)

        def reject(self, status=403):
            self.respond(status, b'{"error":"request_rejected"}')

        def valid_host(self):
            return self.headers.get("Host") in (f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}")

        def authorized(self):
            supplied = self.headers.get("X-Preview-Token", "")
            return self.valid_host() and len(supplied) <= 256 and hmac.compare_digest(supplied.encode("utf-8"), token.encode("ascii"))

        def dimensions(self, query):
            values = parse_qs(query)
            return max(80, min(220, int(values.get("width", [120])[0]))), max(24, min(70, int(values.get("height", [36])[0])))

        def do_GET(self):
            if not self.valid_host():
                return self.reject()
            if self.headers.get("Origin") not in (None, f"http://{self.headers.get('Host')}"):
                return self.reject()
            url = urlsplit(self.path)
            if url.path == "/":
                body = (ASSETS / "index.html").read_text().replace("PREVIEW_TOKEN", token).encode()
                return self.respond(200, body, "text/html; charset=utf-8")
            if url.path in ("/app.js", "/style.css"):
                body = (ASSETS / url.path[1:]).read_bytes()
                mime = "text/javascript; charset=utf-8" if url.path.endswith(".js") else "text/css; charset=utf-8"
                return self.respond(200, body, mime)
            if url.path != "/api/frame":
                return self.reject(404)
            if not self.authorized():
                return self.reject()
            try:
                width, height = self.dimensions(url.query)
                with lock:
                    frame = safe_frame(width, height)
                self.respond(200, json.dumps(frame, ensure_ascii=True).encode())
            except (ProbentiumError, ValueError, TypeError, OSError):
                self.respond(400, b'{"error":"frame_unavailable"}')

        def do_POST(self):
            if not self.authorized():
                return self.reject()
            origin = self.headers.get("Origin")
            if origin != f"http://{self.headers.get('Host')}":
                return self.reject()
            if self.path != "/api/key" or self.headers.get("Content-Type") != "application/json":
                return self.reject(400)
            try:
                size = int(self.headers.get("Content-Length", "-1"))
                if size < 0 or size > 4096 or self.headers.get("Transfer-Encoding"):
                    return self.reject(413)
                data = strict_json(self.rfile.read(size), max_bytes=4096)
                if not isinstance(data, dict) or set(data) != {"key", "width", "height"}:
                    return self.reject(400)
                if type(data["width"]) is not int or type(data["height"]) is not int:
                    return self.reject(400)
                width, height = max(80, min(220, data["width"])), max(24, min(70, data["height"]))
                with lock:
                    safe_frame(width, height)
                    if board.closed:
                        board.closed = False
                    board.key(data["key"])
                    frame = safe_frame(width, height)
                self.respond(200, json.dumps(frame, ensure_ascii=True).encode())
            except (ProbentiumError, ValueError, TypeError, OSError):
                self.respond(400, b'{"error":"action_unavailable"}')

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    return server


def main():
    parser = argparse.ArgumentParser(description="Synthetic-only local development viewer")
    parser.add_argument("--case", required=True)
    parser.add_argument("--port", type=int, default=5197)
    args = parser.parse_args()
    server = build_server(args.case, args.port)
    print(f"Local development preview: http://127.0.0.1:{server.server_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
