"""
HeartbeatGuard Dashboard — Local Web Server

Zero-dependency HTTP server using Python stdlib. Serves the dashboard
HTML template and provides a JSON API for live scan results.

Usage:
    from heartbeat_guard.dashboard import start_dashboard
    start_dashboard(port=8765)

Copyright (c) 2026 Monomoy Strategies LLC
"""

import json
import os
import signal
import sys
import threading
import time
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs
from typing import Any, Dict, Optional

from ..scanner import run_security_scan, ensure_data_files
from .transform import scan_to_modules
from .. import __version__


# ---------------------------------------------------------------------------
# Module-level scan cache
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_last_response: Optional[Dict[str, Any]] = None
_last_scan_time: float = 0.0
_SCAN_COOLDOWN: float = 10.0  # seconds between scans


# ---------------------------------------------------------------------------
# Template loading
# ---------------------------------------------------------------------------

_template_cache: Optional[bytes] = None


def _load_template() -> bytes:
    """Load the dashboard HTML template, with caching."""
    global _template_cache
    if _template_cache is not None:
        return _template_cache

    # Strategy 1: importlib.resources (works with installed packages)
    try:
        from importlib.resources import files
        template_bytes = (
            files("heartbeat_guard.dashboard")
            .joinpath("template.html")
            .read_bytes()
        )
        _template_cache = template_bytes
        return template_bytes
    except Exception:
        pass

    # Strategy 2: __file__-based (works with editable installs and dev)
    here = os.path.dirname(os.path.abspath(__file__))
    template_path = os.path.join(here, "template.html")
    if os.path.isfile(template_path):
        with open(template_path, "rb") as f:
            _template_cache = f.read()
        return _template_cache

    raise FileNotFoundError(
        "Dashboard template not found. Reinstall heartbeat-guard or check "
        "that template.html exists in the dashboard package directory."
    )


# ---------------------------------------------------------------------------
# HTTP Handler
# ---------------------------------------------------------------------------

class DashboardHandler(BaseHTTPRequestHandler):
    """Handle dashboard HTTP requests."""

    # Default scan level — set by start_dashboard()
    scan_level: str = "light"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/":
            self._serve_template()
        elif path == "/api/scan":
            params = parse_qs(parsed.query)
            level = params.get("level", [self.scan_level])[0]
            if level not in ("light", "full"):
                level = "light"
            self._handle_scan(level)
        elif path == "/api/status":
            self._handle_status()
        else:
            self.send_error(404, "Not Found")

    # ── Route handlers ────────────────────────────────────────────────────

    def _serve_template(self) -> None:
        try:
            html = _load_template()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(html)
        except FileNotFoundError as e:
            self._send_json({"error": str(e)}, status=500)

    def _handle_scan(self, level: str) -> None:
        global _last_response, _last_scan_time

        now = time.time()

        # Check cooldown — return cached result if too recent
        with _lock:
            if (
                _last_response is not None
                and (now - _last_scan_time) < _SCAN_COOLDOWN
            ):
                self._send_json(_last_response)
                return

        # Run the scan (outside the lock so other requests aren't blocked)
        try:
            ensure_data_files()
            scan_result = run_security_scan(level)
            response = scan_to_modules(scan_result)
        except Exception as e:
            response = {
                "modules": [],
                "summary": {
                    "total": 0, "passing": 0, "warnings": 0, "critical": 0
                },
                "error": str(e),
                "version": __version__,
            }

        # Cache the result
        with _lock:
            _last_response = response
            _last_scan_time = time.time()

        self._send_json(response)

    def _handle_status(self) -> None:
        with _lock:
            if _last_response is not None:
                self._send_json(_last_response)
                return

        # No scan run yet — return empty
        self._send_json({
            "modules": [],
            "summary": {
                "total": 0, "passing": 0, "warnings": 0, "critical": 0
            },
            "message": "No scan has been run yet. Waiting for first scan...",
            "version": __version__,
        })

    # ── Helpers ────────────────────────────────────────────────────────────

    def _send_json(self, data: Dict[str, Any], status: int = 200) -> None:
        body = json.dumps(data, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default stderr logging to keep console clean."""
        pass


# ---------------------------------------------------------------------------
# Threaded server (so long scans don't block page loads)
# ---------------------------------------------------------------------------

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def start_dashboard(
    port: int = 8765,
    scan_level: str = "light",
    open_browser: bool = True,
) -> None:
    """
    Start the HeartbeatGuard dashboard web server.

    Args:
        port: TCP port to listen on (default 8765)
        scan_level: 'light' or 'full' scan mode
        open_browser: whether to auto-open the browser
    """
    DashboardHandler.scan_level = scan_level

    # Try to bind, incrementing port if busy
    server = None
    for attempt in range(10):
        try:
            server = ThreadedHTTPServer(("127.0.0.1", port + attempt), DashboardHandler)
            if attempt > 0:
                port = port + attempt
            break
        except OSError:
            if attempt == 9:
                print(
                    f"Could not bind to any port in range "
                    f"{port}-{port + 9}. Check for other services.",
                    file=sys.stderr,
                )
                sys.exit(1)

    assert server is not None

    # Pre-load template to fail fast
    try:
        _load_template()
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    url = f"http://localhost:{port}"

    print()
    print("  ====================================================")
    print(f"   HeartbeatGuard Dashboard v{__version__}")
    print("  ====================================================")
    print(f"   URL:        {url}")
    print(f"   Scan mode:  {scan_level}")
    print(f"   Refresh:    every 60 seconds")
    print("  ====================================================")
    print()
    print("  Press Ctrl+C to stop the dashboard server.")
    print()

    # Start server in background thread
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    # Open browser
    if open_browser:
        webbrowser.open(url)

    # Block main thread until Ctrl+C (Windows-safe approach)
    stop_event = threading.Event()

    def _signal_handler(signum: int, frame: Any) -> None:
        stop_event.set()

    signal.signal(signal.SIGINT, _signal_handler)

    try:
        # On Windows, signal doesn't interrupt Event.wait() without a timeout
        while not stop_event.is_set():
            stop_event.wait(timeout=1.0)
    except KeyboardInterrupt:
        pass
    finally:
        print("\n  Shutting down dashboard server...")
        server.shutdown()
        print("  Done.")
