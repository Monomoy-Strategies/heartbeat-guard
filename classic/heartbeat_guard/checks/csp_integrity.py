#!/usr/bin/env python3
"""
HeartbeatGuard Check — CSP Integrity Verification (OpenClaw 2026.3.23)

Verifies that the gateway's served index.html has proper Content Security
Policy (CSP) headers with SHA-256 hashed inline scripts, as introduced in
OpenClaw 2026.3.23.

What it checks:
  1. OpenClaw version — pre-2026.3.23 installs lack CSP inline-script hashing
  2. Gateway index.html — looks for CSP meta tags or checks for SHA-256
     script-src directives
  3. Gateway HTTP response — if the gateway is reachable locally, fetches
     headers to verify CSP is served

Severity mapping:
  CRITICAL — Gateway reachable but no CSP script-src with sha256 hashes
  HIGH     — OpenClaw < 2026.3.23 (CSP hardening not available)
  WARN     — Cannot verify (gateway not reachable or index.html not found)
  PASS     — CSP script-src includes sha256 hashes

Why it matters: Without CSP hash-pinning, injected inline scripts (via XSS
or plugin tampering) execute freely in the Control UI. The 2026.3.23 fix
computes SHA-256 hashes for inline <script> blocks and blocks all others.

Copyright (c) 2026 Monomoy Strategies LLC
"""

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import urllib.request
    import urllib.error
    HTTP_AVAILABLE = True
except ImportError:
    HTTP_AVAILABLE = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_windows() -> bool:
    return os.name == "nt" or sys.platform.startswith("win")


def _get_openclaw_version() -> Optional[str]:
    """Try to get the installed OpenClaw version."""
    try:
        import shutil
        binary = shutil.which("openclaw")
        if not binary:
            return None
        result = subprocess.run(
            [binary, "--version"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            match = re.search(r"(\d{4}\.\d+\.\d+)", result.stdout)
            if match:
                return match.group(1)
    except Exception:
        pass
    return None


def _parse_version_tuple(version_str: str) -> Tuple[int, ...]:
    try:
        return tuple(int(p) for p in version_str.split("."))
    except (ValueError, AttributeError):
        return (0, 0, 0)


def _find_gateway_index_html() -> Optional[Path]:
    """Locate the gateway's served index.html."""
    home = Path.home()
    candidates: List[Path] = []

    # npm global install locations
    if _is_windows():
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            candidates.append(
                Path(appdata) / "npm" / "node_modules" / "openclaw" / "dist" / "control-ui" / "index.html"
            )
    else:
        candidates.extend([
            Path("/usr/local/lib/node_modules/openclaw/dist/control-ui/index.html"),
            Path("/usr/lib/node_modules/openclaw/dist/control-ui/index.html"),
        ])

    # npm root -g
    try:
        result = subprocess.run(
            "npm root -g",
            capture_output=True, text=True, timeout=10,
            shell=True, check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            npm_root = result.stdout.strip()
            candidates.append(
                Path(npm_root) / "openclaw" / "dist" / "control-ui" / "index.html"
            )
    except Exception:
        pass

    for path in candidates:
        if path.exists():
            return path
    return None


def _check_csp_in_html(html_content: str) -> Tuple[bool, List[str]]:
    """
    Check index.html for CSP meta tags with sha256 hashes in script-src.

    Returns (has_sha256_hashes, details_list).
    """
    details: List[str] = []

    # Look for <meta http-equiv="Content-Security-Policy" content="...">
    csp_meta_pattern = re.compile(
        r'<meta\s+http-equiv=["\']Content-Security-Policy["\']\s+'
        r'content=["\']([^"\']+)["\']',
        re.IGNORECASE
    )

    matches = csp_meta_pattern.findall(html_content)
    if not matches:
        details.append("No CSP meta tag found in index.html")
        return False, details

    for csp_value in matches:
        details.append(f"CSP meta tag found: {csp_value[:120]}...")

        # Check for sha256 hashes in script-src
        script_src_match = re.search(
            r"script-src\s+([^;]+)", csp_value, re.IGNORECASE
        )
        if script_src_match:
            script_src = script_src_match.group(1)
            sha256_hashes = re.findall(r"'sha256-[A-Za-z0-9+/=]+'", script_src)
            if sha256_hashes:
                details.append(
                    f"script-src includes {len(sha256_hashes)} SHA-256 hash(es) "
                    f"for inline scripts"
                )
                return True, details
            else:
                details.append(
                    "script-src directive found but no SHA-256 hashes present"
                )
        else:
            details.append("No script-src directive found in CSP")

    return False, details


def _check_gateway_csp_headers(port: int = 3001) -> Tuple[Optional[bool], List[str]]:
    """
    Fetch gateway response headers and check for CSP.

    Returns (has_csp_hashes_or_None, details).
    """
    details: List[str] = []
    if not HTTP_AVAILABLE:
        return None, ["HTTP library not available for header check"]

    url = f"http://localhost:{port}/"
    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=5) as resp:
            csp_header = resp.headers.get("Content-Security-Policy", "")
            if csp_header:
                details.append(f"CSP header present on gateway :{port}")
                sha256_hashes = re.findall(r"'sha256-[A-Za-z0-9+/=]+'", csp_header)
                if sha256_hashes:
                    details.append(
                        f"CSP script-src includes {len(sha256_hashes)} SHA-256 hash(es)"
                    )
                    return True, details
                else:
                    details.append("CSP header present but no SHA-256 script hashes")
                    return False, details
            else:
                details.append(f"No CSP header in gateway response on :{port}")
                return False, details
    except (urllib.error.URLError, OSError, TimeoutError):
        details.append(f"Gateway not reachable on localhost:{port} (may not be running)")
        return None, details
    except Exception as exc:
        details.append(f"Gateway header check failed: {exc}")
        return None, details


# ---------------------------------------------------------------------------
# Main check
# ---------------------------------------------------------------------------

def check_csp_integrity() -> Dict[str, Any]:
    """
    Verify CSP integrity on the OpenClaw gateway Control UI.

    Returns a standard HeartbeatGuard result dict.
    """
    findings: List[str] = []
    warnings: List[str] = []
    critical: List[str] = []

    try:
        # 1. Version check
        version = _get_openclaw_version()

        if version:
            ver_tuple = _parse_version_tuple(version)
            if ver_tuple < (2026, 3, 23):
                critical.append(
                    f"HIGH — OpenClaw {version} does not include CSP inline-script "
                    f"hashing (added in 2026.3.23). Without SHA-256 hash-pinning, "
                    f"injected inline scripts execute freely in the Control UI. "
                    f"Upgrade to 2026.3.23+."
                )
            else:
                findings.append(
                    f"PASS — OpenClaw {version} includes CSP hardening (2026.3.23+)"
                )

        # 2. Check index.html for CSP meta tags
        index_path = _find_gateway_index_html()
        if index_path:
            try:
                html_content = index_path.read_text(encoding="utf-8", errors="ignore")
                has_hashes, details = _check_csp_in_html(html_content)
                for detail in details:
                    findings.append(f"CSP file check: {detail}")

                if has_hashes:
                    findings.append(
                        f"PASS — Gateway index.html at {index_path} has CSP "
                        f"with SHA-256 inline script hashes"
                    )
                else:
                    if version and _parse_version_tuple(version) >= (2026, 3, 23):
                        warnings.append(
                            f"WARN — OpenClaw {version} should have CSP hashes but "
                            f"none found in {index_path}. Run `openclaw doctor --fix` "
                            f"to regenerate Control UI assets."
                        )
                    # Don't double-flag if version already flagged as critical
            except OSError as exc:
                warnings.append(f"Could not read gateway index.html: {exc}")
        else:
            findings.append(
                "CSP file check: Gateway index.html not found in standard locations. "
                "Skipping file-level CSP verification."
            )

        # 3. Live gateway header check
        gateway_port = int(os.environ.get("OPENCLAW_GATEWAY_PORT", "3001"))
        has_headers, header_details = _check_gateway_csp_headers(gateway_port)
        for detail in header_details:
            findings.append(f"CSP header check: {detail}")

        if has_headers is True:
            findings.append("PASS — Live gateway serving CSP with SHA-256 hashes")
        elif has_headers is False:
            warnings.append(
                f"WARN — Gateway on port {gateway_port} is serving responses without "
                f"SHA-256 CSP hashes. Inline scripts are not hash-pinned."
            )
        # has_headers is None → gateway not reachable, already noted in findings

    except Exception as exc:
        warnings.append(f"CSP integrity check failed with unexpected error: {exc}")

    return {
        "category": "csp_integrity",
        "findings": findings,
        "warnings": warnings,
        "critical": critical,
    }
