#!/usr/bin/env python3
"""
HeartbeatGuard Check — Credential Cache-Trace Audit (OpenClaw 2026.3.23)

Scans for JSONL cache-trace files that may contain leaked credentials from
pre-2026.3.23 OpenClaw installs. The 2026.3.23 release strips credential
fields from cache-trace output, but existing trace files written before the
patch may still contain sensitive data.

What it checks:
  1. Cache-trace JSONL files for credential patterns (API keys, tokens,
     passwords, secrets)
  2. Permissions on cache-trace files (world-readable = elevated risk)
  3. OpenClaw version — flags pre-2026.3.23 installs as still writing
     unredacted traces

Severity mapping:
  CRITICAL — Credential patterns found in cache-trace files
  HIGH     — Cache-trace files are world-readable and contain potential secrets
  WARN     — Pre-2026.3.23 version (still writing unredacted traces)
  PASS     — No credential leaks found in trace files, or no trace files exist

Why it matters: Cache-trace files may contain API keys, tokens, and other
credentials in plaintext. These files can be read by other processes on the
system or exfiltrated by compromised agents.

Copyright (c) 2026 Monomoy Strategies LLC
"""

import glob
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Patterns that indicate credential presence in trace data
_CREDENTIAL_PATTERNS = [
    re.compile(r'"(api[_-]?key|apiKey)"\s*:\s*"[^"]{8,}"', re.IGNORECASE),
    re.compile(r'"(token|auth[_-]?token|authToken)"\s*:\s*"[^"]{16,}"', re.IGNORECASE),
    re.compile(r'"(password|passwd|secret)"\s*:\s*"[^"]{4,}"', re.IGNORECASE),
    re.compile(r'"(access[_-]?key|accessKey)"\s*:\s*"[^"]{8,}"', re.IGNORECASE),
    re.compile(r'"(private[_-]?key|privateKey)"\s*:\s*"[^"]{16,}"', re.IGNORECASE),
    re.compile(r'"(bearer|authorization)"\s*:\s*"[^"]{8,}"', re.IGNORECASE),
    re.compile(r'"(bot[_-]?token|botToken)"\s*:\s*"[^"]{20,}"', re.IGNORECASE),
    re.compile(r'(sk-[a-zA-Z0-9]{20,})', re.IGNORECASE),  # OpenAI-style keys
    re.compile(r'(xoxb-[a-zA-Z0-9-]{20,})', re.IGNORECASE),  # Slack bot tokens
    re.compile(r'(ghp_[a-zA-Z0-9]{20,})', re.IGNORECASE),  # GitHub PATs
]

# Maximum bytes to scan per file (avoid reading huge trace files entirely)
_MAX_SCAN_BYTES = 5 * 1024 * 1024  # 5 MB

# Fields that should be redacted (present = leak)
_REDACTED_FIELD_NAMES = {
    "apiKey", "api_key", "token", "authToken", "auth_token",
    "password", "secret", "accessKey", "access_key",
    "privateKey", "private_key", "botToken", "bot_token",
    "bearerToken", "bearer_token", "credentials",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_windows() -> bool:
    return os.name == "nt" or sys.platform.startswith("win")


def _get_openclaw_version() -> Optional[str]:
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


def _find_cache_trace_files() -> List[Path]:
    """Locate cache-trace JSONL files in standard locations."""
    home = Path.home()
    trace_files: List[Path] = []

    search_dirs: List[Path] = []

    if _is_windows():
        appdata = os.environ.get("APPDATA", "")
        search_dirs.extend([
            home / ".openclaw" / "cache",
            home / ".openclaw" / "logs",
            home / ".openclaw" / "traces",
            home / ".openclaw" / "data",
        ])
        if appdata:
            search_dirs.extend([
                Path(appdata) / "openclaw" / "cache",
                Path(appdata) / "openclaw" / "logs",
                Path(appdata) / "openclaw" / "traces",
            ])
    else:
        search_dirs.extend([
            home / ".openclaw" / "cache",
            home / ".openclaw" / "logs",
            home / ".openclaw" / "traces",
            home / ".openclaw" / "data",
        ])

    for d in search_dirs:
        if d.exists():
            for ext in ("*.jsonl", "*cache-trace*", "*trace*.json"):
                for fp in d.glob(ext):
                    if fp.is_file():
                        trace_files.append(fp)

    return trace_files


def _is_world_readable(filepath: Path) -> bool:
    """Check if a file is world-readable (Unix only)."""
    if _is_windows():
        return False  # Windows ACLs are different; skip this check
    try:
        st = filepath.stat()
        return bool(st.st_mode & stat.S_IROTH)
    except OSError:
        return False


def _scan_file_for_credentials(filepath: Path) -> List[str]:
    """
    Scan a trace file for credential patterns.

    Returns list of findings (redacted — we never output the actual secret).
    """
    hits: List[str] = []
    try:
        with filepath.open("r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read(_MAX_SCAN_BYTES)

        for pattern in _CREDENTIAL_PATTERNS:
            matches = pattern.findall(content)
            if matches:
                # Report the field name, never the value
                sample = matches[0] if isinstance(matches[0], str) else matches[0]
                if len(sample) > 20:
                    sample = sample[:8] + "..." + sample[-4:]
                hits.append(
                    f"Credential pattern found in {filepath.name}: "
                    f"matched pattern '{pattern.pattern[:40]}...' "
                    f"({len(matches)} occurrence(s))"
                )

        # Also check for known field names that should be redacted
        for field in _REDACTED_FIELD_NAMES:
            # Look for "fieldName": "<non-redacted-value>"
            field_pattern = re.compile(
                rf'"{re.escape(field)}"\s*:\s*"(?!\[REDACTED\])[^"]+?"',
                re.IGNORECASE,
            )
            if field_pattern.search(content):
                hits.append(
                    f"Unredacted field '{field}' found in {filepath.name}. "
                    f"This field should be '[REDACTED]' in post-2026.3.23 traces."
                )

    except OSError as exc:
        hits.append(f"Could not read {filepath.name}: {exc}")

    return hits


# ---------------------------------------------------------------------------
# Main check
# ---------------------------------------------------------------------------

def check_cache_trace_audit() -> Dict[str, Any]:
    """
    Audit cache-trace files for leaked credentials.

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
                warnings.append(
                    f"WARN — OpenClaw {version} does not strip credentials from "
                    f"cache-trace output (fixed in 2026.3.23). Active trace files "
                    f"may contain plaintext API keys and tokens. Upgrade to stop "
                    f"writing new unredacted traces."
                )
            else:
                findings.append(
                    f"PASS — OpenClaw {version} strips credentials from cache-trace "
                    f"output (2026.3.23+). Checking for legacy trace files..."
                )

        # 2. Find and scan trace files
        trace_files = _find_cache_trace_files()

        if not trace_files:
            findings.append(
                "PASS — No cache-trace files found in standard locations. "
                "No credential leak risk from trace files."
            )
            return {
                "category": "cache_trace_audit",
                "findings": findings,
                "warnings": warnings,
                "critical": critical,
            }

        findings.append(
            f"Cache-trace audit: scanning {len(trace_files)} trace file(s)"
        )

        total_hits = 0
        for trace_file in trace_files:
            # Check permissions
            if _is_world_readable(trace_file):
                warnings.append(
                    f"WARN — {trace_file.name} is world-readable. "
                    f"Restrict permissions: chmod 600 {trace_file}"
                )

            # Scan for credentials
            hits = _scan_file_for_credentials(trace_file)
            if hits:
                total_hits += len(hits)
                for hit in hits[:3]:  # Limit output per file
                    critical.append(f"CRITICAL — {hit}")
                if len(hits) > 3:
                    critical.append(
                        f"... and {len(hits) - 3} more credential findings in "
                        f"{trace_file.name}"
                    )

        if total_hits == 0:
            findings.append(
                f"PASS — Scanned {len(trace_files)} trace file(s), "
                f"no credential patterns found."
            )
        else:
            critical.append(
                f"ACTION REQUIRED — {total_hits} credential leak(s) found across "
                f"{len(trace_files)} trace file(s). Delete or redact these files: "
                f"they may contain plaintext API keys, tokens, or passwords from "
                f"pre-2026.3.23 OpenClaw runs."
            )

    except Exception as exc:
        warnings.append(
            f"Cache-trace audit failed with unexpected error: {exc}"
        )

    return {
        "category": "cache_trace_audit",
        "findings": findings,
        "warnings": warnings,
        "critical": critical,
    }
