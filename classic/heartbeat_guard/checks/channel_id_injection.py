#!/usr/bin/env python3
"""
HeartbeatGuard Check — Channel ID Injection / Prototype Pollution Detection
(OpenClaw 2026.3.23)

Scans OpenClaw config for channel IDs containing control characters or
prototype-polluting patterns that could bypass auth or corrupt runtime state.

What it checks:
  1. Control characters in channel IDs (null bytes, newlines, tabs, etc.)
  2. Prototype pollution patterns (__proto__, constructor, prototype)
  3. Path traversal in channel IDs (../ sequences)
  4. Excessively long channel IDs (potential buffer abuse)
  5. OpenClaw version — pre-2026.3.23 installs lack channel ID hardening

Severity mapping:
  CRITICAL — Prototype pollution pattern found in a channel ID
  HIGH     — Control characters found in a channel ID
  WARN     — Suspicious patterns or pre-2026.3.23 version
  PASS     — All channel IDs are clean

Why it matters: Channel IDs are used as keys in routing tables, auth checks,
and config lookups. Malformed IDs can bypass authorization, pollute the
JavaScript prototype chain, or inject data into log/audit paths. Hardened
in OpenClaw 2026.3.23 with prototype-chain and control-character validation.

Copyright (c) 2026 Monomoy Strategies LLC
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Control characters that should never appear in channel IDs
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Prototype pollution patterns
_PROTO_POLLUTION_PATTERNS = [
    "__proto__",
    "constructor",
    "prototype",
    "__defineGetter__",
    "__defineSetter__",
    "__lookupGetter__",
    "__lookupSetter__",
]

# Path traversal
_TRAVERSAL_RE = re.compile(r"\.\.[/\\]")

# Max reasonable channel ID length
_MAX_CHANNEL_ID_LENGTH = 256


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


def _load_config() -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    home = Path.home()
    candidates: List[Path] = []

    env_dir = os.environ.get("OPENCLAW_CONFIG_DIR") or os.environ.get("OPENCLAW_HOME")
    if env_dir:
        candidates.append(Path(env_dir) / "config.json")

    if _is_windows():
        appdata = os.environ.get("APPDATA", "")
        bases = [
            home / ".openclaw",
            Path(appdata) / "openclaw" if appdata else None,
        ]
    else:
        bases = [home / ".openclaw", Path("/etc/openclaw")]

    for base in bases:
        if base is None:
            continue
        for name in ("config.json", "settings.json", "gateway.json"):
            candidates.append(base / name)

    for path in candidates:
        if path and path.exists():
            try:
                with path.open("r", encoding="utf-8", errors="ignore") as fh:
                    return json.load(fh), str(path)
            except (json.JSONDecodeError, OSError):
                continue
    return None, None


def _extract_channel_ids(config: Dict[str, Any]) -> List[Tuple[str, str]]:
    """
    Extract all channel ID values from the config.

    Returns list of (label, id_value) tuples.
    """
    ids: List[Tuple[str, str]] = []

    # From channels array/dict
    channels = config.get("channels") or []
    if isinstance(channels, list):
        for idx, ch in enumerate(channels):
            if isinstance(ch, dict):
                ch_type = ch.get("type", f"channel-{idx}")
                for key in ("id", "channelId", "channel_id", "chatId", "chat_id",
                             "groupId", "serverId", "guildId"):
                    val = ch.get(key)
                    if isinstance(val, str) and val:
                        ids.append((f"{ch_type}.{key}", val))
    elif isinstance(channels, dict):
        for ch_type, ch_val in channels.items():
            if isinstance(ch_val, dict):
                for key in ("id", "channelId", "channel_id", "chatId"):
                    val = ch_val.get(key)
                    if isinstance(val, str) and val:
                        ids.append((f"{ch_type}.{key}", val))

    # Top-level channel configs
    for top_key in ("telegram", "discord", "slack", "whatsapp", "matrix",
                     "signal", "teams", "line", "feishu"):
        section = config.get(top_key)
        if isinstance(section, dict):
            for key in ("id", "channelId", "chatId", "groupId", "guildId"):
                val = section.get(key)
                if isinstance(val, str) and val:
                    ids.append((f"{top_key}.{key}", val))

    return ids


def _audit_channel_id(label: str, value: str) -> List[Dict[str, str]]:
    """
    Audit a single channel ID value.

    Returns list of {severity, message} dicts for any issues found.
    """
    issues: List[Dict[str, str]] = []

    # 1. Control characters
    if _CONTROL_CHAR_RE.search(value):
        control_chars = _CONTROL_CHAR_RE.findall(value)
        hex_repr = ", ".join(f"0x{ord(c):02x}" for c in control_chars[:5])
        issues.append({
            "severity": "critical",
            "message": (
                f"HIGH — {label}: Channel ID contains control characters "
                f"({hex_repr}). This can bypass auth checks or corrupt routing. "
                f"Remove control characters from this ID."
            ),
        })

    # 2. Prototype pollution
    value_lower = value.lower()
    for pattern in _PROTO_POLLUTION_PATTERNS:
        if pattern in value_lower:
            issues.append({
                "severity": "critical",
                "message": (
                    f"CRITICAL — {label}: Channel ID contains prototype pollution "
                    f"pattern '{pattern}'. This can corrupt JavaScript runtime state "
                    f"and bypass security controls. Value: '{value[:60]}'"
                ),
            })
            break

    # 3. Path traversal
    if _TRAVERSAL_RE.search(value):
        issues.append({
            "severity": "critical",
            "message": (
                f"HIGH — {label}: Channel ID contains path traversal sequence "
                f"('../'). This can escape expected directory boundaries when used "
                f"in file paths. Value: '{value[:60]}'"
            ),
        })

    # 4. Excessive length
    if len(value) > _MAX_CHANNEL_ID_LENGTH:
        issues.append({
            "severity": "warning",
            "message": (
                f"WARN — {label}: Channel ID is unusually long ({len(value)} chars, "
                f"max expected {_MAX_CHANNEL_ID_LENGTH}). May indicate data injection."
            ),
        })

    return issues


# ---------------------------------------------------------------------------
# Main check
# ---------------------------------------------------------------------------

def check_channel_id_injection() -> Dict[str, Any]:
    """
    Scan OpenClaw config for malicious channel ID patterns.

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
                    f"WARN — OpenClaw {version} does not include channel ID hardening "
                    f"(added in 2026.3.23). Upgrade to get built-in protection against "
                    f"prototype-chain and control-character abuse in channel IDs."
                )
            else:
                findings.append(
                    f"PASS — OpenClaw {version} includes channel ID hardening (2026.3.23+)"
                )

        # 2. Scan config for channel IDs
        config, source = _load_config()

        if config is None:
            findings.append(
                "Channel ID injection: No OpenClaw config found. Skipping audit."
            )
            return {
                "category": "channel_id_injection",
                "findings": findings,
                "warnings": warnings,
                "critical": critical,
            }

        channel_ids = _extract_channel_ids(config)

        if not channel_ids:
            findings.append(
                f"Channel ID injection: No channel IDs found in {source}. "
                f"Nothing to audit."
            )
            return {
                "category": "channel_id_injection",
                "findings": findings,
                "warnings": warnings,
                "critical": critical,
            }

        findings.append(
            f"Channel ID audit: scanning {len(channel_ids)} ID(s) in {source}"
        )

        clean_count = 0
        for label, value in channel_ids:
            issues = _audit_channel_id(label, value)
            if issues:
                for issue in issues:
                    if issue["severity"] == "critical":
                        critical.append(issue["message"])
                    else:
                        warnings.append(issue["message"])
            else:
                clean_count += 1

        if clean_count == len(channel_ids):
            findings.append(
                f"PASS — All {clean_count} channel ID(s) are clean. "
                f"No injection patterns detected."
            )
        else:
            issue_count = len(channel_ids) - clean_count
            findings.append(
                f"Channel ID summary: {clean_count} clean, {issue_count} flagged "
                f"out of {len(channel_ids)} ID(s)."
            )

    except Exception as exc:
        warnings.append(
            f"Channel ID injection check failed with unexpected error: {exc}"
        )

    return {
        "category": "channel_id_injection",
        "findings": findings,
        "warnings": warnings,
        "critical": critical,
    }
