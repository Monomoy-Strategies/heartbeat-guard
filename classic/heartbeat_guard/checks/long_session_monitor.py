#!/usr/bin/env python3
"""
HeartbeatGuard Check — Long-Running Agent Session Monitor (OpenClaw 2026.3.24)

Detects agent sessions that have been running for an unusually long time.
OpenClaw 2026.3.24 raised the default agent timeout from 600s to 48 hours,
meaning compromised agents can now run for 2 days before timing out.

What it checks:
  1. Session store — scans for active sessions exceeding a configurable
     duration threshold (default: 6 hours)
  2. Config audit — checks if the default timeout has been explicitly set
     or is riding the new 48h default
  3. Process check — looks for long-running openclaw agent processes

Severity mapping:
  CRITICAL — Session running > 24h (likely zombie or compromised)
  HIGH     — Session running > 12h
  WARN     — Session running > 6h OR using default 48h timeout without
             explicit configuration
  PASS     — All sessions within expected bounds

Why it matters: The Kugelfang incident (March 2026) showed compromised agents
that restart and wipe logs. A 48-hour timeout window gives attackers extended
persistence. Combined with cross-agent communication, this creates a larger
blast radius.

Copyright (c) 2026 Monomoy Strategies LLC
"""

import glob
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

WARN_THRESHOLD_HOURS: int = 6
HIGH_THRESHOLD_HOURS: int = 12
CRITICAL_THRESHOLD_HOURS: int = 24
DEFAULT_NEW_TIMEOUT_SECONDS: int = 172800  # 48h — the new 2026.3.24 default


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_windows() -> bool:
    return os.name == "nt" or sys.platform.startswith("win")


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


def _candidate_session_paths() -> List[str]:
    """Return glob patterns for OpenClaw session stores."""
    home = str(Path.home())
    patterns = []

    if _is_windows():
        patterns.extend([
            os.path.join(home, ".openclaw", "agents", "*", "sessions", "*.json"),
            os.path.join(home, ".openclaw", "agents", "*", "sessions", "*.jsonl"),
        ])
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            patterns.extend([
                os.path.join(appdata, "openclaw", "agents", "*", "sessions", "*.json"),
                os.path.join(appdata, "openclaw", "agents", "*", "sessions", "*.jsonl"),
            ])
    else:
        patterns.extend([
            os.path.join(home, ".openclaw", "agents", "*", "sessions", "*.json"),
            os.path.join(home, ".openclaw", "agents", "*", "sessions", "*.jsonl"),
        ])

    return patterns


def _parse_session_timestamp(value: Any) -> Optional[datetime]:
    """Parse a timestamp from various formats into a datetime."""
    if value is None:
        return None

    if isinstance(value, (int, float)):
        # Unix timestamp (seconds or milliseconds)
        if value > 1e12:
            value = value / 1000  # milliseconds
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (OSError, ValueError):
            return None

    if isinstance(value, str):
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S",
        ):
            try:
                dt = datetime.strptime(value, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue
    return None


def _scan_session_files() -> List[Dict[str, Any]]:
    """Scan session files and return info about active sessions."""
    sessions: List[Dict[str, Any]] = []
    now = datetime.now(tz=timezone.utc)

    for pattern in _candidate_session_paths():
        for filepath in glob.glob(pattern):
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()

                # Try JSON first
                try:
                    data = json.loads(content)
                except json.JSONDecodeError:
                    # Try reading last line as JSONL
                    lines = [l for l in content.strip().split("\n") if l.strip()]
                    if not lines:
                        continue
                    try:
                        data = json.loads(lines[-1])
                    except json.JSONDecodeError:
                        continue

                if not isinstance(data, dict):
                    continue

                # Extract session info
                started = (
                    _parse_session_timestamp(data.get("startedAt"))
                    or _parse_session_timestamp(data.get("started_at"))
                    or _parse_session_timestamp(data.get("createdAt"))
                    or _parse_session_timestamp(data.get("created_at"))
                    or _parse_session_timestamp(data.get("timestamp"))
                )
                last_activity = (
                    _parse_session_timestamp(data.get("lastActivity"))
                    or _parse_session_timestamp(data.get("last_activity"))
                    or _parse_session_timestamp(data.get("updatedAt"))
                    or _parse_session_timestamp(data.get("updated_at"))
                )

                status = data.get("status", "").lower()
                session_id = data.get("id") or data.get("sessionId") or os.path.basename(filepath)

                # Skip clearly ended sessions
                if status in ("completed", "ended", "cancelled", "failed"):
                    continue

                if started:
                    duration = now - started
                    hours = duration.total_seconds() / 3600

                    if hours > WARN_THRESHOLD_HOURS:
                        sessions.append({
                            "id": str(session_id)[:40],
                            "started": started.isoformat(),
                            "last_activity": last_activity.isoformat() if last_activity else "unknown",
                            "hours": round(hours, 1),
                            "status": status or "active",
                            "file": filepath,
                        })

            except OSError:
                continue

    return sessions


def _check_long_processes() -> List[Dict[str, Any]]:
    """Check for long-running openclaw agent processes."""
    long_procs: List[Dict[str, Any]] = []

    if not PSUTIL_AVAILABLE:
        return long_procs

    now = time.time()
    for proc in psutil.process_iter(["pid", "name", "cmdline", "create_time"]):
        try:
            pinfo = proc.info
            name = (pinfo.get("name") or "").lower()
            cmdline = " ".join(pinfo.get("cmdline") or []).lower()

            if "openclaw" not in name and "openclaw" not in cmdline:
                continue

            create_time = pinfo.get("create_time", 0)
            if create_time <= 0:
                continue

            hours = (now - create_time) / 3600
            if hours > WARN_THRESHOLD_HOURS:
                long_procs.append({
                    "pid": pinfo["pid"],
                    "name": pinfo.get("name", "unknown"),
                    "hours": round(hours, 1),
                })

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return long_procs


# ---------------------------------------------------------------------------
# Main check
# ---------------------------------------------------------------------------

def check_long_session_monitor() -> Dict[str, Any]:
    """
    Monitor for long-running agent sessions that may indicate
    compromise or zombie processes.

    Returns a standard HeartbeatGuard result dict.
    """
    findings: List[str] = []
    warnings: List[str] = []
    critical: List[str] = []

    try:
        # 1. Check timeout configuration
        config, source = _load_config()

        if config:
            agent_config = config.get("agent") or config.get("agents") or {}
            timeout = (
                agent_config.get("timeout")
                or agent_config.get("sessionTimeout")
                or config.get("agentTimeout")
            )

            if timeout is None:
                warnings.append(
                    f"WARN — No explicit agent timeout configured in {source}. "
                    f"OpenClaw 2026.3.24 raised the default from 600s to 48 hours. "
                    f"Set agent.timeout explicitly to limit session duration. "
                    f"Recommended: 3600 (1h) for most use cases."
                )
            elif isinstance(timeout, (int, float)) and timeout >= DEFAULT_NEW_TIMEOUT_SECONDS:
                warnings.append(
                    f"WARN — Agent timeout is set to {timeout}s ({timeout/3600:.0f}h) "
                    f"in {source}. This matches or exceeds the new 48h default. "
                    f"Consider reducing to limit blast radius of compromised sessions."
                )
            else:
                findings.append(
                    f"PASS — Agent timeout explicitly configured: {timeout}s "
                    f"({timeout/3600:.1f}h) in {source}"
                )

        # 2. Scan session files
        long_sessions = _scan_session_files()

        if long_sessions:
            for session in sorted(long_sessions, key=lambda s: s["hours"], reverse=True):
                hours = session["hours"]
                sid = session["id"]

                if hours > CRITICAL_THRESHOLD_HOURS:
                    critical.append(
                        f"CRITICAL — Agent session '{sid}' has been running for "
                        f"{hours:.1f} hours (>{CRITICAL_THRESHOLD_HOURS}h). "
                        f"Likely zombie or compromised. Started: {session['started']}. "
                        f"Last activity: {session['last_activity']}. "
                        f"Investigate and terminate if unauthorized."
                    )
                elif hours > HIGH_THRESHOLD_HOURS:
                    critical.append(
                        f"HIGH — Agent session '{sid}' running for {hours:.1f} hours "
                        f"(>{HIGH_THRESHOLD_HOURS}h). Review for legitimacy."
                    )
                else:
                    warnings.append(
                        f"WARN — Agent session '{sid}' running for {hours:.1f} hours "
                        f"(>{WARN_THRESHOLD_HOURS}h). Monitor closely."
                    )
        else:
            findings.append(
                "PASS — No long-running agent sessions detected "
                f"(threshold: >{WARN_THRESHOLD_HOURS}h)."
            )

        # 3. Check processes
        long_procs = _check_long_processes()
        if long_procs:
            for proc in long_procs:
                severity = "CRITICAL" if proc["hours"] > CRITICAL_THRESHOLD_HOURS else "WARN"
                msg = (
                    f"{severity} — OpenClaw process PID {proc['pid']} "
                    f"({proc['name']}) running for {proc['hours']:.1f} hours."
                )
                if severity == "CRITICAL":
                    critical.append(msg)
                else:
                    warnings.append(msg)
        elif PSUTIL_AVAILABLE:
            findings.append(
                "PASS — No long-running OpenClaw processes detected."
            )

    except Exception as exc:
        warnings.append(
            f"Long session monitor check failed with unexpected error: {exc}"
        )

    return {
        "category": "long_session_monitor",
        "findings": findings,
        "warnings": warnings,
        "critical": critical,
    }
