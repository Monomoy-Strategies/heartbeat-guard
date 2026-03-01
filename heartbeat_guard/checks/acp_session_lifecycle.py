#!/usr/bin/env python3
"""
HeartbeatGuard Check — ACP Session Lifecycle

Reads the OpenClaw session store and audits ACP / thread-bound sessions
for signs of zombie sessions, unused sessions, and spawn loops.

Severity mapping:
  FAIL  — session count > 20 (possible spawn loop that could exhaust resources)
  WARN  — zombie sessions (last activity > 48h ago) OR unused sessions (no messages)
  PASS  — all ACP sessions look healthy (or session store absent)

Copyright (c) 2026 Monomoy Strategies LLC
"""

import json
import os
import re
import sys
import glob
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ZOMBIE_THRESHOLD_HOURS: int = 48    # sessions idle longer than this are zombies
SESSION_COUNT_LIMIT: int = 20       # more than this → possible spawn loop


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_windows() -> bool:
    return os.name == "nt" or sys.platform.startswith("win")


def _candidate_session_globs() -> List[str]:
    """
    Return glob patterns that cover the OpenClaw session store on both
    Windows and Linux/macOS.

    Typical paths:
      Linux:   ~/.openclaw/agents/*/sessions/sessions.json
      Windows: C:\\Users\\<user>\\.openclaw\\agents\\*\\sessions\\sessions.json
    """
    home = Path.home()
    patterns: List[str] = []

    # Environment override (highest priority)
    env_dir = os.environ.get("OPENCLAW_CONFIG_DIR") or os.environ.get("OPENCLAW_HOME")
    if env_dir:
        patterns.append(str(Path(env_dir) / "agents" / "*" / "sessions" / "sessions.json"))
        # Some installs put sessions.json one level up
        patterns.append(str(Path(env_dir) / "agents" / "*" / "sessions.json"))

    if _is_windows():
        appdata = os.environ.get("APPDATA", "")
        bases = [
            home / ".openclaw",
            Path(appdata) / "openclaw" if appdata else None,
            home / "AppData" / "Roaming" / "openclaw",
        ]
    else:
        bases = [
            home / ".openclaw",
            Path("/etc/openclaw"),
            Path("/usr/local/etc/openclaw"),
        ]

    for base in bases:
        if base is None:
            continue
        # Primary: agents/<agent-id>/sessions/sessions.json
        patterns.append(str(base / "agents" / "*" / "sessions" / "sessions.json"))
        # Alternative: agents/<agent-id>/sessions.json  (flat layout)
        patterns.append(str(base / "agents" / "*" / "sessions.json"))
        # Fallback: single global sessions file
        patterns.append(str(base / "sessions" / "sessions.json"))
        patterns.append(str(base / "sessions.json"))

    return patterns


def _find_session_files() -> List[str]:
    """Return all session.json files that actually exist on disk."""
    found: List[str] = []
    seen: set = set()
    for pattern in _candidate_session_globs():
        for match in glob.glob(pattern):
            if match not in seen and os.path.isfile(match):
                seen.add(match)
                found.append(match)
    return found


def _parse_timestamp(value: Any) -> Optional[datetime]:
    """
    Attempt to parse a timestamp value to a UTC-aware datetime.

    Handles:
      - Unix epoch int/float (seconds or milliseconds)
      - ISO-8601 strings
    """
    if value is None:
        return None

    # Numeric epoch
    if isinstance(value, (int, float)):
        ts = float(value)
        # Heuristic: milliseconds if > year 3000 in seconds
        if ts > 32_503_680_000:
            ts /= 1000.0
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None

    # String — try ISO-8601 variants
    if isinstance(value, str):
        raw = value.strip()
        # Normalise: replace trailing Z with +00:00, then try datetime.fromisoformat
        normalised = raw.rstrip("Z")
        # Remove timezone offset suffix (+HH:MM or -HH:MM) for strptime fallback
        tz_stripped = re.sub(r"[+-]\d{2}:?\d{2}$", "", normalised)
        for candidate in (raw, normalised, tz_stripped):
            for fmt in (
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S",
            ):
                try:
                    dt = datetime.strptime(candidate, fmt)
                    return dt.replace(tzinfo=timezone.utc)
                except ValueError:
                    continue

    return None


def _is_acp_session(session: Dict[str, Any]) -> bool:
    """
    Return True if this session record is ACP or thread-bound.

    Detection heuristics:
      - session.get('kind') contains 'acp' (case-insensitive)
      - session has a non-empty 'threadId' / 'thread_id' field
      - session has a non-empty 'acpContext' field
      - session type/kind is 'subagent' or 'beacon' bound to a thread
    """
    kind = str(session.get("kind") or session.get("type") or "").lower()
    if "acp" in kind:
        return True

    thread_id = session.get("threadId") or session.get("thread_id") or session.get("thread")
    if thread_id:
        return True

    if session.get("acpContext"):
        return True

    # Some installs store bound sessions with a 'binding' block
    binding = session.get("binding") or {}
    if isinstance(binding, dict) and binding.get("thread"):
        return True

    return False


def _session_last_activity(session: Dict[str, Any]) -> Optional[datetime]:
    """Return the most recent activity timestamp for a session."""
    candidates = [
        session.get("lastActivity"),
        session.get("last_activity"),
        session.get("lastMessage"),
        session.get("last_message"),
        session.get("updatedAt"),
        session.get("updated_at"),
        session.get("lastSeen"),
    ]
    parsed = [_parse_timestamp(v) for v in candidates if v is not None]
    valid = [dt for dt in parsed if dt is not None]
    return max(valid) if valid else None


def _session_message_count(session: Dict[str, Any]) -> int:
    """Return the message count for a session (0 = never used)."""
    mc = (
        session.get("messageCount")
        or session.get("message_count")
        or session.get("messages")
        or 0
    )
    if isinstance(mc, int):
        return mc
    if isinstance(mc, list):
        return len(mc)
    return 0


def _session_label(session: Dict[str, Any]) -> str:
    """Return a short human-readable label for a session."""
    sid = (
        session.get("id")
        or session.get("sessionId")
        or session.get("session_id")
        or "unknown"
    )
    kind = session.get("kind") or session.get("type") or ""
    label = str(sid)[:32]
    if kind:
        label += f" ({kind})"
    return label


def _load_sessions_from_file(path: str) -> List[Dict[str, Any]]:
    """
    Load and normalise sessions from a sessions.json file.

    The file may contain:
      - A JSON object (single session)
      - A JSON array of sessions
      - A JSON object with a 'sessions' key containing an array
    """
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            raw = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return []

    if isinstance(raw, list):
        return [s for s in raw if isinstance(s, dict)]

    if isinstance(raw, dict):
        # Shape: { "sessions": [...] }
        inner = raw.get("sessions") or raw.get("data")
        if isinstance(inner, list):
            return [s for s in inner if isinstance(s, dict)]
        # Shape: { "<session-id>": { ... } }  (object-keyed map)
        all_values = list(raw.values())
        if all(isinstance(v, dict) for v in all_values):
            return all_values
        # Fallback: treat the object itself as a single session
        return [raw]

    return []


# ---------------------------------------------------------------------------
# Main check
# ---------------------------------------------------------------------------

def check_acp_session_lifecycle() -> Dict[str, Any]:
    """
    Audit ACP / thread-bound sessions in the OpenClaw session store.

    Returns a standard HeartbeatGuard result dict:
      {
        "category": "acp_session_lifecycle",
        "findings": [...],   # PASS / informational
        "warnings": [...],   # WARN items
        "critical": [...],   # FAIL items
      }
    """
    findings: List[str] = []
    warnings: List[str] = []
    critical: List[str] = []

    try:
        session_files = _find_session_files()

        if not session_files:
            findings.append(
                "ACP session lifecycle: No OpenClaw session store found. "
                "This is normal on a fresh install or if sessions are stored remotely."
            )
            return {
                "category": "acp_session_lifecycle",
                "findings": findings,
                "warnings": warnings,
                "critical": critical,
            }

        findings.append(
            f"ACP session lifecycle: Found {len(session_files)} session file(s)."
        )

        # Collect all ACP sessions across all files
        all_sessions: List[Dict[str, Any]] = []
        for sf in session_files:
            sessions_in_file = _load_sessions_from_file(sf)
            for s in sessions_in_file:
                s["__source_file__"] = sf
            all_sessions.extend(sessions_in_file)

        total_all = len(all_sessions)
        acp_sessions = [s for s in all_sessions if _is_acp_session(s)]
        total_acp = len(acp_sessions)

        findings.append(
            f"Total sessions: {total_all} | ACP/thread-bound: {total_acp}"
        )

        if total_acp == 0:
            findings.append("ACP session lifecycle: No ACP sessions found — PASS")
            return {
                "category": "acp_session_lifecycle",
                "findings": findings,
                "warnings": warnings,
                "critical": critical,
            }

        # ── Check 1: Too many ACP sessions (spawn loop risk) ─────────────
        if total_acp > SESSION_COUNT_LIMIT:
            critical.append(
                f"FAIL — {total_acp} ACP/thread-bound sessions found "
                f"(limit: {SESSION_COUNT_LIMIT}). This may indicate a sub-agent "
                f"spawn loop. Inspect and clean up stale sessions. "
                f"Run: openclaw sessions list --kind acp"
            )
        else:
            findings.append(
                f"Session count OK: {total_acp} ACP session(s) "
                f"(below limit of {SESSION_COUNT_LIMIT})"
            )

        # ── Check 2 & 3: Zombie and unused sessions ───────────────────────
        now = datetime.now(tz=timezone.utc)
        zombie_threshold = now - timedelta(hours=ZOMBIE_THRESHOLD_HOURS)

        zombie_sessions: List[Tuple[str, datetime]] = []   # (label, last_activity)
        unused_sessions: List[str] = []                    # labels

        for session in acp_sessions:
            label = _session_label(session)
            msg_count = _session_message_count(session)
            last_activity = _session_last_activity(session)

            # Unused: spawned but never messaged
            if msg_count == 0:
                unused_sessions.append(label)

            # Zombie: last activity exceeds threshold
            if last_activity is not None and last_activity < zombie_threshold:
                zombie_sessions.append((label, last_activity))
            elif last_activity is None and msg_count == 0:
                # No timestamp AND no messages → treat as zombie-candidate
                unused_sessions.append(label)   # already added above, but mark intention

        # Report unused sessions
        if unused_sessions:
            # Deduplicate labels
            unique_unused = list(dict.fromkeys(unused_sessions))
            warnings.append(
                f"WARN — {len(unique_unused)} ACP session(s) have no messages "
                f"(spawned but never used): "
                + ", ".join(unique_unused[:5])
                + ("..." if len(unique_unused) > 5 else "")
            )

        # Report zombie sessions
        if zombie_sessions:
            # Sort by oldest first
            zombie_sessions.sort(key=lambda x: x[1])
            oldest_label, oldest_ts = zombie_sessions[0]
            hours_idle = (now - oldest_ts).total_seconds() / 3600

            warnings.append(
                f"WARN — {len(zombie_sessions)} zombie ACP session(s) detected "
                f"(idle > {ZOMBIE_THRESHOLD_HOURS}h). "
                f"Oldest: '{oldest_label}' last active "
                f"{hours_idle:.0f}h ago ({oldest_ts.strftime('%Y-%m-%d %H:%M')} UTC). "
                f"Consider running: openclaw sessions cleanup --older-than 48h"
            )

        # Overall PASS if no problems
        if not warnings and not critical:
            findings.append(
                f"ACP session lifecycle: All {total_acp} session(s) look healthy — PASS"
            )

    except Exception as exc:
        warnings.append(f"ACP session lifecycle check failed with unexpected error: {exc}")

    return {
        "category": "acp_session_lifecycle",
        "findings": findings,
        "warnings": warnings,
        "critical": critical,
    }
