#!/usr/bin/env python3
"""
HeartbeatGuard Check — Config Validate (OpenClaw 2026.3.2)

Runs `openclaw config validate --json` (new in OpenClaw 2026.3.2) and surfaces
any config errors or warnings as HeartbeatGuard findings before they can cause
a gateway failure.

Severity mapping:
  CRITICAL — config errors present (gateway will not start with these)
  MEDIUM   — config warnings present (review before next upgrade)
  INFO     — command not available (pre-2026.3.2 install) or timeout
  PASS     — config is clean

Why it matters: Catches misconfigurations before they cause 3 AM outages.
The --json flag (new in 2026.3.2) makes this machine-readable and scriptable
for the first time.

Copyright (c) 2026 Monomoy Strategies LLC
"""

import json
import os
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_windows() -> bool:
    return os.name == "nt" or sys.platform.startswith("win")


def _find_openclaw_binary() -> Optional[str]:
    """
    Locate the openclaw binary using multiple strategies:
    1. shutil.which (PATH-based)
    2. %APPDATA%/npm/openclaw or openclaw.cmd (Windows npm global)
    3. npm root -g resolution
    4. /usr/local/bin/openclaw (common Unix install)
    """
    # Strategy 1: PATH
    found = shutil.which("openclaw")
    if found:
        return found

    if _is_windows():
        appdata = os.environ.get("APPDATA", "")
        candidates = []
        if appdata:
            candidates += [
                os.path.join(appdata, "npm", "openclaw.cmd"),
                os.path.join(appdata, "npm", "openclaw"),
            ]
        home = os.path.expanduser("~")
        candidates += [
            os.path.join(home, "AppData", "Roaming", "npm", "openclaw.cmd"),
            os.path.join(home, "AppData", "Roaming", "npm", "openclaw"),
        ]
        for c in candidates:
            if os.path.isfile(c):
                return c
    else:
        unix_candidates = [
            "/usr/local/bin/openclaw",
            "/usr/bin/openclaw",
            os.path.join(os.path.expanduser("~"), ".npm-global", "bin", "openclaw"),
        ]
        for c in unix_candidates:
            if os.path.isfile(c):
                return c

    # Strategy 3: npm root -g
    try:
        result = subprocess.run(
            "npm root -g",
            capture_output=True,
            text=True,
            timeout=10,
            shell=True,
            check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            npm_root = result.stdout.strip()
            candidates = [
                os.path.join(npm_root, ".bin", "openclaw"),
                os.path.join(npm_root, ".bin", "openclaw.cmd"),
            ]
            for c in candidates:
                if os.path.isfile(c):
                    return c
    except Exception:
        pass

    return None


def _run_config_validate(binary: str) -> Dict[str, Any]:
    """
    Run `openclaw config validate --json` and return a result dict:
        {
            "success": bool,
            "json_output": dict or None,
            "raw_stdout": str,
            "raw_stderr": str,
            "timed_out": bool,
            "not_found": bool,
        }
    """
    result: Dict[str, Any] = {
        "success": False,
        "json_output": None,
        "raw_stdout": "",
        "raw_stderr": "",
        "timed_out": False,
        "not_found": False,
    }

    try:
        proc = subprocess.run(
            [binary, "config", "validate", "--json"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        result["raw_stdout"] = proc.stdout.strip()
        result["raw_stderr"] = proc.stderr.strip()

        # Try to parse JSON from stdout
        if result["raw_stdout"]:
            try:
                result["json_output"] = json.loads(result["raw_stdout"])
                result["success"] = True
            except json.JSONDecodeError:
                # Command ran but didn't output JSON — flag as not available
                result["not_found"] = True
        else:
            # No stdout — could be old version or error
            result["not_found"] = True

    except subprocess.TimeoutExpired:
        result["timed_out"] = True
    except FileNotFoundError:
        result["not_found"] = True
    except Exception as exc:
        result["raw_stderr"] = str(exc)
        result["not_found"] = True

    return result


def _extract_errors_and_warnings(
    json_output: Dict[str, Any]
) -> tuple[List[str], List[str]]:
    """
    Extract error and warning messages from the JSON output of
    `openclaw config validate --json`.

    The schema may vary by openclaw version. We look for:
      - top-level 'errors', 'error', 'invalid' keys → errors list
      - top-level 'warnings', 'warning' keys → warnings list
      - top-level 'valid' / 'ok' bool → if False, treat as error
      - nested 'issues[]' with severity field
    """
    errors: List[str] = []
    warnings: List[str] = []

    if not isinstance(json_output, dict):
        return errors, warnings

    # ── Direct error keys ──────────────────────────────────────────────────
    for key in ("errors", "error"):
        val = json_output.get(key)
        if isinstance(val, list):
            errors.extend(str(v) for v in val if v)
        elif isinstance(val, str) and val:
            errors.append(val)
        elif isinstance(val, dict) and val:
            errors.append(json.dumps(val))

    # ── 'invalid' key ─────────────────────────────────────────────────────
    invalid = json_output.get("invalid")
    if isinstance(invalid, list):
        errors.extend(str(v) for v in invalid if v)
    elif isinstance(invalid, bool) and invalid:
        errors.append("Config is marked invalid by openclaw config validate")

    # ── 'valid' / 'ok' flag ───────────────────────────────────────────────
    for bool_key in ("valid", "ok"):
        val = json_output.get(bool_key)
        if val is False and not errors:
            errors.append(f"openclaw config validate reported {bool_key}=false")

    # ── Warning keys ──────────────────────────────────────────────────────
    for key in ("warnings", "warning"):
        val = json_output.get(key)
        if isinstance(val, list):
            warnings.extend(str(v) for v in val if v)
        elif isinstance(val, str) and val:
            warnings.append(val)

    # ── Generic 'issues' array with severity ─────────────────────────────
    issues = json_output.get("issues") or []
    if isinstance(issues, list):
        for issue in issues:
            if not isinstance(issue, dict):
                continue
            sev = str(issue.get("severity") or issue.get("level") or "").lower()
            msg = (
                issue.get("message")
                or issue.get("msg")
                or issue.get("description")
                or str(issue)
            )
            if sev in ("error", "critical", "fatal"):
                errors.append(str(msg))
            elif sev in ("warning", "warn", "medium"):
                warnings.append(str(msg))
            else:
                # Unknown severity — treat as warning
                warnings.append(str(msg))

    return errors, warnings


# ---------------------------------------------------------------------------
# Main check
# ---------------------------------------------------------------------------

def check_config_validate() -> Dict[str, Any]:
    """
    Run `openclaw config validate --json` and surface findings.

    Returns a standard HeartbeatGuard result dict:
      {
        "category": "config_validate",
        "findings": [...],   # PASS / informational
        "warnings": [...],   # MEDIUM items
        "critical": [...],   # CRITICAL items
      }
    """
    findings: List[str] = []
    warnings: List[str] = []
    critical: List[str] = []

    try:
        binary = _find_openclaw_binary()

        if binary is None:
            findings.append(
                "Config validate: openclaw binary not found in PATH or common install "
                "locations. Skipping config validation."
            )
            return {
                "category": "config_validate",
                "findings": findings,
                "warnings": warnings,
                "critical": critical,
            }

        run_result = _run_config_validate(binary)

        # ── Command not available / timed out ─────────────────────────────
        if run_result["timed_out"]:
            findings.append(
                "openclaw config validate not available (requires 2026.3.2+) — "
                "command timed out after 10s"
            )
            return {
                "category": "config_validate",
                "findings": findings,
                "warnings": warnings,
                "critical": critical,
            }

        if run_result["not_found"] or not run_result["success"]:
            stderr_hint = run_result.get("raw_stderr", "")
            # Check if the flag itself is unrecognised (pre-2026.3.2)
            if (
                "unknown" in stderr_hint.lower()
                or "unrecognized" in stderr_hint.lower()
                or "invalid" in stderr_hint.lower()
                or not run_result["raw_stdout"]
            ):
                findings.append(
                    "openclaw config validate not available (requires 2026.3.2+). "
                    "Upgrade to enable machine-readable config validation."
                )
            else:
                findings.append(
                    f"openclaw config validate not available (requires 2026.3.2+). "
                    f"stderr: {stderr_hint[:200]}" if stderr_hint else
                    "openclaw config validate not available (requires 2026.3.2+)"
                )
            return {
                "category": "config_validate",
                "findings": findings,
                "warnings": warnings,
                "critical": critical,
            }

        # ── Parse errors and warnings ──────────────────────────────────────
        json_output = run_result["json_output"] or {}
        errors, warn_msgs = _extract_errors_and_warnings(json_output)

        if errors:
            error_detail = "; ".join(errors[:5])
            if len(errors) > 5:
                error_detail += f" ... ({len(errors) - 5} more)"
            critical.append(
                f"Config validation failed: {error_detail}. "
                f"Fix before next gateway restart or your agent will not start."
            )

        if warn_msgs and not errors:
            # Only surface warnings if no errors (errors subsume warnings)
            warn_detail = "; ".join(warn_msgs[:5])
            if len(warn_msgs) > 5:
                warn_detail += f" ... ({len(warn_msgs) - 5} more)"
            warnings.append(
                f"Config warnings detected: {warn_detail}. "
                f"Review before next upgrade."
            )
        elif warn_msgs and errors:
            # Mention warnings exist but escalated to critical already
            findings.append(
                f"Additionally, {len(warn_msgs)} config warning(s) found "
                f"(resolve errors above first)."
            )

        # ── PASS ──────────────────────────────────────────────────────────
        if not errors and not warn_msgs:
            findings.append(
                "Config validate: openclaw config validate --json passed cleanly — PASS"
            )

    except Exception as exc:
        warnings.append(
            f"Config validate check encountered an unexpected error: {exc}"
        )

    return {
        "category": "config_validate",
        "findings": findings,
        "warnings": warnings,
        "critical": critical,
    }
