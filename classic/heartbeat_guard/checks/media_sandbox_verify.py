#!/usr/bin/env python3
"""
HeartbeatGuard Check — Media Sandbox Escape Detection (OpenClaw 2026.3.24)

Detects the mediaUrl/fileUrl alias bypass (patched in OpenClaw 2026.3.24) that
allowed outbound tool and message actions to escape media-root restrictions.

What it checks:
  1. OpenClaw version — pre-2026.3.24 installs are vulnerable
  2. Config audit — scans for workspaceOnly/mediaRoot settings and verifies
     that media sandbox policy is explicitly configured
  3. Plugin scan — flags plugins or skills that reference mediaUrl/fileUrl
     aliasing patterns known to exploit the bypass

Severity mapping:
  CRITICAL — OpenClaw < 2026.3.24 AND media sandbox not locked down
  HIGH     — OpenClaw < 2026.3.24 (patch not applied)
  WARN     — No explicit mediaRoot / workspaceOnly policy configured
  PASS     — OpenClaw >= 2026.3.24 with explicit media sandbox policy

Why it matters: The sandbox escape allowed outbound tool and message actions
to read files outside the media root, enabling data exfiltration from the
host filesystem. CVE closed in 2026.3.24 release (#54034).

Copyright (c) 2026 Monomoy Strategies LLC
"""

import json
import os
import re
import subprocess
import sys
import glob
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


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
            # Extract version like "2026.3.24" from output
            match = re.search(r"(\d{4}\.\d+\.\d+)", result.stdout)
            if match:
                return match.group(1)
    except Exception:
        pass
    return None


def _parse_version_tuple(version_str: str) -> Tuple[int, ...]:
    """Parse '2026.3.24' into (2026, 3, 24)."""
    try:
        return tuple(int(p) for p in version_str.split("."))
    except (ValueError, AttributeError):
        return (0, 0, 0)


def _load_config() -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Load the first readable OpenClaw config file."""
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


def _scan_plugins_for_media_bypass(config: Dict[str, Any]) -> List[str]:
    """Scan plugin/skill directories for mediaUrl/fileUrl aliasing patterns."""
    flagged: List[str] = []
    home = Path.home()

    # Gather plugin/skill directories to scan
    dirs_to_scan: List[Path] = []
    openclaw_dir = home / ".openclaw"
    if openclaw_dir.exists():
        dirs_to_scan.append(openclaw_dir / "skills")
        dirs_to_scan.append(openclaw_dir / "plugins")

    # Also check workspace skills if configured
    workspace = config.get("workspace") or config.get("workspaceDir")
    if workspace:
        ws_path = Path(workspace)
        dirs_to_scan.append(ws_path / "skills")
        dirs_to_scan.append(ws_path / "plugins")

    bypass_patterns = [
        re.compile(r"mediaUrl\s*[=:]\s*.*fileUrl", re.IGNORECASE),
        re.compile(r"fileUrl\s*[=:]\s*.*mediaUrl", re.IGNORECASE),
        re.compile(r'["\'](media|file)Url["\'].*["\'](file|media)Url["\']', re.IGNORECASE),
        re.compile(r"alias.*media.*root", re.IGNORECASE),
        re.compile(r"(mediaUrl|fileUrl).*path\.join.*\.\.", re.IGNORECASE),
    ]

    for scan_dir in dirs_to_scan:
        if not scan_dir.exists():
            continue
        for ext in ("*.js", "*.ts", "*.mjs", "*.py"):
            for filepath in scan_dir.rglob(ext):
                try:
                    content = filepath.read_text(encoding="utf-8", errors="ignore")
                    if len(content) > 1_000_000:
                        continue
                    for pattern in bypass_patterns:
                        if pattern.search(content):
                            rel = str(filepath.relative_to(scan_dir.parent))
                            flagged.append(
                                f"{rel}: mediaUrl/fileUrl alias pattern detected "
                                f"(potential sandbox bypass)"
                            )
                            break
                except OSError:
                    continue

    return flagged


# ---------------------------------------------------------------------------
# Main check
# ---------------------------------------------------------------------------

def check_media_sandbox_verify() -> Dict[str, Any]:
    """
    Verify media sandbox integrity against the 2026.3.24 CVE.

    Returns a standard HeartbeatGuard result dict.
    """
    findings: List[str] = []
    warnings: List[str] = []
    critical: List[str] = []

    try:
        # 1. Version check
        version = _get_openclaw_version()
        patched = False

        if version:
            ver_tuple = _parse_version_tuple(version)
            patch_tuple = (2026, 3, 24)
            patched = ver_tuple >= patch_tuple

            if not patched:
                critical.append(
                    f"CRITICAL — OpenClaw {version} is vulnerable to media sandbox "
                    f"escape (mediaUrl/fileUrl alias bypass). Upgrade to 2026.3.24+ "
                    f"immediately. This allows outbound actions to read files outside "
                    f"the media root. (CVE patched in #54034)"
                )
            else:
                findings.append(
                    f"PASS — OpenClaw {version} includes the media sandbox escape fix "
                    f"(2026.3.24+)"
                )
        else:
            findings.append(
                "Media sandbox: OpenClaw version could not be determined. "
                "Verify manually that you are on 2026.3.24+."
            )

        # 2. Config audit — check media sandbox policy
        config, source = _load_config()

        if config:
            # Check for explicit workspaceOnly / mediaRoot settings
            agent_config = config.get("agent") or config.get("agents") or {}
            fs_policy = (
                agent_config.get("fsPolicy")
                or agent_config.get("fs_policy")
                or config.get("fsPolicy")
            )
            workspace_only = (
                agent_config.get("workspaceOnly")
                or config.get("workspaceOnly")
            )
            media_root = (
                config.get("mediaRoot")
                or config.get("media_root")
                or (config.get("gateway") or {}).get("mediaRoot")
            )

            if workspace_only is True or fs_policy == "workspaceOnly":
                findings.append(
                    f"PASS — workspaceOnly policy is enabled in {source}. "
                    f"Media sandbox restricts file access to workspace."
                )
            elif media_root:
                findings.append(
                    f"PASS — mediaRoot is explicitly configured in {source}: "
                    f"{str(media_root)[:60]}"
                )
            else:
                warnings.append(
                    f"WARN — No explicit workspaceOnly or mediaRoot policy in {source}. "
                    f"Without an explicit media sandbox policy, agents may access files "
                    f"outside the intended scope. Set fsPolicy: 'workspaceOnly' or "
                    f"configure mediaRoot."
                )

            # 3. Plugin scan
            bypass_hits = _scan_plugins_for_media_bypass(config)
            if bypass_hits:
                for hit in bypass_hits[:5]:
                    critical.append(f"CRITICAL — {hit}")
                if len(bypass_hits) > 5:
                    critical.append(
                        f"... and {len(bypass_hits) - 5} more mediaUrl/fileUrl "
                        f"bypass patterns found"
                    )
            else:
                findings.append(
                    "PASS — No mediaUrl/fileUrl alias bypass patterns found in "
                    "installed plugins/skills."
                )
        else:
            findings.append(
                "Media sandbox: No OpenClaw config found to audit. "
                "Skipping media policy and plugin scan."
            )

    except Exception as exc:
        warnings.append(f"Media sandbox check failed with unexpected error: {exc}")

    return {
        "category": "media_sandbox_verify",
        "findings": findings,
        "warnings": warnings,
        "critical": critical,
    }
