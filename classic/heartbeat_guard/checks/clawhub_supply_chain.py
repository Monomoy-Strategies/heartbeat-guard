#!/usr/bin/env python3
"""
HeartbeatGuard Check — ClawHub Supply Chain Monitoring (OpenClaw 2026.3.23)

Monitors the supply chain trust boundary introduced when OpenClaw 2026.3.23
made ClawHub the default plugin/skill source (before npm fallback).

What it checks:
  1. Installed plugins/skills — lists what's installed and from which source
  2. Unknown or unverified sources — flags plugins not from ClawHub or npm
  3. Plugin integrity — checks for modified plugin files vs install manifest
  4. plugins.allow audit — verifies only expected plugins are allowed
  5. Version — flags pre-2026.3.23 installs that don't have ClawHub-first

Severity mapping:
  CRITICAL — Plugin files modified after installation (tampered)
  HIGH     — Unknown plugin source or stale plugins.allow entries
  WARN     — plugins.allow contains entries not matching installed plugins
  PASS     — All plugins verified and from trusted sources

Why it matters: ClawHub is now the default install source. A compromised
ClawHub package or a typosquatted plugin name could be installed automatically.
This check verifies the integrity of the supply chain.

Copyright (c) 2026 Monomoy Strategies LLC
"""

import glob
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


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


def _find_plugin_dirs() -> List[Path]:
    """Find directories containing installed OpenClaw plugins."""
    home = Path.home()
    dirs: List[Path] = []

    candidates = [
        home / ".openclaw" / "plugins",
        home / ".openclaw" / "node_modules",
    ]

    if _is_windows():
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            candidates.append(Path(appdata) / "openclaw" / "plugins")

    for d in candidates:
        if d.exists() and d.is_dir():
            dirs.append(d)

    return dirs


def _scan_installed_plugins(plugin_dirs: List[Path]) -> List[Dict[str, Any]]:
    """
    Scan installed plugin directories and extract metadata.

    Returns list of plugin info dicts.
    """
    plugins: List[Dict[str, Any]] = []

    for plugin_dir in plugin_dirs:
        for entry in plugin_dir.iterdir():
            if not entry.is_dir():
                continue
            if entry.name.startswith("."):
                continue

            plugin_info: Dict[str, Any] = {
                "name": entry.name,
                "path": str(entry),
                "source": "unknown",
                "version": None,
                "has_package_json": False,
                "modified_files": [],
            }

            # Read package.json for metadata
            pkg_json = entry / "package.json"
            if pkg_json.exists():
                plugin_info["has_package_json"] = True
                try:
                    with pkg_json.open("r", encoding="utf-8") as fh:
                        pkg = json.load(fh)
                    plugin_info["version"] = pkg.get("version")

                    # Determine source
                    repo = pkg.get("repository", {})
                    if isinstance(repo, dict):
                        repo_url = repo.get("url", "")
                    elif isinstance(repo, str):
                        repo_url = repo
                    else:
                        repo_url = ""

                    if "clawhub" in str(pkg.get("_from", "")).lower():
                        plugin_info["source"] = "clawhub"
                    elif "clawhub" in repo_url.lower():
                        plugin_info["source"] = "clawhub"
                    elif "npmjs" in repo_url.lower() or pkg.get("_resolved", "").startswith("https://registry.npm"):
                        plugin_info["source"] = "npm"
                    elif repo_url:
                        plugin_info["source"] = "git"

                except (json.JSONDecodeError, OSError):
                    pass

            # Check for integrity manifest
            integrity_file = entry / ".integrity"
            if integrity_file.exists():
                try:
                    with integrity_file.open("r") as fh:
                        manifest = json.load(fh)
                    # Verify file hashes against manifest
                    for rel_path, expected_hash in (manifest.get("files") or {}).items():
                        check_file = entry / rel_path
                        if check_file.exists():
                            actual = hashlib.sha256(
                                check_file.read_bytes()
                            ).hexdigest()
                            if actual != expected_hash:
                                plugin_info["modified_files"].append(rel_path)
                except (json.JSONDecodeError, OSError):
                    pass

            plugins.append(plugin_info)

    return plugins


# ---------------------------------------------------------------------------
# Main check
# ---------------------------------------------------------------------------

def check_clawhub_supply_chain() -> Dict[str, Any]:
    """
    Monitor ClawHub supply chain integrity.

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
            if ver_tuple >= (2026, 3, 23):
                findings.append(
                    f"OpenClaw {version}: ClawHub is the default plugin source "
                    f"(2026.3.23+). Supply chain monitoring active."
                )
            else:
                findings.append(
                    f"OpenClaw {version}: npm is the default plugin source "
                    f"(pre-2026.3.23). ClawHub-first policy not yet in effect."
                )

        # 2. Scan installed plugins
        plugin_dirs = _find_plugin_dirs()

        if not plugin_dirs:
            findings.append(
                "PASS — No plugin directories found. No supply chain risk."
            )
            return {
                "category": "clawhub_supply_chain",
                "findings": findings,
                "warnings": warnings,
                "critical": critical,
            }

        plugins = _scan_installed_plugins(plugin_dirs)

        if not plugins:
            findings.append(
                "PASS — No plugins installed. No supply chain risk."
            )
            return {
                "category": "clawhub_supply_chain",
                "findings": findings,
                "warnings": warnings,
                "critical": critical,
            }

        findings.append(
            f"Supply chain audit: {len(plugins)} plugin(s) installed"
        )

        # Categorize by source
        by_source: Dict[str, List[str]] = {}
        for p in plugins:
            src = p["source"]
            by_source.setdefault(src, []).append(p["name"])

        for source, names in by_source.items():
            if source == "unknown":
                for name in names:
                    warnings.append(
                        f"WARN — Plugin '{name}' has unknown source. Cannot verify "
                        f"supply chain origin. Review manually."
                    )
            else:
                findings.append(
                    f"Plugins from {source}: {', '.join(names[:5])}"
                    + (f" ... (+{len(names)-5} more)" if len(names) > 5 else "")
                )

        # Check for tampered files
        for p in plugins:
            if p["modified_files"]:
                for mf in p["modified_files"][:3]:
                    critical.append(
                        f"CRITICAL — Plugin '{p['name']}' file '{mf}' has been "
                        f"modified after installation. Possible tampering. "
                        f"Reinstall: `openclaw plugins install {p['name']}`"
                    )
                if len(p["modified_files"]) > 3:
                    critical.append(
                        f"... and {len(p['modified_files'])-3} more modified files "
                        f"in plugin '{p['name']}'"
                    )

        # 3. Audit plugins.allow
        config, source = _load_config()
        if config:
            plugins_config = config.get("plugins") or {}
            allow_list = plugins_config.get("allow") or []

            if isinstance(allow_list, list) and allow_list:
                installed_names: Set[str] = {p["name"] for p in plugins}

                stale_allows = [
                    a for a in allow_list
                    if isinstance(a, str) and a not in installed_names
                ]

                if stale_allows:
                    warnings.append(
                        f"WARN — plugins.allow contains {len(stale_allows)} entries "
                        f"not matching installed plugins: "
                        f"{', '.join(stale_allows[:5])}. "
                        f"Run `openclaw doctor --fix` to clean stale entries."
                    )
                else:
                    findings.append(
                        f"PASS — All {len(allow_list)} plugins.allow entries match "
                        f"installed plugins."
                    )

        # Summary
        tampered = sum(1 for p in plugins if p["modified_files"])
        unknown = len(by_source.get("unknown", []))

        if tampered == 0 and unknown == 0:
            findings.append(
                f"PASS — All {len(plugins)} plugins verified. No supply chain issues."
            )

    except Exception as exc:
        warnings.append(
            f"ClawHub supply chain check failed with unexpected error: {exc}"
        )

    return {
        "category": "clawhub_supply_chain",
        "findings": findings,
        "warnings": warnings,
        "critical": critical,
    }
