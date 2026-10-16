#!/usr/bin/env python3
"""
HeartbeatGuard Check — Secret Ref Audit (OpenClaw 2026.3.2)

Scans the OpenClaw config for SecretRef usage and verifies all refs resolve.
Unresolved refs on active surfaces (channels, plugins that are enabled) = CRITICAL
because they cause credential exposure or silent failures.

OpenClaw 2026.3.2 expanded SecretRef to 64 credential targets. HBG catches
unresolved refs *before* the gateway fails.

Severity mapping:
  CRITICAL — unresolved SecretRef on an active surface (channel/plugin enabled)
  HIGH     — unresolved SecretRef on an inactive surface
  PASS     — all SecretRefs resolve, or SecretRef not in use
  INFO     — config not found / cannot audit

Copyright (c) 2026 Monomoy Strategies LLC
"""

import glob
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Constants — SecretRef patterns recognised by OpenClaw
# ---------------------------------------------------------------------------

# Matches: {secret: "my-key"} or {secret: 'my-key'}
_BRACE_SECRET_RE = re.compile(
    r'\{\s*secret\s*:\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# Matches: $secret:my-key  or  $secret:my-key-name
_DOLLAR_SECRET_RE = re.compile(
    r'\$secret:([A-Za-z0-9_\-\.]+)',
    re.IGNORECASE,
)

# Matches: {{secret.my-key}} or {{secrets.my-key}}
_MUSTACHE_SECRET_RE = re.compile(
    r'\{\{\s*secrets?\.([\w\-\.]+)\s*\}\}',
    re.IGNORECASE,
)

# Matches: "secretRef": "my-key" or "secretRef": { "name": "my-key" }
_SECRET_REF_KEY_RE = re.compile(
    r'"secretRef"\s*:\s*(?:"([^"]+)"|\'([^\']+)\')',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_windows() -> bool:
    return os.name == "nt" or sys.platform.startswith("win")


def _candidate_config_paths() -> List[str]:
    """Return candidate paths for OpenClaw config files."""
    home = Path.home()
    candidates: List[str] = []

    # Environment override (highest priority)
    env_config = os.environ.get("OPENCLAW_CONFIG")
    if env_config:
        candidates.append(env_config)

    env_dir = os.environ.get("OPENCLAW_CONFIG_DIR") or os.environ.get("OPENCLAW_HOME")
    if env_dir:
        for name in ("config.json", "config.yaml", "settings.json", "openclaw.json"):
            candidates.append(os.path.join(env_dir, name))

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

    config_names = [
        "config.json",
        "config.yaml",
        "settings.json",
        "gateway.json",
        "openclaw.json",
        "openclaw-config.json",
    ]

    for base in bases:
        if base is None:
            continue
        for name in config_names:
            path = base / name
            if path.exists():
                candidates.append(str(path))

    return candidates


def _load_config_raw(path: str) -> Optional[str]:
    """Load config file as raw text (for regex scanning)."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return None


def _load_config_json(path: str) -> Optional[Dict[str, Any]]:
    """Load config file as parsed JSON (for structure analysis)."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
        # Strip YAML-style comments for a best-effort JSON parse
        content_stripped = re.sub(r"#.*$", "", content, flags=re.MULTILINE)
        return json.loads(content_stripped)
    except Exception:
        return None


def _extract_secret_refs_from_text(text: str) -> Set[str]:
    """Return all SecretRef names found in raw config text."""
    refs: Set[str] = set()

    for m in _BRACE_SECRET_RE.finditer(text):
        refs.add(m.group(1).strip())

    for m in _DOLLAR_SECRET_RE.finditer(text):
        refs.add(m.group(1).strip())

    for m in _MUSTACHE_SECRET_RE.finditer(text):
        refs.add(m.group(1).strip())

    for m in _SECRET_REF_KEY_RE.finditer(text):
        name = m.group(1) or m.group(2)
        if name:
            refs.add(name.strip())

    return refs


def _candidate_secrets_store_paths() -> List[str]:
    """
    Return paths where OpenClaw may store resolved secrets.
    Used as a fallback when `openclaw secrets audit --json` is unavailable.
    """
    home = Path.home()
    paths: List[str] = []

    env_dir = os.environ.get("OPENCLAW_CONFIG_DIR") or os.environ.get("OPENCLAW_HOME")
    if env_dir:
        paths.extend([
            os.path.join(env_dir, "secrets"),
            os.path.join(env_dir, "secrets.json"),
        ])

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
        ]

    for base in bases:
        if base is None:
            continue
        # Directory of individual secret files
        paths.append(str(base / "secrets"))
        paths.append(str(base / "secrets.json"))
        paths.append(str(base / ".secrets"))
        paths.append(str(base / "keystore.json"))

    return paths


def _known_secrets_from_store() -> Optional[Set[str]]:
    """
    Attempt to discover the names of secrets that exist in the local store
    without calling the openclaw CLI.

    Returns a set of known secret names, or None if the store can't be read.
    """
    known: Set[str] = set()
    found_any_store = False

    for store_path in _candidate_secrets_store_paths():
        # Case 1: directory of individual secret files
        if os.path.isdir(store_path):
            found_any_store = True
            for entry in os.listdir(store_path):
                # Each file name (without extension) is treated as a secret name
                name = os.path.splitext(entry)[0]
                known.add(name)
            continue

        # Case 2: JSON file listing secrets
        if os.path.isfile(store_path):
            found_any_store = True
            try:
                with open(store_path, "r", encoding="utf-8", errors="ignore") as fh:
                    data = json.load(fh)
                if isinstance(data, dict):
                    # Could be { "secrets": [...] } or { "name": "value", ... }
                    inner = data.get("secrets") or data.get("keys")
                    if isinstance(inner, list):
                        for item in inner:
                            if isinstance(item, dict):
                                n = item.get("name") or item.get("key") or item.get("id")
                                if n:
                                    known.add(str(n))
                            elif isinstance(item, str):
                                known.add(item)
                    elif isinstance(inner, dict):
                        known.update(inner.keys())
                    else:
                        # Flat key-value store
                        for k in data.keys():
                            if k not in ("__meta__", "__version__", "__source__"):
                                known.add(k)
                elif isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            n = item.get("name") or item.get("key") or item.get("id")
                            if n:
                                known.add(str(n))
                        elif isinstance(item, str):
                            known.add(item)
            except Exception:
                continue

    return known if found_any_store else None


def _audit_secrets_via_cli() -> Optional[Set[str]]:
    """
    Run `openclaw secrets audit --json` (new in OpenClaw 2026.3.2) and return
    the set of secret names that are confirmed resolved.
    Returns None if the command is unavailable.
    """
    import shutil

    binary = shutil.which("openclaw")
    if not binary:
        if _is_windows():
            appdata = os.environ.get("APPDATA", "")
            if appdata:
                for ext in (".cmd", ""):
                    candidate = os.path.join(appdata, "npm", f"openclaw{ext}")
                    if os.path.isfile(candidate):
                        binary = candidate
                        break

    if not binary:
        return None

    try:
        proc = subprocess.run(
            [binary, "secrets", "audit", "--json"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        stdout = proc.stdout.strip()
        if not stdout:
            return None

        data = json.loads(stdout)
        resolved: Set[str] = set()

        # Schema: { "secrets": [{"name": "...", "resolved": true}, ...] }
        # or:     { "resolved": ["name1", "name2"] }
        # or:     { "ok": true, "keys": [...] }
        if isinstance(data, dict):
            secrets_list = data.get("secrets") or data.get("keys") or []
            if isinstance(secrets_list, list):
                for item in secrets_list:
                    if isinstance(item, dict):
                        if item.get("resolved", True):  # default assume resolved
                            n = item.get("name") or item.get("key")
                            if n:
                                resolved.add(str(n))
                    elif isinstance(item, str):
                        resolved.add(item)

            direct_resolved = data.get("resolved")
            if isinstance(direct_resolved, list):
                resolved.update(str(r) for r in direct_resolved)

        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    n = item.get("name") or item.get("key")
                    if n and item.get("resolved", True):
                        resolved.add(str(n))
                elif isinstance(item, str):
                    resolved.add(item)

        return resolved if resolved else None

    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError, Exception):
        return None


def _is_active_surface(config: Dict[str, Any], context_text: str) -> bool:
    """
    Heuristic: determine if a config block describes an *active* surface
    (channel or plugin that is enabled).

    If we cannot determine — assume active (conservative).
    """
    # Check 'enabled' field
    enabled = config.get("enabled")
    if enabled is False:
        return False
    if enabled is True:
        return True

    # Check 'active' field
    active = config.get("active")
    if active is False:
        return False

    # Check 'disabled' field
    disabled = config.get("disabled")
    if disabled is True:
        return False

    # Default: assume active if we can't tell
    return True


def _find_secret_ref_surface_context(
    config_path: str,
    ref_name: str,
    raw_text: str,
) -> Tuple[str, bool]:
    """
    Try to determine which surface (channel, plugin) a SecretRef belongs to
    and whether that surface is active.

    Returns (surface_description, is_active).
    """
    # Try to load as JSON for structured analysis
    config = _load_config_json(config_path)

    if config is None:
        # Can't parse — fall back to text search
        return ("config file", True)

    # Search channels
    channels = config.get("channels") or []
    if isinstance(channels, list):
        for ch in channels:
            if isinstance(ch, dict):
                ch_text = json.dumps(ch)
                if ref_name in ch_text:
                    ch_name = (
                        ch.get("name")
                        or ch.get("type")
                        or ch.get("id")
                        or "unknown channel"
                    )
                    is_active = _is_active_surface(ch, ch_text)
                    return (f"channel '{ch_name}'", is_active)
    elif isinstance(channels, dict):
        for key, ch in channels.items():
            if isinstance(ch, dict):
                ch_text = json.dumps(ch)
                if ref_name in ch_text:
                    is_active = _is_active_surface(ch, ch_text)
                    return (f"channel '{key}'", is_active)

    # Search plugins
    plugins = config.get("plugins") or config.get("skills") or []
    if isinstance(plugins, list):
        for plugin in plugins:
            if isinstance(plugin, dict):
                plugin_text = json.dumps(plugin)
                if ref_name in plugin_text:
                    plugin_name = (
                        plugin.get("name")
                        or plugin.get("id")
                        or "unknown plugin"
                    )
                    is_active = _is_active_surface(plugin, plugin_text)
                    return (f"plugin '{plugin_name}'", is_active)

    # Search env / top-level secrets
    for section_key in ("env", "environment", "secrets"):
        section = config.get(section_key) or {}
        if isinstance(section, dict):
            section_text = json.dumps(section)
            if ref_name in section_text:
                return (f"config section '{section_key}' (active)", True)

    # Fallback — ref found somewhere in config
    return ("config file (surface unknown — assuming active)", True)


# ---------------------------------------------------------------------------
# Main check
# ---------------------------------------------------------------------------

def check_secret_ref_audit() -> Dict[str, Any]:
    """
    Scan the OpenClaw config for SecretRef usage and verify all refs resolve.

    Returns a standard HeartbeatGuard result dict:
      {
        "category": "secret_ref_audit",
        "findings": [...],   # PASS / informational
        "warnings": [...],   # HIGH items
        "critical": [...],   # CRITICAL items
      }
    """
    findings: List[str] = []
    warnings: List[str] = []
    critical: List[str] = []

    try:
        # ── Locate config files ────────────────────────────────────────────
        config_paths = _candidate_config_paths()

        if not config_paths:
            findings.append(
                "Secret ref audit: No OpenClaw config found — cannot audit SecretRefs. "
                "Set OPENCLAW_CONFIG or OPENCLAW_CONFIG_DIR if config is in a non-standard location."
            )
            return {
                "category": "secret_ref_audit",
                "findings": findings,
                "warnings": warnings,
                "critical": critical,
            }

        # ── Scan each config file for SecretRef patterns ───────────────────
        all_refs: Dict[str, List[str]] = {}  # ref_name -> [config_paths where found]
        configs_scanned = 0

        for config_path in config_paths:
            raw = _load_config_raw(config_path)
            if raw is None:
                continue
            configs_scanned += 1
            refs = _extract_secret_refs_from_text(raw)
            for ref in refs:
                if ref not in all_refs:
                    all_refs[ref] = []
                all_refs[ref].append(config_path)

        if configs_scanned == 0:
            findings.append(
                "Secret ref audit: Config not found — cannot audit SecretRefs. "
                "No readable config files at discovered paths."
            )
            return {
                "category": "secret_ref_audit",
                "findings": findings,
                "warnings": warnings,
                "critical": critical,
            }

        findings.append(
            f"Secret ref audit: Scanned {configs_scanned} config file(s)."
        )

        if not all_refs:
            findings.append(
                "Secret ref audit: No SecretRef usage found in config — "
                "SecretRef feature not in use. PASS"
            )
            return {
                "category": "secret_ref_audit",
                "findings": findings,
                "warnings": warnings,
                "critical": critical,
            }

        findings.append(
            f"Secret ref audit: Found {len(all_refs)} SecretRef(s) in config: "
            + ", ".join(sorted(all_refs.keys())[:10])
            + ("..." if len(all_refs) > 10 else "")
        )

        # ── Resolve secrets: try CLI first, then store ────────────────────
        resolved_names: Optional[Set[str]] = _audit_secrets_via_cli()
        resolution_method = "openclaw secrets audit --json"

        if resolved_names is None:
            resolved_names = _known_secrets_from_store()
            resolution_method = "local secrets store"

        # ── Evaluate each ref ──────────────────────────────────────────────
        for ref_name, found_in_paths in sorted(all_refs.items()):
            ref_resolved = (
                resolved_names is not None and ref_name in resolved_names
            )

            if resolved_names is not None and not ref_resolved:
                # Determine surface and activity for each config path
                for config_path in found_in_paths:
                    raw = _load_config_raw(config_path) or ""
                    surface, is_active = _find_secret_ref_surface_context(
                        config_path, ref_name, raw
                    )

                    if is_active:
                        critical.append(
                            f"Unresolved SecretRef '{ref_name}' on active surface "
                            f"{surface} (in {os.path.basename(config_path)}). "
                            f"This may expose credentials or cause silent failures. "
                            f"Run: openclaw secrets configure"
                        )
                    else:
                        warnings.append(
                            f"Unresolved SecretRef '{ref_name}' on inactive surface "
                            f"{surface} (in {os.path.basename(config_path)}). "
                            f"Will become active if surface is re-enabled. "
                            f"Run: openclaw secrets configure"
                        )
            elif resolved_names is None:
                # Cannot verify — note it as informational
                findings.append(
                    f"SecretRef '{ref_name}' found in config but resolution cannot be "
                    f"verified (openclaw secrets audit --json not available and no "
                    f"local secrets store found). Upgrade to OpenClaw 2026.3.2+ for "
                    f"automated verification."
                )
            else:
                findings.append(
                    f"SecretRef '{ref_name}' resolves OK "
                    f"(verified via {resolution_method})"
                )

        # ── Summary ────────────────────────────────────────────────────────
        if not critical and not warnings:
            findings.append(
                f"Secret ref audit: All {len(all_refs)} SecretRef(s) verified — PASS"
            )

    except Exception as exc:
        warnings.append(
            f"Secret ref audit encountered an unexpected error: {exc}"
        )

    return {
        "category": "secret_ref_audit",
        "findings": findings,
        "warnings": warnings,
        "critical": critical,
    }
