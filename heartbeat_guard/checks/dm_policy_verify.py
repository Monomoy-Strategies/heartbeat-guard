#!/usr/bin/env python3
"""
HeartbeatGuard Check — DM Policy Verification

Reads the OpenClaw config file and audits dmPolicy / directPolicy settings
across all configured channels (Telegram, Discord, Signal, etc.).

Severity mapping:
  FAIL  — allowlist policy with empty or missing allowFrom (silent drop risk)
  WARN  — channel riding a default value (could flip on upgrade)
  PASS  — explicitly configured and allowFrom is populated (when applicable)

Copyright (c) 2026 Monomoy Strategies LLC
"""

import json
import os
import glob
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_windows() -> bool:
    return os.name == "nt" or sys.platform.startswith("win")


def _candidate_config_paths() -> List[Path]:
    """Return ordered list of candidate OpenClaw config paths."""
    home = Path.home()
    candidates: List[Path] = []

    # Environment override
    env_dir = os.environ.get("OPENCLAW_CONFIG_DIR") or os.environ.get("OPENCLAW_HOME")
    if env_dir:
        candidates.append(Path(env_dir) / "config.json")

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
        "settings.json",
        "gateway.json",
        "openclaw.json",
        "openclaw-config.json",
    ]

    for base in bases:
        if base is None:
            continue
        for name in config_names:
            candidates.append(base / name)

    return [p for p in candidates if p is not None]


def _load_config() -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Load the first readable OpenClaw config file.

    Returns:
        (config_dict, source_path) or (None, None) if no config found.
    """
    for path in _candidate_config_paths():
        if path.exists():
            try:
                with path.open("r", encoding="utf-8", errors="ignore") as fh:
                    data = json.load(fh)
                return data, str(path)
            except (json.JSONDecodeError, OSError):
                continue
    return None, None


def _extract_channels(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract all channel definitions from an OpenClaw config dict.

    Handles two common shapes:
      channels: [{"type": "discord", ...}, ...]        (list)
      channels: {"discord": {...}, "telegram": {...}}   (dict keyed by type)
    Also looks for top-level named channel keys (telegram, discord, signal).
    """
    channels: List[Dict[str, Any]] = []

    raw = config.get("channels") or []

    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                channels.append(item)
    elif isinstance(raw, dict):
        for type_key, value in raw.items():
            if isinstance(value, dict):
                merged = dict(value)
                merged.setdefault("type", type_key)
                channels.append(merged)
            elif isinstance(value, list):
                for sub in value:
                    if isinstance(sub, dict):
                        sub_merged = dict(sub)
                        sub_merged.setdefault("type", type_key)
                        channels.append(sub_merged)

    # Also look for top-level singular channel keys
    for top_key in ("telegram", "discord", "signal", "whatsapp", "slack", "matrix"):
        val = config.get(top_key)
        if isinstance(val, dict) and val:
            merged = dict(val)
            merged.setdefault("type", top_key)
            # Only add if not already captured via "channels" list
            already_present = any(
                ch.get("type", "").lower() == top_key.lower() for ch in channels
            )
            if not already_present:
                channels.append(merged)

    return channels


def _get_dm_policy(channel: Dict[str, Any], account_policy: Optional[str]) -> Tuple[Optional[str], bool]:
    """
    Return (effective_policy, is_default) for a channel entry.

    is_default=True means the channel has no explicit dmPolicy/directPolicy
    setting and is relying on the account-level (or system) default.
    """
    # Channel-level keys to check, in priority order
    explicit = (
        channel.get("dmPolicy")
        or channel.get("directPolicy")
        or channel.get("dm_policy")
        or channel.get("direct_policy")
    )

    if explicit is not None:
        return str(explicit).lower(), False

    # Fall back to account/global level
    if account_policy is not None:
        return str(account_policy).lower(), True

    # Absolute default: treat as unknown/default
    return None, True


def _get_allow_from(channel: Dict[str, Any]) -> Optional[List[Any]]:
    """Return the allowFrom list for a channel, or None if not set."""
    for key in ("allowFrom", "allow_from"):
        if key in channel:
            af = channel[key]
            if isinstance(af, list):
                return af
            # Non-list value present → treat as empty (misconfigured)
            return []
    return None  # key not present at all


def _channel_label(channel: Dict[str, Any], idx: int) -> str:
    """Return a human-readable label for a channel."""
    parts = []
    ch_type = channel.get("type") or channel.get("platform") or "channel"
    parts.append(str(ch_type).capitalize())

    name = channel.get("name") or channel.get("id") or channel.get("channelId")
    if name:
        parts.append(f"'{name}'")
    else:
        parts.append(f"#{idx + 1}")

    return " ".join(parts)


# ---------------------------------------------------------------------------
# Main check
# ---------------------------------------------------------------------------

def check_dm_policy_verify() -> Dict[str, Any]:
    """
    Audit dmPolicy / directPolicy settings across all OpenClaw channels.

    Returns a standard HeartbeatGuard result dict:
      {
        "category": "dm_policy_verify",
        "findings": [...],   # PASS / informational
        "warnings": [...],   # WARN items
        "critical": [...],   # FAIL items
      }
    """
    findings: List[str] = []
    warnings: List[str] = []
    critical: List[str] = []

    try:
        config, source = _load_config()

        if config is None:
            findings.append(
                "DM policy: No OpenClaw config file found "
                f"(searched: {', '.join(str(p) for p in _candidate_config_paths()[:3])} ...)"
            )
            return {
                "category": "dm_policy_verify",
                "findings": findings,
                "warnings": warnings,
                "critical": critical,
            }

        # Account-level dmPolicy (top-level or under "account" / "defaults")
        account_policy: Optional[str] = None
        for lookup in [
            config.get("dmPolicy"),
            config.get("directPolicy"),
            config.get("dm_policy"),
            (config.get("account") or {}).get("dmPolicy"),
            (config.get("defaults") or {}).get("dmPolicy"),
        ]:
            if lookup is not None:
                account_policy = str(lookup).lower()
                break

        channels = _extract_channels(config)

        if not channels:
            findings.append(
                f"DM policy: No channels found in {source}. "
                "Nothing to audit."
            )
            return {
                "category": "dm_policy_verify",
                "findings": findings,
                "warnings": warnings,
                "critical": critical,
            }

        findings.append(
            f"DM policy audit: scanning {len(channels)} channel(s) in {source}"
        )
        if account_policy:
            findings.append(f"Account-level dmPolicy: '{account_policy}'")
        else:
            warnings.append(
                "No account-level dmPolicy set. Channels with no explicit policy "
                "will use the system default (which may change on upgrade)."
            )

        pass_count = 0
        warn_count = 0
        fail_count = 0

        for idx, channel in enumerate(channels):
            label = _channel_label(channel, idx)
            effective_policy, is_default = _get_dm_policy(channel, account_policy)
            allow_from = _get_allow_from(channel)

            # ── Case 1: allowlist policy with empty/missing allowFrom ──────
            if effective_policy == "allowlist":
                if allow_from is None or len(allow_from) == 0:
                    critical.append(
                        f"FAIL — {label}: dmPolicy is 'allowlist' but allowFrom is "
                        f"{'missing' if allow_from is None else 'empty'}. "
                        f"All DMs will be silently dropped (no senders allowed). "
                        f"Add at least one entry to allowFrom or change the policy."
                    )
                    fail_count += 1
                else:
                    # allowlist with populated allowFrom
                    if is_default:
                        warnings.append(
                            f"WARN — {label}: Inheriting account-level dmPolicy 'allowlist' "
                            f"({len(allow_from)} allowFrom entries). Explicit per-channel "
                            f"setting recommended to survive account-level changes."
                        )
                        warn_count += 1
                    else:
                        findings.append(
                            f"PASS — {label}: Explicit dmPolicy 'allowlist' with "
                            f"{len(allow_from)} allowFrom entries."
                        )
                        pass_count += 1

            # ── Case 2: riding a default (no explicit policy set) ─────────
            elif is_default:
                policy_display = f"'{effective_policy}'" if effective_policy else "system default"
                warnings.append(
                    f"WARN — {label}: No explicit dmPolicy set; riding {policy_display}. "
                    f"A future upgrade could change the default and silently alter "
                    f"DM behaviour. Set dmPolicy explicitly in the channel config."
                )
                warn_count += 1

            # ── Case 3: explicit non-allowlist policy ─────────────────────
            else:
                findings.append(
                    f"PASS — {label}: Explicit dmPolicy '{effective_policy}'."
                )
                pass_count += 1

        # Summary
        findings.append(
            f"DM policy summary: {pass_count} PASS, {warn_count} WARN, {fail_count} FAIL "
            f"across {len(channels)} channel(s)."
        )

    except Exception as exc:
        warnings.append(f"DM policy check failed with unexpected error: {exc}")

    return {
        "category": "dm_policy_verify",
        "findings": findings,
        "warnings": warnings,
        "critical": critical,
    }
