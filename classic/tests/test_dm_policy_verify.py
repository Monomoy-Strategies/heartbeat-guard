"""
Tests for heartbeat_guard.checks.dm_policy_verify
"""

import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

# Ensure the package root is on the path when running tests directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from heartbeat_guard.checks.dm_policy_verify import (
    check_dm_policy_verify,
    _extract_channels,
    _get_dm_policy,
    _get_allow_from,
    _channel_label,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _result_is_valid(result: dict) -> None:
    """Assert the return dict conforms to the standard shape."""
    assert isinstance(result, dict), "Result must be a dict"
    assert "category" in result, "Result must have 'category'"
    assert "findings" in result, "Result must have 'findings'"
    assert "warnings" in result, "Result must have 'warnings'"
    assert "critical" in result, "Result must have 'critical'"
    assert result["category"] == "dm_policy_verify", "Category must match"


def _make_config(channels, account_policy=None):
    cfg = {}
    if account_policy:
        cfg["dmPolicy"] = account_policy
    cfg["channels"] = channels
    return cfg


# ---------------------------------------------------------------------------
# Unit tests — helpers
# ---------------------------------------------------------------------------

class TestExtractChannels(unittest.TestCase):
    def test_list_of_dicts(self):
        cfg = {"channels": [{"type": "discord"}, {"type": "telegram"}]}
        result = _extract_channels(cfg)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["type"], "discord")

    def test_dict_keyed_by_type(self):
        cfg = {"channels": {"discord": {"name": "main"}, "telegram": {"name": "alerts"}}}
        result = _extract_channels(cfg)
        types = {ch["type"] for ch in result}
        self.assertIn("discord", types)
        self.assertIn("telegram", types)

    def test_top_level_telegram_key(self):
        cfg = {"telegram": {"token": "abc123"}}
        result = _extract_channels(cfg)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "telegram")

    def test_empty_config(self):
        result = _extract_channels({})
        self.assertEqual(result, [])


class TestGetDmPolicy(unittest.TestCase):
    def test_explicit_channel_policy(self):
        channel = {"type": "discord", "dmPolicy": "allowlist"}
        policy, is_default = _get_dm_policy(channel, account_policy="open")
        self.assertEqual(policy, "allowlist")
        self.assertFalse(is_default)

    def test_inherits_account_policy(self):
        channel = {"type": "discord"}
        policy, is_default = _get_dm_policy(channel, account_policy="closed")
        self.assertEqual(policy, "closed")
        self.assertTrue(is_default)

    def test_no_policy_anywhere(self):
        channel = {"type": "signal"}
        policy, is_default = _get_dm_policy(channel, account_policy=None)
        self.assertIsNone(policy)
        self.assertTrue(is_default)

    def test_directPolicy_key(self):
        channel = {"type": "telegram", "directPolicy": "OPEN"}
        policy, is_default = _get_dm_policy(channel, account_policy=None)
        self.assertEqual(policy, "open")
        self.assertFalse(is_default)


class TestGetAllowFrom(unittest.TestCase):
    def test_populated(self):
        channel = {"allowFrom": ["user1", "user2"]}
        self.assertEqual(_get_allow_from(channel), ["user1", "user2"])

    def test_empty_list(self):
        channel = {"allowFrom": []}
        self.assertEqual(_get_allow_from(channel), [])

    def test_missing(self):
        channel = {}
        self.assertIsNone(_get_allow_from(channel))

    def test_allow_from_alias(self):
        channel = {"allow_from": ["admin"]}
        self.assertEqual(_get_allow_from(channel), ["admin"])


class TestChannelLabel(unittest.TestCase):
    def test_with_name(self):
        label = _channel_label({"type": "discord", "name": "general"}, 0)
        self.assertIn("Discord", label)
        self.assertIn("general", label)

    def test_without_name(self):
        label = _channel_label({"type": "telegram"}, 2)
        self.assertIn("Telegram", label)
        self.assertIn("#3", label)

    def test_fallback_type(self):
        label = _channel_label({}, 0)
        self.assertIn("#1", label)


# ---------------------------------------------------------------------------
# Integration tests — check_dm_policy_verify
# ---------------------------------------------------------------------------

class TestDmPolicyVerifyNoConfig(unittest.TestCase):
    """check_dm_policy_verify handles missing config gracefully (WARN not crash)."""

    @patch("heartbeat_guard.checks.dm_policy_verify._candidate_config_paths", return_value=[])
    def test_no_config_returns_pass_not_crash(self, _mock_paths):
        result = check_dm_policy_verify()
        _result_is_valid(result)
        # No config → should be informational, not a hard failure
        self.assertEqual(result["critical"], [], "No config should not produce a FAIL")


class TestDmPolicyVerifyAllowlistEmpty(unittest.TestCase):
    """allowlist policy with empty allowFrom → FAIL."""

    def _run_with_config(self, cfg: dict):
        """Patch _load_config directly so we control the config dict without file I/O."""
        with patch(
            "heartbeat_guard.checks.dm_policy_verify._load_config",
            return_value=(cfg, "/fake/config.json"),
        ):
            return check_dm_policy_verify()

    def test_allowlist_with_empty_allow_from_is_fail(self):
        cfg = _make_config([
            {"type": "discord", "dmPolicy": "allowlist", "allowFrom": []}
        ])
        result = self._run_with_config(cfg)
        _result_is_valid(result)
        self.assertTrue(
            len(result["critical"]) > 0,
            "Empty allowFrom with allowlist policy must produce FAIL"
        )

    def test_allowlist_with_missing_allow_from_is_fail(self):
        cfg = _make_config([
            {"type": "telegram", "dmPolicy": "allowlist"}
        ])
        result = self._run_with_config(cfg)
        _result_is_valid(result)
        self.assertTrue(
            len(result["critical"]) > 0,
            "Missing allowFrom with allowlist policy must produce FAIL"
        )

    def test_allowlist_with_populated_allow_from_is_pass(self):
        cfg = _make_config([
            {"type": "discord", "dmPolicy": "allowlist", "allowFrom": ["user123"]}
        ])
        result = self._run_with_config(cfg)
        _result_is_valid(result)
        self.assertEqual(result["critical"], [], "Populated allowFrom must not FAIL")

    def test_no_explicit_policy_is_warn(self):
        cfg = _make_config([{"type": "signal"}])  # no account policy, no channel policy
        result = self._run_with_config(cfg)
        _result_is_valid(result)
        self.assertTrue(
            len(result["warnings"]) > 0 or len(result["findings"]) > 0,
            "Riding default should produce at least a WARN or finding"
        )

    def test_explicit_open_policy_is_pass(self):
        cfg = _make_config([
            {"type": "telegram", "dmPolicy": "open"}
        ])
        result = self._run_with_config(cfg)
        _result_is_valid(result)
        self.assertEqual(result["critical"], [], "Explicit non-allowlist policy must not FAIL")


class TestDmPolicyVerifyReturnShape(unittest.TestCase):
    """Result must always conform to the standard shape regardless of input."""

    @patch("heartbeat_guard.checks.dm_policy_verify._candidate_config_paths",
           return_value=[Path("/nonexistent/config.json")])
    def test_return_shape_when_no_config(self, _):
        result = check_dm_policy_verify()
        _result_is_valid(result)
        for key in ("findings", "warnings", "critical"):
            self.assertIsInstance(result[key], list)
