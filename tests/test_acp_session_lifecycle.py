"""
Tests for heartbeat_guard.checks.acp_session_lifecycle
"""

import json
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

# Ensure the package root is on the path when running tests directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from heartbeat_guard.checks.acp_session_lifecycle import (
    check_acp_session_lifecycle,
    _is_acp_session,
    _session_last_activity,
    _session_message_count,
    _session_label,
    _parse_timestamp,
    _load_sessions_from_file,
    ZOMBIE_THRESHOLD_HOURS,
    SESSION_COUNT_LIMIT,
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
    assert result["category"] == "acp_session_lifecycle", "Category must match"


def _make_session(kind="acp", thread_id=None, messages=5, last_activity=None) -> dict:
    """Build a minimal session dict."""
    s: dict = {}
    if kind:
        s["kind"] = kind
    if thread_id is not None:
        s["threadId"] = thread_id
    s["messageCount"] = messages
    if last_activity is not None:
        # Store as ISO string
        s["lastActivity"] = last_activity.isoformat()
    return s


def _sessions_file(sessions, tmp_dir) -> str:
    """Write sessions to a temp file and return the path."""
    path = os.path.join(tmp_dir, "sessions.json")
    with open(path, "w") as fh:
        json.dump(sessions, fh)
    return path


# ---------------------------------------------------------------------------
# Unit tests — helpers
# ---------------------------------------------------------------------------

class TestParseTimestamp(unittest.TestCase):
    def test_unix_epoch_seconds(self):
        now = datetime.now(tz=timezone.utc)
        ts = now.timestamp()
        result = _parse_timestamp(ts)
        self.assertIsNotNone(result)
        self.assertAlmostEqual(result.timestamp(), ts, delta=1)

    def test_unix_epoch_milliseconds(self):
        now = datetime.now(tz=timezone.utc)
        ts_ms = int(now.timestamp() * 1000)
        result = _parse_timestamp(ts_ms)
        self.assertIsNotNone(result)
        self.assertAlmostEqual(result.timestamp(), now.timestamp(), delta=1)

    def test_iso_string(self):
        result = _parse_timestamp("2026-02-01T12:00:00")
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2026)
        self.assertEqual(result.month, 2)

    def test_iso_string_with_z(self):
        result = _parse_timestamp("2026-03-01T00:00:00Z")
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2026)

    def test_none_input(self):
        self.assertIsNone(_parse_timestamp(None))

    def test_invalid_string(self):
        self.assertIsNone(_parse_timestamp("not-a-date"))


class TestIsAcpSession(unittest.TestCase):
    def test_kind_acp(self):
        self.assertTrue(_is_acp_session({"kind": "acp"}))

    def test_kind_acp_subagent(self):
        self.assertTrue(_is_acp_session({"kind": "acp:subagent"}))

    def test_thread_id_present(self):
        self.assertTrue(_is_acp_session({"kind": "normal", "threadId": "thread-xyz"}))

    def test_acp_context(self):
        self.assertTrue(_is_acp_session({"acpContext": {"parentId": "abc"}}))

    def test_binding_thread(self):
        self.assertTrue(_is_acp_session({"binding": {"thread": "t123"}}))

    def test_non_acp(self):
        self.assertFalse(_is_acp_session({"kind": "main", "messageCount": 10}))

    def test_empty_session(self):
        self.assertFalse(_is_acp_session({}))


class TestSessionLastActivity(unittest.TestCase):
    def test_returns_most_recent(self):
        old = datetime(2026, 1, 1, tzinfo=timezone.utc)
        new = datetime(2026, 2, 1, tzinfo=timezone.utc)
        s = {
            "lastActivity": old.isoformat(),
            "updatedAt": new.isoformat(),
        }
        result = _session_last_activity(s)
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2026)
        self.assertEqual(result.month, 2)

    def test_no_timestamp(self):
        self.assertIsNone(_session_last_activity({"kind": "acp"}))


class TestSessionMessageCount(unittest.TestCase):
    def test_int_field(self):
        self.assertEqual(_session_message_count({"messageCount": 7}), 7)

    def test_list_field(self):
        self.assertEqual(_session_message_count({"messages": ["a", "b"]}), 2)

    def test_zero(self):
        self.assertEqual(_session_message_count({}), 0)


class TestLoadSessionsFromFile(unittest.TestCase):
    def _write_and_load(self, data) -> list:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as fh:
            json.dump(data, fh)
            path = fh.name
        try:
            return _load_sessions_from_file(path)
        finally:
            os.unlink(path)

    def test_array_format(self):
        sessions = [{"kind": "acp", "id": "s1"}, {"kind": "main", "id": "s2"}]
        result = self._write_and_load(sessions)
        self.assertEqual(len(result), 2)

    def test_object_with_sessions_key(self):
        data = {"sessions": [{"kind": "acp"}, {"kind": "acp"}]}
        result = self._write_and_load(data)
        self.assertEqual(len(result), 2)

    def test_object_keyed_map(self):
        data = {"sess-1": {"kind": "acp"}, "sess-2": {"kind": "main"}}
        result = self._write_and_load(data)
        self.assertEqual(len(result), 2)

    def test_corrupted_json_returns_empty(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as fh:
            fh.write("{not valid json{{")
            path = fh.name
        try:
            result = _load_sessions_from_file(path)
            self.assertEqual(result, [])
        finally:
            os.unlink(path)

    def test_nonexistent_file_returns_empty(self):
        result = _load_sessions_from_file("/nonexistent/path/sessions.json")
        self.assertEqual(result, [])


# ---------------------------------------------------------------------------
# Integration tests — check_acp_session_lifecycle
# ---------------------------------------------------------------------------

class TestAcpSessionLifecycleNoStore(unittest.TestCase):
    """No session store → PASS with informational note (not a crash)."""

    @patch("heartbeat_guard.checks.acp_session_lifecycle._find_session_files",
           return_value=[])
    def test_missing_store_is_pass(self, _mock):
        result = check_acp_session_lifecycle()
        _result_is_valid(result)
        self.assertEqual(result["critical"], [], "Missing store must not FAIL")
        self.assertEqual(result["warnings"], [], "Missing store must not WARN")
        self.assertTrue(len(result["findings"]) > 0)


class TestAcpSessionLifecycleHealthy(unittest.TestCase):
    """A small number of active ACP sessions → PASS."""

    def test_healthy_sessions_pass(self):
        now = datetime.now(tz=timezone.utc)
        recent = now - timedelta(hours=2)
        sessions = [
            _make_session(kind="acp", messages=10, last_activity=recent),
            _make_session(kind="acp:subagent", messages=3, last_activity=recent),
        ]

        with tempfile.TemporaryDirectory() as tmp:
            sf = _sessions_file(sessions, tmp)
            with patch(
                "heartbeat_guard.checks.acp_session_lifecycle._find_session_files",
                return_value=[sf]
            ):
                result = check_acp_session_lifecycle()

        _result_is_valid(result)
        self.assertEqual(result["critical"], [], "Healthy sessions must not FAIL")
        self.assertEqual(result["warnings"], [], "Healthy sessions must not WARN")


class TestAcpSessionLifecycleZombie(unittest.TestCase):
    """Sessions idle > ZOMBIE_THRESHOLD_HOURS → WARN."""

    def test_zombie_sessions_warn(self):
        now = datetime.now(tz=timezone.utc)
        zombie_ts = now - timedelta(hours=ZOMBIE_THRESHOLD_HOURS + 5)
        sessions = [
            _make_session(kind="acp", messages=5, last_activity=zombie_ts),
        ]

        with tempfile.TemporaryDirectory() as tmp:
            sf = _sessions_file(sessions, tmp)
            with patch(
                "heartbeat_guard.checks.acp_session_lifecycle._find_session_files",
                return_value=[sf]
            ):
                result = check_acp_session_lifecycle()

        _result_is_valid(result)
        self.assertTrue(
            len(result["warnings"]) > 0,
            "Zombie session must produce a WARN"
        )
        self.assertEqual(result["critical"], [], "Zombie alone must not FAIL")


class TestAcpSessionLifecycleUnused(unittest.TestCase):
    """Sessions with zero messages → WARN."""

    def test_unused_sessions_warn(self):
        now = datetime.now(tz=timezone.utc)
        recent = now - timedelta(hours=1)
        sessions = [
            _make_session(kind="acp", messages=0, last_activity=recent),
        ]

        with tempfile.TemporaryDirectory() as tmp:
            sf = _sessions_file(sessions, tmp)
            with patch(
                "heartbeat_guard.checks.acp_session_lifecycle._find_session_files",
                return_value=[sf]
            ):
                result = check_acp_session_lifecycle()

        _result_is_valid(result)
        self.assertTrue(
            len(result["warnings"]) > 0,
            "Unused (zero-message) session must produce a WARN"
        )


class TestAcpSessionLifecycleSpawnLoop(unittest.TestCase):
    """More than SESSION_COUNT_LIMIT ACP sessions → FAIL."""

    def test_too_many_sessions_fail(self):
        now = datetime.now(tz=timezone.utc)
        recent = now - timedelta(hours=1)
        sessions = [
            _make_session(kind="acp", messages=1, last_activity=recent)
            for _ in range(SESSION_COUNT_LIMIT + 5)
        ]

        with tempfile.TemporaryDirectory() as tmp:
            sf = _sessions_file(sessions, tmp)
            with patch(
                "heartbeat_guard.checks.acp_session_lifecycle._find_session_files",
                return_value=[sf]
            ):
                result = check_acp_session_lifecycle()

        _result_is_valid(result)
        self.assertTrue(
            len(result["critical"]) > 0,
            f"More than {SESSION_COUNT_LIMIT} sessions must produce a FAIL"
        )


class TestAcpSessionLifecycleReturnShape(unittest.TestCase):
    """Result must always conform to the standard shape."""

    @patch("heartbeat_guard.checks.acp_session_lifecycle._find_session_files",
           return_value=[])
    def test_return_shape(self, _):
        result = check_acp_session_lifecycle()
        _result_is_valid(result)
        for key in ("findings", "warnings", "critical"):
            self.assertIsInstance(result[key], list)


class TestAcpSessionLifecycleThreadBound(unittest.TestCase):
    """Sessions with threadId (not acp kind) are still classified as ACP."""

    def test_thread_bound_session_detected(self):
        now = datetime.now(tz=timezone.utc)
        zombie_ts = now - timedelta(hours=ZOMBIE_THRESHOLD_HOURS + 10)
        # kind is 'main' but has a threadId → should be treated as ACP
        sessions = [
            {"kind": "main", "threadId": "t-abc", "messageCount": 3,
             "lastActivity": zombie_ts.isoformat()}
        ]

        with tempfile.TemporaryDirectory() as tmp:
            sf = _sessions_file(sessions, tmp)
            with patch(
                "heartbeat_guard.checks.acp_session_lifecycle._find_session_files",
                return_value=[sf]
            ):
                result = check_acp_session_lifecycle()

        _result_is_valid(result)
        self.assertTrue(
            len(result["warnings"]) > 0,
            "Thread-bound zombie session should generate a WARN"
        )
