"""Tests for the event normalizer and deduplication."""

import os
import sys
import pytest

PLUGIN_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
if PLUGIN_DIR not in sys.path:
    sys.path.insert(0, PLUGIN_DIR)

from modules.ssh_monitor.parser import parse_line, ParsedEvent
from modules.ssh_monitor.normalizer import (
    DedupWindow,
    normalize_event,
    normalize_events,
    _event_hash,
)

CURRENT_YEAR = 2026


class TestDedupWindow:
    def test_first_seen_not_duplicate(self):
        dw = DedupWindow(window_seconds=60)
        assert dw.is_duplicate("abc123") is False

    def test_second_seen_is_duplicate(self):
        dw = DedupWindow(window_seconds=60)
        assert dw.is_duplicate("abc123") is False
        assert dw.is_duplicate("abc123") is True

    def test_different_keys_not_duplicate(self):
        dw = DedupWindow(window_seconds=60)
        assert dw.is_duplicate("key1") is False
        assert dw.is_duplicate("key2") is False
        assert dw.is_duplicate("key1") is True  # already seen

    def test_expiry(self):
        dw = DedupWindow(window_seconds=0)  # instant expiry
        dw.is_duplicate("short_lived")
        # After the window (which is 0 seconds), it should not be duplicate
        # if there was a prune, but since we call is_duplicate immediately
        # the entry is still there. This tests the mechanism.
        # With window=0, cutoff = now - 0 = now, entry_time = now,
        # so entry_time >= cutoff and it stays.
        assert dw.is_duplicate("short_lived") is True


class TestEventHash:
    def test_same_event_same_hash(self):
        line = "Jun  3 10:00:01 server sshd[12345]: Accepted password for admin from 192.168.1.100 port 22 ssh2"
        ev1 = parse_line(line, CURRENT_YEAR)
        ev2 = parse_line(line, CURRENT_YEAR)
        h1 = _event_hash(ev1)
        h2 = _event_hash(ev2)
        assert h1 == h2

    def test_different_events_different_hash(self):
        ev1 = ParsedEvent(event_type="login.success", username="alice",
                          ip_address="1.2.3.4", message="Accepted password")
        ev2 = ParsedEvent(event_type="login.success", username="bob",
                          ip_address="1.2.3.4", message="Accepted password")
        assert _event_hash(ev1) != _event_hash(ev2)


class TestNormalizeEvent:
    def test_returns_dict(self):
        ev = parse_line(
            "Jun  3 10:00:01 server sshd[12345]: Accepted password for admin from 192.168.1.100 port 22 ssh2",
            CURRENT_YEAR,
        )
        row = normalize_event(ev)
        assert row is not None
        assert isinstance(row, dict)
        assert row["event_type"] == "login.success"
        assert row["username"] == "admin"
        assert row["ip_address"] == "192.168.1.100"

    def test_none_input(self):
        assert normalize_event(None) is None

    def test_root_success_login_adds_flag(self):
        ev = parse_line(
            "Jun  3 10:35:00 server sshd[12359]: Accepted password for root from 192.168.1.10 port 22 ssh2",
            CURRENT_YEAR,
        )
        row = normalize_event(ev)
        assert row is not None
        assert row["event_type"] == "login.success"
        assert row.get("_also_root_login") is True

    def test_non_root_no_flag(self):
        # Use a unique line that hasn't been dedup'd by earlier tests
        ev = parse_line(
            "Jun  3 11:00:01 server sshd[12363]: Accepted publickey for admin from 192.168.1.200 port 33333 ssh2",
            CURRENT_YEAR,
        )
        row = normalize_event(ev)
        assert row is not None
        assert row.get("_also_root_login") is not True


class TestNormalizeEvents:
    def test_batch_returns_list_of_dicts(self):
        from modules.ssh_monitor.parser import parse_lines as _parse_lines
        fixture_path = os.path.join(
            os.path.dirname(__file__), "fixtures", "auth_sample.log"
        )
        with open(fixture_path, "r") as f:
            lines = f.readlines()
        parsed = _parse_lines(lines, CURRENT_YEAR)
        result = normalize_events(parsed)
        assert isinstance(result, list)
        assert len(result) > 0
        assert all(isinstance(r, dict) for r in result)

    def test_root_login_generates_extra_event(self):
        """A successful root login should produce both login.success and login.root."""
        from modules.ssh_monitor.parser import parse_lines as _parse_lines
        lines = [
            "Jun  3 12:35:00 server sshd[99999]: Accepted password for root from 10.99.99.99 port 22 ssh2",
        ]
        parsed = _parse_lines(lines, CURRENT_YEAR)
        result = normalize_events(parsed)
        event_types = [r["event_type"] for r in result]
        assert "login.success" in event_types
        assert "login.root" in event_types
