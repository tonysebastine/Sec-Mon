"""Tests for the Configuration manager."""

import os
import sys
import tempfile
import pytest

PLUGIN_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
if PLUGIN_DIR not in sys.path:
    sys.path.insert(0, PLUGIN_DIR)

# Reset singleton for tests
from lib import config as _cfg_module
_cfg_module.Config._instance = None

from lib.config import Config


@pytest.fixture(autouse=True)
def reset_singleton():
    """Ensure a fresh Config singleton for each test."""
    _cfg_module.Config._instance = None
    cfg = Config()
    yield cfg
    _cfg_module.Config._instance = None


class TestConfigDefaults:
    def test_loads_defaults(self, reset_singleton):
        cfg = reset_singleton
        # ssh_monitor.log_path should come from default.json
        assert cfg.get("ssh_monitor.log_path") == "/var/log/auth.log"

    def test_database_defaults(self, reset_singleton):
        cfg = reset_singleton
        assert cfg.get("database.host") == "127.0.0.1"
        assert cfg.get("database.port") == 3306
        assert cfg.get("database.name") == "sec_mon"

    def test_nested_default(self, reset_singleton):
        cfg = reset_singleton
        assert cfg.get("alerts.rules.brute_force.threshold") == 10

    def test_missing_key_returns_none(self, reset_singleton):
        cfg = reset_singleton
        assert cfg.get("nonexistent.key.path") is None

    def test_missing_key_returns_custom_default(self, reset_singleton):
        cfg = reset_singleton
        assert cfg.get("nonexistent.key", "fallback") == "fallback"


class TestConfigSet:
    def test_set_and_get(self, reset_singleton):
        cfg = reset_singleton
        cfg.set("ssh_monitor.poll_interval", 120)
        assert cfg.get("ssh_monitor.poll_interval") == 120

    def test_set_new_key(self, reset_singleton):
        cfg = reset_singleton
        cfg.set("custom.new_key", "hello")
        assert cfg.get("custom.new_key") == "hello"


class TestConfigIsEnabled:
    def test_enabled_module(self, reset_singleton):
        cfg = reset_singleton
        assert cfg.is_enabled("ssh_monitor") is True

    def test_disabled_module(self, reset_singleton):
        cfg = reset_singleton
        # geolocation is disabled by default
        assert cfg.is_enabled("geolocation") is False

    def test_missing_module_defaults_to_true(self, reset_singleton):
        cfg = reset_singleton
        assert cfg.is_enabled("nonexistent_module") is True


class TestDeepMerge:
    def test_merge_adds_new_keys(self):
        base = {"a": 1, "b": {"c": 2, "d": 3}}
        overlay = {"b": {"c": 99}, "e": 5}
        result = Config._deep_merge(base, overlay)
        assert result["a"] == 1
        assert result["b"]["c"] == 99  # overridden
        assert result["b"]["d"] == 3   # kept
        assert result["e"] == 5        # new

    def test_merge_empty_overlay(self):
        base = {"x": 1}
        assert Config._deep_merge(base, {}) == {"x": 1}

    def test_merge_empty_base(self):
        overlay = {"y": 2}
        assert Config._deep_merge({}, overlay) == {"y": 2}