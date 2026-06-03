"""
Configuration manager for Security Monitor.

Loads config/config.json (user settings) and merges it on top of
config/default.json (built-in defaults).  Missing keys are filled from
defaults so the plugin never crashes on a missing config key.

Usage::

    from lib.config import Config
    cfg = Config()
    cfg.get('database.host')               # "127.0.0.1"
    cfg.get('ssh_monitor.poll_interval')   # 30
    cfg.is_enabled('ssh_monitor')          # True
"""

import json
import os
import threading
from typing import Any, Optional

PLUGIN_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_PATH = os.path.join(PLUGIN_DIR, "config", "default.json")
CONFIG_PATH = os.path.join(PLUGIN_DIR, "config", "config.json")


class Config:
    """Thread-safe, merge-on-top configuration singleton."""

    _instance: Optional["Config"] = None
    _lock = threading.Lock()

    def __new__(cls, *args: Any, **kwargs: Any) -> "Config":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        if getattr(self, "_initialized", False):
            return
        self._data: dict[str, Any] = {}
        self._mutex = threading.Lock()
        self.reload()
        self._initialized = True

    # ------------------------------------------------------------------
    # Load / reload
    # ------------------------------------------------------------------
    def reload(self) -> None:
        """Re-read defaults and user config from disk."""
        merged: dict[str, Any] = {}

        # 1. Built-in defaults
        try:
            with open(DEFAULT_PATH, "r", encoding="utf-8") as f:
                defaults = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            defaults = {}
            self._warn(f"Could not load defaults ({exc})")

        # 2. User overrides
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                overrides = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            overrides = {}

        # 3. Deep merge
        merged = self._deep_merge(defaults, overrides)
        with self._mutex:
            self._data = merged

    # ------------------------------------------------------------------
    # Public accessors
    # ------------------------------------------------------------------
    def get(self, dotted_key: str, default: Any = None) -> Any:
        """Fetch a value by dot-separated key, e.g. ``database.host``."""
        with self._mutex:
            val = self._data
            for part in dotted_key.split("."):
                if isinstance(val, dict):
                    val = val.get(part, {})
                else:
                    return default
            return val if val != {} else default

    def set(self, dotted_key: str, value: Any) -> None:
        """Set a value in memory and persist to disk."""
        with self._mutex:
            keys = dotted_key.split(".")
            target = self._data
            for part in keys[:-1]:
                target = target.setdefault(part, {})
            target[keys[-1]] = value
            self._persist()

    def is_enabled(self, module_key: str) -> bool:
        """Convenience: check if a module is enabled (default True)."""
        return bool(self.get(f"{module_key}.enabled", True))

    def all(self) -> dict[str, Any]:
        """Return a deep copy of the full configuration."""
        import copy
        with self._mutex:
            return copy.deepcopy(self._data)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _deep_merge(base: dict, overlay: dict) -> dict:
        """Recursively merge overlay into base and return the result."""
        result = {}
        for key in base:
            if key in overlay:
                if isinstance(base[key], dict) and isinstance(overlay[key], dict):
                    result[key] = Config._deep_merge(base[key], overlay[key])
                else:
                    result[key] = overlay[key]
            else:
                result[key] = base[key]
        for key in overlay:
            if key not in base:
                result[key] = overlay[key]
        return result

    def _persist(self) -> None:
        """Write the current in-memory config to disk."""
        dirpath = os.path.dirname(CONFIG_PATH)
        os.makedirs(dirpath, exist_ok=True)
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2, ensure_ascii=False)

    @staticmethod
    def _warn(msg: str) -> None:
        import sys
        print(f"[sec_mon.config] {msg}", file=sys.stderr)