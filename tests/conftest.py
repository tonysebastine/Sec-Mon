"""Pytest configuration for Security Monitor tests."""

import os
import sys

# Ensure the plugin root is on sys.path so imports work
PLUGIN_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
if PLUGIN_DIR not in sys.path:
    sys.path.insert(0, PLUGIN_DIR)

# Ensure the config singleton uses the real default.json (which exists in
# the repo) even when config/config.json does not.
os.environ.setdefault("SEC_MON_TESTING", "1")