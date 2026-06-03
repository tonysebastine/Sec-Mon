"""
Rotating file logger for Security Monitor.

Three log files are maintained under <plugin_root>/logs/:

* app.log           - general application events
* daemon.log        - background daemon / scheduler events
* error.log         - exceptions and errors only

Each log rotates when it reaches max_bytes (default 10 MiB) and
keeps backup_count rotated copies (default 5).

Usage::

    from lib.logger import get_logger
    log = get_logger("app")
    log.info("SSH event processed: user=%s ip=%s", user, ip)
"""

import logging
import logging.handlers
import os
import sys
from typing import Optional

PLUGIN_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_LOG_DIR = os.path.join(PLUGIN_DIR, "logs")
DEFAULT_MAX_BYTES = 10 * 1024 * 1024   # 10 MiB
DEFAULT_BACKUP_COUNT = 5

# Cache so repeated calls to get_logger() return the same instance
_loggers: dict[str, logging.Logger] = {}

# Read config lazily to avoid circular import at module load time
_config_loaded = False
_log_level = logging.INFO
_log_dir = DEFAULT_LOG_DIR
_max_bytes = DEFAULT_MAX_BYTES
_backup_count = DEFAULT_BACKUP_COUNT


def _load_config() -> None:
    """One-time load of logging config from the Config singleton."""
    # Use late import to break circular dependency
    from lib.config import Config  # noqa: PLC0415
    global _log_level, _log_dir, _max_bytes, _backup_count, _config_loaded  # noqa: PLW0603

    if _config_loaded:
        return

    try:
        cfg = Config()
        raw_level = cfg.get("logging.level", "INFO").upper()
        _log_level = getattr(logging, raw_level, logging.INFO)
        _log_dir = cfg.get("logging.log_dir", DEFAULT_LOG_DIR)
        _max_bytes = cfg.get("logging.max_bytes", DEFAULT_MAX_BYTES)
        _backup_count = cfg.get("logging.backup_count", DEFAULT_BACKUP_COUNT)
    except Exception:
        _log_level = logging.INFO
        _log_dir = DEFAULT_LOG_DIR
        _max_bytes = DEFAULT_MAX_BYTES
        _backup_count = DEFAULT_BACKUP_COUNT

    _config_loaded = True


def _ensure_log_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


_formatter = logging.Formatter(
    "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def _create_handler(log_name: str) -> logging.Handler:
    """Create a rotating file handler for log_name.log."""
    log_dir = _ensure_log_dir(_log_dir)
    log_path = os.path.join(log_dir, f"{log_name}.log")
    handler = logging.handlers.RotatingFileHandler(
        filename=log_path,
        maxBytes=_max_bytes,
        backupCount=_backup_count,
        encoding="utf-8",
    )
    handler.setFormatter(_formatter)
    return handler


def get_logger(name: str = "app") -> logging.Logger:
    """
    Return a logging.Logger named ``sec_mon.<name>``.

    The logger writes to logs/<name>.log with rotation.
    Three predefined names are special:

    * "app"    - general application log
    * "err"    - error-only log
    * "daemon" - background scheduler log
    """
    _load_config()

    logger_key = f"sec_mon.{name}"
    if logger_key in _loggers:
        return _loggers[logger_key]

    logger = logging.getLogger(logger_key)
    logger.setLevel(_log_level)
    logger.propagate = False

    if name in ("app", "daemon", "err"):
        handler = _create_handler(name)
        logger.addHandler(handler)

        if name == "err":
            logger.setLevel(logging.ERROR)
    else:
        handler = _create_handler(name)
        logger.addHandler(handler)

    _loggers[logger_key] = logger
    return logger


# ------------------------------------------------------------------
# Shorthand helpers
# ------------------------------------------------------------------
def app_logger() -> logging.Logger:
    """Shortcut for the application log."""
    return get_logger("app")


def daemon_logger() -> logging.Logger:
    """Shortcut for the daemon/scheduler log."""
    return get_logger("daemon")


def error_logger() -> logging.Logger:
    """Shortcut for the error-only log."""
    return get_logger("err")