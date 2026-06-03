"""
MariaDB connection manager for Security Monitor.

Provides a simple thread-safe connection pool built on top of PyMySQL.
Connections are lazily created and recycled according to the plugin's
config/database.* settings.

Usage::

    from database.connection import get_connection
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
"""

import json
import threading
from contextlib import contextmanager
from typing import Any, Generator, Optional

import pymysql
import pymysql.cursors

from lib.config import Config
from lib.logger import get_logger

log = get_logger("app")

# ---------------------------------------------------------------------------
# Internal pool
# ---------------------------------------------------------------------------
_pool_lock = threading.Lock()
_connections: list[pymysql.Connection] = []
_pool_size: int = 5
_config_loaded = False


def _load_pool_config() -> None:
    """Read pool settings from the Config singleton (once)."""
    global _pool_size, _config_loaded  # noqa: PLW0603
    if _config_loaded:
        return
    cfg = Config()
    _pool_size = cfg.get("database.pool_size", 5)
    _config_loaded = True


def _db_params() -> dict[str, Any]:
    """Extract PyMySQL kwargs from the Config singleton."""
    cfg = Config()
    user = cfg.get("database.user") or cfg.get("database.root_user", "root")
    password = cfg.get("database.password") or cfg.get("database.root_password", "")
    host = cfg.get("database.host", "127.0.0.1")
    port = int(cfg.get("database.port", 3306))
    charset = cfg.get("database.charset", "utf8mb4")
    connect_timeout = int(cfg.get("database.connect_timeout", 10))

    return dict(
        host=host,
        port=port,
        user=user,
        password=password,
        charset=charset,
        database="sec_mon",
        connect_timeout=connect_timeout,
        read_timeout=connect_timeout,
        write_timeout=connect_timeout,
        autocommit=True,
        cursorclass=pymysql.cursors.DictCursor,
    )


def _new_connection() -> pymysql.Connection:
    """Create and return a fresh PyMySQL connection."""
    params = _db_params()
    log.debug("Opening new MariaDB connection to %s:%s", params["host"], params["port"])
    return pymysql.connect(**params)


def _is_alive(conn: pymysql.Connection) -> bool:
    """Return True if the connection is still usable."""
    try:
        conn.ping(reconnect=False)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_connection() -> pymysql.Connection:
    """
    Return an existing idle connection from the pool, or create a new one.

    The returned connection must be used as a context manager::

        with get_connection() as conn:
            ...
    """
    _load_pool_config()

    with _pool_lock:
        # Reuse an existing idle connection
        while _connections:
            conn = _connections.pop()
            if _is_alive(conn):
                try:
                    conn.ping(reconnect=True)
                except Exception:
                    continue
                return conn
            # dead connection — drop it
            try:
                conn.close()
            except Exception:
                pass

    # Pool exhausted — create a fresh connection
    try:
        conn = _new_connection()
        return conn
    except pymysql.OperationalError as exc:
        log.error("Failed to connect to MariaDB: %s", exc)
        raise


def return_connection(conn: pymysql.Connection) -> None:
    """Return a connection to the pool for reuse."""
    _load_pool_config()
    with _pool_lock:
        if len(_connections) < _pool_size:
            try:
                _connections.append(conn)
                return
            except Exception:
                pass
    # Pool full or error — just close it
    try:
        conn.close()
    except Exception:
        pass


def close_all() -> None:
    """Close every pooled connection (for clean shutdown)."""
    with _pool_lock:
        while _connections:
            conn = _connections.pop()
            try:
                conn.close()
            except Exception:
                pass
    log.debug("All pooled DB connections closed.")


def is_available() -> bool:
    """Quick check: can we connect to the database?"""
    try:
        conn = _new_connection()
        conn.close()
        return True
    except Exception:
        return False