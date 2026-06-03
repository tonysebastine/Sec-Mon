"""
Query helpers for Security Monitor.

Thin convenience wrappers around PyMySQL cursors.  All helpers acquire
a connection from the pool, execute the statement, and return the
connection to the pool when done.

Usage::

    from database.query import execute, fetchone, fetchall, insert

    execute("DELETE FROM events WHERE timestamp < %s", (cutoff,))
    row = fetchone("SELECT * FROM events WHERE id = %s", (event_id,))
    rows = fetchall("SELECT * FROM events ORDER BY id DESC LIMIT %s", (50,))
    new_id = insert("INSERT INTO events (event_type) VALUES (%s)", ("login.success",))
"""

from typing import Any, Dict, List, Optional, Tuple

import pymysql

from database.connection import get_connection, return_connection
from lib.logger import get_logger

log = get_logger("app")


def _get_cursor():
    """Acquire a connection and return (connection, cursor)."""
    conn = get_connection()
    cur = conn.cursor()
    return conn, cur


def execute(sql: str, params: Optional[Tuple] = None, many: bool = False) -> int:
    """
    Execute a single statement.  Returns affected row count.

    Set *many=True* to use executemany (bulk insert).
    """
    conn, cur = _get_cursor()
    try:
        if many and isinstance(params, list):
            cur.executemany(sql, params)
        else:
            cur.execute(sql, params)
        conn.commit()
        affected = cur.rowcount
        return affected
    except Exception as exc:
        conn.rollback()
        log.error("execute() failed: %s  |  SQL: %s", exc, sql[:200])
        raise
    finally:
        cur.close()
        return_connection(conn)


def executemany(sql: str, params_list: List[Tuple]) -> int:
    """Execute a statement with many parameter sets (bulk insert)."""
    return execute(sql, params_list, many=True)


def fetchone(sql: str, params: Optional[Tuple] = None) -> Optional[Dict[str, Any]]:
    """Execute a query and return a single row (as dict) or None."""
    conn, cur = _get_cursor()
    try:
        cur.execute(sql, params)
        return cur.fetchone()
    except Exception as exc:
        log.error("fetchone() failed: %s  |  SQL: %s", exc, sql[:200])
        raise
    finally:
        cur.close()
        return_connection(conn)


def fetchall(sql: str, params: Optional[Tuple] = None) -> List[Dict[str, Any]]:
    """Execute a query and return all rows (as list of dicts)."""
    conn, cur = _get_cursor()
    try:
        cur.execute(sql, params)
        return cur.fetchall()
    except Exception as exc:
        log.error("fetchall() failed: %s  |  SQL: %s", exc, sql[:200])
        raise
    finally:
        cur.close()
        return_connection(conn)


def fetchmany(sql: str, size: int, params: Optional[Tuple] = None) -> List[Dict[str, Any]]:
    """Execute a query and return *size* rows."""
    conn, cur = _get_cursor()
    try:
        cur.execute(sql, params)
        return cur.fetchmany(size)
    except Exception as exc:
        log.error("fetchmany() failed: %s  |  SQL: %s", exc, sql[:200])
        raise
    finally:
        cur.close()
        return_connection(conn)


def insert(sql: str, params: Optional[Tuple] = None) -> int:
    """
    Execute an INSERT and return the lastrowid (auto-increment id).

    Useful for tables with an AUTO_INCREMENT primary key.
    """
    conn, cur = _get_cursor()
    try:
        cur.execute(sql, params)
        conn.commit()
        return cur.lastrowid
    except Exception as exc:
        conn.rollback()
        log.error("insert() failed: %s  |  SQL: %s", exc, sql[:200])
        raise
    finally:
        cur.close()
        return_connection(conn)


def insert_many(sql: str, params_list: List[Tuple]) -> int:
    """Bulk INSERT.  Returns total number of affected rows."""
    conn, cur = _get_cursor()
    try:
        cur.executemany(sql, params_list)
        conn.commit()
        return cur.rowcount
    except Exception as exc:
        conn.rollback()
        log.error("insert_many() failed: %s  |  SQL: %s", exc, sql[:200])
        raise
    finally:
        cur.close()
        return_connection(conn)


def upsert(sql: str, params: Optional[Tuple] = None) -> int:
    """
    Execute an INSERT ... ON DUPLICATE KEY UPDATE (MySQL/MariaDB dialect).
    Returns affected row count (2 if updated, 1 if inserted, 0 if unchanged).
    """
    conn, cur = _get_cursor()
    try:
        cur.execute(sql, params)
        conn.commit()
        return cur.rowcount
    except Exception as exc:
        conn.rollback()
        log.error("upsert() failed: %s  |  SQL: %s", exc, sql[:200])
        raise
    finally:
        cur.close()
        return_connection(conn)