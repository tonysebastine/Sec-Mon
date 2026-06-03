"""
Transaction helper for Security Monitor.

Provides a context-manager wrapper that acquires a connection, begins
a transaction, and either commits on success or rolls back on exception.

Usage::

    from database.transaction import transaction

    with transaction() as conn:
        cur = conn.cursor()
        cur.execute("INSERT INTO events (...) VALUES (...)")
        cur.execute("UPDATE attacker_stats SET ...")
    # Connection is automatically committed and returned to the pool.

    # On any exception inside the block the transaction is rolled back:
    try:
        with transaction() as conn:
            cur = conn.cursor()
            cur.execute("INSERT INTO events (...) VALUES (...)")
            raise RuntimeError("boom")  # rolls back
    except RuntimeError:
        pass
"""

from contextlib import contextmanager
from typing import Generator

import pymysql

from database.connection import get_connection, return_connection
from lib.logger import get_logger

log = get_logger("app")


@contextmanager
def transaction() -> Generator[pymysql.Connection, None, None]:
    """
    Yield a PyMySQL connection with an active transaction.

    On normal exit the transaction is committed; on exception it is
    rolled back.  The connection is always returned to the pool afterward.
    """
    conn = get_connection()
    started = False
    try:
        # Disable autocommit so we can control the transaction boundary
        conn.autocommit(False)
        started = True
        yield conn
        conn.commit()
        log.debug("Transaction committed.")
    except Exception:
        if started:
            try:
                conn.rollback()
                log.debug("Transaction rolled back due to exception.")
            except Exception:
                log.warning("Failed to rollback transaction.", exc_info=True)
        raise
    finally:
        # Restore autocommit before returning to pool
        try:
            conn.autocommit(True)
        except Exception:
            pass
        return_connection(conn)