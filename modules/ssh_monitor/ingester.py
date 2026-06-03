"""
SSH log ingestion pipeline for Security Monitor.

Ties together the parser, offset tracker, normalizer, and database
layer into a single ``ingest()`` function that can be called on a timer
(from the daemon) or on-demand from the CLI.

Pipeline flow:
    1. Load the persisted offset for the log file.
    2. Read new lines from the file (or journalctl fallback).
    3. Parse each line into a ``ParsedEvent``.
    4. Normalize + deduplicate.
    5. Batch-insert into the ``events`` table.
    6. Update ``attacker_stats`` for IPs with failures.
    7. Save the new offset (byte position + inode).
"""

import json
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from lib.config import Config
from lib.logger import get_logger
from modules.ssh_monitor.parser import parse_lines
from modules.ssh_monitor.normalizer import normalize_events
from modules.ssh_monitor.offset import (
    load_offset, save_offset, get_file_inode, reset_offset,
    OffsetState,
)

log = get_logger("app")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_new_lines(file_path: str, byte_offset: int) -> Tuple[str, List[str]]:
    """
    Read the portion of *file_path* starting at *byte_offset*.

    Returns (new_byte_offset, new_lines).
    Handles file truncation (rotation) gracefully.
    """
    try:
        size = os.path.getsize(file_path)
        if size < byte_offset:
            # File was truncated / rotated — read from start
            byte_offset = 0

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(byte_offset)
            content = f.read()
            new_offset = f.tell()

        lines = content.splitlines()
        return new_offset, lines

    except FileNotFoundError:
        log.warning("Log file not found: %s", file_path)
        return byte_offset, []
    except PermissionError:
        log.error("Permission denied reading %s", file_path)
        return byte_offset, []
    except Exception as exc:
        log.error("Error reading %s: %s", file_path, exc)
        return byte_offset, []


def _db_available() -> bool:
    try:
        from database.connection import is_available
        return is_available()
    except Exception:
        return False


def _insert_events(rows: List[Dict]) -> int:
    """Batch-insert normalized event rows into the database."""
    from database.query import insert_many  # noqa: PLC0415

    if not rows:
        return 0

    sql = (
        "INSERT INTO events "
        "(timestamp, event_type, username, ip_address, port, hostname, "
        " message, raw_line, metadata, country, city, asn) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
    )

    params_list = []
    for r in rows:
        ts = r["timestamp"]
        if isinstance(ts, datetime):
            ts_str = ts.strftime("%Y-%m-%d %H:%M:%S")
        else:
            ts_str = str(ts) if ts else None

        params_list.append((
            ts_str,
            r["event_type"],
            r.get("username", ""),
            r.get("ip_address", ""),
            r.get("port"),
            r.get("hostname", ""),
            r.get("message", ""),
            r.get("raw_line", ""),
            r.get("metadata"),
            r.get("country", ""),
            r.get("city", ""),
            r.get("asn", ""),
        ))

    try:
        affected = insert_many(sql, params_list)
        return affected
    except Exception as exc:
        log.error("Failed to insert %d events: %s", len(params_list), exc)
        return 0


def _update_attacker_stats(rows: List[Dict]) -> None:
    """
    Upsert ``attacker_stats`` for IP/username pairs that had login
    failures.
    """
    if not _db_available():
        return

    from database.query import upsert  # noqa: PLC0415

    failure_rows = [r for r in rows if r["event_type"] == "login.failure"]
    if not failure_rows:
        return

    for r in failure_rows:
        ip = r.get("ip_address", "")
        user = r.get("username", "")
        ts = r["timestamp"]
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if isinstance(ts, datetime) else str(ts)

        if not ip:
            continue

        try:
            upsert(
                "INSERT INTO attacker_stats "
                "(ip_address, username, first_seen, last_seen, total_attempts, failed) "
                "VALUES (%s, %s, %s, %s, 1, 1) "
                "ON DUPLICATE KEY UPDATE "
                "last_seen=GREATEST(last_seen, VALUES(last_seen)), "
                "total_attempts=total_attempts+1, "
                "failed=failed+1",
                (ip, user, ts_str, ts_str),
            )
        except Exception as exc:
            log.debug("upsert attacker_stats failed: %s", exc)


def _update_attacker_stats_success(rows: List[Dict]) -> None:
    """Upsert attacker_stats for successful logins."""
    if not _db_available():
        return

    from database.query import upsert  # noqa: PLC0415

    success_rows = [r for r in rows if r["event_type"] == "login.success"]
    if not success_rows:
        return

    for r in success_rows:
        ip = r.get("ip_address", "")
        user = r.get("username", "")
        ts = r["timestamp"]
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if isinstance(ts, datetime) else str(ts)

        if not ip:
            continue

        try:
            upsert(
                "INSERT INTO attacker_stats "
                "(ip_address, username, first_seen, last_seen, total_attempts, successful) "
                "VALUES (%s, %s, %s, %s, 1, 1) "
                "ON DUPLICATE KEY UPDATE "
                "last_seen=GREATEST(last_seen, VALUES(last_seen)), "
                "total_attempts=total_attempts+1, "
                "successful=successful+1",
                (ip, user, ts_str, ts_str),
            )
        except Exception as exc:
            log.debug("upsert attacker_stats (success) failed: %s", exc)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def ingest(
    log_path: Optional[str] = None,
    log_key: str = "auth.log",
    since_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Run one full ingestion cycle.

    Parameters
    ----------
    log_path : str or None
        Path to the log file.  If None, read from config.
    log_key : str
        Logical key for offset tracking.
    since_seconds : int or None
        Only used with journalctl fallback.

    Returns
    -------
    dict
        Summary: ``{ lines_read, events_parsed, events_inserted, source, errors }``
    """
    cfg = Config()
    if log_path is None:
        log_path = cfg.get("ssh_monitor.log_path", "/var/log/auth.log")
    if since_seconds is None:
        since_seconds = cfg.get("ssh_monitor.poll_interval", 30)

    max_lines = cfg.get("ssh_monitor.max_lines_per_poll", 5000)

    summary: Dict[str, Any] = {
        "lines_read": 0,
        "events_parsed": 0,
        "events_inserted": 0,
        "source": "none",
        "errors": 0,
    }

    # 1. Load offset
    state = load_offset(log_key)

    # 2. Determine source and read new lines
    use_journal = cfg.get("ssh_monitor.journal_fallback", True)

    new_lines: List[str] = []
    source = "auth.log"

    # Try the file first
    if os.path.isfile(log_path) and os.access(log_path, os.R_OK):
        # Check for rotation
        current_inode = get_file_inode(log_path)
        if current_inode != state.file_inode and state.byte_offset > 0:
            log.info("Log file rotated (inode changed %d -> %d). Reading from start.",
                     state.file_inode, current_inode)
            state.byte_offset = 0

        new_offset, new_lines = _read_new_lines(log_path, state.byte_offset)
        summary["source"] = "auth.log"

        # Update state for next round
        state.file_path = log_path
        state.file_inode = current_inode

    elif use_journal:
        # Fallback to journalctl
        from modules.ssh_monitor.journal import read_journal  # noqa: PLC0415
        log.info("Using journalctl fallback.")
        journal_lines = read_journal(
            since_seconds=since_seconds,
            unit=cfg.get("ssh_monitor.journal_unit", "sshd"),
            max_lines=max_lines,
        )
        new_lines = journal_lines
        summary["source"] = "journalctl"
        state.file_path = "journalctl"
        state.file_inode = 0
        # journalctl returns fresh data each call; no offset to maintain
        new_offset = 0
    else:
        log.warning("Log file not found and journalctl disabled.")
        summary["errors"] += 1
        return summary

    summary["lines_read"] = len(new_lines)

    if not new_lines:
        # Save offset even if nothing new (in case inode changed)
        if summary["source"] == "auth.log":
            state.byte_offset = new_offset
            save_offset(state)
        return summary

    # 3. Parse lines
    parsed = parse_lines(new_lines)
    summary["events_parsed"] = len(parsed)

    # 4. Normalize + dedup
    normalized = normalize_events(parsed)

    # 5. Insert into database
    if _db_available():
        inserted = _insert_events(normalized)
        summary["events_inserted"] = inserted

        # 6. Update attacker stats
        _update_attacker_stats(normalized)
        _update_attacker_stats_success(normalized)
    else:
        log.debug("Database unavailable; events parsed but not stored.")

    # 7. Save offset
    if summary["source"] == "auth.log":
        state.byte_offset = new_offset
        state.line_number += len(new_lines)
        save_offset(state)

    log.info(
        "Ingestion complete: lines=%d parsed=%d inserted=%d source=%s",
        summary["lines_read"], summary["events_parsed"],
        summary["events_inserted"], summary["source"],
    )

    return summary


def run_once() -> Dict[str, Any]:
    """Convenience wrapper: run one ingestion cycle with default config."""
    return ingest()


if __name__ == "__main__":
    """CLI entry point for testing the ingestion pipeline."""
    import sys
    # Ensure plugin dir is on path
    plugin_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
    if plugin_dir not in sys.path:
        sys.path.insert(0, plugin_dir)

    result = run_once()
    print(json.dumps(result, indent=2, default=str))