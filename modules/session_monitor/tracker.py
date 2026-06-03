"""
Session lifecycle tracker for Security Monitor.

Monitors session open/close events from /var/log/auth.log and calculates
session durations.  Tracks sudo commands and su transitions as separate
event types stored in the ``events`` table.

This module works in tandem with the SSH monitor: the SSH parser
recognizes session/sudo/su lines, and this tracker enriches them with
duration data and stores them.
"""

import json
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from lib.config import Config
from lib.logger import get_logger
from database.query import fetchall, fetchone, upsert

log = get_logger("app")

# ---------------------------------------------------------------------------
# In-memory session state (username -> first seen open time)
# Tracks which sessions are currently "open" so we can compute duration
# when the close event arrives.
# ---------------------------------------------------------------------------
_open_sessions: Dict[str, float] = {}  # key = "user:pid" or "user"


def _session_key(username: str, pid: Optional[str] = None) -> str:
    """Build a session lookup key."""
    if pid:
        return f"{username}:{pid}"
    return username


def track_session_event(event: Dict) -> Optional[Dict]:
    """
    Process a session.open or session.close event.

    Returns an enriched dict with ``duration_seconds`` added for close
    events, or None if the event should not be stored (e.g. duplicate).
    """
    event_type = event.get("event_type", "")
    username = event.get("username", "")
    ts = event.get("timestamp")

    if not username or not event_type:
        return event

    if ts and isinstance(ts, str):
        try:
            ts = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass

    now_ts = ts.timestamp() if isinstance(ts, datetime) else time.time()
    key = _session_key(username)

    if event_type == "session.open":
        _open_sessions[key] = now_ts
        event["duration_seconds"] = None
        return event

    elif event_type == "session.close":
        open_time = _open_sessions.pop(key, None)
        if open_time is not None:
            duration = int(now_ts - open_time)
            event["duration_seconds"] = max(0, duration)
        else:
            event["duration_seconds"] = None
        return event

    return event


def track_sudo_event(event: Dict) -> Dict:
    """
    Enrich a sudo.command event with additional metadata.

    The SSH parser already extracts user, target_user, command, tty, pwd.
    This function ensures the event is ready for database storage.
    """
    # Ensure metadata is a JSON string
    if "metadata" in event and isinstance(event["metadata"], dict):
        event["metadata"] = json.dumps(event["metadata"])
    return event


def track_su_event(event: Dict) -> Dict:
    """
    Enrich a su.transition event with additional metadata.
    """
    if "metadata" in event and isinstance(event["metadata"], dict):
        event["metadata"] = json.dumps(event["metadata"])
    return event


def store_session_events(events: List[Dict]) -> int:
    """
    Batch-insert session lifecycle events into the database.

    Handles session.open, session.close, sudo.command, and su.transition.
    Returns the number of rows inserted.
    """
    if not events:
        return 0

    from database.query import insert_many  # noqa: PLC0415

    rows = []
    for ev in events:
        ev_type = ev.get("event_type", "")
        if ev_type not in ("session.open", "session.close",
                           "sudo.command", "su.transition"):
            continue

        # Enrich based on type
        if ev_type in ("session.open", "session.close"):
            ev = track_session_event(ev)
        elif ev_type == "sudo.command":
            ev = track_sudo_event(ev)
        elif ev_type == "su.transition":
            ev = track_su_event(ev)

        ts = ev.get("timestamp")
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if isinstance(ts, datetime) else str(ts) if ts else None

        # Build message with duration for close events
        message = ev.get("message", "")
        if ev_type == "session.close" and ev.get("duration_seconds") is not None:
            dur = ev["duration_seconds"]
            mins, secs = divmod(dur, 60)
            hours, mins = divmod(mins, 60)
            if hours:
                message += f" (duration: {hours}h {mins}m {secs}s)"
            elif mins:
                message += f" (duration: {mins}m {secs}s)"
            else:
                message += f" (duration: {secs}s)"

        # Parse metadata
        metadata = ev.get("metadata")
        if isinstance(metadata, dict):
            metadata = json.dumps(metadata)

        rows.append((
            ts_str,
            ev_type,
            ev.get("username", ""),
            ev.get("ip_address", ""),
            ev.get("port"),
            ev.get("hostname", ""),
            message,
            ev.get("raw_line", ""),
            metadata,
            ev.get("country", ""),
            ev.get("city", ""),
            ev.get("asn", ""),
        ))

    if not rows:
        return 0

    sql = (
        "INSERT INTO events "
        "(timestamp, event_type, username, ip_address, port, hostname, "
        " message, raw_line, metadata, country, city, asn) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
    )

    try:
        affected = insert_many(sql, rows)
        return affected
    except Exception as exc:
        log.error("Failed to insert %d session events: %s", len(rows), exc)
        return 0


def get_active_sessions() -> List[Dict]:
    """
    Return a list of currently open sessions.

    These are sessions where we've seen session.open but no session.close
    yet (based on in-memory state).
    """
    now = time.time()
    sessions = []
    for key, open_time in _open_sessions.items():
        username = key.split(":")[0]
        duration = int(now - open_time)
        sessions.append({
            "username": username,
            "session_key": key,
            "opened_at": datetime.fromtimestamp(open_time).strftime("%Y-%m-%d %H:%M:%S"),
            "duration_seconds": duration,
        })
    return sessions


def get_session_stats() -> Dict:
    """
    Query aggregate session statistics from the database.
    """
    stats: Dict[str, Any] = {}

    # Sessions opened in last 24h
    row = fetchone(
        "SELECT COUNT(*) AS cnt FROM events "
        "WHERE event_type = 'session.open' "
        "AND timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"
    )
    stats["sessions_24h"] = row["cnt"] if row else 0

    # Sessions closed in last 24h
    row = fetchone(
        "SELECT COUNT(*) AS cnt FROM events "
        "WHERE event_type = 'session.close' "
        "AND timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"
    )
    stats["closes_24h"] = row["cnt"] if row else 0

    # sudo commands in last 24h
    row = fetchone(
        "SELECT COUNT(*) AS cnt FROM events "
        "WHERE event_type = 'sudo.command' "
        "AND timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"
    )
    stats["sudo_24h"] = row["cnt"] if row else 0

    # su transitions in last 24h
    row = fetchone(
        "SELECT COUNT(*) AS cnt FROM events "
        "WHERE event_type = 'su.transition' "
        "AND timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"
    )
    stats["su_24h"] = row["cnt"] if row else 0

    # Currently active (in-memory)
    stats["active_sessions"] = len(_open_sessions)

    return stats


def get_recent_sessions(limit: int = 50) -> List[Dict]:
    """Fetch the most recent session open/close events."""
    rows = fetchall(
        "SELECT * FROM events "
        "WHERE event_type IN ('session.open', 'session.close', 'sudo.command', 'su.transition') "
        "ORDER BY id DESC LIMIT %s",
        (limit,),
    )
    return rows