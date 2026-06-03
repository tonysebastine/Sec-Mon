"""
Log file offset tracker for Security Monitor.

Persists the read position (inode + byte offset) for each monitored log
file so the parser can resume after restart or log rotation without
re-processing the entire file.

Two storage backends are supported:

1. **Database** (preferred) - row in the ``log_offsets`` table.
2. **JSON fallback** - ``data/offsets/<log_key>.json`` when the database
   is unreachable (e.g. during first boot before install.sh has run).

Each tracker entry stores:
- log_key      : logical identifier (e.g. ``auth.log``, ``fail2ban.log``)
- file_path    : absolute path of the file being tracked
- file_inode   : inode of the file (used to detect rotation)
- byte_offset  : byte position we have read up to
- line_number  : total lines read (for stats)
"""

import json
import os
import time
from dataclasses import dataclass, field, asdict
from typing import Optional

from lib.config import Config
from lib.logger import get_logger

log = get_logger("app")

PLUGIN_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
OFFSETS_DB_DIR = os.path.join(PLUGIN_DIR, "data", "offsets")


@dataclass
class OffsetState:
    log_key: str
    file_path: str
    file_inode: int = 0
    byte_offset: int = 0
    line_number: int = 0
    updated_at: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def _db_available() -> bool:
    try:
        from database.connection import is_available
        return is_available()
    except Exception:
        return False


def _load_from_db(log_key: str) -> Optional[OffsetState]:
    try:
        from database.query import fetchone
        row = fetchone(
            "SELECT log_key, file_path, file_inode, byte_offset, line_number "
            "FROM log_offsets WHERE log_key = %s",
            (log_key,),
        )
        if row:
            return OffsetState(
                log_key=row["log_key"],
                file_path=row["file_path"],
                file_inode=row["file_inode"],
                byte_offset=row["byte_offset"],
                line_number=row["line_number"],
            )
    except Exception as exc:
        log.debug("_load_from_db(%s) failed: %s", log_key, exc)
    return None


def _save_to_db(state: OffsetState) -> bool:
    try:
        from database.query import upsert
        upsert(
            "INSERT INTO log_offsets (log_key, file_path, file_inode, byte_offset, line_number) "
            "VALUES (%s, %s, %s, %s, %s) "
            "ON DUPLICATE KEY UPDATE "
            "file_path=VALUES(file_path), file_inode=VALUES(file_inode), "
            "byte_offset=VALUES(byte_offset), line_number=VALUES(line_number)",
            (state.log_key, state.file_path, state.file_inode,
             state.byte_offset, state.line_number),
        )
        return True
    except Exception as exc:
        log.debug("_save_to_db(%s) failed: %s", state.log_key, exc)
        return False


# ---------------------------------------------------------------------------
# JSON file fallback
# ---------------------------------------------------------------------------

def _json_path(log_key: str) -> str:
    os.makedirs(OFFSETS_DB_DIR, exist_ok=True)
    safe_key = log_key.replace("/", "_").replace("\\", "_")
    return os.path.join(OFFSETS_DB_DIR, f"{safe_key}.json")


def _load_from_json(log_key: str) -> Optional[OffsetState]:
    path = _json_path(log_key)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return OffsetState(**data)
    except Exception as exc:
        log.debug("_load_from_json(%s) failed: %s", log_key, exc)
        return None


def _save_to_json(state: OffsetState) -> bool:
    try:
        path = _json_path(state.log_key)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(asdict(state), f, indent=2)
        return True
    except Exception as exc:
        log.debug("_save_to_json(%s) failed: %s", state.log_key, exc)
        return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_offset(log_key: str) -> OffsetState:
    """
    Load the persisted offset for *log_key*.

    Tries the database first; falls back to JSON file storage.
    Returns a zero-offset state if nothing is found.
    """
    state: Optional[OffsetState] = None

    if _db_available():
        state = _load_from_db(log_key)

    if state is None:
        state = _load_from_json(log_key)

    if state is None:
        log.info("No existing offset for '%s'; starting from zero.", log_key)
        state = OffsetState(log_key=log_key, file_path="", file_inode=0,
                            byte_offset=0, line_number=0)

    return state


def save_offset(state: OffsetState) -> None:
    """
    Persist the current offset state.

    Writes to the database and to the JSON fallback simultaneously
    (best-effort) so that at least one backend has the latest position.
    """
    state.updated_at = time.time()
    db_ok = False
    json_ok = False

    if _db_available():
        db_ok = _save_to_db(state)

    json_ok = _save_to_json(state)

    if not db_ok and not json_ok:
        log.error("Failed to persist offset for '%s' to any backend.", state.log_key)


def file_has_rotated(log_key: str, current_inode: int) -> bool:
    """
    Check whether the log file has been rotated (inode changed).

    Returns True if the stored inode differs from *current_inode*
    AND the stored offset is non-zero (i.e. we had previously read
    from the old file).
    """
    state = load_offset(log_key)
    if state.byte_offset > 0 and state.file_inode != current_inode and state.file_inode != 0:
        return True
    return False


def reset_offset(log_key: str) -> None:
    """Reset the offset for *log_key* to zero (e.g. after a manual log rotation)."""
    state = OffsetState(log_key=log_key, file_path="",
                        file_inode=0, byte_offset=0, line_number=0)
    save_offset(state)
    log.info("Offset for '%s' reset to zero.", log_key)


def get_file_inode(path: str) -> int:
    """Return the inode of the file at *path*, or 0 if it doesn't exist."""
    try:
        stat = os.stat(path)
        return stat.st_ino
    except (OSError, FileNotFoundError):
        return 0