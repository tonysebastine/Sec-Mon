"""
Event normalizer for Security Monitor.

Takes raw ``ParsedEvent`` objects from the parser and enriches them
with:

1. **Deduplication** — suppresses duplicate events within a configurable
   time window (e.g. two identical "Failed password" lines for the same
   user/IP within 60 seconds).
2. **Root-login flagging** — adds ``login.root`` event type for
   successful root logins.
3. **Metadata enrichment** — fills in default metadata fields so every
   event has a consistent shape before database storage.
"""

import hashlib
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set

from lib.config import Config
from lib.logger import get_logger

log = get_logger("app")


class DedupWindow:
    """
    In-memory sliding-window deduplication.

    Keeps a bounded dictionary of event hashes and drops any event
    whose hash is already present within the last *window_seconds*.
    """

    def __init__(self, window_seconds: int = 60, max_entries: int = 10000) -> None:
        self._window = window_seconds
        self._max = max_entries
        self._seen: Dict[str, float] = {}

    def is_duplicate(self, key: str) -> bool:
        """Return True if *key* was seen within the dedup window."""
        now = time.time()
        cutoff = now - self._window

        # Prune stale entries periodically
        if len(self._seen) > self._max:
            self._prune(cutoff)

        if key in self._seen:
            return True

        self._seen[key] = now
        return False

    def _prune(self, cutoff: float) -> None:
        stale = [k for k, t in self._seen.items() if t < cutoff]
        for k in stale:
            del self._seen[k]


def _event_hash(event) -> str:
    """Generate a deterministic hash for deduplication."""
    parts = [
        str(event.event_type or ""),
        str(event.username or ""),
        str(event.ip_address or ""),
        str(event.message or ""),
    ]
    digest = hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]
    return digest


# Module-level dedup window instance
_dedup_window: Optional[DedupWindow] = None


def _get_dedup_window() -> DedupWindow:
    global _dedup_window  # noqa: PLW0603
    if _dedup_window is None:
        cfg = Config()
        window_sec = cfg.get("ssh_monitor.dedup_window_seconds", 60)
        _dedup_window = DedupWindow(window_seconds=window_sec)
    return _dedup_window


def normalize_event(event) -> Optional[Dict]:
    """
    Normalize and enrich a single ParsedEvent.

    Returns a dictionary suitable for database insertion, or None if
    the event is a duplicate and should be skipped.
    """
    if event is None:
        return None

    # 1. Deduplication
    dedup = _get_dedup_window()
    h = _event_hash(event)
    if dedup.is_duplicate(h):
        return None

    # 2. Build normalized dict
    row: Dict = {
        "timestamp": event.timestamp,
        "event_type": event.event_type,
        "username": event.username or "",
        "ip_address": event.ip_address or "",
        "port": event.port,
        "hostname": "",  # filled by ingester if available
        "message": event.message or "",
        "raw_line": event.raw_line,
        "metadata": json.dumps(event.metadata) if event.metadata else None,
        "country": "",
        "city": "",
        "asn": "",
    }

    # 3. Root-login enrichment: a successful login for user root also
    #    generates an additional login.root event.
    if event.event_type == "login.success" and event.username == "root":
        # The event itself keeps event_type=login.success;
        # the ingester will also store a login.root variant.
        row["_also_root_login"] = True

    return row


def normalize_events(events: list) -> List[Dict]:
    """
    Normalize a batch of ParsedEvents.

    Returns the list of normalized dicts (duplicates removed).
    Also appends a ``login.root`` event whenever a successful root
    login is found.
    """
    out: List[Dict] = []
    for ev in events:
        row = normalize_event(ev)
        if row is None:
            continue

        # If this is a root success login, generate an extra root event
        also_root = row.pop("_also_root_login", False)

        out.append(row)

        if also_root:
            root_row = dict(row)
            root_row["event_type"] = "login.root"
            root_row["message"] = f"Successful root login from {row['ip_address']}"
            out.append(root_row)

    return out