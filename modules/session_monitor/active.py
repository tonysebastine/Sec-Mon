"""
Active session monitor for Security Monitor.

Reads currently logged-in users via the ``who`` and ``w`` commands,
merges the results, and provides a unified view of active sessions
on the server.

This is independent of the SSH log parser — it provides a point-in-time
snapshot of who is currently connected.
"""

import os
import re
import subprocess
from datetime import datetime
from typing import Dict, List, Optional

from lib.logger import get_logger

log = get_logger("app")


def _run_cmd(cmd: List[str], timeout: int = 5) -> str:
    """Run a command and return stdout, or empty string on failure."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout if result.returncode == 0 else ""
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        log.debug("_run_cmd(%s) failed: %s", cmd, exc)
        return ""


def parse_who(output: str) -> List[Dict]:
    """
    Parse the output of the ``who`` command.

    Typical output::

        admin    pts/0        2026-06-03 10:15 (192.168.1.100)
        deploy   pts/1        2026-06-03 11:30 (10.0.0.5)
        root     tty1         2026-06-03 09:00

    Returns a list of dicts with keys:
        user, terminal, login_time, source_ip
    """
    sessions: List[Dict] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        # who output: user terminal login_time [ip]
        m = re.match(
            r"(\S+)\s+(\S+)\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})\s*(?:\((\S+)\))?",
            line,
        )
        if m:
            sessions.append({
                "user": m.group(1),
                "terminal": m.group(2),
                "login_time": m.group(3),
                "source_ip": m.group(4) or "",
                "idle": "",
                "pcpu": "",
                "from_command": "who",
            })
    return sessions


def parse_w(output: str) -> List[Dict]:
    """
    Parse the output of the ``w`` command.

    Typical output::

        15:30:01 up 10 days,  2:15,  2 users,  load average: 0.10, 0.05, 0.01
        USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
        admin    pts/0    192.168.1.100    10:15    0.00s  0.12s  0.01s -bash
        deploy   pts/1    10.0.0.5         11:30    5:23   0.05s  0.05s top

    Returns a list of dicts with keys:
        user, terminal, source_ip, login_time, idle, pcpu, command
    """
    sessions: List[Dict] = []
    lines = output.splitlines()
    for line in lines[2:]:  # skip header lines (uptime + column headers)
        line = line.strip()
        if not line:
            continue
        # w output is whitespace-separated
        parts = line.split()
        if len(parts) < 8:
            continue
        sessions.append({
            "user": parts[0],
            "terminal": parts[1],
            "source_ip": parts[2] if parts[2] != "-" else "",
            "login_time": parts[3],
            "idle": parts[4],
            "pcpu": parts[7] if len(parts) > 7 else "",
            "from_command": "w",
        })
    return sessions


def merge_sessions(who_sessions: List[Dict], w_sessions: List[Dict]) -> List[Dict]:
    """
    Merge results from ``who`` and ``w``.

    The ``w`` output is preferred when available because it includes idle
    time and current process info.  ``who`` fills in gaps.
    """
    merged: Dict[str, Dict] = {}

    # Index by (user, terminal)
    for s in who_sessions:
        key = (s["user"], s["terminal"])
        merged[key] = s

    # Override with w data (richer)
    for s in w_sessions:
        key = (s["user"], s["terminal"])
        if key in merged:
            # Merge: keep w data, fill in any missing fields
            existing = merged[key]
            for field in ("idle", "pcpu", "command", "source_ip", "login_time"):
                if field in s and s[field]:
                    existing[field] = s[field]
        else:
            merged[key] = s

    return list(merged.values())


def get_active_sessions() -> List[Dict]:
    """
    Get a merged snapshot of currently active sessions.

    Returns a list of dicts sorted by login_time.
    """
    who_out = _run_cmd(["who"])
    w_out = _run_cmd(["w", "-h"])

    who_sessions = parse_who(who_out) if who_out else []
    w_sessions = parse_w(w_out) if w_out else []

    sessions = merge_sessions(who_sessions, w_sessions)

    # Sort by login_time
    sessions.sort(key=lambda s: s.get("login_time", ""))

    return sessions


def get_active_sessions_count() -> int:
    """Return the number of active sessions."""
    return len(get_active_sessions())