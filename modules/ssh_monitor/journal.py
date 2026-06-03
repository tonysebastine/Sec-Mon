"""
journalctl fallback reader for Security Monitor.

When /var/log/auth.log is missing or rotated, this module falls back to
reading SSH-related entries from journald via the ``journalctl`` command.

It produces the same raw line format as auth.log so the parser can be
reused without modification.
"""

import os
import subprocess
import time
from typing import List, Optional, Tuple

from lib.config import Config
from lib.logger import get_logger

log = get_logger("app")

JOURNALCTL_BIN = "/usr/bin/journalctl"


def is_journalctl_available() -> bool:
    """Return True if journalctl is installed and usable."""
    return os.path.isfile(JOURNALCTL_BIN) and os.access(JOURNALCTL_BIN, os.X_OK)


def read_journal(
    since_seconds: int = 300,
    unit: Optional[str] = "sshd",
    max_lines: int = 5000,
) -> List[str]:
    """
    Read recent SSH log lines from journald.

    Parameters
    ----------
    since_seconds : int
        Lookback window in seconds (default 5 minutes).
    unit : str or None
        systemd unit to filter on (default ``sshd``).
    max_lines : int
        Hard cap on lines returned.

    Returns
    -------
    list[str]
        Raw log lines in syslog-compatible format.
    """
    if not is_journalctl_available():
        log.warning("journalctl is not available on this system.")
        return []

    cmd: List[str] = [
        JOURNALCTL_BIN,
        "--no-pager",
        "--output=short-iso",
        "--since", f"{since_seconds} seconds ago",
        "-q",  # quiet — suppress headers
    ]
    if unit:
        cmd.extend(["-u", unit])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            log.warning("journalctl exited with code %d: %s",
                        result.returncode, result.stderr.strip()[:200])
            return []

        lines = result.stdout.splitlines()
        # journalctl --output=short-iso gives lines like:
        #   2026-06-03T14:22:10+05:30 hostname sshd[12345]: Accepted password ...
        # We need to convert this to auth.log format:
        #   Jun  3 14:22:10 hostname sshd[12345]: Accepted password ...
        converted = [_iso_to_syslog(line) for line in lines]
        return converted[-max_lines:]

    except subprocess.TimeoutExpired:
        log.warning("journalctl read timed out after 30s.")
        return []
    except Exception as exc:
        log.error("journalctl read failed: %s", exc)
        return []


def _iso_to_syslog(line: str) -> str:
    """
    Convert an ISO-8601 timestamp line to syslog-style format.

    Input:  ``2026-06-03T14:22:10+05:30 hostname sshd[12345]: ...``
    Output: ``Jun  3 14:22:10 hostname sshd[12345]: ...``
    """
    # Try to split on the first space after the ISO timestamp
    # ISO timestamp can be: 2026-06-03T14:22:10+05:30  or 2026-06-03T14:22:10.123456+05:30
    parts = line.split(" ", 2)
    if len(parts) < 2:
        return line

    ts_part = parts[0]
    rest = parts[1] if len(parts) > 1 else ""
    remainder = parts[2] if len(parts) > 2 else ""

    # Parse ISO timestamp
    try:
        from datetime import datetime as _dt
        # Strip timezone offset for parsing
        ts_clean = ts_part.replace("T", " ").split("+")[0].split(".")[0]
        dt = _dt.strptime(ts_clean, "%Y-%m-%d %H:%M:%S")
        syslog_ts = dt.strftime("%b %d %H:%M:%S")
        return f"{syslog_ts} {rest} {remainder}".strip()
    except (ValueError, IndexError):
        # If parsing fails, just return as-is
        return line


def read_with_fallback(
    auth_log_path: str,
    since_seconds: int = 300,
    unit: Optional[str] = "sshd",
    max_lines: int = 5000,
) -> Tuple[List[str], str]:
    """
    Try reading from auth.log first; fall back to journalctl.

    Returns
    -------
    (lines, source) where source is one of "auth.log" or "journalctl".
    """
    # Try auth.log
    if os.path.isfile(auth_log_path) and os.access(auth_log_path, os.R_OK):
        try:
            with open(auth_log_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
                # Return the tail
                return lines[-max_lines:], "auth.log"
        except Exception as exc:
            log.warning("Failed to read %s: %s", auth_log_path, exc)

    # Fallback to journalctl
    if is_journalctl_available():
        log.info("Falling back to journalctl for SSH log reading.")
        lines = read_journal(since_seconds=since_seconds, unit=unit, max_lines=max_lines)
        return lines, "journalctl"

    log.warning("Neither %s nor journalctl available.", auth_log_path)
    return [], "none"