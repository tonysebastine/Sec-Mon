"""
SSH log parser for Security Monitor.

Parses lines from /var/log/auth.log (Debian/Ubuntu) and /var/log/secure
(RHEL/CentOS) and extracts structured SSH authentication events.

Supported patterns:
  - Accepted password for <user> from <ip> port <port> ssh2
  - Accepted publickey for <user> from <ip> port <port> ssh2
  - Failed password for <user> from <ip> port <port> ssh2
  - Failed password for invalid user <user> from <ip> port <port> ssh2
  - Invalid user <user> from <ip>
  - Failed publickey for <user> from <ip>
  - Connection closed by authenticating user <user> <ip>
  - Connection closed by unknown user <ip>
  - Received disconnect from <ip>
  - pam_unix(sshd:session): session opened / closed for user=<user>
  - su: pam_unix(su:session): session opened for user=<target>
  - <user> : TTY=... ; PWD=... ; USER=<target> ; COMMAND=...
"""

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from dateutil import parser as _dateutil_parser

from lib.logger import get_logger

log = get_logger("app")

# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

_TS_RE = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")

# Successful login -----------------------------------------------------------
_ACC_PASS_RE = re.compile(
    r"Accepted\s+(password)\s+for\s+(?P<user>\S+)\s+"
    r"from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)
_ACC_PUBKEY_RE = re.compile(
    r"Accepted\s+(publickey)\s+for\s+(?P<user>\S+)\s+"
    r"from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)

# Failed login ---------------------------------------------------------------
_FAIL_PASS_RE = re.compile(
    r"Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+"
    r"from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)
_FAIL_PUBKEY_RE = re.compile(
    r"Failed\s+publickey\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+"
    r"from\s+(?P<ip>\S+)"
)
_INVALID_USER_RE = re.compile(
    r"Invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)"
)

# Connection closed ----------------------------------------------------------
# Matches "authenticating user <user> <ip>" and "invalid user <user> <ip>"
_CONN_CLOSED_USER_RE = re.compile(
    r"Connection\s+closed\s+by\s+(?:authenticating|invalid)\s+user\s+"
    r"(?P<user>\S+)\s+(?P<ip>\S+)"
)
# Matches "unknown user <ip> port ..." - we only care about the IP
_CONN_CLOSED_UNKNOWN_RE = re.compile(
    r"Connection\s+closed\s+by\s+unknown\s+user\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"
)
# Matches a bare IP without "user" keyword, e.g. "Connection closed by 1.2.3.4"
_CONN_CLOSED_IP_RE = re.compile(
    r"Connection\s+closed\s+by\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"
)

# Disconnect -----------------------------------------------------------------
_DISCONNECT_RE = re.compile(
    r"Received\s+disconnect\s+from\s+(?P<ip>\S+)"
)

# Session open/close ---------------------------------------------------------
_SESSION_OPEN_RE = re.compile(
    r"pam_unix\(sshd:session\):\s+session\s+opened\s+.*?user=(?P<user>\S+)"
)
_SESSION_CLOSE_RE = re.compile(
    r"pam_unix\(sshd:session\):\s+session\s+closed\s+.*?user=(?P<user>\S+)"
)

# sudo -----------------------------------------------------------------------
# No ^ anchor -- the line is prefixed by a syslog timestamp like "Jun  3 10:15:31 server sudo: "
_SUDO_CMD_RE = re.compile(
    r"(?P<user>\S+)\s*:\s+TTY=(?P<tty>\S+)\s+;\s+PWD=(?P<pwd>\S+)\s+;"
    r"\s+USER=(?P<target>\S+)\s+;\s+COMMAND=(?P<cmd>.+)$"
)

# su -------------------------------------------------------------------------
_SU_OPEN_RE = re.compile(
    r"pam_unix\(su:session\):\s+session\s+opened\s+.*?user=(?P<target>\S+)"
)

# Root -----------------------------------------------------------------------
_ROOT_LOGIN_RE = re.compile(
    r"(?:Accepted|Failed)\s+\S+\s+for\s+root\s+from\s+(?P<ip>\S+)"
)

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _parse_ts(ts_str: str, current_year: Optional[int] = None) -> Optional[datetime]:
    """
    Parse a syslog timestamp like ``Jun  3 14:22:10`` into a datetime.

    The year is not present in auth.log, so we assume *current_year*
    (or the local year if not provided).
    """
    if current_year is None:
        current_year = datetime.now().year
    try:
        dt = _dateutil_parser.parse(ts_str, fuzzy=False)
        return dt.replace(year=current_year, tzinfo=None)
    except (ValueError, OverflowError):
        pass
    # Manual fallback
    try:
        dt = datetime.strptime(ts_str.strip(), "%b %d %H:%M:%S")
        return dt.replace(year=current_year, tzinfo=None)
    except ValueError:
        return None


def _first_match(line: str, patterns):
    """Try each regex in *patterns*; return the Match or None."""
    for pat in patterns:
        m = pat.search(line)
        if m:
            return m
    return None


class ParsedEvent:
    """Lightweight container for one parsed auth log event."""

    __slots__ = (
        "timestamp", "event_type", "username", "ip_address",
        "port", "message", "raw_line", "metadata",
    )

    def __init__(self, **kwargs: Any) -> None:
        for slot in self.__slots__:
            setattr(self, slot, kwargs.get(slot))

    def as_dict(self) -> Dict[str, Any]:
        d = {s: getattr(self, s) for s in self.__slots__ if getattr(self, s) is not None}
        return d

    def __repr__(self) -> str:
        return f"<ParsedEvent {self.event_type} user={self.username!r} ip={self.ip_address!r}>"


def parse_line(line: str, current_year: Optional[int] = None) -> Optional[ParsedEvent]:
    """
    Parse a single auth.log line.

    Returns a ``ParsedEvent`` if the line is recognised, or ``None``
    if the line is irrelevant (e.g. "pam_env(sshd:setenv): ...").
    """
    line = line.rstrip("\n\r")
    if not line:
        return None

    # --- extract timestamp ---
    ts_match = _TS_RE.match(line)
    ts: Optional[datetime] = None
    if ts_match:
        ts = _parse_ts(ts_match.group(1), current_year)

    # --- Successful login (password or publickey) ---
    m = _first_match(line, [_ACC_PASS_RE, _ACC_PUBKEY_RE])
    if m:
        method = m.group(1) if m.lastindex else "unknown"
        return ParsedEvent(
            timestamp=ts,
            event_type="login.success",
            username=m.group("user"),
            ip_address=m.group("ip"),
            port=int(m.group("port")) if "port" in m.groupdict() else None,
            message=f"Accepted {method} login",
            raw_line=line,
            metadata={"method": method},
        )

    # --- Failed login (password) ---
    m = _FAIL_PASS_RE.search(line)
    if m:
        user = m.group("user")
        ip = m.group("ip")
        is_root = (user == "root")
        return ParsedEvent(
            timestamp=ts,
            event_type="login.failure",
            username=user,
            ip_address=ip,
            port=int(m.group("port")) if "port" in m.groupdict() else None,
            message=f"Failed password for {user}",
            raw_line=line,
            metadata={"root_attempt": is_root},
        )

    # --- Failed login (publickey) ---
    m = _FAIL_PUBKEY_RE.search(line)
    if m:
        return ParsedEvent(
            timestamp=ts,
            event_type="login.failure",
            username=m.group("user"),
            ip_address=m.group("ip"),
            message="Failed publickey",
            raw_line=line,
        )

    # --- Invalid user ---
    m = _INVALID_USER_RE.search(line)
    if m:
        return ParsedEvent(
            timestamp=ts,
            event_type="login.failure",
            username=m.group("user"),
            ip_address=m.group("ip"),
            message=f"Invalid user {m.group('user')}",
            raw_line=line,
        )

    # --- Connection closed ---
    m = _CONN_CLOSED_USER_RE.search(line)
    if m:
        return ParsedEvent(
            timestamp=ts,
            event_type="connection.closed",
            username=m.group("user"),
            ip_address=m.group("ip"),
            message="Connection closed",
            raw_line=line,
        )

    m = _CONN_CLOSED_UNKNOWN_RE.search(line)
    if m:
        return ParsedEvent(
            timestamp=ts,
            event_type="connection.closed",
            username="unknown",
            ip_address=m.group("ip"),
            message="Connection closed by unknown user",
            raw_line=line,
        )

    m = _CONN_CLOSED_IP_RE.search(line)
    if m:
        return ParsedEvent(
            timestamp=ts,
            event_type="connection.closed",
            ip_address=m.group("ip"),
            message="Connection closed",
            raw_line=line,
        )

    # --- Disconnect ---
    m = _DISCONNECT_RE.search(line)
    if m:
        return ParsedEvent(
            timestamp=ts,
            event_type="connection.disconnect",
            ip_address=m.group("ip"),
            message="Received disconnect",
            raw_line=line,
        )

    # --- Session open/close ---
    m = _SESSION_OPEN_RE.search(line)
    if m:
        return ParsedEvent(
            timestamp=ts,
            event_type="session.open",
            username=m.group("user"),
            message="Session opened",
            raw_line=line,
        )

    m = _SESSION_CLOSE_RE.search(line)
    if m:
        return ParsedEvent(
            timestamp=ts,
            event_type="session.close",
            username=m.group("user"),
            message="Session closed",
            raw_line=line,
        )

    # --- sudo command ---
    m = _SUDO_CMD_RE.search(line)
    if m:
        return ParsedEvent(
            timestamp=ts,
            event_type="sudo.command",
            username=m.group("user"),
            message=f"sudo -> {m.group('target')}: {m.group('cmd')}",
            raw_line=line,
            metadata={
                "target_user": m.group("target"),
                "command": m.group("cmd"),
                "tty": m.group("tty"),
                "pwd": m.group("pwd"),
            },
        )

    # --- su session open ---
    m = _SU_OPEN_RE.search(line)
    if m:
        return ParsedEvent(
            timestamp=ts,
            event_type="su.transition",
            username="root",
            message=f"su -> {m.group('target')}",
            raw_line=line,
            metadata={"target_user": m.group("target")},
        )

    # --- Line not recognised ---
    return None


def parse_lines(
    lines: List[str],
    current_year: Optional[int] = None,
) -> List[ParsedEvent]:
    """
    Parse multiple log lines and return the list of recognised events.

    Lines that do not match any known pattern are silently skipped.
    """
    events: List[ParsedEvent] = []
    if current_year is None:
        current_year = datetime.now().year
    for line in lines:
        ev = parse_line(line, current_year)
        if ev is not None:
            events.append(ev)
    return events