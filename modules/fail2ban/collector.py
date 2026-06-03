"""
Fail2Ban collector for Security Monitor.

Detects Fail2Ban installation, enumerates jails, collects ban/unban
events from /var/log/fail2ban.log, and stores results in the
fail2ban_jails and fail2ban_bans tables.
"""

import os
import re
import subprocess
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from lib.config import Config
from lib.logger import get_logger
from database.query import fetchall, fetchone, upsert, insert

log = get_logger("app")

F2B_CLIENT = "/usr/bin/fail2ban-client"


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def is_installed() -> bool:
    """Return True if fail2ban-client is available."""
    return os.path.isfile(F2B_CLIENT) and os.access(F2B_CLIENT, os.X_OK)


def get_version() -> Optional[str]:
    """Return the Fail2Ban version string, or None."""
    if not is_installed():
        return None
    try:
        result = subprocess.run(
            [F2B_CLIENT, "--version"],
            capture_output=True, text=True, timeout=5,
        )
        output = result.stdout.strip() or result.stderr.strip()
        # Output is typically "Fail2Ban v1.0.2"
        m = re.search(r"v?(\d+\.\d+[\.\d]*)", output)
        return m.group(1) if m else output
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Jail enumeration
# ---------------------------------------------------------------------------

def _f2b_cmd(args: List[str], timeout: int = 10) -> str:
    """Run a fail2ban-client command and return stdout."""
    try:
        result = subprocess.run(
            [F2B_CLIENT] + args,
            capture_output=True, text=True, timeout=timeout,
        )
        return result.stdout.strip()
    except Exception as exc:
        log.debug("fail2ban-client %s failed: %s", args, exc)
        return ""


def list_jails() -> List[str]:
    """Return the list of active jail names."""
    output = _f2b_cmd(["status"])
    # Output: "Status\n|- Number of jail:      3\n|- Jail list:   sshd, apache-badbot, ..."
    jails = []
    for line in output.splitlines():
        if "Jail list:" in line:
            # Extract after "Jail list:"
            parts = line.split("Jail list:", 1)
            if len(parts) == 2:
                jails = [j.strip() for j in parts[1].split(",") if j.strip()]
    return jails


def get_jail_status(jail: str) -> Dict[str, Any]:
    """Get detailed status for a specific jail."""
    output = _f2b_cmd(["status", jail])
    info: Dict[str, Any] = {"jail_name": jail, "status": "active"}

    for line in output.splitlines():
        line = line.strip()
        if "Currently banned:" in line:
            val = line.split(":", 1)[1].strip()
            info["currently_banned"] = int(val) if val.isdigit() else 0
        elif "Total banned:" in line:
            val = line.split(":", 1)[1].strip()
            info["total_banned"] = int(val) if val.isdigit() else 0
        elif "Currently failed:" in line:
            val = line.split(":", 1)[1].strip()
            info["currently_failed"] = int(val) if val.isdigit() else 0
        elif "Total failed:" in line:
            val = line.split(":", 1)[1].strip()
            info["total_failed"] = int(val) if val.isdigit() else 0
        elif "Banned IP list:" in line:
            val = line.split(":", 1)[1].strip()
            info["banned_ips"] = [ip.strip() for ip in val.split() if ip.strip()]

    return info


# ---------------------------------------------------------------------------
# Database storage
# ---------------------------------------------------------------------------

def store_jail_snapshot(jails: List[Dict]) -> None:
    """Upsert jail status into the fail2ban_jails table."""
    for jail in jails:
        try:
            upsert(
                "INSERT INTO fail2ban_jails "
                "(jail_name, status, total_banned, currently_banned, "
                " total_failed, currently_failed) "
                "VALUES (%s, %s, %s, %s, %s, %s) "
                "ON DUPLICATE KEY UPDATE "
                "status=VALUES(status), total_banned=VALUES(total_banned), "
                "currently_banned=VALUES(currently_banned), "
                "total_failed=VALUES(total_failed), "
                "currently_failed=VALUES(currently_failed), "
                "fetched_at=NOW()",
                (jail.get("jail_name", ""), jail.get("status", "active"),
                 jail.get("total_banned", 0), jail.get("currently_banned", 0),
                 jail.get("total_failed", 0), jail.get("currently_failed", 0)),
            )
        except Exception as exc:
            log.debug("store_jail_snapshot failed for %s: %s",
                      jail.get("jail_name"), exc)


def store_ban_event(jail_name: str, ip: str, banned_at: Optional[datetime] = None) -> Optional[int]:
    """Insert a ban event into the fail2ban_bans table."""
    ts = banned_at or datetime.now()
    ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if isinstance(ts, datetime) else str(ts)
    try:
        return insert(
            "INSERT INTO fail2ban_bans (jail_name, ip_address, banned_at) "
            "VALUES (%s, %s, %s)",
            (jail_name, ip, ts_str),
        )
    except Exception as exc:
        log.debug("store_ban_event failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# End-to-end collection cycle
# ---------------------------------------------------------------------------

def collect() -> Dict[str, Any]:
    """
    Run a full Fail2Ban collection cycle.

    1. Check installation
    2. Enumerate jails
    3. Collect status for each jail
    4. Store snapshots in database

    Returns a summary dict.
    """
    from modules.ssh_monitor.ingester import _db_available  # noqa: PLC0415

    summary: Dict[str, Any] = {
        "installed": is_installed(),
        "version": get_version(),
        "jails": [],
        "errors": 0,
    }

    if not summary["installed"]:
        return summary

    jails = list_jails()
    for jail_name in jails:
        status = get_jail_status(jail_name)
        summary["jails"].append(status)

    if _db_available():
        store_jail_snapshot(summary["jails"])

    return summary


def get_all_jails() -> List[Dict]:
    """Fetch the latest jail data from the database."""
    return fetchall(
        "SELECT * FROM fail2ban_jails ORDER BY jail_name"
    )


def get_recent_bans(limit: int = 50) -> List[Dict]:
    """Fetch recent ban events."""
    return fetchall(
        "SELECT * FROM fail2ban_bans ORDER BY id DESC LIMIT %s",
        (limit,),
    )


def get_active_bans() -> List[Dict]:
    """Fetch currently active bans (unbanned_at is NULL)."""
    return fetchall(
        "SELECT * FROM fail2ban_bans "
        "WHERE unbanned_at IS NULL "
        "ORDER BY banned_at DESC"
    )


def get_f2b_stats() -> Dict[str, Any]:
    """Aggregate Fail2Ban statistics."""
    stats: Dict[str, Any] = {}

    row = fetchone("SELECT COUNT(*) AS cnt FROM fail2ban_jails")
    stats["total_jails"] = row["cnt"] if row else 0

    row = fetchone(
        "SELECT SUM(currently_banned) AS total FROM fail2ban_jails"
    )
    stats["currently_banned"] = row["total"] if row and row.get("total") else 0

    row = fetchone(
        "SELECT COUNT(*) AS cnt FROM fail2ban_bans "
        "WHERE banned_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"
    )
    stats["bans_24h"] = row["cnt"] if row else 0

    row = fetchone(
        "SELECT COUNT(*) AS cnt FROM fail2ban_bans "
        "WHERE unbanned_at IS NULL"
    )
    stats["active_bans"] = row["cnt"] if row else 0

    return stats