"""
Service health checker for Security Monitor.

Monitors critical systemd services (sshd, fail2ban, mariadb, nginx, apache2)
and stores their current status in the service_status table.

Uses systemctl to query service state, PID, memory, and uptime.
"""

import subprocess
from datetime import datetime
from typing import Any, Dict, List, Optional

from lib.config import Config
from lib.logger import get_logger
from database.query import fetchall, fetchone, insert

log = get_logger("app")


def _run_cmd(cmd: List[str], timeout: int = 5) -> str:
    """Run a command and return stdout."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip() if result.returncode == 0 else ""
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


def _systemctl_is_active(unit: str) -> str:
    """Check if a service is active. Returns 'running', 'stopped', 'failed', or 'unknown'."""
    output = _run_cmd(["systemctl", "is-active", unit])
    if not output:
        # Service might not exist; try is-enabled
        enabled = _run_cmd(["systemctl", "is-enabled", unit])
        if enabled == "enabled":
            return "stopped"
        return "unknown"

    status_map = {
        "active": "running",
        "inactive": "stopped",
        "failed": "failed",
        "activating": "running",
        "deactivating": "stopped",
    }
    return status_map.get(output.split("\n")[0].strip(), "unknown")


def _systemctl_show(unit: str) -> Dict[str, str]:
    """Get systemctl show properties for a unit."""
    output = _run_cmd([
        "systemctl", "show", unit,
        "--property=MainPID,MemoryCurrent,ActiveEnterTimestamp,SubState",
    ])
    props: Dict[str, str] = {}
    for line in output.splitlines():
        if "=" in line:
            key, _, val = line.partition("=")
            props[key.strip()] = val.strip()
    return props


def check_service(service_name: str, unit_name: str) -> Dict[str, Any]:
    """
    Check the status of a single service.

    Returns a dict with keys:
        service_name, unit_name, status, sub_status, pid, memory_kb, uptime_seconds
    """
    status = _systemctl_is_active(unit_name)
    props = _systemctl_show(unit_name)

    pid: Optional[int] = None
    memory_kb: Optional[int] = None
    uptime_seconds: Optional[int] = None
    sub_status = props.get("SubState", "")

    # Parse PID
    pid_str = props.get("MainPID", "0")
    if pid_str.isdigit() and int(pid_str) > 0:
        pid = int(pid_str)

    # Parse memory (systemctl returns bytes or "[not set]")
    mem_str = props.get("MemoryCurrent", "")
    if mem_str.isdigit():
        memory_kb = int(mem_str) // 1024

    # Parse uptime from ActiveEnterTimestamp
    enter_ts = props.get("ActiveEnterTimestamp", "")
    if enter_ts:
        try:
            # Format: "Wed 2026-06-03 10:15:30 IST"
            # Try multiple formats
            for fmt in ("%a %Y-%m-%d %H:%M:%S %Z", "%a %Y-%m-%d %H:%M:%S",
                        "%Y-%m-%d %H:%M:%S"):
                try:
                    dt = datetime.strptime(enter_ts.strip(), fmt)
                    uptime_seconds = int((datetime.now() - dt).total_seconds())
                    break
                except ValueError:
                    continue
        except Exception:
            pass

    return {
        "service_name": service_name,
        "unit_name": unit_name,
        "status": status,
        "sub_status": sub_status,
        "pid": pid,
        "memory_kb": memory_kb,
        "uptime_seconds": uptime_seconds,
    }


def store_service_status(services: List[Dict]) -> int:
    """Store service status snapshots in the database."""
    if not services:
        return 0

    rows = []
    for svc in services:
        rows.append((
            svc.get("service_name", ""),
            svc.get("unit_name", ""),
            svc.get("status", "unknown"),
            svc.get("sub_status", ""),
            svc.get("pid"),
            svc.get("memory_kb"),
            svc.get("uptime_seconds"),
        ))

    sql = (
        "INSERT INTO service_status "
        "(service_name, unit_name, status, sub_status, pid, memory_kb, uptime_seconds) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s)"
    )

    try:
        from database.query import insert_many
        affected = insert_many(sql, rows)
        return affected
    except Exception as exc:
        log.error("store_service_status failed: %s", exc)
        return 0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_all_services() -> List[Dict]:
    """
    Check all configured services.

    Reads the watched list from config/services.watched.
    """
    cfg = Config()
    watched = cfg.get("services.watched", [
        {"name": "sshd", "unit": "sshd", "type": "systemd"},
        {"name": "ssh", "unit": "ssh", "type": "systemd"},
        {"name": "fail2ban", "unit": "fail2ban", "type": "systemd"},
        {"name": "mariadb", "unit": "mariadb", "type": "systemd"},
        {"name": "mysql", "unit": "mysql", "type": "systemd"},
        {"name": "nginx", "unit": "nginx", "type": "systemd"},
        {"name": "apache2", "unit": "apache2", "type": "systemd"},
    ])

    results = []
    for svc_cfg in watched:
        name = svc_cfg.get("name", "")
        unit = svc_cfg.get("unit", name)
        svc_type = svc_cfg.get("type", "systemd")

        if svc_type == "systemd":
            result = check_service(name, unit)
            results.append(result)
        else:
            results.append({
                "service_name": name,
                "unit_name": unit,
                "status": "unknown",
                "sub_status": "",
                "pid": None,
                "memory_kb": None,
                "uptime_seconds": None,
            })

    return results


def collect() -> Dict[str, Any]:
    """
    Run a full service health collection cycle.

    Checks all services and stores results in the database.
    """
    from modules.ssh_monitor.ingester import _db_available  # noqa: PLC0415

    services = check_all_services()

    summary: Dict[str, Any] = {
        "total": len(services),
        "running": sum(1 for s in services if s["status"] == "running"),
        "stopped": sum(1 for s in services if s["status"] == "stopped"),
        "failed": sum(1 for s in services if s["status"] == "failed"),
        "unknown": sum(1 for s in services if s["status"] == "unknown"),
        "services": services,
    }

    if _db_available():
        store_service_status(services)

    return summary


def get_service_status() -> List[Dict]:
    """Get the most recent status for each service from the database."""
    # Get the latest entry for each service_name
    rows = fetchall(
        "SELECT ss.* FROM service_status ss "
        "INNER JOIN ("
        "  SELECT service_name, MAX(checked_at) AS max_checked "
        "  FROM service_status GROUP BY service_name"
        ") latest ON ss.service_name = latest.service_name "
        "AND ss.checked_at = latest.max_checked "
        "ORDER BY ss.service_name"
    )
    return rows


def get_service_history(service_name: str, limit: int = 100) -> List[Dict]:
    """Get status history for a specific service."""
    return fetchall(
        "SELECT * FROM service_status "
        "WHERE service_name = %s "
        "ORDER BY checked_at DESC LIMIT %s",
        (service_name, limit),
    )


def get_service_stats() -> Dict[str, Any]:
    """Aggregate service health statistics."""
    services = get_service_status()
    return {
        "total": len(services),
        "running": sum(1 for s in services if s.get("status") == "running"),
        "stopped": sum(1 for s in services if s.get("status") == "stopped"),
        "failed": sum(1 for s in services if s.get("status") == "failed"),
        "services": services,
    }