"""
Alert engine for Security Monitor.

Rule-based alert generation.  Evaluates configured rules against recent
events and generates alerts stored in the ``alerts`` table.  Alerts can
be acknowledged and trigger notifications via the notification system.

Supported rules:
  - failed_root_login   : threshold-based within a time window
  - successful_root_login : immediate
  - new_country_login   : first login from a new country
  - brute_force         : threshold-based within a time window
  - ssl_expiring_7d     : certificates expiring within 7 days
  - ssl_expiring_30d    : certificates expiring within 30 days
  - f2b_ban             : new Fail2Ban ban event
  - service_down        : critical service not running
"""

import json
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from lib.config import Config
from lib.logger import get_logger
from database.query import fetchall, fetchone, insert

log = get_logger("app")

# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

def _get_rule(rule_id: str) -> Optional[Dict]:
    """Get a rule configuration from the config."""
    cfg = Config()
    return cfg.get(f"alerts.rules.{rule_id}")


def _is_rule_enabled(rule_id: str) -> bool:
    """Check if a rule is enabled."""
    rule = _get_rule(rule_id)
    if rule is None:
        return False
    return rule.get("enabled", True)


def _check_recent_alert(rule_id: str, window_minutes: int = 60) -> bool:
    """
    Check if an identical alert was already generated within the window.
    Returns True if a duplicate would be created.
    """
    try:
        row = fetchone(
            "SELECT id FROM alerts "
            "WHERE rule_id = %s "
            "AND created_at >= DATE_SUB(NOW(), INTERVAL %s MINUTE) "
            "LIMIT 1",
            (rule_id, window_minutes),
        )
        return row is not None
    except Exception:
        return False


def _store_alert(rule_id: str, title: str, body: str = "",
                 severity: str = "warning",
                 metadata: Optional[Dict] = None,
                 event_id: Optional[int] = None) -> Optional[int]:
    """Store a new alert and return its ID."""
    meta_json = json.dumps(metadata) if metadata else None
    try:
        alert_id = insert(
            "INSERT INTO alerts (rule_id, title, body, severity, metadata, event_id) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (rule_id, title, body, severity, meta_json, event_id),
        )
        log.info("Alert generated: [%s] %s (id=%d)", severity, title, alert_id or 0)
        return alert_id
    except Exception as exc:
        log.error("Failed to store alert: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Rule evaluators
# ---------------------------------------------------------------------------

def _eval_failed_root_login() -> List[Dict]:
    """Check for failed root login attempts above threshold."""
    rule_id = "failed_root_login"
    if not _is_rule_enabled(rule_id):
        return []

    rule = _get_rule(rule_id)
    threshold = rule.get("threshold", 1)
    window = rule.get("window_minutes", 60)

    if _check_recent_alert(rule_id, window):
        return []

    row = fetchone(
        "SELECT COUNT(*) AS cnt FROM events "
        "WHERE event_type = 'login.failure' "
        "AND username = 'root' "
        "AND timestamp >= DATE_SUB(NOW(), INTERVAL %s MINUTE)",
        (window,),
    )
    count = row["cnt"] if row else 0

    if count >= threshold:
        # Get the source IPs
        ips = fetchall(
            "SELECT DISTINCT ip_address FROM events "
            "WHERE event_type = 'login.failure' AND username = 'root' "
            "AND timestamp >= DATE_SUB(NOW(), INTERVAL %s MINUTE)",
            (window,),
        )
        ip_list = [r["ip_address"] for r in ips if r.get("ip_address")]
        title = f"Failed root login: {count} attempts in {window}min"
        body = f"Source IPs: {', '.join(ip_list[:5])}"
        alert_id = _store_alert(rule_id, title, body, "critical",
                                {"count": count, "ips": ip_list})
        return [{"alert_id": alert_id, "rule_id": rule_id, "title": title}]
    return []


def _eval_successful_root_login() -> List[Dict]:
    """Alert on any successful root login."""
    rule_id = "successful_root_login"
    if not _is_rule_enabled(rule_id):
        return []

    if _check_recent_alert(rule_id, 5):  # 5-min dedup
        return []

    row = fetchone(
        "SELECT * FROM events "
        "WHERE event_type = 'login.root' "
        "AND timestamp >= DATE_SUB(NOW(), INTERVAL 5 MINUTE) "
        "ORDER BY id DESC LIMIT 1",
    )
    if row:
        title = f"Root login from {row.get('ip_address', 'unknown')}"
        body = row.get("message", "")
        alert_id = _store_alert(rule_id, title, body, "critical",
                                {"ip": row.get("ip_address", "")},
                                event_id=row.get("id"))
        return [{"alert_id": alert_id, "rule_id": rule_id, "title": title}]
    return []


def _eval_brute_force() -> List[Dict]:
    """Detect brute-force attempts (many failures from one IP)."""
    rule_id = "brute_force"
    if not _is_rule_enabled(rule_id):
        return []

    rule = _get_rule(rule_id)
    threshold = rule.get("threshold", 10)
    window = rule.get("window_minutes", 5)

    if _check_recent_alert(rule_id, window):
        return []

    rows = fetchall(
        "SELECT ip_address, COUNT(*) AS cnt FROM events "
        "WHERE event_type = 'login.failure' "
        "AND ip_address != '' "
        "AND timestamp >= DATE_SUB(NOW(), INTERVAL %s MINUTE) "
        "GROUP BY ip_address "
        "HAVING cnt >= %s "
        "ORDER BY cnt DESC LIMIT 5",
        (window, threshold),
    )

    results = []
    for row in rows:
        ip = row["ip_address"]
        count = row["cnt"]
        title = f"Brute-force detected: {count} failures from {ip}"
        alert_id = _store_alert(rule_id, title, "", "warning",
                                {"ip": ip, "count": count})
        results.append({"alert_id": alert_id, "rule_id": rule_id, "title": title})
    return results


def _eval_ssl_expiring() -> List[Dict]:
    """Check for SSL certificates expiring within thresholds."""
    results = []

    for rule_id, threshold_key, days, severity in [
        ("ssl_expiring_7d", "critical_days", 7, "critical"),
        ("ssl_expiring_30d", "warn_days", 30, "warning"),
    ]:
        if not _is_rule_enabled(rule_id):
            continue

        if _check_recent_alert(rule_id, 360):  # 6-hour dedup
            continue

        rows = fetchall(
            "SELECT * FROM ssl_certificates "
            "WHERE days_remaining IS NOT NULL "
            "AND days_remaining <= %s "
            "AND days_remaining > 0",
            (days,),
        )

        for row in rows:
            domain = row.get("domain", "unknown")
            days_left = row.get("days_remaining", 0)
            title = f"SSL expiring: {domain} ({days_left} days)"
            alert_id = _store_alert(rule_id, title, "", severity,
                                    {"domain": domain, "days_remaining": days_left},
                                    event_id=row.get("id"))
            results.append({"alert_id": alert_id, "rule_id": rule_id, "title": title})

    return results


def _eval_f2b_ban() -> List[Dict]:
    """Alert on new Fail2Ban bans."""
    rule_id = "f2b_ban"
    if not _is_rule_enabled(rule_id):
        return []

    if _check_recent_alert(rule_id, 5):
        return []

    row = fetchone(
        "SELECT * FROM fail2ban_bans "
        "WHERE banned_at >= DATE_SUB(NOW(), INTERVAL 5 MINUTE) "
        "ORDER BY id DESC LIMIT 1",
    )
    if row:
        title = f"Fail2Ban ban: {row.get('ip_address', 'unknown')} in {row.get('jail_name', 'unknown')}"
        alert_id = _store_alert(rule_id, title, "", "info",
                                {"ip": row.get("ip_address"), "jail": row.get("jail_name")})
        return [{"alert_id": alert_id, "rule_id": rule_id, "title": title}]
    return []


def _eval_service_down() -> List[Dict]:
    """Alert on critical services that are not running."""
    rule_id = "service_down"
    if not _is_rule_enabled(rule_id):
        return []

    if _check_recent_alert(rule_id, 30):
        return []

    rows = fetchall(
        "SELECT * FROM service_status ss "
        "INNER JOIN ("
        "  SELECT service_name, MAX(checked_at) AS max_checked "
        "  FROM service_status GROUP BY service_name"
        ") latest ON ss.service_name = latest.service_name "
        "AND ss.checked_at = latest.max_checked "
        "WHERE ss.status = 'failed'"
    )

    results = []
    for row in rows:
        svc = row.get("service_name", "unknown")
        title = f"Service down: {svc}"
        alert_id = _store_alert(rule_id, title, "", "critical",
                                {"service": svc})
        results.append({"alert_id": alert_id, "rule_id": rule_id, "title": title})
    return results


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

EVALUATORS = [
    _eval_failed_root_login,
    _eval_successful_root_login,
    _eval_brute_force,
    _eval_ssl_expiring,
    _eval_f2b_ban,
    _eval_service_down,
]


def run_rules() -> List[Dict]:
    """
    Evaluate all alert rules and return newly generated alerts.
    """
    all_alerts: List[Dict] = []
    for evaluator in EVALUATORS:
        try:
            alerts = evaluator()
            all_alerts.extend(alerts)
        except Exception as exc:
            log.error("Alert rule failed: %s", exc)

    return all_alerts


def get_recent_alerts(limit: int = 50, severity: Optional[str] = None,
                      acknowledged: Optional[bool] = None) -> List[Dict]:
    """Fetch recent alerts with optional filters."""
    where_parts: list[str] = []
    params: list = []

    if severity:
        where_parts.append("severity = %s")
        params.append(severity)

    if acknowledged is not None:
        where_parts.append("acknowledged = %s")
        params.append(1 if acknowledged else 0)

    where_sql = ""
    if where_parts:
        where_sql = "WHERE " + " AND ".join(where_parts)

    return fetchall(
        f"SELECT * FROM alerts {where_sql} ORDER BY id DESC LIMIT %s",
        tuple(params) + (limit,),
    )


def acknowledge_alert(alert_id: int, user: str = "admin") -> bool:
    """Mark an alert as acknowledged."""
    try:
        from database.query import execute
        execute(
            "UPDATE alerts SET acknowledged = 1, ack_at = NOW(), ack_by = %s "
            "WHERE id = %s AND acknowledged = 0",
            (user, alert_id),
        )
        return True
    except Exception as exc:
        log.error("acknowledge_alert failed: %s", exc)
        return False


def get_alert_stats() -> Dict[str, Any]:
    """Aggregate alert statistics."""
    stats: Dict[str, Any] = {}

    row = fetchone("SELECT COUNT(*) AS cnt FROM alerts")
    stats["total"] = row["cnt"] if row else 0

    row = fetchone(
        "SELECT COUNT(*) AS cnt FROM alerts WHERE acknowledged = 0"
    )
    stats["unacknowledged"] = row["cnt"] if row else 0

    for sev in ("info", "warning", "critical"):
        row = fetchone(
            "SELECT COUNT(*) AS cnt FROM alerts WHERE severity = %s "
            "AND acknowledged = 0",
            (sev,),
        )
        stats[f"{sev}_unacked"] = row["cnt"] if row else 0

    row = fetchone(
        "SELECT COUNT(*) AS cnt FROM alerts "
        "WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"
    )
    stats["last_24h"] = row["cnt"] if row else 0

    return stats