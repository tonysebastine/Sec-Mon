"""
Security Monitor - Main plugin class for aaPanel.

aaPanel discovers this class through index.py and calls its methods
based on HTTP request parameters.  Each public method corresponds to
a UI page or an API action.

Route dispatch:  index.py -> request['action'] -> sec_mon_main.<action>
"""

import json
import os
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

# Ensure the plugin root is on sys.path so imports work at runtime
PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
if PLUGIN_DIR not in sys.path:
    sys.path.insert(0, PLUGIN_DIR)

from lib.config import Config
from lib.logger import get_logger
from database.connection import is_available as db_available, close_all as db_close

log = get_logger("app")


def _json_ok(data: Any = None) -> str:
    """Return a success JSON response as a string."""
    payload = {"status": 0, "msg": "success", "data": data}
    return json.dumps(payload, ensure_ascii=False, default=str)


def _json_err(msg: str = "error", code: int = 1) -> str:
    """Return an error JSON response as a string."""
    payload = {"status": code, "msg": msg, "data": None}
    return json.dumps(payload, ensure_ascii=False)


def _get_args(args: dict) -> Dict[str, Any]:
    """Normalise the raw aaPanel request dict."""
    p = args.get("params", {})
    if isinstance(p, str):
        try:
            p = json.loads(p)
        except (json.JSONDecodeError, TypeError):
            p = {}
    return p if isinstance(p, dict) else {}


# =============================================================================
# Main plugin class
# =============================================================================

class sec_mon_main:
    """
    aaPanel plugin entry-point.  All public methods are reachable via
    HTTP routes dispatched by index.py.
    """

    __plugin_name = "sec_mon"
    __plugin_version = "1.0.0"

    def __init__(self) -> None:
        try:
            self._cfg = Config()
        except Exception:
            log.warning("Config not loaded yet; using defaults.")
            self._cfg = None

    # ------------------------------------------------------------------
    # Page loaders (HTML templates)
    # ------------------------------------------------------------------

    def return_index(self, args: dict = {}) -> str:
        """Main dashboard page."""
        tpl = self._read_tpl("index.html")
        if tpl:
            return tpl
        return self._fallback_page("Dashboard", "Plugin template not found. Please reinstall.")

    def return_dashboard(self, args: dict = {}) -> str:
        return self._read_tpl("dashboard.html") or self._fallback_page("Dashboard", "Missing")

    def return_events(self, args: dict = {}) -> str:
        return self._read_tpl("events.html") or self._fallback_page("Events", "Missing")

    def return_sessions(self, args: dict = {}) -> str:
        return self._read_tpl("sessions.html") or self._fallback_page("Sessions", "Missing")

    def return_fail2ban(self, args: dict = {}) -> str:
        return self._read_tpl("fail2ban.html") or self._fallback_page("Fail2Ban", "Missing")

    def return_ssl(self, args: dict = {}) -> str:
        return self._read_tpl("ssl.html") or self._fallback_page("SSL", "Missing")

    def return_services(self, args: dict = {}) -> str:
        return self._read_tpl("services.html") or self._fallback_page("Services", "Missing")

    def return_analytics(self, args: dict = {}) -> str:
        return self._read_tpl("analytics.html") or self._fallback_page("Analytics", "Missing")

    def return_alerts(self, args: dict = {}) -> str:
        return self._read_tpl("alerts.html") or self._fallback_page("Alerts", "Missing")

    def return_settings(self, args: dict = {}) -> str:
        return self._read_tpl("settings.html") or self._fallback_page("Settings", "Missing")

    # ------------------------------------------------------------------
    # API actions (JSON)
    # ------------------------------------------------------------------

    def api_status(self, args: dict = {}) -> str:
        """Return plugin status and connectivity checks."""
        db_ok = False
        try:
            db_ok = db_available()
        except Exception:
            pass
        data = {
            "version": self.__plugin_version,
            "uptime": self._uptime(),
            "db_connected": db_ok,
            "config_loaded": self._cfg is not None,
            "server_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        return _json_ok(data)

    def api_get_config(self, args: dict = {}) -> str:
        """Return the current (merged) configuration."""
        if not self._cfg:
            return _json_err("Config not loaded")
        return _json_ok(self._cfg.all())

    def api_save_config(self, args: dict = {}) -> str:
        """Persist a config value.  Expects { key, value }."""
        p = _get_args(args)
        key = p.get("key")
        value = p.get("value")
        if not key:
            return _json_err("Missing 'key'")
        try:
            self._cfg.set(key, value)
            self._cfg.reload()
            log.info("Config updated: %s = %s", key, value)
            return _json_ok({"key": key, "value": value})
        except Exception as exc:
            log.error("api_save_config failed: %s", exc)
            return _json_err(str(exc))

    def api_reload_config(self, args: dict = {}) -> str:
        """Force a config reload from disk."""
        try:
            self._cfg.reload()
            return _json_ok()
        except Exception as exc:
            return _json_err(str(exc))

    # ------------------------------------------------------------------
    # SSH Events API  (Phase 3)
    # ------------------------------------------------------------------

    def api_events(self, args: dict = {}) -> str:
        """
        List recent events.  Accepts optional params:
            page, limit, event_type, username, ip_address, search
        """
        from database.query import fetchall, fetchone  # noqa: PLC0415

        p = _get_args(args)
        page = max(1, int(p.get("page", 1)))
        limit = min(500, max(1, int(p.get("limit", 50))))
        offset = (page - 1) * limit

        where_parts: list[str] = []
        params: list[Any] = []

        etype = p.get("event_type")
        if etype:
            where_parts.append("event_type = %s")
            params.append(etype)

        user = p.get("username")
        if user:
            where_parts.append("username = %s")
            params.append(user)

        ip = p.get("ip_address")
        if ip:
            where_parts.append("ip_address = %s")
            params.append(ip)

        search = p.get("search")
        if search:
            where_parts.append("(message LIKE %s OR username LIKE %s OR ip_address LIKE %s)")
            like = f"%{search}%"
            params.extend([like, like, like])

        where_sql = ""
        if where_parts:
            where_sql = "WHERE " + " AND ".join(where_parts)

        count_row = fetchone(
            f"SELECT COUNT(*) AS total FROM events {where_sql}", tuple(params)
        )
        total = count_row["total"] if count_row else 0

        rows = fetchall(
            f"SELECT * FROM events {where_sql} ORDER BY id DESC LIMIT %s OFFSET %s",
            tuple(params) + (limit, offset),
        )

        return _json_ok({
            "events": rows,
            "total": total,
            "page": page,
            "limit": limit,
            "pages": max(1, -(-total // limit)),  # ceil div
        })

    def api_event_stats(self, args: dict = {}) -> str:
        """Aggregate stats for the dashboard."""
        from database.query import fetchone  # noqa: PLC0415

        stats = {}
        for event_type in ("login.success", "login.failure", "login.root",
                           "session.open", "session.close", "sudo.command",
                           "f2b.ban", "ssl.alert", "service.status"):
            row = fetchone(
                "SELECT COUNT(*) AS cnt FROM events WHERE event_type = %s "
                "AND timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)",
                (event_type,),
            )
            stats[event_type] = row["cnt"] if row else 0

        # Unique IPs in last 24h
        row = fetchone(
            "SELECT COUNT(DISTINCT ip_address) AS cnt FROM events "
            "WHERE ip_address != '' AND timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"
        )
        stats["unique_ips_24h"] = row["cnt"] if row else 0

        # Total events
        row = fetchone("SELECT COUNT(*) AS cnt FROM events")
        stats["total_events"] = row["cnt"] if row else 0

        return _json_ok(stats)

    # ------------------------------------------------------------------
    # Attacker stats
    # ------------------------------------------------------------------

    def api_top_attackers(self, args: dict = {}) -> str:
        """Return top attackers by total attempts."""
        p = _get_args(args)
        limit = min(100, max(1, int(p.get("limit", 25))))
        from database.query import fetchall  # noqa: PLC0415

        rows = fetchall(
            "SELECT * FROM attacker_stats ORDER BY total_attempts DESC LIMIT %s",
            (limit,),
        )
        return _json_ok(rows)

    # ------------------------------------------------------------------
    # Session monitoring (Phase 4-5)
    # ------------------------------------------------------------------

    def api_sessions(self, args: dict = {}) -> str:
        """List recent session/sudo/su events."""
        from modules.session_monitor.tracker import get_recent_sessions  # noqa: PLC0415
        p = _get_args(args)
        limit = min(200, max(1, int(p.get("limit", 50))))
        return _json_ok(get_recent_sessions(limit))

    def api_active_sessions(self, args: dict = {}) -> str:
        """Get currently active SSH sessions (who/w)."""
        from modules.session_monitor.active import get_active_sessions  # noqa: PLC0415
        return _json_ok(get_active_sessions())

    def api_session_stats(self, args: dict = {}) -> str:
        """Aggregate session statistics."""
        from modules.session_monitor.tracker import get_session_stats  # noqa: PLC0415
        return _json_ok(get_session_stats())

    # ------------------------------------------------------------------
    # Geolocation (Phase 6)
    # ------------------------------------------------------------------

    def api_geo_lookup(self, args: dict = {}) -> str:
        """Look up geographic information for an IP address."""
        from modules.geolocation.lookup import lookup_ip  # noqa: PLC0415
        p = _get_args(args)
        ip = p.get("ip", "")
        if not ip:
            return _json_err("Missing 'ip' parameter")
        result = lookup_ip(ip)
        return _json_ok(result.as_dict())

    def api_geo_status(self, args: dict = {}) -> str:
        """Geolocation engine status."""
        from modules.geolocation.lookup import get_status  # noqa: PLC0415
        return _json_ok(get_status())

    # ------------------------------------------------------------------
    # Attack intelligence (Phase 7)
    # ------------------------------------------------------------------

    def api_attack_summary(self, args: dict = {}) -> str:
        """High-level attack summary."""
        from modules.ssh_monitor.analytics import get_attack_summary  # noqa: PLC0415
        return _json_ok(get_attack_summary())

    def api_top_attackers(self, args: dict = {}) -> str:
        """Return top attackers by total attempts."""
        from modules.ssh_monitor.analytics import get_top_attackers  # noqa: PLC0415
        p = _get_args(args)
        limit = min(100, max(1, int(p.get("limit", 25))))
        return _json_ok(get_top_attackers(limit))

    def api_most_targeted_users(self, args: dict = {}) -> str:
        """Return users targeted by the most unique IPs."""
        from modules.ssh_monitor.analytics import get_most_targeted_users  # noqa: PLC0415
        return _json_ok(get_most_targeted_users())

    def api_login_trends(self, args: dict = {}) -> str:
        """Daily login trends."""
        from modules.ssh_monitor.analytics import get_login_trends  # noqa: PLC0415
        p = _get_args(args)
        days = min(90, max(1, int(p.get("days", 7))))
        return _json_ok(get_login_trends(days))

    def api_hourly_logins(self, args: dict = {}) -> str:
        """Per-hour login counts."""
        from modules.ssh_monitor.analytics import get_failed_logins_per_hour  # noqa: PLC0415
        from modules.ssh_monitor.analytics import get_successful_logins_per_hour  # noqa: PLC0415
        p = _get_args(args)
        hours = min(168, max(1, int(p.get("hours", 24))))
        return _json_ok({
            "failed": get_failed_logins_per_hour(hours),
            "successful": get_successful_logins_per_hour(hours),
        })

    # ------------------------------------------------------------------
    # Fail2Ban (Phase 8)
    # ------------------------------------------------------------------

    def api_fail2ban_collect(self, args: dict = {}) -> str:
        """Run a Fail2Ban collection cycle."""
        from modules.fail2ban.collector import collect  # noqa: PLC0415
        return _json_ok(collect())

    def api_fail2ban_jails(self, args: dict = {}) -> str:
        """List Fail2Ban jails."""
        from modules.fail2ban.collector import get_all_jails  # noqa: PLC0415
        return _json_ok(get_all_jails())

    def api_fail2ban_bans(self, args: dict = {}) -> str:
        """Recent ban events."""
        from modules.fail2ban.collector import get_recent_bans  # noqa: PLC0415
        p = _get_args(args)
        limit = min(200, max(1, int(p.get("limit", 50))))
        return _json_ok(get_recent_bans(limit))

    def api_fail2ban_stats(self, args: dict = {}) -> str:
        """Fail2Ban aggregate statistics."""
        from modules.fail2ban.collector import get_f2b_stats  # noqa: PLC0415
        return _json_ok(get_f2b_stats())

    # ------------------------------------------------------------------
    # SSL certificates (Phase 9)
    # ------------------------------------------------------------------

    def api_ssl_scan(self, args: dict = {}) -> str:
        """Run an SSL certificate scan."""
        from modules.ssl_monitor.scanner import scan  # noqa: PLC0415
        return _json_ok(scan())

    def api_ssl_certificates(self, args: dict = {}) -> str:
        """List discovered certificates."""
        from modules.ssl_monitor.scanner import get_certificates  # noqa: PLC0415
        return _json_ok(get_certificates())

    def api_ssl_stats(self, args: dict = {}) -> str:
        """SSL certificate statistics."""
        from modules.ssl_monitor.scanner import get_certificate_stats  # noqa: PLC0415
        return _json_ok(get_certificate_stats())

    # ------------------------------------------------------------------
    # Services (Phase 10)
    # ------------------------------------------------------------------

    def api_services_collect(self, args: dict = {}) -> str:
        """Check all services and store status."""
        from modules.service_monitor.checker import collect  # noqa: PLC0415
        return _json_ok(collect())

    def api_services_status(self, args: dict = {}) -> str:
        """Get latest service status."""
        from modules.service_monitor.checker import get_service_status  # noqa: PLC0415
        return _json_ok(get_service_status())

    def api_services_stats(self, args: dict = {}) -> str:
        """Aggregate service statistics."""
        from modules.service_monitor.checker import get_service_stats  # noqa: PLC0415
        return _json_ok(get_service_stats())

    # ------------------------------------------------------------------
    # Alert engine (Phase 11)
    # ------------------------------------------------------------------

    def api_alerts(self, args: dict = {}) -> str:
        """List recent alerts."""
        from modules.alerts.engine import get_recent_alerts  # noqa: PLC0415
        p = _get_args(args)
        limit = min(200, max(1, int(p.get("limit", 50))))
        severity = p.get("severity")
        return _json_ok(get_recent_alerts(limit, severity=severity))

    def api_alert_stats(self, args: dict = {}) -> str:
        """Alert statistics."""
        from modules.alerts.engine import get_alert_stats  # noqa: PLC0415
        return _json_ok(get_alert_stats())

    def api_alert_run(self, args: dict = {}) -> str:
        """Run alert rules manually."""
        from modules.alerts.engine import run_rules  # noqa: PLC0415
        return _json_ok(run_rules())

    def api_alert_ack(self, args: dict = {}) -> str:
        """Acknowledge an alert."""
        from modules.alerts.engine import acknowledge_alert  # noqa: PLC0415
        p = _get_args(args)
        alert_id = p.get("id")
        if not alert_id:
            return _json_err("Missing 'id'")
        ok = acknowledge_alert(int(alert_id))
        return _json_ok({"acknowledged": ok})

    # ------------------------------------------------------------------
    # Notifications (Phase 12)
    # ------------------------------------------------------------------

    def api_notifications_queue(self, args: dict = {}) -> str:
        """Process pending notifications."""
        from modules.notifications.notifier import process_queue  # noqa: PLC0415
        return _json_ok(process_queue())

    def api_notifications_stats(self, args: dict = {}) -> str:
        """Notification queue statistics."""
        from modules.notifications.notifier import get_queue_stats  # noqa: PLC0415
        return _json_ok(get_queue_stats())

    def api_notifications_test(self, args: dict = {}) -> str:
        """Test a notification channel."""
        from modules.notifications.notifier import test_channel  # noqa: PLC0415
        p = _get_args(args)
        channel = p.get("channel", "")
        if not channel:
            return _json_err("Missing 'channel' (telegram|discord|email)")
        return _json_ok(test_channel(channel))

    # ------------------------------------------------------------------
    # Daemon control (Phase 18)
    # ------------------------------------------------------------------

    def api_daemon_start(self, args: dict = {}) -> str:
        """Start the background daemon."""
        import subprocess  # noqa: PLC0415
        py_bin = sys.executable
        script = os.path.join(PLUGIN_DIR, "modules", "daemon", "scheduler.py")
        try:
            subprocess.Popen(
                [py_bin, script],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            return _json_ok({"message": "Daemon started"})
        except Exception as exc:
            return _json_err(str(exc))

    def api_daemon_status(self, args: dict = {}) -> str:
        """Check daemon status."""
        cfg = Config()
        pid_path = os.path.join(PLUGIN_DIR, cfg.get("daemon.pid_file", "data/sec_mon.pid"))
        running = False
        pid = None
        if os.path.isfile(pid_path):
            try:
                with open(pid_path, "r") as f:
                    pid = int(f.read().strip())
                os.kill(pid, 0)
                running = True
            except (OSError, ValueError):
                running = False
        return _json_ok({"running": running, "pid": pid})

    # ------------------------------------------------------------------
    # Heartbeat / keep-alive
    # ------------------------------------------------------------------

    def api_ping(self, args: dict = {}) -> str:
        return _json_ok({"ts": time.time()})

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _read_tpl(self, name: str) -> Optional[str]:
        tpl_path = os.path.join(PLUGIN_DIR, "templates", name)
        if os.path.isfile(tpl_path):
            with open(tpl_path, "r", encoding="utf-8") as f:
                return f.read()
        return None

    @staticmethod
    def _fallback_page(title: str, body: str) -> str:
        return (
            "<!DOCTYPE html><html><head><title>Security Monitor</title></head>"
            "<body><h2>{title}</h2><p>{body}</p>"
            "<p><em>Templates not installed. Run install.sh on the server.</em></p>"
            "</body></html>"
        ).format(title=title, body=body)

    @staticmethod
    def _uptime() -> float:
        """Seconds since this Python process started."""
        return time.time()