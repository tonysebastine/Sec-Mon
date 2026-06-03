"""
Background daemon/scheduler for Security Monitor.

Runs as a background process (started by install.sh or manually).
Periodically executes:
  - Every 30s : SSH log ingestion, session tracking, Fail2Ban collection
  - Every 5min: Alert rule evaluation, notification queue processing
  - Every 1h  : SSL certificate scanning, service health checks
  - Every 24h : Database cleanup (>90-day events), statistics aggregation

Can be started standalone or integrated with aaPanel's task scheduler.
"""

import json
import os
import signal
import sys
import time
from datetime import datetime
from typing import Dict

PLUGIN_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PLUGIN_DIR not in sys.path:
    sys.path.insert(0, PLUGIN_DIR)

from lib.config import Config
from lib.logger import get_logger, daemon_logger

log = get_logger("app")
dlog = daemon_logger()

_running = True


def _signal_handler(signum, frame):
    """Handle SIGTERM/SIGINT for graceful shutdown."""
    global _running
    dlog.info("Received signal %d, shutting down...", signum)
    _running = False


def _write_pid(pid_path: str) -> None:
    """Write current PID to file."""
    os.makedirs(os.path.dirname(pid_path), exist_ok=True)
    with open(pid_path, "w") as f:
        f.write(str(os.getpid()))


def _remove_pid(pid_path: str) -> None:
    """Remove PID file."""
    try:
        os.remove(pid_path)
    except OSError:
        pass


def _is_already_running(pid_path: str) -> bool:
    """Check if another instance is already running."""
    if not os.path.isfile(pid_path):
        return False
    try:
        with open(pid_path, "r") as f:
            old_pid = int(f.read().strip())
        # Check if the process is alive
        os.kill(old_pid, 0)
        return True
    except (OSError, ValueError):
        return False


# ---------------------------------------------------------------------------
# Task functions
# ---------------------------------------------------------------------------

def _task_fast_poll() -> None:
    """Run every 30 seconds: SSH ingestion, session tracking, Fail2Ban."""
    try:
        from modules.ssh_monitor.ingester import ingest
        result = ingest()
        if result.get("events_parsed", 0) > 0:
            dlog.info("SSH ingestion: parsed=%d inserted=%d",
                      result["events_parsed"], result["events_inserted"])
    except Exception as exc:
        dlog.error("SSH ingestion failed: %s", exc)

    try:
        from modules.fail2ban.collector import collect as f2b_collect
        f2b_collect()
    except Exception as exc:
        dlog.error("Fail2Ban collection failed: %s", exc)


def _task_medium_poll() -> None:
    """Run every 5 minutes: alerts, notifications."""
    try:
        from modules.alerts.engine import run_rules
        alerts = run_rules()
        if alerts:
            dlog.info("Generated %d alerts", len(alerts))

            # Queue notifications for new alerts
            from modules.notifications.notifier import queue_alert
            for alert_data in alerts:
                alert_id = alert_data.get("alert_id")
                if alert_id:
                    # Fetch full alert from DB
                    from database.query import fetchone
                    full = fetchone("SELECT * FROM alerts WHERE id = %s", (alert_id,))
                    if full:
                        queue_alert(dict(full))
    except Exception as exc:
        dlog.error("Alert evaluation failed: %s", exc)

    try:
        from modules.notifications.notifier import process_queue
        result = process_queue()
        if result.get("processed", 0) > 0:
            dlog.info("Notifications: sent=%d failed=%d",
                      result["sent"], result["failed"])
    except Exception as exc:
        dlog.error("Notification queue failed: %s", exc)


def _task_slow_poll() -> None:
    """Run every hour: SSL scan, service checks."""
    try:
        from modules.ssl_monitor.scanner import scan as ssl_scan
        ssl_scan()
        dlog.info("SSL scan completed")
    except Exception as exc:
        dlog.error("SSL scan failed: %s", exc)

    try:
        from modules.service_monitor.checker import collect as svc_collect
        svc_collect()
        dlog.info("Service health check completed")
    except Exception as exc:
        dlog.error("Service health check failed: %s", exc)


def _task_daily_cleanup() -> None:
    """Run once daily: cleanup old data, aggregate statistics."""
    cfg = Config()
    retention_days = cfg.get("retention.events_days", 90)

    try:
        from database.query import execute
        # Clean old events
        result = execute(
            "DELETE FROM events WHERE timestamp < DATE_SUB(NOW(), INTERVAL %s DAY)",
            (retention_days,),
        )
        dlog.info("Cleaned up %d old events (>%d days)", result, retention_days)

        # Clean old alerts
        alert_days = cfg.get("retention.alerts_days", 90)
        result = execute(
            "DELETE FROM alerts WHERE created_at < DATE_SUB(NOW(), INTERVAL %s DAY)",
            (alert_days,),
        )
        dlog.info("Cleaned up %d old alerts", result)

        # Clean old notification queue entries
        result = execute(
            "DELETE FROM notification_queue "
            "WHERE status IN ('sent', 'failed') "
            "AND created_at < DATE_SUB(NOW(), INTERVAL 30 DAY)"
        )
        dlog.info("Cleaned up %d old notification queue entries", result)

        # Update attacker_stats with country info from geo_cache
        execute(
            "UPDATE attacker_stats a "
            "JOIN geo_cache g ON a.ip_address = g.ip_address "
            "SET a.country = g.country, a.city = g.city, a.asn = g.asn "
            "WHERE a.country = '' AND g.country != ''"
        )
        dlog.info("Updated attacker geolocation data")
    except Exception as exc:
        dlog.error("Daily cleanup failed: %s", exc)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run_daemon() -> None:
    """
    Main daemon loop.

    Reads timing configuration from config and runs tasks on schedule.
    """
    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    cfg = Config()
    pid_path = os.path.join(PLUGIN_DIR, cfg.get("daemon.pid_file", "data/sec_mon.pid"))

    if _is_already_running(pid_path):
        dlog.error("Another instance is already running. Exiting.")
        return

    _write_pid(pid_path)

    # Schedule intervals (seconds)
    fast_interval = cfg.get("daemon.tasks.fast_poll", 30)
    medium_interval = cfg.get("daemon.tasks.slow_poll", 300)
    slow_interval = cfg.get("daemon.tasks.ssl_check", 3600)
    daily_interval = cfg.get("daemon.tasks.cleanup", 86400)

    dlog.info("Daemon started (PID=%d)", os.getpid())
    dlog.info("Intervals: fast=%ds medium=%ds slow=%ds daily=%ds",
              fast_interval, medium_interval, slow_interval, daily_interval)

    last_fast = 0
    last_medium = 0
    last_slow = 0
    last_daily = 0

    try:
        while _running:
            now = time.time()

            # Fast poll (30s)
            if now - last_fast >= fast_interval:
                _task_fast_poll()
                last_fast = now

            # Medium poll (5min)
            if now - last_medium >= medium_interval:
                _task_medium_poll()
                last_medium = now

            # Slow poll (1h)
            if now - last_slow >= slow_interval:
                _task_slow_poll()
                last_slow = now

            # Daily cleanup
            if now - last_daily >= daily_interval:
                _task_daily_cleanup()
                last_daily = now

            # Sleep 1 second between iterations
            time.sleep(1)
    finally:
        _remove_pid(pid_path)
        dlog.info("Daemon stopped.")


if __name__ == "__main__":
    run_daemon()