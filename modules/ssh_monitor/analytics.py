"""
Attack intelligence and profiling for Security Monitor.

Queries the ``attacker_stats`` table and cross-references with
``geo_cache`` to produce attacker rankings, most-targeted users,
and country-based attack summaries.
"""

from typing import Any, Dict, List

from lib.logger import get_logger
from database.query import fetchall, fetchone

log = get_logger("app")


def get_top_attackers(limit: int = 25) -> List[Dict]:
    """Return the top attackers by total failed attempts."""
    return fetchall(
        "SELECT * FROM attacker_stats "
        "ORDER BY failed DESC, total_attempts DESC LIMIT %s",
        (limit,),
    )


def get_top_successful_attackers(limit: int = 25) -> List[Dict]:
    """Return IPs with the most successful logins (potential compromised accounts)."""
    return fetchall(
        "SELECT * FROM attacker_stats "
        "WHERE successful > 0 "
        "ORDER BY successful DESC LIMIT %s",
        (limit,),
    )


def get_most_targeted_users(limit: int = 20) -> List[Dict]:
    """Return users targeted by the most unique IPs."""
    return fetchall(
        "SELECT username, COUNT(DISTINCT ip_address) AS unique_ips, "
        "SUM(total_attempts) AS total_attempts, "
        "SUM(failed) AS total_failed "
        "FROM attacker_stats "
        "WHERE username != '' "
        "GROUP BY username "
        "ORDER BY unique_ips DESC, total_attempts DESC "
        "LIMIT %s",
        (limit,),
    )


def get_country_attack_summary() -> List[Dict]:
    """Aggregate attacks by country (from attacker_stats)."""
    return fetchall(
        "SELECT country, country_code, "
        "COUNT(DISTINCT ip_address) AS unique_ips, "
        "SUM(total_attempts) AS total_attempts, "
        "SUM(failed) AS total_failed, "
        "SUM(successful) AS total_successful "
        "FROM attacker_stats "
        "WHERE country != '' "
        "GROUP BY country, country_code "
        "ORDER BY total_failed DESC"
    )


def get_failed_logins_per_hour(hours: int = 24) -> List[Dict]:
    """Return failed login counts per hour for the last N hours."""
    return fetchall(
        "SELECT DATE_FORMAT(timestamp, '%%Y-%%m-%%d %%H:00:00') AS hour, "
        "COUNT(*) AS cnt "
        "FROM events "
        "WHERE event_type = 'login.failure' "
        "AND timestamp >= DATE_SUB(NOW(), INTERVAL %s HOUR) "
        "GROUP BY hour "
        "ORDER BY hour",
        (hours,),
    )


def get_successful_logins_per_hour(hours: int = 24) -> List[Dict]:
    """Return successful login counts per hour for the last N hours."""
    return fetchall(
        "SELECT DATE_FORMAT(timestamp, '%%Y-%%m-%%d %%H:00:00') AS hour, "
        "COUNT(*) AS cnt "
        "FROM events "
        "WHERE event_type = 'login.success' "
        "AND timestamp >= DATE_SUB(NOW(), INTERVAL %s HOUR) "
        "GROUP BY hour "
        "ORDER BY hour",
        (hours,),
    )


def get_login_trends(days: int = 7) -> List[Dict]:
    """Return daily login counts (success + failure) for the last N days."""
    return fetchall(
        "SELECT DATE(timestamp) AS day, "
        "SUM(CASE WHEN event_type='login.success' THEN 1 ELSE 0 END) AS successful, "
        "SUM(CASE WHEN event_type='login.failure' THEN 1 ELSE 0 END) AS failed, "
        "COUNT(DISTINCT ip_address) AS unique_ips "
        "FROM events "
        "WHERE event_type IN ('login.success', 'login.failure') "
        "AND timestamp >= DATE_SUB(NOW(), INTERVAL %s DAY) "
        "GROUP BY day "
        "ORDER BY day",
        (days,),
    )


def get_attack_summary() -> Dict[str, Any]:
    """Return a high-level attack summary for the dashboard."""
    summary: Dict[str, Any] = {}

    # Total attackers
    row = fetchone("SELECT COUNT(*) AS cnt FROM attacker_stats")
    summary["total_attackers"] = row["cnt"] if row else 0

    # Active today
    row = fetchone(
        "SELECT COUNT(DISTINCT ip_address) AS cnt FROM events "
        "WHERE event_type IN ('login.failure', 'login.success') "
        "AND timestamp >= CURDATE()"
    )
    summary["active_ips_today"] = row["cnt"] if row else 0

    # Failed logins today
    row = fetchone(
        "SELECT COUNT(*) AS cnt FROM events "
        "WHERE event_type = 'login.failure' "
        "AND timestamp >= CURDATE()"
    )
    summary["failed_today"] = row["cnt"] if row else 0

    # Successful logins today
    row = fetchone(
        "SELECT COUNT(*) AS cnt FROM events "
        "WHERE event_type = 'login.success' "
        "AND timestamp >= CURDATE()"
    )
    summary["successful_today"] = row["cnt"] if row else 0

    # Root login attempts today
    row = fetchone(
        "SELECT COUNT(*) AS cnt FROM events "
        "WHERE event_type = 'login.failure' "
        "AND metadata LIKE '%%root_attempt%%' "
        "AND timestamp >= CURDATE()"
    )
    summary["root_attempts_today"] = row["cnt"] if row else 0

    # Countries involved
    row = fetchone(
        "SELECT COUNT(DISTINCT country) AS cnt FROM attacker_stats "
        "WHERE country != ''"
    )
    summary["unique_countries"] = row["cnt"] if row else 0

    return summary