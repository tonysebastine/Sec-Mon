"""
Notification dispatcher for Security Monitor.

Sends alerts via Telegram, Discord, and Email.  Uses the
``notification_queue`` table for reliable delivery with retry.

Channels:
  - Telegram : Bot API (HTTP POST to api.telegram.org)
  - Discord  : Webhook (HTTP POST to webhook URL)
  - Email    : SMTP with optional TLS
"""

import json
import smtplib
import time
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Any, Dict, List, Optional

import requests

from lib.config import Config
from lib.logger import get_logger
from database.query import fetchall, fetchone, execute, insert

log = get_logger("app")

MAX_RETRIES = 3


# ---------------------------------------------------------------------------
# Telegram
# ---------------------------------------------------------------------------

def _send_telegram(text: str, bot_token: str, chat_id: str) -> bool:
    """Send a message via the Telegram Bot API."""
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    try:
        resp = requests.post(url, json=payload, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("ok", False)
        log.warning("Telegram API returned %d: %s", resp.status_code, resp.text[:200])
        return False
    except Exception as exc:
        log.error("Telegram send failed: %s", exc)
        return False


def _test_telegram(bot_token: str, chat_id: str) -> bool:
    """Send a test message to verify Telegram configuration."""
    text = "✅ <b>Security Monitor</b>\nTest message sent successfully."
    return _send_telegram(text, bot_token, chat_id)


# ---------------------------------------------------------------------------
# Discord
# ---------------------------------------------------------------------------

def _send_discord(text: str, webhook_url: str) -> bool:
    """Send a message via a Discord webhook."""
    payload = {
        "content": text,
        "username": "Security Monitor",
    }
    try:
        resp = requests.post(webhook_url, json=payload, timeout=10)
        return resp.status_code in (200, 204)
    except Exception as exc:
        log.error("Discord send failed: %s", exc)
        return False


def _test_discord(webhook_url: str) -> bool:
    """Send a test message to verify Discord configuration."""
    text = "✅ **Security Monitor** — Test message sent successfully."
    return _send_discord(text, webhook_url)


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

def _send_email(subject: str, body: str, smtp_host: str, smtp_port: int,
                smtp_user: str, smtp_password: str, smtp_tls: bool,
                from_addr: str, to_addrs: List[str]) -> bool:
    """Send an email via SMTP."""
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = ", ".join(to_addrs)

        # Plain text part
        msg.attach(MIMEText(body, "plain", "utf-8"))

        # HTML part (simple)
        html_body = f"<html><body><pre style='font-family:monospace'>{body}</pre></body></html>"
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
        if smtp_tls:
            server.starttls()
        if smtp_user and smtp_password:
            server.login(smtp_user, smtp_password)
        server.sendmail(from_addr, to_addrs, msg.as_string())
        server.quit()
        return True
    except Exception as exc:
        log.error("Email send failed: %s", exc)
        return False


def _test_email(cfg: Dict) -> bool:
    """Send a test email."""
    return _send_email(
        subject="Security Monitor — Test Email",
        body="This is a test message from Security Monitor.",
        smtp_host=cfg.get("smtp_host", ""),
        smtp_port=cfg.get("smtp_port", 587),
        smtp_user=cfg.get("smtp_user", ""),
        smtp_password=cfg.get("smtp_password", ""),
        smtp_tls=cfg.get("smtp_tls", True),
        from_addr=cfg.get("from_addr", ""),
        to_addrs=cfg.get("to_addrs", []),
    )


# ---------------------------------------------------------------------------
# Alert formatting
# ---------------------------------------------------------------------------

def _format_alert_telegram(alert: Dict) -> str:
    """Format an alert for Telegram (HTML)."""
    severity_emoji = {"critical": "🔴", "warning": "🟡", "info": "🔵"}
    emoji = severity_emoji.get(alert.get("severity", ""), "⚪")
    return (
        f"{emoji} <b>{alert.get('title', 'Alert')}</b>\n"
        f"Rule: {alert.get('rule_id', '')}\n"
        f"Severity: {alert.get('severity', '').upper()}\n"
        f"Time: {alert.get('created_at', '')}"
        f"{'\\n' + alert.get('body', '') if alert.get('body') else ''}"
    )


def _format_alert_discord(alert: Dict) -> str:
    """Format an alert for Discord (Markdown)."""
    severity_emoji = {"critical": "🔴", "warning": "🟡", "info": "🔵"}
    emoji = severity_emoji.get(alert.get("severity", ""), "⚪")
    parts = [
        f"{emoji} **{alert.get('title', 'Alert')}**",
        f"Rule: `{alert.get('rule_id', '')}`",
        f"Severity: **{alert.get('severity', '').upper()}**",
        f"Time: {alert.get('created_at', '')}",
    ]
    if alert.get("body"):
        parts.append(alert["body"])
    return "\n".join(parts)


def _format_alert_email(alert: Dict) -> str:
    """Format an alert for email (plain text)."""
    parts = [
        f"ALERT: {alert.get('title', 'Alert')}",
        f"Rule: {alert.get('rule_id', '')}",
        f"Severity: {alert.get('severity', '').upper()}",
        f"Time: {alert.get('created_at', '')}",
    ]
    if alert.get("body"):
        parts.append(f"Details: {alert['body']}")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Queue management
# ---------------------------------------------------------------------------

def queue_alert(alert: Dict, channels: Optional[List[str]] = None) -> None:
    """
    Queue an alert for notification on the specified channels.

    If channels is None, all enabled channels are used.
    """
    cfg = Config()
    if channels is None:
        channels = []
        if cfg.is_enabled("notifications.telegram"):
            channels.append("telegram")
        if cfg.is_enabled("notifications.discord"):
            channels.append("discord")
        if cfg.is_enabled("notifications.email"):
            channels.append("email")

    for channel in channels:
        try:
            payload = {"alert": alert, "channel": channel}
            insert(
                "INSERT INTO notification_queue (channel, alert_id, payload, status) "
                "VALUES (%s, %s, %s, 'pending')",
                (channel, alert.get("id"), json.dumps(payload, default=str)),
            )
        except Exception as exc:
            log.error("queue_alert failed for channel=%s: %s", channel, exc)


def process_queue(max_items: int = 20) -> Dict[str, Any]:
    """
    Process pending notifications from the queue.

    Returns a summary of sent/failed counts.
    """
    cfg = Config()
    summary: Dict[str, Any] = {"processed": 0, "sent": 0, "failed": 0}

    rows = fetchall(
        "SELECT id, channel, payload, attempts FROM notification_queue "
        "WHERE status = 'pending' "
        "AND scheduled_at <= NOW() "
        "ORDER BY id ASC LIMIT %s",
        (max_items,),
    )

    for row in rows:
        nq_id = row["id"]
        channel = row["channel"]
        attempts = row.get("attempts", 0)

        try:
            payload = json.loads(row["payload"])
        except (json.JSONDecodeError, TypeError):
            _mark_failed(nq_id, "Invalid payload JSON")
            summary["failed"] += 1
            continue

        alert = payload.get("alert", {})

        # Mark as sending
        execute(
            "UPDATE notification_queue SET status = 'sending', attempts = attempts + 1 "
            "WHERE id = %s",
            (nq_id,),
        )

        sent = False

        if channel == "telegram":
            t_cfg = cfg.get("notifications.telegram", {})
            bot_token = t_cfg.get("bot_token", "")
            chat_id = t_cfg.get("chat_id", "")
            if bot_token and chat_id:
                text = _format_alert_telegram(alert)
                sent = _send_telegram(text, bot_token, chat_id)

        elif channel == "discord":
            d_cfg = cfg.get("notifications.discord", {})
            webhook_url = d_cfg.get("webhook_url", "")
            if webhook_url:
                text = _format_alert_discord(alert)
                sent = _send_discord(text, webhook_url)

        elif channel == "email":
            e_cfg = cfg.get("notifications.email", {})
            if e_cfg.get("smtp_host"):
                subject = f"[Security Monitor] {alert.get('title', 'Alert')}"
                body = _format_alert_email(alert)
                sent = _send_email(
                    subject=subject, body=body,
                    smtp_host=e_cfg.get("smtp_host", ""),
                    smtp_port=e_cfg.get("smtp_port", 587),
                    smtp_user=e_cfg.get("smtp_user", ""),
                    smtp_password=e_cfg.get("smtp_password", ""),
                    smtp_tls=e_cfg.get("smtp_tls", True),
                    from_addr=e_cfg.get("from_addr", ""),
                    to_addrs=e_cfg.get("to_addrs", []),
                )

        if sent:
            execute(
                "UPDATE notification_queue SET status = 'sent', sent_at = NOW() "
                "WHERE id = %s",
                (nq_id,),
            )
            summary["sent"] += 1
        else:
            if attempts >= MAX_RETRIES:
                _mark_failed(nq_id, f"Failed after {MAX_RETRIES} attempts")
                summary["failed"] += 1
            else:
                # Re-queue for retry
                execute(
                    "UPDATE notification_queue SET status = 'pending' WHERE id = %s",
                    (nq_id,),
                )

        summary["processed"] += 1

    return summary


def _mark_failed(nq_id: int, error: str) -> None:
    """Mark a queue item as permanently failed."""
    execute(
        "UPDATE notification_queue SET status = 'failed', last_error = %s WHERE id = %s",
        (error, nq_id),
    )


# ---------------------------------------------------------------------------
# Test functions
# ---------------------------------------------------------------------------

def test_channel(channel: str) -> Dict[str, Any]:
    """Send a test message to the specified channel."""
    cfg = Config()
    result = {"channel": channel, "success": False, "error": ""}

    if channel == "telegram":
        t_cfg = cfg.get("notifications.telegram", {})
        bot_token = t_cfg.get("bot_token", "")
        chat_id = t_cfg.get("chat_id", "")
        if not bot_token or not chat_id:
            result["error"] = "bot_token or chat_id not configured"
            return result
        result["success"] = _test_telegram(bot_token, chat_id)

    elif channel == "discord":
        d_cfg = cfg.get("notifications.discord", {})
        webhook_url = d_cfg.get("webhook_url", "")
        if not webhook_url:
            result["error"] = "webhook_url not configured"
            return result
        result["success"] = _test_discord(webhook_url)

    elif channel == "email":
        e_cfg = cfg.get("notifications.email", {})
        if not e_cfg.get("smtp_host"):
            result["error"] = "SMTP not configured"
            return result
        result["success"] = _test_email(e_cfg)

    else:
        result["error"] = f"Unknown channel: {channel}"

    return result


def get_queue_stats() -> Dict[str, Any]:
    """Get notification queue statistics."""
    stats: Dict[str, Any] = {}

    for status in ("pending", "sending", "sent", "failed"):
        row = fetchone(
            "SELECT COUNT(*) AS cnt FROM notification_queue WHERE status = %s",
            (status,),
        )
        stats[status] = row["cnt"] if row else 0

    return stats