"""
SSL/TLS certificate scanner for Security Monitor.

Discovers and parses certificates from:
  - aaPanel certificate directories (/www/server/panel/vhost/cert/)
  - Let's Encrypt live directories (/etc/letsencrypt/live/)
  - System SSL directories (/etc/ssl/certs/)

Stores results in the ssl_certificates table and calculates health
status based on days until expiry.
"""

import glob
import json
import os
import re
import subprocess
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from lib.config import Config
from lib.logger import get_logger
from database.query import fetchall, fetchone, upsert, execute

log = get_logger("app")

# Try to import cryptography (preferred) or fall back to openssl CLI
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False


# ---------------------------------------------------------------------------
# Certificate discovery
# ---------------------------------------------------------------------------

def _find_cert_files(scan_paths: List[str]) -> List[Dict[str, str]]:
    """
    Scan directories for .pem, .crt, and fullchain*.pem files.

    Returns list of dicts with keys: path, domain (derived from dir name), source.
    """
    certs: List[Dict[str, str]] = []

    for scan_path in scan_paths:
        if not os.path.isdir(scan_path):
            continue

        # Determine source
        if "letsencrypt" in scan_path:
            source = "letsencrypt"
        elif "panel" in scan_path or "aapanel" in scan_path.lower():
            source = "aapanel"
        else:
            source = "other"

        # Find certificate files
        patterns = ["**/*.pem", "**/*.crt"]
        for pattern in patterns:
            for filepath in glob.glob(os.path.join(scan_path, pattern), recursive=True):
                filename = os.path.basename(filepath)
                # Skip private keys
                if "privkey" in filename or "key" == filename:
                    continue
                # Derive domain from parent directory
                domain = os.path.basename(os.path.dirname(filepath))
                if domain in ("live", "cert", "certs"):
                    domain = os.path.splitext(filename)[0]

                certs.append({
                    "path": filepath,
                    "domain": domain,
                    "source": source,
                })

    # Deduplicate by path
    seen = set()
    unique: List[Dict[str, str]] = []
    for c in certs:
        if c["path"] not in seen:
            seen.add(c["path"])
            unique.append(c)
    return unique


# ---------------------------------------------------------------------------
# Certificate parsing
# ---------------------------------------------------------------------------

def _parse_with_cryptography(cert_path: str) -> Optional[Dict]:
    """Parse a PEM certificate using the cryptography library."""
    try:
        with open(cert_path, "rb") as f:
            pem_data = f.read()

        # Try loading as PEM
        cert = x509.load_pem_x509_certificate(pem_data)

        # Extract fields
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()

        # Try to get CN from subject
        cn = ""
        for attr in cert.subject:
            if attr.oid == x509.oid.NameOID.COMMON_NAME:
                cn = attr.value
                break

        # SANs
        sans: List[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass

        # Serial number
        serial = hex(cert.serial_number)

        return {
            "domain": cn or sans[0] if sans else "",
            "issuer": issuer,
            "subject": subject,
            "serial": serial,
            "not_before": cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S"),
            "not_after": cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S"),
            "sans": json.dumps(sans) if sans else None,
        }
    except Exception as exc:
        log.debug("cryptography parse failed for %s: %s", cert_path, exc)
        return None


def _parse_with_openssl(cert_path: str) -> Optional[Dict]:
    """Parse a PEM certificate using the openssl CLI."""
    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-noout",
             "-subject", "-issuer", "-dates", "-serial", "-ext", "subjectAltName"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return None

        output = result.stdout
        info: Dict[str, Any] = {}

        # Subject
        m = re.search(r"subject\s*=\s*(.+)", output)
        if m:
            info["subject"] = m.group(1).strip()

        # CN from subject
        m = re.search(r"CN\s*=\s*([^\s,/]+)", output)
        if m:
            info["domain"] = m.group(1)

        # Issuer
        m = re.search(r"issuer\s*=\s*(.+)", output)
        if m:
            info["issuer"] = m.group(1).strip()

        # Serial
        m = re.search(r"serial\s*=\s*(.+)", output)
        if m:
            info["serial"] = m.group(1).strip()

        # Not Before
        m = re.search(r"notBefore\s*=\s*(.+)", output)
        if m:
            try:
                dt = datetime.strptime(m.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
                info["not_before"] = dt.strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                info["not_before"] = m.group(1).strip()

        # Not After
        m = re.search(r"notAfter\s*=\s*(.+)", output)
        if m:
            try:
                dt = datetime.strptime(m.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
                info["not_after"] = dt.strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                info["not_after"] = m.group(1).strip()

        # SANs
        sans: List[str] = []
        san_section = re.findall(r"DNS:([^\s,]+)", output)
        sans = list(set(san_section))
        info["sans"] = json.dumps(sans) if sans else None

        # Use first SAN as domain if CN not found
        if "domain" not in info and sans:
            info["domain"] = sans[0]

        return info
    except Exception as exc:
        log.debug("openssl parse failed for %s: %s", cert_path, exc)
        return None


def parse_certificate(cert_path: str) -> Optional[Dict]:
    """Parse a certificate file, preferring cryptography, falling back to openssl."""
    if _CRYPTO_AVAILABLE:
        result = _parse_with_cryptography(cert_path)
        if result:
            return result
    return _parse_with_openssl(cert_path)


# ---------------------------------------------------------------------------
# Health evaluation
# ---------------------------------------------------------------------------

def evaluate_health(not_after: Optional[str], warn_days: int = 30,
                    critical_days: int = 7) -> str:
    """Calculate certificate health status."""
    if not not_after:
        return "unknown"
    try:
        expiry = datetime.strptime(not_after, "%Y-%m-%d %H:%M:%S")
        days_left = (expiry - datetime.now()).days
        if days_left < 0:
            return "critical"
        elif days_left <= critical_days:
            return "critical"
        elif days_left <= warn_days:
            return "warning"
        else:
            return "healthy"
    except ValueError:
        return "unknown"


def days_remaining(not_after: Optional[str]) -> Optional[int]:
    """Calculate days until certificate expires."""
    if not not_after:
        return None
    try:
        expiry = datetime.strptime(not_after, "%Y-%m-%d %H:%M:%S")
        return (expiry - datetime.now()).days
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Database storage
# ---------------------------------------------------------------------------

def store_certificates(certs: List[Dict]) -> int:
    """Upsert certificates into the ssl_certificates table."""
    cfg = Config()
    warn_days = cfg.get("ssl_monitor.warn_days", 30)
    critical_days = cfg.get("ssl_monitor.critical_days", 7)
    stored = 0

    for cert in certs:
        not_after = cert.get("not_after")
        status = evaluate_health(not_after, warn_days, critical_days)
        days = days_remaining(not_after)

        try:
            upsert(
                "INSERT INTO ssl_certificates "
                "(domain, issuer, subject, serial, not_before, not_after, "
                " sans, status, days_remaining, path, source, last_scanned) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW()) "
                "ON DUPLICATE KEY UPDATE "
                "issuer=VALUES(issuer), subject=VALUES(subject), serial=VALUES(serial), "
                "not_before=VALUES(not_before), not_after=VALUES(not_after), "
                "sans=VALUES(sans), status=VALUES(status), "
                "days_remaining=VALUES(days_remaining), "
                "last_scanned=NOW()",
                (cert.get("domain", ""), cert.get("issuer", ""),
                 cert.get("subject", ""), cert.get("serial", ""),
                 cert.get("not_before"), not_after,
                 cert.get("sans"), status, days,
                 cert.get("path", ""), cert.get("source", "")),
            )
            stored += 1
        except Exception as exc:
            log.debug("store_certificates failed for %s: %s", cert.get("path"), exc)

    return stored


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan() -> Dict[str, Any]:
    """
    Run a full SSL certificate scan.

    1. Discover cert files in configured paths
    2. Parse each certificate
    3. Store results in the database

    Returns a summary dict.
    """
    cfg = Config()
    scan_paths = cfg.get("ssl_monitor.scan_paths", [
        "/www/server/panel/vhost/cert",
        "/etc/letsencrypt/live",
        "/etc/ssl/certs",
    ])

    summary: Dict[str, Any] = {
        "scan_paths": scan_paths,
        "certificates_found": 0,
        "certificates_stored": 0,
        "healthy": 0,
        "warning": 0,
        "critical": 0,
        "unknown": 0,
        "errors": 0,
    }

    # 1. Discover
    cert_files = _find_cert_files(scan_paths)
    summary["certificates_found"] = len(cert_files)

    # 2. Parse
    parsed_certs: List[Dict] = []
    for cf in cert_files:
        info = parse_certificate(cf["path"])
        if info:
            info["path"] = cf["path"]
            info["source"] = cf["source"]
            if "domain" not in info or not info["domain"]:
                info["domain"] = cf["domain"]
            parsed_certs.append(info)
        else:
            summary["errors"] += 1

    # 3. Evaluate health
    cfg = Config()
    warn_days = cfg.get("ssl_monitor.warn_days", 30)
    critical_days = cfg.get("ssl_monitor.critical_days", 7)

    for cert in parsed_certs:
        status = evaluate_health(cert.get("not_after"), warn_days, critical_days)
        cert["status"] = status
        summary[status] = summary.get(status, 0) + 1

    # 4. Store
    stored = store_certificates(parsed_certs)
    summary["certificates_stored"] = stored

    log.info(
        "SSL scan complete: found=%d stored=%d healthy=%d warn=%d crit=%d",
        summary["certificates_found"], summary["certificates_stored"],
        summary["healthy"], summary["warning"], summary["critical"],
    )

    return summary


def get_certificates() -> List[Dict]:
    """Fetch all certificates from the database."""
    return fetchall(
        "SELECT * FROM ssl_certificates ORDER BY domain, path"
    )


def get_certificate_stats() -> Dict[str, Any]:
    """Aggregate certificate statistics."""
    stats: Dict[str, Any] = {}

    row = fetchone("SELECT COUNT(*) AS cnt FROM ssl_certificates")
    stats["total"] = row["cnt"] if row else 0

    for status in ("healthy", "warning", "critical", "unknown"):
        row = fetchone(
            "SELECT COUNT(*) AS cnt FROM ssl_certificates WHERE status = %s",
            (status,),
        )
        stats[status] = row["cnt"] if row else 0

    # Expiring soonest
    row = fetchone(
        "SELECT domain, not_after, days_remaining "
        "FROM ssl_certificates "
        "WHERE status != 'unknown' "
        "ORDER BY not_after ASC LIMIT 1"
    )
    stats["expiring_soonest"] = dict(row) if row else None

    return stats