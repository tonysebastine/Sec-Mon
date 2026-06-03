"""
Geolocation lookup engine for Security Monitor.

Uses MaxMind GeoLite2-City and GeoLite2-ASN databases to resolve IP
addresses to geographic information (country, city, ASN).

Features:
  - Database-backed cache (geo_cache table) to avoid repeated lookups
  - Graceful degradation when GeoLite2 databases are missing
  - Supports both local .mmdb files and API-based fallback

Setup:
  1. Register at https://www.maxmind.com/en/geolite2/signup
  2. Download GeoLite2-City.mmdb and GeoLite2-ASN.mmdb
  3. Place them in <plugin_root>/data/ or configure paths in config.json
"""

import os
import socket
import struct
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple

from lib.config import Config
from lib.logger import get_logger

log = get_logger("app")

# Try to import geoip2 (optional dependency)
try:
    import geoip2.database as _geodb
    import geoip2.errors as _geerrors
    _GEOIP_AVAILABLE = True
except ImportError:
    _GEOIP_AVAILABLE = False


class GeoResult:
    """Container for geolocation lookup results."""

    __slots__ = ("ip", "country", "country_code", "city",
                 "latitude", "longitude", "asn", "org", "found")

    def __init__(self, ip: str = "", country: str = "", country_code: str = "",
                 city: str = "", latitude: float = 0.0, longitude: float = 0.0,
                 asn: str = "", org: str = "", found: bool = False) -> None:
        self.ip = ip
        self.country = country
        self.country_code = country_code
        self.city = city
        self.latitude = latitude
        self.longitude = longitude
        self.asn = asn
        self.org = org
        self.found = found

    def as_dict(self) -> Dict:
        return {s: getattr(self, s) for s in self.__slots__}

    def __repr__(self) -> str:
        return (f"<GeoResult {self.ip} country={self.country!r} "
                f"city={self.city!r} asn={self.asn!r}>")


# ---------------------------------------------------------------------------
# Private: MMDB reader singletons
# ---------------------------------------------------------------------------
_city_reader = None
_asn_reader = None
_readers_loaded = False


def _load_readers() -> None:
    """Lazily load the MaxMind readers."""
    global _city_reader, _asn_reader, _readers_loaded  # noqa: PLW0603
    if _readers_loaded:
        return
    _readers_loaded = True

    if not _GEOIP_AVAILABLE:
        log.info("geoip2 not installed; geolocation will use cache only.")
        return

    cfg = Config()
    city_path = os.path.join(
        os.path.dirname(__file__), "..", "..",
        cfg.get("geolocation.database_path", "data/GeoLite2-City.mmdb")
    )
    asn_path = os.path.join(
        os.path.dirname(__file__), "..", "..",
        cfg.get("geolocation.asn_database_path", "data/GeoLite2-ASN.mmdb")
    )

    if os.path.isfile(city_path):
        try:
            _city_reader = _geodb.Reader(city_path)
            log.info("Loaded GeoLite2-City database: %s", city_path)
        except Exception as exc:
            log.warning("Failed to load GeoLite2-City: %s", exc)
    else:
        log.info("GeoLite2-City database not found at %s", city_path)

    if os.path.isfile(asn_path):
        try:
            _asn_reader = _geodb.Reader(asn_path)
            log.info("Loaded GeoLite2-ASN database: %s", asn_path)
        except Exception as exc:
            log.warning("Failed to load GeoLite2-ASN: %s", exc)
    else:
        log.info("GeoLite2-ASN database not found at %s", asn_path)


# ---------------------------------------------------------------------------
# Private: database cache helpers
# ---------------------------------------------------------------------------
def _db_available() -> bool:
    try:
        from database.connection import is_available
        return is_available()
    except Exception:
        return False


def _cache_lookup(ip: str) -> Optional[Dict]:
    """Try to find IP in the geo_cache table."""
    if not _db_available():
        return None
    try:
        from database.query import fetchone
        row = fetchone(
            "SELECT ip_address, country, country_code, city, latitude, longitude, asn, org "
            "FROM geo_cache WHERE ip_address = %s",
            (ip,),
        )
        if row:
            # Check staleness (re-fetch after cache_ttl_days)
            cfg = Config()
            ttl_days = cfg.get("geolocation.cache_ttl_days", 30)
            fetched = row.get("fetched_at")
            if fetched:
                if isinstance(fetched, str):
                    fetched = datetime.strptime(fetched, "%Y-%m-%d %H:%M:%S")
                if datetime.now() - fetched > timedelta(days=ttl_days):
                    return None  # stale
            return dict(row)
    except Exception:
        pass
    return None


def _cache_store(result: GeoResult) -> None:
    """Store a geolocation result in the cache table."""
    if not _db_available():
        return
    try:
        from database.query import upsert
        upsert(
            "INSERT INTO geo_cache "
            "(ip_address, country, country_code, city, latitude, longitude, asn, org) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s) "
            "ON DUPLICATE KEY UPDATE "
            "country=VALUES(country), country_code=VALUES(country_code), "
            "city=VALUES(city), latitude=VALUES(latitude), longitude=VALUES(longitude), "
            "asn=VALUES(asn), org=VALUES(org), fetched_at=NOW()",
            (result.ip, result.country, result.country_code, result.city,
             result.latitude, result.longitude, result.asn, result.org),
        )
    except Exception as exc:
        log.debug("_cache_store failed: %s", exc)


# ---------------------------------------------------------------------------
# Private: MMDB lookup
# ---------------------------------------------------------------------------
def _mmdb_lookup(ip: str) -> GeoResult:
    """Perform a live MaxMind database lookup."""
    _load_readers()
    result = GeoResult(ip=ip)

    if _city_reader:
        try:
            resp = _city_reader.city(ip)
            result.country = resp.country.name or ""
            result.country_code = resp.country.iso_code or ""
            result.city = resp.city.name or ""
            if resp.location.latitude:
                result.latitude = resp.location.latitude
            if resp.location.longitude:
                result.longitude = resp.location.longitude
            result.found = True
        except _geerrors.AddressNotFoundError:
            pass
        except Exception as exc:
            log.debug("GeoLite2-City lookup failed for %s: %s", ip, exc)

    if _asn_reader:
        try:
            resp = _asn_reader.asn(ip)
            result.asn = str(resp.autonomous_system_number) if resp.autonomous_system_number else ""
            result.org = resp.autonomous_system_organization or ""
            result.found = True
        except _geerrors.AddressNotFoundError:
            pass
        except Exception as exc:
            log.debug("GeoLite2-ASN lookup failed for %s: %s", ip, exc)

    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def lookup_ip(ip: str) -> GeoResult:
    """
    Resolve an IP address to geographic information.

    Resolution order:
      1. Database cache (geo_cache table)
      2. MaxMind GeoLite2 local databases
      3. Empty result (graceful degradation)

    Parameters
    ----------
    ip : str
        IPv4 or IPv6 address.

    Returns
    -------
    GeoResult
        Populated with country, city, ASN, etc. if available.
    """
    if not ip or ip in ("127.0.0.1", "::1", "localhost"):
        return GeoResult(ip=ip, country="Local", country_code="LO",
                         city="Localhost", found=True)

    # 1. Check cache
    cached = _cache_lookup(ip)
    if cached:
        return GeoResult(
            ip=cached.get("ip_address", ip),
            country=cached.get("country", ""),
            country_code=cached.get("country_code", ""),
            city=cached.get("city", ""),
            latitude=cached.get("latitude", 0.0) or 0.0,
            longitude=cached.get("longitude", 0.0) or 0.0,
            asn=cached.get("asn", ""),
            org=cached.get("org", ""),
            found=True,
        )

    # 2. MMDB lookup
    if _GEOIP_AVAILABLE:
        result = _mmdb_lookup(ip)
        if result.found:
            _cache_store(result)
            return result

    # 3. No data available
    return GeoResult(ip=ip)


def lookup_ips(ips: list) -> Dict[str, GeoResult]:
    """Batch lookup multiple IPs."""
    return {ip: lookup_ip(ip) for ip in ips}


def is_available() -> bool:
    """Return True if at least one GeoLite2 database is loaded."""
    _load_readers()
    return _city_reader is not None or _asn_reader is not None


def get_status() -> Dict:
    """Return geolocation engine status."""
    _load_readers()
    return {
        "geoip2_installed": _GEOIP_AVAILABLE,
        "city_database": _city_reader is not None,
        "asn_database": _asn_reader is not None,
    }