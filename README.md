# Security Monitor

An aaPanel plugin that monitors SSH authentication, active sessions, Fail2Ban, SSL certificates, and services on a Debian 13 / MariaDB stack. Provides a security dashboard, alerting, and outbound notifications (Telegram / Discord / Email).

> **Status:** Phase 1-3 delivered (Foundation + Database + SSH log ingestion)
> **Target:** aaPanel 8.0.3 Free, Debian 13, MariaDB, Python 3
> **Version:** 1.0.0

---

## Features in this build

| Phase | Module | Status |
|------:|--------|--------|
| 1 | Plugin skeleton, installer/uninstaller, config, logging | done |
| 2 | MariaDB schema, connection / query / transaction helpers | done |
| 3 | SSH log ingestion (`/var/log/auth.log` + `journalctl` fallback), offset tracking, dedup | done |
| 4-20 | Session, Fail2Ban, SSL, alerts, notifications, UI | not started (next sessions) |

---

## Repository layout

```
Sec-Mon/
├── info.json                  # aaPanel plugin manifest
├── install.sh                 # Installer (runs on the aaPanel host)
├── uninstall.sh               # Uninstaller
├── requirements.txt           # Python deps (light, mostly stdlib)
├── sec_mon_main.py            # Plugin class with route handlers
├── index.py                   # Entry point imported by aaPanel
├── config/
│   └── default.json           # Default configuration
├── lib/
│   ├── __init__.py
│   ├── config.py              # Configuration manager
│   └── logger.py              # Rotating file logger
├── database/
│   ├── __init__.py
│   ├── connection.py          # PyMySQL/MariaDB connection pool
│   ├── query.py               # Query helper
│   ├── transaction.py         # Transaction context manager
│   └── schema.sql             # DDL for all 8 tables
├── modules/
│   └── ssh_monitor/
│       ├── __init__.py
│       ├── parser.py          # auth.log line parser
│       ├── journal.py         # journalctl fallback
│       ├── offset.py          # Inode/offset tracker (rotation safe)
│       ├── normalizer.py      # Event normalization
│       └── ingester.py        # End-to-end ingestion pipeline
├── logs/                      # Created at runtime
├── data/                      # Created at runtime (offset store)
└── tests/                     # Smoke tests
```

---

## Quick start (development)

```bash
# 1. Copy to aaPanel's plugin directory
sudo cp -r . /www/server/panel/plugin/sec_mon/
sudo chown -R root:root /www/server/panel/plugin/sec_mon

# 2. Install
sudo bash /www/server/panel/plugin/sec_mon/install.sh install

# 3. Reload aaPanel
sudo bt reload

# 4. The plugin appears in aaPanel under "Security Monitor"
```

The installer:
- Creates a `sec_mon` MariaDB database (uses aaPanel's stored credentials)
- Applies `database/schema.sql`
- Creates `logs/` and `data/` directories
- Writes `config/config.json` from defaults
- Installs Python dependencies via `pip`

---

## Configuration

`config/config.json` is generated from `config/default.json` on first run. Edit it directly or via the plugin UI (Phase 14).

Key keys:
```json
{
  "database": { "name": "sec_mon", "pool_size": 5 },
  "ssh_monitor": { "log_path": "/var/log/auth.log", "poll_interval": 30, "journal_fallback": true },
  "logging": { "level": "INFO", "max_bytes": 10485760, "backup_count": 5 }
}
```

---

## Testing

```bash
python3 -m pytest tests/
```

A `tests/fixtures/auth_sample.log` is included to exercise the parser without root access.

---

## Roadmap

Phase 4: session & sudo/su tracking • Phase 5: live sessions page • Phase 6: GeoIP • Phase 7: attacker intelligence • Phase 8: Fail2Ban • Phase 9: SSL • Phase 10: services • Phase 11: alerts • Phase 12: notifications • Phase 13: REST API • Phase 14: frontend • Phase 15: analytics • Phase 16: real-time • Phase 17: hardening • Phase 18: daemon • Phase 19: tests • Phase 20: release.
