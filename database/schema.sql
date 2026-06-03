-- =============================================================================
-- Security Monitor - MariaDB schema
-- Target: MariaDB 10.x+  (Debian 13 ships MariaDB 11.x)
-- Character set: utf8mb4 / utf8mb4_unicode_ci
-- =============================================================================

-- ┌─────────────────────────────────────────────────────────────────────────────┐
-- │ 1. events                                                                  │
-- └─────────────────────────────────────────────────────────────────────────────┘
-- Stores: login (success/fail), session open/close, sudo/su, SSL alerts,
--         Fail2Ban bans, service status changes, and any other event the
--         plugin emits.
CREATE TABLE IF NOT EXISTS `events` (
    `id`            BIGINT UNSIGNED   NOT NULL AUTO_INCREMENT,
    `timestamp`     DATETIME          NOT NULL,
    `event_type`    VARCHAR(64)       NOT NULL COMMENT 'login.success|login.failure|login.root|session.open|session.close|sudo.command|su.transition|ssl.alert|f2b.ban|service.status',
    `username`      VARCHAR(128)      NOT NULL DEFAULT '',
    `ip_address`    VARCHAR(45)       NOT NULL DEFAULT '' COMMENT 'IPv4 or IPv6',
    `port`          INT UNSIGNED      DEFAULT NULL,
    `hostname`      VARCHAR(255)      NOT NULL DEFAULT '',
    `message`       TEXT,
    `raw_line`      TEXT              DEFAULT NULL COMMENT 'Original log line for audit',
    `metadata`      JSON              DEFAULT NULL COMMENT 'Extra per-event data',
    `country`       VARCHAR(128)      NOT NULL DEFAULT '',
    `city`          VARCHAR(128)      NOT NULL DEFAULT '',
    `asn`           VARCHAR(128)      NOT NULL DEFAULT '',
    `created_at`    DATETIME          NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    INDEX `idx_events_timestamp`      (`timestamp`),
    INDEX `idx_events_ip`             (`ip_address`),
    INDEX `idx_events_user`           (`username`),
    INDEX `idx_events_type`           (`event_type`),
    INDEX `idx_events_ts_type`        (`timestamp`, `event_type`),
    INDEX `idx_events_ip_type`        (`ip_address`, `event_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ┌─────────────────────────────────────────────────────────────────────────────┐
-- │ 2. attacker_stats                                                          │
-- └─────────────────────────────────────────────────────────────────────────────┘
-- Aggregated view of attacker behaviour, updated by the ingestor and the
-- hourly analytics task.
CREATE TABLE IF NOT EXISTS `attacker_stats` (
    `id`            BIGINT UNSIGNED   NOT NULL AUTO_INCREMENT,
    `ip_address`    VARCHAR(45)       NOT NULL,
    `username`      VARCHAR(128)      NOT NULL DEFAULT '',
    `first_seen`    DATETIME          NOT NULL,
    `last_seen`     DATETIME          NOT NULL,
    `total_attempts` INT UNSIGNED     NOT NULL DEFAULT 0,
    `successful`    INT UNSIGNED      NOT NULL DEFAULT 0,
    `failed`        INT UNSIGNED      NOT NULL DEFAULT 0,
    `country`       VARCHAR(128)      NOT NULL DEFAULT '',
    `city`          VARCHAR(128)      NOT NULL DEFAULT '',
    `asn`           VARCHAR(128)      NOT NULL DEFAULT '',
    `created_at`    DATETIME          NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at`    DATETIME          NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE INDEX `uq_attacker_ip_user` (`ip_address`, `username`),
    INDEX `idx_attacker_ip`            (`ip_address`),
    INDEX `idx_attacker_last_seen`     (`last_seen`),
    INDEX `idx_attacker_total`         (`total_attempts` DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ┌─────────────────────────────────────────────────────────────────────────────┐
-- │ 3. geo_cache                                                               │
-- └─────────────────────────────────────────────────────────────────────────────┘
-- Per-IP geolocation cache to avoid repeated GeoLite2 lookups.
CREATE TABLE IF NOT EXISTS `geo_cache` (
    `id`            INT UNSIGNED      NOT NULL AUTO_INCREMENT,
    `ip_address`    VARCHAR(45)       NOT NULL,
    `country`       VARCHAR(128)      NOT NULL DEFAULT '',
    `country_code`  CHAR(2)           NOT NULL DEFAULT '',
    `city`          VARCHAR(255)      NOT NULL DEFAULT '',
    `latitude`      DECIMAL(9,6)      DEFAULT NULL,
    `longitude`     DECIMAL(9,6)      DEFAULT NULL,
    `asn`           VARCHAR(255)      NOT NULL DEFAULT '',
    `org`           VARCHAR(255)      NOT NULL DEFAULT '',
    `fetched_at`    DATETIME          NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE INDEX `uq_geo_ip` (`ip_address`),
    INDEX `idx_geo_fetched`  (`fetched_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ┌─────────────────────────────────────────────────────────────────────────────┐
-- │ 4. ssl_certificates                                                        │
-- └─────────────────────────────────────────────────────────────────────────────┘
-- Inventory of TLS/SSL certificates discovered on the server.
CREATE TABLE IF NOT EXISTS `ssl_certificates` (
    `id`            INT UNSIGNED      NOT NULL AUTO_INCREMENT,
    `domain`        VARCHAR(255)      NOT NULL,
    `issuer`        VARCHAR(512)      NOT NULL DEFAULT '',
    `subject`       VARCHAR(512)      NOT NULL DEFAULT '',
    `serial`        VARCHAR(128)      NOT NULL DEFAULT '',
    `not_before`    DATETIME          DEFAULT NULL,
    `not_after`     DATETIME          DEFAULT NULL,
    `sans`          JSON              DEFAULT NULL COMMENT 'Subject Alternative Names',
    `status`        ENUM('healthy','warning','critical','unknown') NOT NULL DEFAULT 'unknown',
    `days_remaining` INT              DEFAULT NULL,
    `path`          VARCHAR(1024)     NOT NULL DEFAULT '' COMMENT 'Filesystem path to cert file',
    `source`        VARCHAR(64)       NOT NULL DEFAULT '' COMMENT 'letsencrypt|aapanel|manual|other',
    `last_scanned`  DATETIME          DEFAULT NULL,
    `created_at`    DATETIME          NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at`    DATETIME          NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE INDEX `uq_ssl_domain_path` (`domain`, `path`),
    INDEX `idx_ssl_status`            (`status`),
    INDEX `idx_ssl_expiry`            (`not_after`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ┌─────────────────────────────────────────────────────────────────────────────┐
-- │ 5. settings                                                                │
-- └─────────────────────────────────────────────────────────────────────────────┘
-- Key-value store for mutable plugin settings that can be changed at runtime
-- via the UI or API.  Overrides config.json for individual keys.
CREATE TABLE IF NOT EXISTS `settings` (
    `key`           VARCHAR(255)      NOT NULL,
    `value`         TEXT              NOT NULL,
    `category`      VARCHAR(64)       NOT NULL DEFAULT 'general',
    `description`   VARCHAR(512)      NOT NULL DEFAULT '',
    `updated_at`    DATETIME          NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`key`),
    INDEX `idx_settings_category` (`category`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ┌─────────────────────────────────────────────────────────────────────────────┐
-- │ 6. alerts                                                                  │
-- └─────────────────────────────────────────────────────────────────────────────┘
-- Generated alert records from the rule engine (Phase 11).
CREATE TABLE IF NOT EXISTS `alerts` (
    `id`            BIGINT UNSIGNED   NOT NULL AUTO_INCREMENT,
    `rule_id`       VARCHAR(128)      NOT NULL COMMENT 'failed_root_login|new_country_login|ssl_expiring_7d|f2b_ban|service_down|custom',
    `title`         VARCHAR(512)      NOT NULL,
    `body`          TEXT,
    `severity`      ENUM('info','warning','critical') NOT NULL DEFAULT 'warning',
    `acknowledged`  TINYINT(1)        NOT NULL DEFAULT 0,
    `ack_at`        DATETIME          DEFAULT NULL,
    `ack_by`        VARCHAR(128)      NOT NULL DEFAULT '',
    `metadata`      JSON              DEFAULT NULL,
    `event_id`      BIGINT UNSIGNED   DEFAULT NULL COMMENT 'FK to events.id',
    `created_at`    DATETIME          NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    INDEX `idx_alerts_rule`           (`rule_id`),
    INDEX `idx_alerts_severity`       (`severity`),
    INDEX `idx_alerts_ack`            (`acknowledged`),
    INDEX `idx_alerts_created`        (`created_at`),
    INDEX `idx_alerts_event`          (`event_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ┌─────────────────────────────────────────────────────────────────────────────┐
-- │ 7. notification_queue                                                      │
-- └─────────────────────────────────────────────────────────────────────────────┘
-- Outbound notification queue (Telegram / Discord / Email).
-- The queue processor picks up pending messages, attempts delivery,
-- and updates the status.
CREATE TABLE IF NOT EXISTS `notification_queue` (
    `id`            BIGINT UNSIGNED   NOT NULL AUTO_INCREMENT,
    `channel`       VARCHAR(32)       NOT NULL COMMENT 'telegram|discord|email',
    `alert_id`      BIGINT UNSIGNED   DEFAULT NULL,
    `payload`       JSON              NOT NULL COMMENT 'Template + params or raw body',
    `status`        ENUM('pending','sending','sent','failed') NOT NULL DEFAULT 'pending',
    `attempts`      TINYINT UNSIGNED  NOT NULL DEFAULT 0,
    `last_error`    TEXT              DEFAULT NULL,
    `scheduled_at`  DATETIME          NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `sent_at`       DATETIME          DEFAULT NULL,
    `created_at`    DATETIME          NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    INDEX `idx_nq_status`            (`status`),
    INDEX `idx_nq_channel`           (`channel`),
    INDEX `idx_nq_scheduled`         (`scheduled_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ┌─────────────────────────────────────────────────────────────────────────────┐
-- │ 8. log_offsets                                                             │
-- └─────────────────────────────────────────────────────────────────────────────┘
-- Tracks the read position of each monitored log file so the parser
-- can resume after restart / rotation without re-processing the whole file.
-- One row per (log_key = logical file identifier).
CREATE TABLE IF NOT EXISTS `log_offsets` (
    `id`            INT UNSIGNED      NOT NULL AUTO_INCREMENT,
    `log_key`       VARCHAR(128)      NOT NULL COMMENT 'e.g. auth.log, fail2ban.log, journal:sshd',
    `file_path`     VARCHAR(1024)     NOT NULL,
    `file_inode`    BIGINT UNSIGNED   NOT NULL DEFAULT 0,
    `byte_offset`   BIGINT UNSIGNED   NOT NULL DEFAULT 0,
    `line_number`   BIGINT UNSIGNED   NOT NULL DEFAULT 0,
    `updated_at`    DATETIME          NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE INDEX `uq_offset_key` (`log_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ┌─────────────────────────────────────────────────────────────────────────────┐
-- │ 9. service_status                                                          │
-- └─────────────────────────────────────────────────────────────────────────────┘
-- Current and historical status of monitored systemd services.
CREATE TABLE IF NOT EXISTS `service_status` (
    `id`            INT UNSIGNED      NOT NULL AUTO_INCREMENT,
    `service_name`  VARCHAR(128)      NOT NULL,
    `unit_name`     VARCHAR(255)      NOT NULL,
    `status`        ENUM('running','stopped','failed','unknown') NOT NULL DEFAULT 'unknown',
    `sub_status`    VARCHAR(128)      NOT NULL DEFAULT '',
    `pid`           INT UNSIGNED      DEFAULT NULL,
    `memory_kb`     BIGINT UNSIGNED   DEFAULT NULL,
    `uptime_seconds` INT UNSIGNED     DEFAULT NULL,
    `checked_at`    DATETIME          NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `created_at`    DATETIME          NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    INDEX `idx_svc_name`     (`service_name`),
    INDEX `idx_svc_status`   (`status`),
    INDEX `idx_svc_checked`  (`checked_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ┌─────────────────────────────────────────────────────────────────────────────┐
-- │ 10. fail2ban_jails                                                        │
-- └─────────────────────────────────────────────────────────────────────────────┘
-- Periodic snapshot of Fail2Ban jail state.
CREATE TABLE IF NOT EXISTS `fail2ban_jails` (
    `id`            INT UNSIGNED      NOT NULL AUTO_INCREMENT,
    `jail_name`     VARCHAR(255)      NOT NULL,
    `status`        ENUM('active','inactive','error') NOT NULL DEFAULT 'inactive',
    `total_banned`  INT UNSIGNED      NOT NULL DEFAULT 0,
    `currently_banned` INT UNSIGNED   NOT NULL DEFAULT 0,
    `total_failed`  INT UNSIGNED      NOT NULL DEFAULT 0,
    `currently_failed` INT UNSIGNED   NOT NULL DEFAULT 0,
    `filter_name`   VARCHAR(255)      NOT NULL DEFAULT '',
    `action_name`   VARCHAR(255)      NOT NULL DEFAULT '',
    `config_path`   VARCHAR(1024)     NOT NULL DEFAULT '',
    `fetched_at`    DATETIME          NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE INDEX `uq_f2b_jail` (`jail_name`),
    INDEX `idx_f2b_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ┌─────────────────────────────────────────────────────────────────────────────┐
-- │ 11. fail2ban_bans                                                          │
-- └─────────────────────────────────────────────────────────────────────────────┘
-- Individual ban events tracked over time.
CREATE TABLE IF NOT EXISTS `fail2ban_bans` (
    `id`            BIGINT UNSIGNED   NOT NULL AUTO_INCREMENT,
    `jail_name`     VARCHAR(255)      NOT NULL,
    `ip_address`    VARCHAR(45)       NOT NULL,
    `banned_at`     DATETIME          NOT NULL,
    `unbanned_at`   DATETIME          DEFAULT NULL,
    `ban_reason`    TEXT              DEFAULT NULL,
    `created_at`    DATETIME          NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    INDEX `idx_f2b_bans_jail`    (`jail_name`),
    INDEX `idx_f2b_bans_ip`      (`ip_address`),
    INDEX `idx_f2b_bans_time`    (`banned_at`),
    INDEX `idx_f2b_bans_active`  (`jail_name`, `unbanned_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;