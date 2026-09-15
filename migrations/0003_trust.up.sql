-- 0003_trust: dnsrisk 可信库(Phase 6)

SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS `dns_trust_domains` (
    `id`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `domain`      VARCHAR(255) NOT NULL,
    `owner`       VARCHAR(128) NOT NULL DEFAULT '',
    `importance`  VARCHAR(16)  NOT NULL DEFAULT 'high',
    `enabled`     TINYINT(1)   NOT NULL DEFAULT 1,
    `environment` VARCHAR(16)  NOT NULL DEFAULT 'prod',
    `notes`       TEXT,
    `create_time` DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `update_time` DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_domain_env` (`environment`, `domain`),
    KEY `idx_domain_env_enabled` (`environment`, `enabled`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `dns_trust_hosts` (
    `id`               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `domain_id`        BIGINT UNSIGNED NOT NULL,
    `fqdn`             VARCHAR(255) NOT NULL,
    `baseline_source`  VARCHAR(16) NOT NULL DEFAULT 'manual',
    `baseline_status`  VARCHAR(16) NOT NULL DEFAULT 'trusted',
    `allow_wildcard`   TINYINT(1) NOT NULL DEFAULT 0,
    `allow_axfr`       TINYINT(1) NOT NULL DEFAULT 0,
    `allow_rebind`     TINYINT(1) NOT NULL DEFAULT 0,
    `dnssec_expected`  TINYINT(1) NOT NULL DEFAULT 0,
    `enabled`          TINYINT(1) NOT NULL DEFAULT 1,
    `notes`            TEXT,
    `create_time`      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `update_time`      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_host_fqdn` (`domain_id`, `fqdn`),
    KEY `idx_host_status` (`baseline_status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `dns_trust_record_baselines` (
    `id`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `host_id`     BIGINT UNSIGNED NOT NULL,
    `section`     VARCHAR(16) NOT NULL,
    `rrname`      VARCHAR(255) NOT NULL,
    `rrtype`      VARCHAR(16) NOT NULL,
    `rrvalue`     VARCHAR(1024) NOT NULL,
    `rr_hash`     CHAR(64) NOT NULL DEFAULT '',
    `ttl_min`     INT DEFAULT NULL,
    `ttl_max`     INT DEFAULT NULL,
    `is_required` TINYINT(1) NOT NULL DEFAULT 1,
    `create_time` DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_baseline_rr` (`host_id`, `rr_hash`),
    KEY `idx_baseline_host_type` (`host_id`, `rrtype`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `dns_trust_candidate_batches` (
    `id`              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `source_type`     VARCHAR(32) NOT NULL,
    `source_label`    VARCHAR(128) NOT NULL DEFAULT '',
    `environment`     VARCHAR(16) NOT NULL DEFAULT 'prod',
    `status`          VARCHAR(16) NOT NULL DEFAULT 'draft',
    `requested_by_id` BIGINT UNSIGNED DEFAULT NULL,
    `approved_by_id`  BIGINT UNSIGNED DEFAULT NULL,
    `approved_at`     DATETIME(6) DEFAULT NULL,
    `summary_message` VARCHAR(255) NOT NULL DEFAULT '',
    `manifest_text`   MEDIUMTEXT,
    `meta_text`       MEDIUMTEXT,
    `create_time`     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `update_time`     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    KEY `idx_batch_status` (`status`, `environment`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `dns_trust_candidate_records` (
    `id`              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `batch_id`        BIGINT UNSIGNED NOT NULL,
    `host_id`         BIGINT UNSIGNED NOT NULL,
    `status`          VARCHAR(16) NOT NULL DEFAULT 'draft',
    `section`         VARCHAR(16) NOT NULL,
    `rrname`          VARCHAR(255) NOT NULL,
    `rrtype`          VARCHAR(16) NOT NULL,
    `rrvalue`         VARCHAR(1024) NOT NULL,
    `ttl_min`         INT DEFAULT NULL,
    `ttl_max`         INT DEFAULT NULL,
    `is_required`     TINYINT(1) NOT NULL DEFAULT 1,
    `reviewed_by_id`  BIGINT UNSIGNED DEFAULT NULL,
    `reviewed_at`     DATETIME(6) DEFAULT NULL,
    `review_note`     VARCHAR(255) NOT NULL DEFAULT '',
    `create_time`     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `update_time`     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    KEY `idx_candidate_batch_host` (`batch_id`, `host_id`, `status`),
    KEY `idx_candidate_host` (`host_id`, `status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `dns_trust_build_jobs` (
    `id`                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `environment`         VARCHAR(16) NOT NULL DEFAULT 'prod',
    `status`              VARCHAR(16) NOT NULL DEFAULT 'pending',
    `requested_by_id`     BIGINT UNSIGNED DEFAULT NULL,
    `retry_of_id`         BIGINT UNSIGNED DEFAULT NULL,
    `input_path`          VARCHAR(512) NOT NULL DEFAULT '',
    `source_label`        VARCHAR(128) NOT NULL DEFAULT '',
    `resolver_ip`         VARCHAR(64) NOT NULL DEFAULT '223.5.5.5',
    `timeout_seconds`     DOUBLE NOT NULL DEFAULT 2,
    `chunk_size`          INT NOT NULL DEFAULT 300,
    `max_hosts_per_domain` INT NOT NULL DEFAULT 3,
    `limit_count`         INT DEFAULT NULL,
    `import_only`         TINYINT(1) NOT NULL DEFAULT 0,
    `auto_approve`        TINYINT(1) NOT NULL DEFAULT 1,
    `total_input_hosts`   INT NOT NULL DEFAULT 0,
    `total_domains`       INT NOT NULL DEFAULT 0,
    `total_chunks`        INT NOT NULL DEFAULT 0,
    `processed_chunks`    INT NOT NULL DEFAULT 0,
    `imported_domains`    INT NOT NULL DEFAULT 0,
    `imported_hosts`      INT NOT NULL DEFAULT 0,
    `discovered_hosts`    INT NOT NULL DEFAULT 0,
    `candidate_records`   INT NOT NULL DEFAULT 0,
    `approved_hosts`      INT NOT NULL DEFAULT 0,
    `trusted_hosts`       INT NOT NULL DEFAULT 0,
    `draft_hosts`         INT NOT NULL DEFAULT 0,
    `current_chunk`       INT NOT NULL DEFAULT 0,
    `started_at`          DATETIME(6) DEFAULT NULL,
    `finished_at`         DATETIME(6) DEFAULT NULL,
    `summary_message`     VARCHAR(255) NOT NULL DEFAULT '',
    `last_error`          VARCHAR(512) NOT NULL DEFAULT '',
    `worker_task_id`      VARCHAR(64) NOT NULL DEFAULT '',
    `create_time`         DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `update_time`         DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    KEY `idx_build_status` (`status`, `environment`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
