-- 0004_scan: 扫描器 + 观测快照 + 判定(Phase 7)

SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS `dns_ownership_monitor_profiles` (
    `id`                      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `name`                    VARCHAR(128) NOT NULL,
    `environment`             VARCHAR(16) NOT NULL DEFAULT 'prod',
    `enabled`                 TINYINT(1) NOT NULL DEFAULT 1,
    `interval_seconds`        INT NOT NULL DEFAULT 60,
    `target_detection_seconds` INT NOT NULL DEFAULT 120,
    `resolver_ip`             VARCHAR(64) NOT NULL DEFAULT '223.5.5.5',
    `resolver_pool_text`      TEXT,
    `timeout_seconds`         DOUBLE NOT NULL DEFAULT 3,
    `concurrency`             INT NOT NULL DEFAULT 8,
    `keyword`                 VARCHAR(255) NOT NULL DEFAULT '',
    `limit_count`             INT DEFAULT NULL,
    `domain_ids_text`         TEXT,
    `host_ids_text`           TEXT,
    `last_run_at`             DATETIME(6) DEFAULT NULL,
    `last_status`             VARCHAR(32) NOT NULL DEFAULT '',
    `created_by_id`           BIGINT UNSIGNED DEFAULT NULL,
    `create_time`             DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `update_time`             DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    KEY `idx_monitor_due` (`enabled`, `last_run_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `dns_batch_scan_jobs` (
    `id`              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `environment`     VARCHAR(16) NOT NULL DEFAULT 'prod',
    `status`          VARCHAR(16) NOT NULL DEFAULT 'pending',
    `requested_by_id` BIGINT UNSIGNED DEFAULT NULL,
    `resolver_ip`     VARCHAR(64) NOT NULL DEFAULT '223.5.5.5',
    `resolver_pool_text` TEXT,
    `timeout_seconds` DOUBLE NOT NULL DEFAULT 3,
    `concurrency`     INT NOT NULL DEFAULT 8,
    `keyword`         VARCHAR(255) NOT NULL DEFAULT '',
    `limit_count`     INT DEFAULT NULL,
    `domain_ids_text` TEXT,
    `host_ids_text`   TEXT,
    `total_domains`   INT NOT NULL DEFAULT 0,
    `total_hosts`     INT NOT NULL DEFAULT 0,
    `processed_hosts` INT NOT NULL DEFAULT 0,
    `success_hosts`   INT NOT NULL DEFAULT 0,
    `suspicious_hosts` INT NOT NULL DEFAULT 0,
    `error_hosts`     INT NOT NULL DEFAULT 0,
    `avg_latency_ms`  DOUBLE DEFAULT NULL,
    `summary_text`    MEDIUMTEXT,
    `filters_text`    MEDIUMTEXT,
    `summary_message` VARCHAR(255) NOT NULL DEFAULT '',
    `last_error`      VARCHAR(512) NOT NULL DEFAULT '',
    `started_at`      DATETIME(6) DEFAULT NULL,
    `finished_at`     DATETIME(6) DEFAULT NULL,
    `create_time`     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `update_time`     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    KEY `idx_scan_status` (`status`, `create_time`),
    KEY `idx_scan_env` (`environment`, `create_time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `dns_batch_scan_results` (
    `id`                 BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `scan_job_id`        BIGINT UNSIGNED NOT NULL,
    `domain_id`          BIGINT UNSIGNED DEFAULT NULL,
    `host_id`            BIGINT UNSIGNED NOT NULL,
    `snapshot_id`        BIGINT UNSIGNED DEFAULT NULL,
    `status`             VARCHAR(16) NOT NULL DEFAULT 'normal',
    `severity`           VARCHAR(16) NOT NULL DEFAULT '',
    `confidence_tier`    VARCHAR(32) NOT NULL DEFAULT '',
    `confidence_labels_text` TEXT,
    `suspicious_count`   INT NOT NULL DEFAULT 0,
    `summary_message`    VARCHAR(512) NOT NULL DEFAULT '',
    `rcode`              VARCHAR(32) NOT NULL DEFAULT '',
    `error_kind`         VARCHAR(32) NOT NULL DEFAULT '',
    `latency_ms`         DOUBLE DEFAULT NULL,
    `risk_types_text`    TEXT,
    `evidence_text`      MEDIUMTEXT,
    `detected_at`        DATETIME(6) DEFAULT NULL,
    `create_time`        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    KEY `idx_scan_result_job` (`scan_job_id`, `status`),
    KEY `idx_scan_result_host` (`host_id`, `create_time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `dns_risk_verdict_latest` (
    `id`              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `host_id`         BIGINT UNSIGNED NOT NULL,
    `risk_type`       VARCHAR(32) NOT NULL,
    `status`          VARCHAR(16) NOT NULL DEFAULT 'normal',
    `severity`        VARCHAR(16) NOT NULL DEFAULT '',
    `confidence_tier` VARCHAR(32) NOT NULL DEFAULT '',
    `method_code`     VARCHAR(64) NOT NULL DEFAULT '',
    `summary_message` VARCHAR(512) NOT NULL DEFAULT '',
    `evidence_text`   MEDIUMTEXT,
    `detected_at`     DATETIME(6) DEFAULT NULL,
    `update_time`     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_verdict` (`host_id`, `risk_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `dns_observation_snapshots` (
    `id`                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `host_id`             BIGINT UNSIGNED NOT NULL,
    `scan_job_id`         BIGINT UNSIGNED DEFAULT NULL,
    `resolver_ip`         VARCHAR(64) NOT NULL DEFAULT '',
    `rcode`               VARCHAR(32) NOT NULL DEFAULT '',
    `error_kind`          VARCHAR(32) NOT NULL DEFAULT '',
    `latency_ms`          DOUBLE DEFAULT NULL,
    `ns_name_list_text`   TEXT,
    `ns_glue_ip_list_text` TEXT,
    `unique_ip_set_text`  TEXT,
    `soa_mname`           VARCHAR(255) NOT NULL DEFAULT '',
    `soa_serial`          VARCHAR(64) NOT NULL DEFAULT '',
    `wildcard_hit`        TINYINT(1) NOT NULL DEFAULT 0,
    `axfr_success`        TINYINT(1) NOT NULL DEFAULT 0,
    `axfr_record_count`   INT NOT NULL DEFAULT 0,
    `axfr_zone_hash`      VARCHAR(64) NOT NULL DEFAULT '',
    `random_label`        VARCHAR(64) NOT NULL DEFAULT '',
    `query_plan_text`     MEDIUMTEXT,
    `raw_output_text`     MEDIUMTEXT,
    `observed_at`         DATETIME(6) DEFAULT NULL,
    `create_time`         DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    KEY `idx_snapshot_host` (`host_id`, `observed_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `dns_observation_records` (
    `id`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `snapshot_id` BIGINT UNSIGNED NOT NULL,
    `section`     VARCHAR(16) NOT NULL DEFAULT 'answer',
    `rrname`      VARCHAR(255) NOT NULL DEFAULT '',
    `rrtype`      VARCHAR(16) NOT NULL DEFAULT '',
    `rrvalue`     VARCHAR(1024) NOT NULL DEFAULT '',
    `ttl`         INT DEFAULT NULL,
    `create_time` DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    KEY `idx_obs_record_snapshot` (`snapshot_id`, `section`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `dns_observation_method_evidence` (
    `id`           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `snapshot_id`  BIGINT UNSIGNED NOT NULL,
    `method_code`  VARCHAR(64) NOT NULL DEFAULT '',
    `findings_text` MEDIUMTEXT,
    `create_time`  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    KEY `idx_method_evidence` (`snapshot_id`, `method_code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
