-- 0005_probe: MQTT 探针体系(Phase 8)

SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS `probe_agents` (
    `id`             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `agent_code`     VARCHAR(64) NOT NULL,
    `region_code`    VARCHAR(32) NOT NULL DEFAULT '',
    `capabilities_text` TEXT,
    `public_ip`      VARCHAR(64) DEFAULT NULL,
    `version`        VARCHAR(64) NOT NULL DEFAULT '',
    `auth_type`      VARCHAR(16) NOT NULL DEFAULT 'shared_token',
    `state`          VARCHAR(16) NOT NULL DEFAULT 'offline',
    `enabled`        TINYINT(1) NOT NULL DEFAULT 1,
    `last_seen_at`   DATETIME(6) DEFAULT NULL,
    `create_time`    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `update_time`    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_agent_code` (`agent_code`),
    KEY `idx_agent_state` (`state`, `enabled`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `probe_jobs` (
    `id`                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `job_no`              VARCHAR(36) NOT NULL,
    `agent_id`            BIGINT UNSIGNED NOT NULL,
    `job_kind`            VARCHAR(16) NOT NULL DEFAULT 'single',
    `execution_region_id` BIGINT UNSIGNED DEFAULT NULL,
    `batch_execution_id`  BIGINT UNSIGNED DEFAULT NULL,
    `total_steps`         INT NOT NULL DEFAULT 0,
    `status`              VARCHAR(16) NOT NULL DEFAULT 'queued',
    `payload_text`        MEDIUMTEXT,
    `summary_text`        MEDIUMTEXT,
    `max_attempts`        INT NOT NULL DEFAULT 3,
    `retry_count`         INT NOT NULL DEFAULT 0,
    `lease_until`         DATETIME(6) DEFAULT NULL,
    `published_at`        DATETIME(6) DEFAULT NULL,
    `started_at`          DATETIME(6) DEFAULT NULL,
    `finished_at`         DATETIME(6) DEFAULT NULL,
    `deadline_at`         DATETIME(6) DEFAULT NULL,
    `last_error`          VARCHAR(255) NOT NULL DEFAULT '',
    `create_time`         DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `update_time`         DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_probe_job_no` (`job_no`),
    KEY `idx_probe_job_status` (`status`, `lease_until`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `probe_job_steps` (
    `id`                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `probe_job_id`      BIGINT UNSIGNED NOT NULL,
    `step_index`        INT NOT NULL DEFAULT 1,
    `protocol`          VARCHAR(16) NOT NULL,
    `target`            VARCHAR(255) NOT NULL,
    `options_text`      MEDIUMTEXT,
    `status`            VARCHAR(16) NOT NULL DEFAULT 'pending',
    `resolved_target`   VARCHAR(1024) NOT NULL DEFAULT '',
    `latency_ms`        DOUBLE DEFAULT NULL,
    `result_code`       VARCHAR(64) NOT NULL DEFAULT '',
    `error_code`        VARCHAR(64) NOT NULL DEFAULT '',
    `error_message`     VARCHAR(255) NOT NULL DEFAULT '',
    `detail_text`       MEDIUMTEXT,
    `create_time`       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    KEY `idx_probe_step_job` (`probe_job_id`, `step_index`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
