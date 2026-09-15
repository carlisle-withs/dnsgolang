-- 0002_batch: 批量拨测 + 日指标(Phase 4)

SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS `netprobe_batch_tasks` (
    `id`                   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `task_no`              VARCHAR(36) NOT NULL,
    `mode`                 VARCHAR(16) NOT NULL DEFAULT 'once',
    `protocol`             VARCHAR(16) NOT NULL,
    `input_mode`           VARCHAR(16) NOT NULL DEFAULT 'text',
    `source_file_name`     VARCHAR(255) NOT NULL DEFAULT '',
    `region_codes_text`    TEXT,
    `options_text`         TEXT,
    `schedule_cron`        VARCHAR(64) NOT NULL DEFAULT '',
    `is_enabled`           TINYINT(1) NOT NULL DEFAULT 1,
    `status`               VARCHAR(16) NOT NULL DEFAULT 'pending',
    `created_by_id`        BIGINT UNSIGNED DEFAULT NULL,
    `client_ip`            VARCHAR(64) NOT NULL DEFAULT '',
    `total_input_count`    INT NOT NULL DEFAULT 0,
    `valid_target_count`   INT NOT NULL DEFAULT 0,
    `invalid_target_count` INT NOT NULL DEFAULT 0,
    `duplicate_count`      INT NOT NULL DEFAULT 0,
    `started_at`           DATETIME(6) DEFAULT NULL,
    `finished_at`          DATETIME(6) DEFAULT NULL,
    `last_run_at`          DATETIME(6) DEFAULT NULL,
    `next_run_at`          DATETIME(6) DEFAULT NULL,
    `scheduler_ref`        VARCHAR(128) NOT NULL DEFAULT '',
    `create_time`          DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `update_time`          DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_batch_task_no` (`task_no`),
    KEY `idx_batch_task_owner` (`created_by_id`, `protocol`, `status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `netprobe_batch_targets` (
    `id`                 BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `batch_task_id`      BIGINT UNSIGNED NOT NULL,
    `line_no`            INT NOT NULL DEFAULT 0,
    `raw_target`         VARCHAR(255) NOT NULL,
    `normalized_target`  VARCHAR(255) NOT NULL DEFAULT '',
    `input_status`       VARCHAR(16) NOT NULL DEFAULT 'valid',
    `skip_reason`        VARCHAR(255) NOT NULL DEFAULT '',
    `create_time`        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    KEY `idx_bt_task_status` (`batch_task_id`, `input_status`, `normalized_target`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `netprobe_batch_executions` (
    `id`                 BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `execution_no`       VARCHAR(36) NOT NULL,
    `batch_task_id`      BIGINT UNSIGNED NOT NULL,
    `trigger_type`       VARCHAR(16) NOT NULL DEFAULT 'manual',
    `status`             VARCHAR(16) NOT NULL DEFAULT 'pending',
    `started_at`         DATETIME(6) DEFAULT NULL,
    `finished_at`        DATETIME(6) DEFAULT NULL,
    `success_count`      INT NOT NULL DEFAULT 0,
    `failed_count`       INT NOT NULL DEFAULT 0,
    `availability_ratio` DOUBLE NOT NULL DEFAULT 0,
    `avg_latency_ms`     DOUBLE DEFAULT NULL,
    `summary_message`    VARCHAR(255) NOT NULL DEFAULT '',
    `worker_task_id`     VARCHAR(64) NOT NULL DEFAULT '',
    `stop_requested_at`  DATETIME(6) DEFAULT NULL,
    `cancelled_at`       DATETIME(6) DEFAULT NULL,
    `create_time`        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `update_time`        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_batch_execution_no` (`execution_no`),
    KEY `idx_be_task` (`batch_task_id`),
    KEY `idx_be_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `netprobe_batch_results` (
    `id`                 BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `batch_execution_id` BIGINT UNSIGNED NOT NULL,
    `region_code`        VARCHAR(32) NOT NULL DEFAULT '',
    `node_code`          VARCHAR(64) NOT NULL DEFAULT '',
    `target`             VARCHAR(255) NOT NULL,
    `protocol`           VARCHAR(16) NOT NULL,
    `status`             VARCHAR(16) NOT NULL,
    `success`            TINYINT(1) NOT NULL DEFAULT 0,
    `resolved_target`    VARCHAR(1024) NOT NULL DEFAULT '',
    `latency_ms`         DOUBLE DEFAULT NULL,
    `result_code`        VARCHAR(64) NOT NULL DEFAULT '',
    `error_code`         VARCHAR(64) NOT NULL DEFAULT '',
    `error_message`      VARCHAR(255) NOT NULL DEFAULT '',
    `detail_text`        MEDIUMTEXT,
    `raw_payload_text`   MEDIUMTEXT,
    `create_time`        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    KEY `idx_br_exec_status` (`batch_execution_id`, `status`, `latency_ms`),
    KEY `idx_br_exec_protocol` (`batch_execution_id`, `protocol`),
    KEY `idx_br_exec_result_code` (`batch_execution_id`, `result_code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `netprobe_daily_metrics` (
    `id`                 BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `stat_date`          DATE NOT NULL,
    `region_code`        VARCHAR(32) NOT NULL,
    `protocol`           VARCHAR(16) NOT NULL,
    `total_count`        INT NOT NULL DEFAULT 0,
    `success_count`      INT NOT NULL DEFAULT 0,
    `availability_ratio` DOUBLE NOT NULL DEFAULT 0,
    `latency_p50_ms`     DOUBLE DEFAULT NULL,
    `latency_p95_ms`     DOUBLE DEFAULT NULL,
    `create_time`        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `update_time`        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_daily_metric` (`stat_date`, `region_code`, `protocol`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
