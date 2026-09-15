-- 0001_init: 认证 + netprobe 单目标拨测全链路(Phase 0-2)
-- 命名/类型规范:snake_case、BIGINT 主键、DATETIME(6)、utf8mb4_0900_ai_ci、逻辑外键。

SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS `users` (
    `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `username`      VARCHAR(150) NOT NULL,
    `password_hash` VARCHAR(255) NOT NULL DEFAULT '',
    `name`          VARCHAR(20)  NOT NULL DEFAULT '',
    `mobile`        VARCHAR(11)  DEFAULT NULL,
    `avatar`        VARCHAR(255) NOT NULL DEFAULT '',
    `email`         VARCHAR(254) NOT NULL DEFAULT '',
    `is_superuser`  TINYINT(1)   NOT NULL DEFAULT 0,
    `is_active`     TINYINT(1)   NOT NULL DEFAULT 1,
    `create_time`   DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `update_time`   DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_users_username` (`username`),
    UNIQUE KEY `uq_users_mobile` (`mobile`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `netprobe_regions` (
    `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `code`          VARCHAR(32) NOT NULL,
    `name`          VARCHAR(64) NOT NULL,
    `display_order` INT NOT NULL DEFAULT 0,
    `is_active`     TINYINT(1) NOT NULL DEFAULT 1,
    `map_lng`       DOUBLE NOT NULL DEFAULT 0,
    `map_lat`       DOUBLE NOT NULL DEFAULT 0,
    `create_time`   DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `update_time`   DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_region_code` (`code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `netprobe_nodes` (
    `id`                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `code`              VARCHAR(64) NOT NULL,
    `name`              VARCHAR(64) NOT NULL,
    `region_code`       VARCHAR(32) NOT NULL DEFAULT '',
    `queue_name`        VARCHAR(128) NOT NULL DEFAULT '',
    `transport`         VARCHAR(16) NOT NULL DEFAULT 'local',
    `host`              VARCHAR(128) NOT NULL DEFAULT '',
    `public_ip`         VARCHAR(64) DEFAULT NULL,
    `status`            VARCHAR(16) NOT NULL DEFAULT 'offline',
    `capabilities_text` TEXT,
    `last_heartbeat`    DATETIME(6) DEFAULT NULL,
    `is_default`        TINYINT(1) NOT NULL DEFAULT 0,
    `is_schedulable`    TINYINT(1) NOT NULL DEFAULT 1,
    `agent_ref`         VARCHAR(64) NOT NULL DEFAULT '',
    `broker_client_id`  VARCHAR(128) NOT NULL DEFAULT '',
    `create_time`       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `update_time`       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_node_code` (`code`),
    KEY `idx_node_region` (`region_code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `netprobe_tasks` (
    `id`              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `task_no`         VARCHAR(36) NOT NULL,
    `mode`            VARCHAR(16) NOT NULL,
    `protocol`        VARCHAR(16) NOT NULL,
    `target`          VARCHAR(255) NOT NULL,
    `target_display`  VARCHAR(255) NOT NULL DEFAULT '',
    `region_codes_text` TEXT,
    `options_text`    TEXT,
    `schedule_cron`   VARCHAR(64) NOT NULL DEFAULT '',
    `is_enabled`      TINYINT(1) NOT NULL DEFAULT 1,
    `status`          VARCHAR(16) NOT NULL DEFAULT 'pending',
    `created_by_id`   BIGINT UNSIGNED DEFAULT NULL,
    `client_ip`       VARCHAR(64) NOT NULL DEFAULT '',
    `source`          VARCHAR(16) NOT NULL DEFAULT 'public',
    `last_run_at`     DATETIME(6) DEFAULT NULL,
    `next_run_at`     DATETIME(6) DEFAULT NULL,
    `scheduler_ref`   VARCHAR(128) NOT NULL DEFAULT '',
    `create_time`     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `update_time`     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_task_no` (`task_no`),
    KEY `idx_task_mode_protocol_status` (`mode`, `protocol`, `status`),
    KEY `idx_task_created_by` (`created_by_id`),
    KEY `idx_task_next_run` (`next_run_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `netprobe_executions` (
    `id`                   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `execution_no`         VARCHAR(36) NOT NULL,
    `task_id`              BIGINT UNSIGNED NOT NULL,
    `trigger_type`         VARCHAR(16) NOT NULL DEFAULT 'manual',
    `status`               VARCHAR(16) NOT NULL DEFAULT 'pending',
    `planned_at`           DATETIME(6) DEFAULT NULL,
    `started_at`           DATETIME(6) DEFAULT NULL,
    `finished_at`          DATETIME(6) DEFAULT NULL,
    `success_region_count` INT NOT NULL DEFAULT 0,
    `total_region_count`   INT NOT NULL DEFAULT 0,
    `availability_ratio`   DOUBLE NOT NULL DEFAULT 0,
    `summary_message`      VARCHAR(255) NOT NULL DEFAULT '',
    `create_time`          DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `update_time`          DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_execution_no` (`execution_no`),
    KEY `idx_execution_task` (`task_id`),
    KEY `idx_execution_status_time` (`status`, `create_time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `netprobe_execution_regions` (
    `id`               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `execution_id`     BIGINT UNSIGNED NOT NULL,
    `region_code`      VARCHAR(32) NOT NULL DEFAULT '',
    `region_name`      VARCHAR(64) NOT NULL DEFAULT '',
    `map_lng`          DOUBLE NOT NULL DEFAULT 0,
    `map_lat`          DOUBLE NOT NULL DEFAULT 0,
    `node_code`        VARCHAR(64) NOT NULL DEFAULT '',
    `node_name`        VARCHAR(64) NOT NULL DEFAULT '',
    `node_transport`   VARCHAR(16) NOT NULL DEFAULT '',
    `status`           VARCHAR(16) NOT NULL DEFAULT 'pending',
    `success`          TINYINT(1) NOT NULL DEFAULT 0,
    `resolved_target`  VARCHAR(1024) NOT NULL DEFAULT '',
    `latency_ms`       DOUBLE DEFAULT NULL,
    `started_at`       DATETIME(6) DEFAULT NULL,
    `finished_at`      DATETIME(6) DEFAULT NULL,
    `error_code`       VARCHAR(64) NOT NULL DEFAULT '',
    `error_message`    VARCHAR(255) NOT NULL DEFAULT '',
    `raw_payload_text` TEXT,
    `create_time`      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `update_time`      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    KEY `idx_exec_region_execution` (`execution_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- 合并原五张协议结果表(netprobe_http_result / ping / dns / mtr / traceroute)
CREATE TABLE IF NOT EXISTS `netprobe_probe_results` (
    `id`                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `execution_region_id` BIGINT UNSIGNED NOT NULL,
    `protocol`            VARCHAR(16) NOT NULL,
    `detail_text`         MEDIUMTEXT,
    `create_time`         DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `update_time`         DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_probe_result` (`execution_region_id`, `protocol`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
