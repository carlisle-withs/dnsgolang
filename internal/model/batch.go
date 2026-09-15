package model

import "time"

// 批量拨测(Phase 4,表结构对照技术方案 6.2 与原 models.py)

type BatchTask struct {
	ID                uint64     `gorm:"column:id;primaryKey;autoIncrement"`
	TaskNo            string     `gorm:"column:task_no;size:36;uniqueIndex"`
	Mode              string     `gorm:"column:mode;size:16;default:once"`
	Protocol          string     `gorm:"column:protocol;size:16"` // http|ping|dns|mtr|traceroute|all
	InputMode         string     `gorm:"column:input_mode;size:16"` // text | file
	SourceFileName    string     `gorm:"column:source_file_name;size:255;default:''"`
	RegionCodesTx     string     `gorm:"column:region_codes_text"`
	OptionsTx         string     `gorm:"column:options_text"`
	ScheduleCron      string     `gorm:"column:schedule_cron;size:64;default:''"`
	IsEnabled         bool       `gorm:"column:is_enabled;default:true"`
	Status            string     `gorm:"column:status;size:16;default:pending"`
	CreatedByID       *uint64    `gorm:"column:created_by_id"`
	ClientIP          string     `gorm:"column:client_ip;size:64;default:''"`
	TotalInputCount   int        `gorm:"column:total_input_count;default:0"`
	ValidTargetCount  int        `gorm:"column:valid_target_count;default:0"`
	InvalidTargetCount int       `gorm:"column:invalid_target_count;default:0"`
	DuplicateCount    int        `gorm:"column:duplicate_count;default:0"`
	StartedAt         *time.Time `gorm:"column:started_at"`
	FinishedAt        *time.Time `gorm:"column:finished_at"`
	LastRunAt         *time.Time `gorm:"column:last_run_at"`
	NextRunAt         *time.Time `gorm:"column:next_run_at"`
	SchedulerRef      string     `gorm:"column:scheduler_ref;size:128;default:''"`
	CreateTime        time.Time  `gorm:"column:create_time;autoCreateTime"`
	UpdateTime        time.Time  `gorm:"column:update_time;autoUpdateTime"`
}

func (BatchTask) TableName() string { return "netprobe_batch_tasks" }

const (
	BatchInputValid     = "valid"
	BatchInputInvalid   = "invalid"
	BatchInputDuplicate = "duplicate"

	BatchStatusPending   = "pending"
	BatchStatusRunning   = "running"
	BatchStatusSuccess   = "success"
	BatchStatusPartial   = "partial"
	BatchStatusFailed    = "failed"
	BatchStatusCancelled = "cancelled"
	BatchStatusDisabled  = "disabled"

	ProtocolAll = "all"
)

type BatchTarget struct {
	ID               uint64 `gorm:"column:id;primaryKey;autoIncrement"`
	BatchTaskID      uint64 `gorm:"column:batch_task_id;index:idx_bt_task_status"`
	LineNo           int    `gorm:"column:line_no;default:0"`
	RawTarget        string `gorm:"column:raw_target;size:255"`
	NormalizedTarget string `gorm:"column:normalized_target;size:255;default:''"`
	InputStatus      string `gorm:"column:input_status;size:16;index:idx_bt_task_status"`
	SkipReason       string `gorm:"column:skip_reason;size:255;default:''"`
	CreateTime       time.Time `gorm:"column:create_time;autoCreateTime"`
}

func (BatchTarget) TableName() string { return "netprobe_batch_targets" }

type BatchExecution struct {
	ID               uint64     `gorm:"column:id;primaryKey;autoIncrement"`
	ExecutionNo      string     `gorm:"column:execution_no;size:36;uniqueIndex"`
	BatchTaskID      uint64     `gorm:"column:batch_task_id;index"`
	TriggerType      string     `gorm:"column:trigger_type;size:16;default:manual"`
	Status           string     `gorm:"column:status;size:16;default:pending;index"`
	StartedAt        *time.Time `gorm:"column:started_at"`
	FinishedAt       *time.Time `gorm:"column:finished_at"`
	SuccessCount     int        `gorm:"column:success_count;default:0"`
	FailedCount      int        `gorm:"column:failed_count;default:0"`
	AvailabilityRatio float64   `gorm:"column:availability_ratio;default:0"`
	AvgLatencyMs     *float64   `gorm:"column:avg_latency_ms"`
	SummaryMessage   string     `gorm:"column:summary_message;size:255;default:''"`
	WorkerTaskID     string     `gorm:"column:worker_task_id;size:64;default:''"`
	StopRequestedAt  *time.Time `gorm:"column:stop_requested_at"`
	CancelledAt      *time.Time `gorm:"column:cancelled_at"`
	CreateTime       time.Time  `gorm:"column:create_time;autoCreateTime"`
	UpdateTime       time.Time  `gorm:"column:update_time;autoUpdateTime"`
}

func (BatchExecution) TableName() string { return "netprobe_batch_executions" }

type BatchResult struct {
	ID             uint64    `gorm:"column:id;primaryKey;autoIncrement"`
	BatchExecutionID uint64  `gorm:"column:batch_execution_id;index:idx_br_exec_status"`
	RegionCode     string    `gorm:"column:region_code;size:32;default:''"`
	NodeCode       string    `gorm:"column:node_code;size:64;default:''"`
	Target         string    `gorm:"column:target;size:255"`
	Protocol       string    `gorm:"column:protocol;size:16"`
	Status         string    `gorm:"column:status;size:16;index:idx_br_exec_status"`
	Success        bool      `gorm:"column:success;default:false"`
	ResolvedTarget string    `gorm:"column:resolved_target;size:1024;default:''"`
	LatencyMs      *float64  `gorm:"column:latency_ms;index:idx_br_exec_latency"`
	ResultCode     string    `gorm:"column:result_code;size:64;default:''"`
	ErrorCode      string    `gorm:"column:error_code;size:64;default:''"`
	ErrorMessage   string    `gorm:"column:error_message;size:255;default:''"`
	DetailTx       string    `gorm:"column:detail_text"`
	RawPayloadTx   string    `gorm:"column:raw_payload_text"`
	CreateTime     time.Time `gorm:"column:create_time;autoCreateTime"`
}

func (BatchResult) TableName() string { return "netprobe_batch_results" }

// DailyMetric 地区×协议日聚合(方案 6.2 口径,risk-board 预聚合兜底)。
type DailyMetric struct {
	ID                uint64    `gorm:"column:id;primaryKey;autoIncrement"`
	StatDate          string    `gorm:"column:stat_date;size:10;uniqueIndex:uq_daily_metric"`
	RegionCode        string    `gorm:"column:region_code;size:32;uniqueIndex:uq_daily_metric"`
	Protocol          string    `gorm:"column:protocol;size:16;uniqueIndex:uq_daily_metric"`
	TotalCount        int       `gorm:"column:total_count;default:0"`
	SuccessCount      int       `gorm:"column:success_count;default:0"`
	AvailabilityRatio float64   `gorm:"column:availability_ratio;default:0"`
	LatencyP50Ms      *float64  `gorm:"column:latency_p50_ms"`
	LatencyP95Ms      *float64  `gorm:"column:latency_p95_ms"`
	CreateTime        time.Time `gorm:"column:create_time;autoCreateTime"`
	UpdateTime        time.Time `gorm:"column:update_time;autoUpdateTime"`
}

func (DailyMetric) TableName() string { return "netprobe_daily_metrics" }
