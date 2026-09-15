package model

import "time"

// MQTT 探针体系(Phase 8,方案 2.9 协议)

type ProbeAgent struct {
	ID              uint64     `gorm:"column:id;primaryKey;autoIncrement"`
	AgentCode       string     `gorm:"column:agent_code;size:64;uniqueIndex"`
	RegionCode      string     `gorm:"column:region_code;size:32;default:''"`
	CapabilitiesTx  string     `gorm:"column:capabilities_text"`
	PublicIP        *string    `gorm:"column:public_ip;size:64"`
	Version         string     `gorm:"column:version;size:64;default:''"`
	AuthType        string     `gorm:"column:auth_type;size:16;default:shared_token"`
	State           string     `gorm:"column:state;size:16;default:offline"` // online|offline|busy|disabled
	Enabled         bool       `gorm:"column:enabled;default:true"`
	LastSeenAt      *time.Time `gorm:"column:last_seen_at"`
	CreateTime      time.Time  `gorm:"column:create_time;autoCreateTime"`
	UpdateTime      time.Time  `gorm:"column:update_time;autoUpdateTime"`
}

func (ProbeAgent) TableName() string { return "probe_agents" }

type ProbeJob struct {
	ID                uint64     `gorm:"column:id;primaryKey;autoIncrement"`
	JobNo             string     `gorm:"column:job_no;size:36;uniqueIndex"`
	AgentID           uint64     `gorm:"column:agent_id"`
	JobKind           string     `gorm:"column:job_kind;size:16;default:single"` // single | batch
	ExecutionRegionID *uint64    `gorm:"column:execution_region_id"`
	BatchExecutionID  *uint64    `gorm:"column:batch_execution_id"`
	TotalSteps        int        `gorm:"column:total_steps;default:0"`
	Status            string     `gorm:"column:status;size:16;default:queued"` // queued|published|leased|completed|failed|timeout|cancelled
	PayloadTx         string     `gorm:"column:payload_text"`
	SummaryTx         string     `gorm:"column:summary_text"`
	MaxAttempts       int        `gorm:"column:max_attempts;default:3"`
	RetryCount        int        `gorm:"column:retry_count;default:0"`
	LeaseUntil        *time.Time `gorm:"column:lease_until"`
	PublishedAt       *time.Time `gorm:"column:published_at"`
	StartedAt         *time.Time `gorm:"column:started_at"`
	FinishedAt        *time.Time `gorm:"column:finished_at"`
	DeadlineAt        *time.Time `gorm:"column:deadline_at"`
	LastError         string     `gorm:"column:last_error;size:255;default:''"`
	CreateTime        time.Time  `gorm:"column:create_time;autoCreateTime"`
	UpdateTime        time.Time  `gorm:"column:update_time;autoUpdateTime"`
}

func (ProbeJob) TableName() string { return "probe_jobs" }

type ProbeJobStep struct {
	ID             uint64    `gorm:"column:id;primaryKey;autoIncrement"`
	ProbeJobID     uint64    `gorm:"column:probe_job_id;index"`
	StepIndex      int       `gorm:"column:step_index;default:1"`
	Protocol       string    `gorm:"column:protocol;size:16"`
	Target         string    `gorm:"column:target;size:255"`
	OptionsTx      string    `gorm:"column:options_text"`
	Status         string    `gorm:"column:status;size:16;default:pending"`
	ResolvedTarget string    `gorm:"column:resolved_target;size:1024;default:''"`
	LatencyMs      *float64  `gorm:"column:latency_ms"`
	ResultCode     string    `gorm:"column:result_code;size:64;default:''"`
	ErrorCode      string    `gorm:"column:error_code;size:64;default:''"`
	ErrorMessage   string    `gorm:"column:error_message;size:255;default:''"`
	DetailTx       string    `gorm:"column:detail_text"`
	CreateTime     time.Time `gorm:"column:create_time;autoCreateTime"`
}

func (ProbeJobStep) TableName() string { return "probe_job_steps" }

const (
	AgentStateOnline  = "online"
	AgentStateOffline = "offline"
	AgentStateBusy    = "busy"
	AgentStateDisabled = "disabled"

	ProbeJobQueued    = "queued"
	ProbeJobPublished = "published"
	ProbeJobLeased    = "leased"
	ProbeJobCompleted = "completed"
	ProbeJobFailed    = "failed"
	ProbeJobTimeout   = "timeout"
	ProbeJobCancelled = "cancelled"
)
