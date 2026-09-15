// Package model 定义 GORM 模型(全新 Go schema,命名遵循技术方案 6.2:
// snake_case 复数表名、BIGINT 自增主键、DATETIME(6)、JSON 以文本列存储、逻辑外键)。
package model

import "time"

// ---------- oauth ----------

type User struct {
	ID           uint64    `gorm:"column:id;primaryKey;autoIncrement"`
	Username     string    `gorm:"column:username;size:150;uniqueIndex"`
	PasswordHash string    `gorm:"column:password_hash;size:255"`
	Name         string    `gorm:"column:name;size:20;default:''"`
	Mobile       *string   `gorm:"column:mobile;size:11;uniqueIndex"`
	Avatar       string    `gorm:"column:avatar;size:255;default:''"`
	Email        string    `gorm:"column:email;size:254;default:''"`
	IsSuperuser  bool      `gorm:"column:is_superuser;default:false"`
	IsActive     bool      `gorm:"column:is_active;default:true"`
	CreateTime   time.Time `gorm:"column:create_time;autoCreateTime"`
	UpdateTime   time.Time `gorm:"column:update_time;autoUpdateTime"`
}

func (User) TableName() string { return "users" }

// ---------- netprobe 基础 ----------

type Region struct {
	ID           uint64    `gorm:"column:id;primaryKey;autoIncrement"`
	Code         string    `gorm:"column:code;size:32;uniqueIndex"`
	Name         string    `gorm:"column:name;size:64"`
	DisplayOrder int       `gorm:"column:display_order;default:0"`
	IsActive     bool      `gorm:"column:is_active;default:true"`
	MapLng       float64   `gorm:"column:map_lng"`
	MapLat       float64   `gorm:"column:map_lat"`
	CreateTime   time.Time `gorm:"column:create_time;autoCreateTime"`
	UpdateTime   time.Time `gorm:"column:update_time;autoUpdateTime"`
}

func (Region) TableName() string { return "netprobe_regions" }

type Node struct {
	ID             uint64     `gorm:"column:id;primaryKey;autoIncrement"`
	Code           string     `gorm:"column:code;size:64;uniqueIndex"`
	Name           string     `gorm:"column:name;size:64"`
	RegionCode     string     `gorm:"column:region_code;size:32;default:''"`
	QueueName      string     `gorm:"column:queue_name;size:128;default:''"`
	Transport      string     `gorm:"column:transport;size:16;default:local"` // local | mqtt
	Host           string     `gorm:"column:host;size:128;default:''"`
	PublicIP       *string    `gorm:"column:public_ip;size:64"`
	Status         string     `gorm:"column:status;size:16;default:offline"` // online | offline | maintenance
	CapabilitiesTx string     `gorm:"column:capabilities_text;default:'[]'"`
	LastHeartbeat  *time.Time `gorm:"column:last_heartbeat"`
	IsDefault      bool       `gorm:"column:is_default;default:false"`
	IsSchedulable  bool       `gorm:"column:is_schedulable;default:true"`
	AgentRef       string     `gorm:"column:agent_ref;size:64;default:''"`
	BrokerClientID string     `gorm:"column:broker_client_id;size:128;default:''"`
	CreateTime     time.Time  `gorm:"column:create_time;autoCreateTime"`
	UpdateTime     time.Time  `gorm:"column:update_time;autoUpdateTime"`
}

func (Node) TableName() string { return "netprobe_nodes" }

type Task struct {
	ID             uint64     `gorm:"column:id;primaryKey;autoIncrement"`
	TaskNo         string     `gorm:"column:task_no;size:36;uniqueIndex"`
	Mode           string     `gorm:"column:mode;size:16"` // once | schedule
	Protocol       string     `gorm:"column:protocol;size:16"`
	Target         string     `gorm:"column:target;size:255"`
	TargetDisplay  string     `gorm:"column:target_display;size:255;default:''"`
	RegionCodesTx  string     `gorm:"column:region_codes_text;default:'[]'"`
	OptionsTx      string     `gorm:"column:options_text;default:'{}'"`
	ScheduleCron   string     `gorm:"column:schedule_cron;size:64;default:''"`
	IsEnabled      bool       `gorm:"column:is_enabled;default:true"`
	Status         string     `gorm:"column:status;size:16;default:pending"`
	CreatedByID    *uint64    `gorm:"column:created_by_id"`
	ClientIP       string     `gorm:"column:client_ip;size:64;default:''"`
	Source         string     `gorm:"column:source;size:16;default:public"` // public | user
	LastRunAt      *time.Time `gorm:"column:last_run_at"`
	NextRunAt      *time.Time `gorm:"column:next_run_at"`
	SchedulerRef   string     `gorm:"column:scheduler_ref;size:128;default:''"`
	CreateTime     time.Time  `gorm:"column:create_time;autoCreateTime"`
	UpdateTime     time.Time  `gorm:"column:update_time;autoUpdateTime"`
}

func (Task) TableName() string { return "netprobe_tasks" }

type Execution struct {
	ID                 uint64     `gorm:"column:id;primaryKey;autoIncrement"`
	ExecutionNo        string     `gorm:"column:execution_no;size:36;uniqueIndex"`
	TaskID             uint64     `gorm:"column:task_id;index"`
	TriggerType        string     `gorm:"column:trigger_type;size:16;default:manual"`
	Status             string     `gorm:"column:status;size:16;default:pending"`
	PlannedAt          *time.Time `gorm:"column:planned_at"`
	StartedAt          *time.Time `gorm:"column:started_at"`
	FinishedAt         *time.Time `gorm:"column:finished_at"`
	SuccessRegionCount int        `gorm:"column:success_region_count;default:0"`
	TotalRegionCount   int        `gorm:"column:total_region_count;default:0"`
	AvailabilityRatio  float64    `gorm:"column:availability_ratio;default:0"`
	SummaryMessage     string     `gorm:"column:summary_message;size:255;default:''"`
	CreateTime         time.Time  `gorm:"column:create_time;autoCreateTime"`
	UpdateTime         time.Time  `gorm:"column:update_time;autoUpdateTime"`
}

func (Execution) TableName() string { return "netprobe_executions" }

// ExecutionRegion 将原版 region/node 外键快照为冗余列,读路径无需 join。
type ExecutionRegion struct {
	ID            uint64     `gorm:"column:id;primaryKey;autoIncrement"`
	ExecutionID   uint64     `gorm:"column:execution_id;index"`
	RegionCode    string     `gorm:"column:region_code;size:32"`
	RegionName    string     `gorm:"column:region_name;size:64"`
	MapLng        float64    `gorm:"column:map_lng"`
	MapLat        float64    `gorm:"column:map_lat"`
	NodeCode      string     `gorm:"column:node_code;size:64;default:''"`
	NodeName      string     `gorm:"column:node_name;size:64;default:''"`
	NodeTransport string     `gorm:"column:node_transport;size:16;default:''"`
	Status        string     `gorm:"column:status;size:16;default:pending"` // pending|running|success|failed
	Success       bool       `gorm:"column:success;default:false"`
	ResolvedTarget string    `gorm:"column:resolved_target;size:1024;default:''"`
	LatencyMs     *float64   `gorm:"column:latency_ms"`
	StartedAt     *time.Time `gorm:"column:started_at"`
	FinishedAt    *time.Time `gorm:"column:finished_at"`
	ErrorCode     string     `gorm:"column:error_code;size:64;default:''"`
	ErrorMessage  string     `gorm:"column:error_message;size:255;default:''"`
	RawPayloadTx  string     `gorm:"column:raw_payload_text;default:'{}'"`
	CreateTime    time.Time  `gorm:"column:create_time;autoCreateTime"`
	UpdateTime    time.Time  `gorm:"column:update_time;autoUpdateTime"`
}

func (ExecutionRegion) TableName() string { return "netprobe_execution_regions" }

// ProbeResult 合并原版五张协议结果表(netprobe_http_result 等),
// 协议专属明细以 JSON 文本存储,对外契约由序列化层重建。
type ProbeResult struct {
	ID                uint64    `gorm:"column:id;primaryKey;autoIncrement"`
	ExecutionRegionID uint64    `gorm:"column:execution_region_id;uniqueIndex:uq_probe_result"`
	Protocol          string    `gorm:"column:protocol;size:16;uniqueIndex:uq_probe_result"`
	DetailTx          string    `gorm:"column:detail_text"`
	CreateTime        time.Time `gorm:"column:create_time;autoCreateTime"`
	UpdateTime        time.Time `gorm:"column:update_time;autoUpdateTime"`
}

func (ProbeResult) TableName() string { return "netprobe_probe_results" }

// ---------- 常量 ----------

const (
	TaskModeOnce     = "once"
	TaskModeSchedule = "schedule"

	TaskStatusPending = "pending"
	TaskStatusRunning = "running"
	TaskStatusSuccess = "success"
	TaskStatusPartial = "partial"
	TaskStatusFailed  = "failed"
	TaskStatusDisabled = "disabled"

	ExecStatusPending = "pending"
	ExecStatusRunning = "running"
	ExecStatusSuccess = "success"
	ExecStatusPartial = "partial"
	ExecStatusFailed  = "failed"

	RegionStatusPending = "pending"
	RegionStatusRunning = "running"
	RegionStatusSuccess = "success"
	RegionStatusFailed  = "failed"

	TriggerManual   = "manual"
	TriggerSchedule = "schedule"
	TriggerRetry    = "retry"

	NodeTransportLocal = "local"
	NodeTransportMQTT  = "mqtt"

	ProtocolHTTP       = "http"
	ProtocolPing       = "ping"
	ProtocolDNS        = "dns"
	ProtocolMTR        = "mtr"
	ProtocolTraceroute = "traceroute"
)
