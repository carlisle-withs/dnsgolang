package model

import "time"

// 扫描器与观测(Phase 7,方案 6.2)

type ScanMonitorProfile struct {
	ID                    uint64     `gorm:"column:id;primaryKey;autoIncrement"`
	Name                  string     `gorm:"column:name;size:128"`
	Environment           string     `gorm:"column:environment;size:16;default:prod"`
	Enabled               bool       `gorm:"column:enabled;default:true"`
	IntervalSeconds       int        `gorm:"column:interval_seconds;default:60"`
	TargetDetectionSeconds int       `gorm:"column:target_detection_seconds;default:120"`
	ResolverIP            string     `gorm:"column:resolver_ip;size:64;default:'223.5.5.5'"`
	ResolverPoolTx        string     `gorm:"column:resolver_pool_text"`
	TimeoutSeconds        float64    `gorm:"column:timeout_seconds;default:3"`
	Concurrency           int        `gorm:"column:concurrency;default:8"`
	Keyword               string     `gorm:"column:keyword;size:255;default:''"`
	LimitCount            *int       `gorm:"column:limit_count"`
	DomainIDsTx           string     `gorm:"column:domain_ids_text"`
	HostIDsTx             string     `gorm:"column:host_ids_text"`
	LastRunAt             *time.Time `gorm:"column:last_run_at"`
	LastStatus            string     `gorm:"column:last_status;size:32;default:''"`
	CreatedByID           *uint64    `gorm:"column:created_by_id"`
	CreateTime            time.Time  `gorm:"column:create_time;autoCreateTime"`
	UpdateTime            time.Time  `gorm:"column:update_time;autoUpdateTime"`
}

func (ScanMonitorProfile) TableName() string { return "dns_ownership_monitor_profiles" }

type ScanJob struct {
	ID              uint64     `gorm:"column:id;primaryKey;autoIncrement"`
	Environment     string     `gorm:"column:environment;size:16;default:prod"`
	Status          string     `gorm:"column:status;size:16;default:pending"`
	RequestedByID   *uint64    `gorm:"column:requested_by_id"`
	ResolverIP      string     `gorm:"column:resolver_ip;size:64;default:'223.5.5.5'"`
	ResolverPoolTx  string     `gorm:"column:resolver_pool_text"`
	TimeoutSeconds  float64    `gorm:"column:timeout_seconds;default:3"`
	Concurrency     int        `gorm:"column:concurrency;default:8"`
	Keyword         string     `gorm:"column:keyword;size:255;default:''"`
	LimitCount      *int       `gorm:"column:limit_count"`
	DomainIDsTx     string     `gorm:"column:domain_ids_text"`
	HostIDsTx       string     `gorm:"column:host_ids_text"`
	TotalDomains    int        `gorm:"column:total_domains;default:0"`
	TotalHosts      int        `gorm:"column:total_hosts;default:0"`
	ProcessedHosts  int        `gorm:"column:processed_hosts;default:0"`
	SuccessHosts    int        `gorm:"column:success_hosts;default:0"`
	SuspiciousHosts int        `gorm:"column:suspicious_hosts;default:0"`
	ErrorHosts      int        `gorm:"column:error_hosts;default:0"`
	AvgLatencyMs    *float64   `gorm:"column:avg_latency_ms"`
	SummaryTx       string     `gorm:"column:summary_text"`
	FiltersTx       string     `gorm:"column:filters_text"`
	SummaryMessage  string     `gorm:"column:summary_message;size:255;default:''"`
	LastError       string     `gorm:"column:last_error;size:512;default:''"`
	StartedAt       *time.Time `gorm:"column:started_at"`
	FinishedAt      *time.Time `gorm:"column:finished_at"`
	CreateTime      time.Time  `gorm:"column:create_time;autoCreateTime"`
	UpdateTime      time.Time  `gorm:"column:update_time;autoUpdateTime"`
}

func (ScanJob) TableName() string { return "dns_batch_scan_jobs" }

const (
	ScanStatusPending   = "pending"
	ScanStatusRunning   = "running"
	ScanStatusCompleted = "completed"
	ScanStatusFailed    = "failed"

	ResultStatusNormal     = "normal"
	ResultStatusSuspicious = "suspicious"
	ResultStatusError      = "error"
)

type ScanResult struct {
	ID                 uint64     `gorm:"column:id;primaryKey;autoIncrement"`
	ScanJobID          uint64     `gorm:"column:scan_job_id;index"`
	DomainID           *uint64    `gorm:"column:domain_id"`
	HostID             uint64     `gorm:"column:host_id"`
	SnapshotID         *uint64    `gorm:"column:snapshot_id"`
	Status             string     `gorm:"column:status;size:16;default:normal"`
	Severity           string     `gorm:"column:severity;size:16;default:''"`
	ConfidenceTier     string     `gorm:"column:confidence_tier;size:32;default:''"`
	ConfidenceLabelsTx string     `gorm:"column:confidence_labels_text"`
	SuspiciousCount    int        `gorm:"column:suspicious_count;default:0"`
	SummaryMessage     string     `gorm:"column:summary_message;size:512;default:''"`
	RCODE              string     `gorm:"column:rcode;size:32;default:''"`
	ErrorKind          string     `gorm:"column:error_kind;size:32;default:''"`
	LatencyMs          *float64   `gorm:"column:latency_ms"`
	RiskTypesTx        string     `gorm:"column:risk_types_text"`
	EvidenceTx         string     `gorm:"column:evidence_text"`
	DetectedAt         *time.Time `gorm:"column:detected_at"`
	CreateTime         time.Time  `gorm:"column:create_time;autoCreateTime"`
}

func (ScanResult) TableName() string { return "dns_batch_scan_results" }

type RiskVerdictLatest struct {
	ID             uint64     `gorm:"column:id;primaryKey;autoIncrement"`
	HostID         uint64     `gorm:"column:host_id;uniqueIndex:uq_verdict"`
	RiskType       string     `gorm:"column:risk_type;size:32;uniqueIndex:uq_verdict"`
	Status         string     `gorm:"column:status;size:16;default:normal"`
	Severity       string     `gorm:"column:severity;size:16;default:''"`
	ConfidenceTier string     `gorm:"column:confidence_tier;size:32;default:''"`
	MethodCode     string     `gorm:"column:method_code;size:64;default:''"`
	SummaryMessage string     `gorm:"column:summary_message;size:512;default:''"`
	EvidenceTx     string     `gorm:"column:evidence_text"`
	DetectedAt     *time.Time `gorm:"column:detected_at"`
	UpdateTime     time.Time  `gorm:"column:update_time;autoUpdateTime"`
}

func (RiskVerdictLatest) TableName() string { return "dns_risk_verdict_latest" }

type ObservationSnapshot struct {
	ID               uint64     `gorm:"column:id;primaryKey;autoIncrement"`
	HostID           uint64     `gorm:"column:host_id;index"`
	ScanJobID        *uint64    `gorm:"column:scan_job_id"`
	ResolverIP       string     `gorm:"column:resolver_ip;size:64;default:''"`
	RCODE            string     `gorm:"column:rcode;size:32;default:''"`
	ErrorKind        string     `gorm:"column:error_kind;size:32;default:''"`
	LatencyMs        *float64   `gorm:"column:latency_ms"`
	NSNameListTx     string     `gorm:"column:ns_name_list_text"`
	NSGlueIPListTx   string     `gorm:"column:ns_glue_ip_list_text"`
	UniqueIPSetTx    string     `gorm:"column:unique_ip_set_text"`
	SOAMname         string     `gorm:"column:soa_mname;size:255;default:''"`
	SOASerial        string     `gorm:"column:soa_serial;size:64;default:''"`
	WildcardHit      bool       `gorm:"column:wildcard_hit;default:false"`
	AXFRSuccess      bool       `gorm:"column:axfr_success;default:false"`
	AXFRRecordCount  int        `gorm:"column:axfr_record_count;default:0"`
	AXFRZoneHash     string     `gorm:"column:axfr_zone_hash;size:64;default:''"`
	RandomLabel      string     `gorm:"column:random_label;size:64;default:''"`
	QueryPlanTx      string     `gorm:"column:query_plan_text"`
	RawOutputTx      string     `gorm:"column:raw_output_text"`
	ObservedAt       *time.Time `gorm:"column:observed_at"`
	CreateTime       time.Time  `gorm:"column:create_time;autoCreateTime"`
}

func (ObservationSnapshot) TableName() string { return "dns_observation_snapshots" }

type ObservationRecord struct {
	ID         uint64    `gorm:"column:id;primaryKey;autoIncrement"`
	SnapshotID uint64    `gorm:"column:snapshot_id;index"`
	Section    string    `gorm:"column:section;size:16;default:answer"`
	RRName     string    `gorm:"column:rrname;size:255;default:''"`
	RRType     string    `gorm:"column:rrtype;size:16;default:''"`
	RRValue    string    `gorm:"column:rrvalue;size:1024;default:''"`
	TTL        *int      `gorm:"column:ttl"`
	CreateTime time.Time `gorm:"column:create_time;autoCreateTime"`
}

func (ObservationRecord) TableName() string { return "dns_observation_records" }

type ObservationMethodEvidence struct {
	ID          uint64    `gorm:"column:id;primaryKey;autoIncrement"`
	SnapshotID  uint64    `gorm:"column:snapshot_id;index"`
	MethodCode  string    `gorm:"column:method_code;size:64;default:''"`
	FindingsTx  string    `gorm:"column:findings_text"`
	CreateTime  time.Time `gorm:"column:create_time;autoCreateTime"`
}

func (ObservationMethodEvidence) TableName() string { return "dns_observation_method_evidence" }
