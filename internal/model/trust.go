package model

import "time"

// dnsrisk 可信库(Phase 6,对照原 dnsrisk/models.py 与方案 6.2)。
// 说明:原版主机"角色"(apex/ns_host)通过 notes 约定表达,保持一致。

type TrustDomain struct {
	ID          uint64    `gorm:"column:id;primaryKey;autoIncrement"`
	Domain      string    `gorm:"column:domain;size:255"`
	Owner       string    `gorm:"column:owner;size:128;default:''"`
	Importance  string    `gorm:"column:importance;size:16;default:high"` // critical|high|medium
	Enabled     bool      `gorm:"column:enabled;default:true"`
	Environment string    `gorm:"column:environment;size:16;default:prod"` // prod|lab
	Notes       string    `gorm:"column:notes"`
	CreateTime  time.Time `gorm:"column:create_time;autoCreateTime"`
	UpdateTime  time.Time `gorm:"column:update_time;autoUpdateTime"`
}

func (TrustDomain) TableName() string { return "dns_trust_domains" }

type TrustHost struct {
	ID              uint64    `gorm:"column:id;primaryKey;autoIncrement"`
	DomainID        uint64    `gorm:"column:domain_id;uniqueIndex:uq_host_fqdn"`
	FQDN            string    `gorm:"column:fqdn;size:255;uniqueIndex:uq_host_fqdn"`
	BaselineSource  string    `gorm:"column:baseline_source;size:16;default:manual"`   // manual|lab_seed
	BaselineStatus  string    `gorm:"column:baseline_status;size:16;default:trusted"`   // trusted|draft
	AllowWildcard   bool      `gorm:"column:allow_wildcard;default:false"`
	AllowAXFR       bool      `gorm:"column:allow_axfr;default:false"`
	AllowRebind     bool      `gorm:"column:allow_rebind;default:false"`
	DNSSECExpected  bool      `gorm:"column:dnssec_expected;default:false"`
	Enabled         bool      `gorm:"column:enabled;default:true"`
	Notes           string    `gorm:"column:notes"`
	CreateTime      time.Time `gorm:"column:create_time;autoCreateTime"`
	UpdateTime      time.Time `gorm:"column:update_time;autoUpdateTime"`
}

func (TrustHost) TableName() string { return "dns_trust_hosts" }

type TrustRecordBaseline struct {
	ID         uint64    `gorm:"column:id;primaryKey;autoIncrement"`
	HostID     uint64    `gorm:"column:host_id;uniqueIndex:uq_baseline_rr"`
	Section    string    `gorm:"column:section;size:16"` // answer|authority|additional
	RRName     string    `gorm:"column:rrname;size:255"`
	RRType     string    `gorm:"column:rrtype;size:16"`
	RRValue    string    `gorm:"column:rrvalue;size:1024"`
	RRHash     string    `gorm:"column:rr_hash;size:64;uniqueIndex:uq_baseline_rr"`
	TTLMin     *int      `gorm:"column:ttl_min"`
	TTLMax     *int      `gorm:"column:ttl_max"`
	IsRequired bool      `gorm:"column:is_required;default:true"`
	CreateTime time.Time `gorm:"column:create_time;autoCreateTime"`
}

func (TrustRecordBaseline) TableName() string { return "dns_trust_record_baselines" }

type TrustCandidateBatch struct {
	ID             uint64     `gorm:"column:id;primaryKey;autoIncrement"`
	SourceType     string     `gorm:"column:source_type;size:32"` // manifest_import|candidate_discovery|lab_seed
	SourceLabel    string     `gorm:"column:source_label;size:128;default:''"`
	Environment    string     `gorm:"column:environment;size:16;default:prod"`
	Status         string     `gorm:"column:status;size:16;default:draft"` // draft|approved|rejected
	RequestedByID  *uint64    `gorm:"column:requested_by_id"`
	ApprovedByID   *uint64    `gorm:"column:approved_by_id"`
	ApprovedAt     *time.Time `gorm:"column:approved_at"`
	SummaryMessage string     `gorm:"column:summary_message;size:255;default:''"`
	ManifestText   string     `gorm:"column:manifest_text"`
	MetaText       string     `gorm:"column:meta_text"`
	CreateTime     time.Time  `gorm:"column:create_time;autoCreateTime"`
	UpdateTime     time.Time  `gorm:"column:update_time;autoUpdateTime"`
}

func (TrustCandidateBatch) TableName() string { return "dns_trust_candidate_batches" }

type TrustCandidateRecord struct {
	ID          uint64     `gorm:"column:id;primaryKey;autoIncrement"`
	BatchID     uint64     `gorm:"column:batch_id;index"`
	HostID      uint64     `gorm:"column:host_id;index"`
	Status      string     `gorm:"column:status;size:16;default:draft"` // draft|approved|rejected
	Section     string     `gorm:"column:section;size:16"`
	RRName      string     `gorm:"column:rrname;size:255"`
	RRType      string     `gorm:"column:rrtype;size:16"`
	RRValue     string     `gorm:"column:rrvalue;size:1024"`
	TTLMin      *int       `gorm:"column:ttl_min"`
	TTLMax      *int       `gorm:"column:ttl_max"`
	IsRequired  bool       `gorm:"column:is_required;default:true"`
	ReviewedBy  *uint64    `gorm:"column:reviewed_by_id"`
	ReviewedAt  *time.Time `gorm:"column:reviewed_at"`
	ReviewNote  string     `gorm:"column:review_note;size:255;default:''"`
	CreateTime  time.Time  `gorm:"column:create_time;autoCreateTime"`
	UpdateTime  time.Time  `gorm:"column:update_time;autoUpdateTime"`
}

func (TrustCandidateRecord) TableName() string { return "dns_trust_candidate_records" }

type TrustBuildJob struct {
	ID                 uint64     `gorm:"column:id;primaryKey;autoIncrement"`
	Environment        string     `gorm:"column:environment;size:16;default:prod"`
	Status             string     `gorm:"column:status;size:16;default:pending"` // pending|running|completed|failed
	RequestedByID      *uint64    `gorm:"column:requested_by_id"`
	RetryOfID          *uint64    `gorm:"column:retry_of_id"`
	InputPath          string     `gorm:"column:input_path;size:512"`
	SourceLabel        string     `gorm:"column:source_label;size:128;default:''"`
	ResolverIP         string     `gorm:"column:resolver_ip;size:64;default:'223.5.5.5'"`
	TimeoutSeconds     float64    `gorm:"column:timeout_seconds;default:2"`
	ChunkSize          int        `gorm:"column:chunk_size;default:300"`
	MaxHostsPerDomain  int        `gorm:"column:max_hosts_per_domain;default:3"`
	LimitCount         *int       `gorm:"column:limit_count"`
	ImportOnly         bool       `gorm:"column:import_only;default:false"`
	AutoApprove        bool       `gorm:"column:auto_approve;default:true"`
	TotalInputHosts    int        `gorm:"column:total_input_hosts;default:0"`
	TotalDomains       int        `gorm:"column:total_domains;default:0"`
	TotalChunks        int        `gorm:"column:total_chunks;default:0"`
	ProcessedChunks    int        `gorm:"column:processed_chunks;default:0"`
	ImportedDomains    int        `gorm:"column:imported_domains;default:0"`
	ImportedHosts      int        `gorm:"column:imported_hosts;default:0"`
	DiscoveredHosts    int        `gorm:"column:discovered_hosts;default:0"`
	CandidateRecords   int        `gorm:"column:candidate_records;default:0"`
	ApprovedHosts      int        `gorm:"column:approved_hosts;default:0"`
	TrustedHosts       int        `gorm:"column:trusted_hosts;default:0"`
	DraftHosts         int        `gorm:"column:draft_hosts;default:0"`
	CurrentChunk       int        `gorm:"column:current_chunk;default:0"`
	StartedAt          *time.Time `gorm:"column:started_at"`
	FinishedAt         *time.Time `gorm:"column:finished_at"`
	SummaryMessage     string     `gorm:"column:summary_message;size:255;default:''"`
	LastError          string     `gorm:"column:last_error;size:512;default:''"`
	WorkerTaskID       string     `gorm:"column:worker_task_id;size:64;default:''"`
	CreateTime         time.Time  `gorm:"column:create_time;autoCreateTime"`
	UpdateTime         time.Time  `gorm:"column:update_time;autoUpdateTime"`
}

func (TrustBuildJob) TableName() string { return "dns_trust_build_jobs" }

const (
	TrustEnvProd = "prod"
	TrustEnvLab  = "lab"

	TrustImportanceCritical = "critical"
	TrustImportanceHigh     = "high"
	TrustImportanceMedium   = "medium"

	TrustSourceManual  = "manual"
	TrustSourceLabSeed = "lab_seed"

	TrustStatusTrusted = "trusted"
	TrustStatusDraft   = "draft"

	BatchSourceManifest  = "manifest_import"
	BatchSourceDiscovery = "candidate_discovery"
	BatchSourceLab       = "lab_seed"

	BatchStatusDraft    = "draft"
	BatchStatusApproved = "approved"
	BatchStatusRejected = "rejected"

	CandidateStatusDraft    = "draft"
	CandidateStatusApproved = "approved"
	CandidateStatusRejected = "rejected"

	BuildStatusPending   = "pending"
	BuildStatusRunning   = "running"
	BuildStatusCompleted = "completed"
	BuildStatusFailed    = "failed"
)
