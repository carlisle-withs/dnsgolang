// Package bridge 实现 MQTT 探针网关(方案 2.9 协议):
// 发布 probe/jobs/<code>,消费 probe/results/+/+ 与 probe/status/+,
// 租约过期重投(180s,重试上限 3)。
package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	pahomqtt "github.com/eclipse/paho.mqtt.golang"
	"gorm.io/gorm"

	"dnsss/internal/config"
)

// JobStepPayload 下行步骤(方案 2.9)。
type JobStepPayload struct {
	StepID   int           `json:"stepId"`
	Protocol string        `json:"protocol"`
	Target   string        `json:"target"`
	Options  map[string]any `json:"options,omitempty"`
}

// JobPayload 下行任务。
type JobPayload struct {
	JobID      int             `json:"jobId"`
	Steps      []JobStepPayload `json:"steps"`
	DeadlineAt string          `json:"deadlineAt"`
	CreatedAt  string          `json:"createdAt"`
}

// ResultStepPayload 上行步骤结果。
type ResultStepPayload struct {
	StepID       int           `json:"stepId"`
	Success      bool          `json:"success"`
	Detail       map[string]any `json:"detail,omitempty"`
	LatencyMs    *float64      `json:"latencyMs,omitempty"`
	ErrorCode    string        `json:"errorCode"`
	ErrorMessage string        `json:"errorMessage"`
}

// ResultPayload 上行任务结果。
type ResultPayload struct {
	JobID      int                 `json:"jobId"`
	AgentCode  string              `json:"agentCode"`
	Status     string              `json:"status"`
	StartedAt  string              `json:"startedAt"`
	FinishedAt string              `json:"finishedAt"`
	Steps      []ResultStepPayload `json:"steps"`
}

// StatusPayload 上行心跳(LWT offline)。
type StatusPayload struct {
	AgentCode  string `json:"agentCode"`
	State      string `json:"state"`
	ActiveJobs int    `json:"activeJobs"`
	Version    string `json:"version"`
	Ts         string `json:"ts"`
}

// RemotePublisher MQTT 发布能力(service 依赖此接口,避免与 bridge 循环依赖)。
type RemotePublisher interface {
	PublishJob(agentCode string, payload JobPayload) error
}

// Applier 结果回填接口(由 service 实现,避免反向依赖)。
type Applier interface {
	ApplyProbeJobResult(ctx context.Context, jobID uint64, agentCode string, result ResultPayload) error
}

type Bridge struct {
	cfg   *config.Config
	db    *gorm.DB
	applier Applier
	client pahomqtt.Client
}

func New(cfg *config.Config, db *gorm.DB, applier Applier) *Bridge {
	return &Bridge{cfg: cfg, db: db, applier: applier}
}

// Start 连接 broker 并订阅结果/状态主题;返回后即可发布。
func (b *Bridge) Start(ctx context.Context) error {
	if b.cfg.MQTTBroker == "" {
		return fmt.Errorf("DNSSS_MQTT_BROKER 未配置")
	}
	opts := pahomqtt.NewClientOptions().
		AddBroker(b.cfg.MQTTBroker).
		SetClientID("dnsss-bridge-" + fmt.Sprint(time.Now().UnixMilli())).
		SetUsername(b.cfg.MQTTUsername).
		SetPassword(b.cfg.MQTTPassword).
		SetAutoReconnect(true).
		SetConnectRetryInterval(5 * time.Second).
		SetOrderMatters(false)
	opts.OnConnect = func(c pahomqtt.Client) {
		slog.Info("MQTT bridge 已连接", "broker", b.cfg.MQTTBroker)
		token := c.Subscribe("probe/results/+/+", 1, b.onResult)
		token.WaitTimeout(5 * time.Second)
		token = c.Subscribe("probe/status/+", 1, b.onStatus)
		token.WaitTimeout(5 * time.Second)
	}
	opts.DefaultPublishHandler = func(c pahomqtt.Client, m pahomqtt.Message) {}
	b.client = pahomqtt.NewClient(opts)
	token := b.client.Connect()
	token.WaitTimeout(15 * time.Second)
	if !token.WaitTimeout(15 * time.Second) && token.Error() != nil {
		return token.Error()
	}
	go b.requeueLoop(ctx)
	return nil
}

func (b *Bridge) onResult(_ pahomqtt.Client, msg pahomqtt.Message) {
	// topic: probe/results/<agentCode>/<jobId>
	var payload ResultPayload
	if err := json.Unmarshal(msg.Payload(), &payload); err != nil {
		slog.Warn("探针结果解析失败", "topic", msg.Topic(), "error", err)
		return
	}
	if err := b.applier.ApplyProbeJobResult(context.Background(), uint64(payload.JobID), payload.AgentCode, payload); err != nil {
		slog.Warn("探针结果回填失败", "jobId", payload.JobID, "error", err)
	}
}

func (b *Bridge) onStatus(_ pahomqtt.Client, msg pahomqtt.Message) {
	parts := strings.Split(msg.Topic(), "/")
	agentCode := parts[len(parts)-1]
	var payload StatusPayload
	if err := json.Unmarshal(msg.Payload(), &payload); err != nil || payload.AgentCode == "" {
		payload = StatusPayload{AgentCode: agentCode, State: "offline"}
	}
	state := payload.State
	now := time.Now()
	b.db.Exec("UPDATE probe_agents SET state = ?, last_seen_at = ? WHERE agent_code = ?", state, now, agentCode)
	b.db.Exec("UPDATE netprobe_nodes SET status = CASE WHEN ? = 'online' THEN 'online' ELSE 'offline' END, last_heartbeat = ? WHERE agent_ref = ?",
		state, now, agentCode)
}

// PublishJob 发布下行任务(QoS1)。
func (b *Bridge) PublishJob(agentCode string, payload JobPayload) error {
	if b.client == nil || !b.client.IsConnected() {
		return fmt.Errorf("MQTT 未连接")
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	token := b.client.Publish("probe/jobs/"+agentCode, 1, false, data)
	token.WaitTimeout(10 * time.Second)
	return token.Error()
}

// PublishControl 控制指令(reconnect | reload-config)。
func (b *Bridge) PublishControl(agentCode, command string) error {
	data, _ := json.Marshal(map[string]string{"command": command})
	token := b.client.Publish("probe/control/"+agentCode, 1, false, data)
	token.WaitTimeout(10 * time.Second)
	return token.Error()
}

// requeueLoop 租约重投:leased_until < now 且未完成 → 重投(≤3 次)。
func (b *Bridge) requeueLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.RequeueStale(ctx)
		}
	}
}

// RequeueStale 扫描过期租约任务并重投。
func (b *Bridge) RequeueStale(ctx context.Context) int {
	type staleJob struct {
		ID         uint64
		JobNo      string
		AgentID    uint64
		RetryCount int
		PayloadTx  string
	}
	var jobs []staleJob
	b.db.WithContext(ctx).Raw(`
		SELECT j.id, j.job_no, j.agent_id, j.retry_count, j.payload_text
		FROM probe_jobs j JOIN probe_agents a ON a.id = j.agent_id
		WHERE j.status IN ('published', 'leased')
		  AND j.lease_until IS NOT NULL AND j.lease_until < ?
		  AND a.enabled = 1
		LIMIT 50`, time.Now()).Scan(&jobs)
	requeued := 0
	for _, job := range jobs {
		var agent struct{ AgentCode string }
		b.db.Raw("SELECT agent_code FROM probe_agents WHERE id = ?", job.AgentID).Scan(&agent)
		if job.RetryCount >= 3 {
			b.db.Exec("UPDATE probe_jobs SET status = 'failed', last_error = 'lease_expired', finished_at = ? WHERE id = ?", time.Now(), job.ID)
			continue
		}
		var payload JobPayload
		if err := json.Unmarshal([]byte(job.PayloadTx), &payload); err != nil {
			continue
		}
		payload.DeadlineAt = time.Now().Add(time.Duration(b.cfg.ProbeLeaseSeconds) * time.Second).Format(time.RFC3339)
		if err := b.PublishJob(agent.AgentCode, payload); err != nil {
			continue
		}
		b.db.Exec("UPDATE probe_jobs SET retry_count = retry_count + 1, status = 'published', lease_until = ?, published_at = ? WHERE id = ?",
			time.Now().Add(time.Duration(b.cfg.ProbeLeaseSeconds)*time.Second), time.Now(), job.ID)
		requeued++
	}
	if requeued > 0 {
		slog.Info("探针租约重投", "count", requeued)
	}
	return requeued
}
