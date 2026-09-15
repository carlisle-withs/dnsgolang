package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"dnsss/internal/apitime"
	"dnsss/internal/bridge"
	"dnsss/internal/dto"
	"dnsss/internal/engine/prober"
	"dnsss/internal/model"
)

// ---------- 探针注册与管理(Phase 8) ----------

// SetRemotePublisher 注入 MQTT 发布能力(bridge 就绪后调用)。
func (s *Service) SetRemotePublisher(pub bridge.RemotePublisher) { s.remote = pub }

// RegisterProbeAgent 镜像原 ProbeAgentRegisterAPIView(共享 token / mTLS 头鉴权)。
func (s *Service) RegisterProbeAgent(ctx context.Context, body map[string]any, probeTokenHeader, mtlsVerify, mtlsDN, remoteAddr string) (map[string]any, error) {
	agentCode := strAny(body["agent_code"], "")
	if agentCode == "" {
		return nil, dto.NewFieldError("agent_code", "该字段是必填项。")
	}
	// 鉴权:共享 token > mTLS > 拒绝(原版还支持本机 insecure,默认关闭属安全修复)
	authType := ""
	if s.cfg.ProbeToken != "" && probeTokenHeader == s.cfg.ProbeToken {
		authType = "shared_token"
	} else if mtlsVerify == "SUCCESS" {
		authType = "mtls"
	} else {
		return nil, dto.NewAPIError(403, "mTLS 证书校验失败")
	}
	regionCode := strAny(body["region_code"], "")
	if regionCode == "" {
		if defaults, err := s.normalizeRegionCodes(ctx, nil, 1); err == nil && len(defaults) > 0 {
			regionCode = defaults[0]
		}
	} else {
		var count int64
		s.gorm.WithContext(ctx).Model(&model.Region{}).Where("code = ? AND is_active = 1", regionCode).Count(&count)
		if count == 0 {
			return nil, dto.NewFieldError("region_code", "无效地区编码")
		}
	}
	now := time.Now()
	nodeCode := "probe-" + agentCode
	var publicIP *string
	if v := strAny(body["public_ip"], ""); v != "" {
		publicIP = &v
	}
	capabilities := anySlice(body["capabilities"])
	// 节点 upsert(mqtt 传输,归属地区)
	var node model.Node
	s.gorm.WithContext(ctx).
		Where(model.Node{Code: nodeCode}).
		Assign(model.Node{
			RegionCode: regionCode, Name: nodeCode, QueueName: "mqtt:" + agentCode,
			Transport: model.NodeTransportMQTT, Status: "online",
			LastHeartbeat: &now, IsSchedulable: true, AgentRef: agentCode,
			CapabilitiesTx: marshalJSON(capabilities), PublicIP: publicIP,
		}).FirstOrCreate(&node)
	if node.ID == 0 {
		s.gorm.WithContext(ctx).Where(model.Node{Code: nodeCode}).First(&node)
	}
	// agent upsert
	var agent model.ProbeAgent
	s.gorm.WithContext(ctx).
		Where(model.ProbeAgent{AgentCode: agentCode}).
		Assign(model.ProbeAgent{
			RegionCode: regionCode, Version: strAny(body["version"], ""),
			AuthType: authType, State: model.AgentStateOnline,
			CapabilitiesTx: marshalJSON(capabilities), PublicIP: publicIP,
			LastSeenAt: &now,
		}).FirstOrCreate(&agent)
	if agent.ID == 0 {
		s.gorm.WithContext(ctx).Where(model.ProbeAgent{AgentCode: agentCode}).First(&agent)
	}
	brokerHost, brokerPort := s.mqttHostPort()
	wssURL := ""
	if brokerHost != "" {
		wssURL = fmt.Sprintf("ws://%s/mqtt", brokerHost)
	}
	return map[string]any{
		"agentId": agent.ID, "agentCode": agent.AgentCode,
		"regionCode": agent.RegionCode, "state": agent.State,
		"broker": map[string]any{
			"host": brokerHost, "port": brokerPort,
			"username": s.cfg.MQTTUsername, "password": s.cfg.MQTTPassword,
			"wssUrl": wssURL,
		},
		"topics": map[string]string{
			"jobs":    "probe/jobs/" + agentCode,
			"control": "probe/control/" + agentCode,
			"status":  "probe/status/" + agentCode,
			"results": "probe/results/" + agentCode + "/+",
			"events":  "probe/events/" + agentCode,
		},
	}, nil
}

func (s *Service) mqttHostPort() (string, int) {
	broker := s.cfg.MQTTBroker
	if broker == "" {
		return "", 0
	}
	// tcp://host:port 或 ws://host:port/path
	rest := broker
	for _, prefix := range []string{"tcp://", "ws://", "ssl://", "wss://"} {
		if len(rest) > len(prefix) && rest[:len(prefix)] == prefix {
			rest = rest[len(prefix):]
			break
		}
	}
	host := rest
	port := 1883
	for i := len(rest) - 1; i >= 0; i-- {
		if rest[i] == ':' {
			host = rest[:i]
			p := 0
			if _, err := fmt.Sscanf(rest[i+1:], "%d", &p); err == nil {
				port = p
			}
			break
		}
		if rest[i] == '/' {
			break
		}
	}
	return host, port
}

// AgentPayload 探针管理页条目。
func (s *Service) AgentPayload(ctx context.Context, agent model.ProbeAgent) map[string]any {
	var capabilities []string
	_ = json.Unmarshal([]byte(agent.CapabilitiesTx), &capabilities)
	if capabilities == nil {
		capabilities = []string{}
	}
	var node model.Node
	nodeCode, nodeName := "", ""
	s.gorm.WithContext(ctx).Where("agent_ref = ?", agent.AgentCode).First(&node)
	if node.ID != 0 {
		nodeCode, nodeName = node.Code, node.Name
	}
	return map[string]any{
		"id": agent.ID, "agentCode": agent.AgentCode, "regionCode": agent.RegionCode,
		"state": agent.State, "enabled": agent.Enabled, "version": agent.Version,
		"capabilities": capabilities, "publicIp": agent.PublicIP,
		"lastSeenAt": apitimeFromPtr(agent.LastSeenAt),
		"nodeCode": nodeCode, "nodeName": nodeName,
		"create_time": apitime.From(agent.CreateTime), "update_time": apitime.From(agent.UpdateTime),
	}
}

func (s *Service) ListAgents(ctx context.Context) []map[string]any {
	var agents []model.ProbeAgent
	s.gorm.WithContext(ctx).Order("agent_code ASC").Find(&agents)
	out := make([]map[string]any, 0, len(agents))
	for _, agent := range agents {
		out = append(out, s.AgentPayload(ctx, agent))
	}
	return out
}

// AgentPayloadByID 按 ID 取探针载荷。
func (s *Service) AgentPayloadByID(ctx context.Context, agentID uint64) (map[string]any, error) {
	var agent model.ProbeAgent
	if err := s.gorm.WithContext(ctx).First(&agent, agentID).Error; err != nil {
		return nil, dto.NewAPIError(400, "探针不存在")
	}
	return s.AgentPayload(ctx, agent), nil
}

func (s *Service) UpdateAgent(ctx context.Context, agentID uint64, body map[string]any) (map[string]any, error) {
	var agent model.ProbeAgent
	if err := s.gorm.WithContext(ctx).First(&agent, agentID).Error; err != nil {
		return nil, dto.NewAPIError(400, "探针不存在")
	}
	updates := map[string]any{}
	if enabled, ok := body["is_enabled"].(bool); ok {
		updates["enabled"] = enabled
		if !enabled {
			updates["state"] = model.AgentStateDisabled
		} else {
			updates["state"] = model.AgentStateOnline
		}
		s.gorm.WithContext(ctx).Exec(
			"UPDATE netprobe_nodes SET status = ? WHERE agent_ref = ?",
			map[bool]string{true: "online", false: "offline"}[enabled], agent.AgentCode)
	}
	if regionCode, ok := body["region_code"].(string); ok && regionCode != "" {
		updates["region_code"] = regionCode
		s.gorm.WithContext(ctx).Exec("UPDATE netprobe_nodes SET region_code = ? WHERE agent_ref = ?", regionCode, agent.AgentCode)
	}
	if len(updates) > 0 {
		s.gorm.WithContext(ctx).Model(&agent).Updates(updates)
	}
	s.gorm.WithContext(ctx).First(&agent, agentID)
	return s.AgentPayload(ctx, agent), nil
}

// ---------- 远程派发 ----------

// agentOnlineByNode 查节点对应探针是否在线可用。
func (s *Service) agentOnlineByNode(ctx context.Context, agentRef string) *model.ProbeAgent {
	if agentRef == "" {
		return nil
	}
	var agent model.ProbeAgent
	if err := s.gorm.WithContext(ctx).
		Where("agent_code = ? AND enabled = 1 AND state IN ('online','busy')", agentRef).
		First(&agent).Error; err != nil {
		return nil
	}
	if agent.LastSeenAt != nil && time.Since(*agent.LastSeenAt) > 5*time.Minute {
		return nil
	}
	return &agent
}

// dispatchSingleToAgent 创建 ProbeJob 并发布到 MQTT(失败回退 agent_unavailable)。
// nodeCode → node.agent_ref → agent(节点编码与探针编码不同:probe-<code> vs <code>)。
func (s *Service) dispatchSingleToAgent(ctx context.Context, row *model.ExecutionRegion, task *model.Task) bool {
	var node model.Node
	if err := s.gorm.WithContext(ctx).Where("code = ?", row.NodeCode).First(&node).Error; err != nil {
		slog.Warn("远程派发失败:节点查询", "node", row.NodeCode, "error", err)
		return false
	}
	agent := s.agentOnlineByNode(ctx, node.AgentRef)
	if agent == nil {
		slog.Warn("远程派发失败:探针不在线", "node", row.NodeCode, "agentRef", node.AgentRef)
		return false
	}
	var options map[string]any
	_ = jsonUnmarshalDefault(task.OptionsTx, &options)
	if options == nil {
		options = map[string]any{}
	}
	deadline := time.Now().Add(time.Duration(s.cfg.ProbeLeaseSeconds) * time.Second)
	job := &model.ProbeJob{
		JobNo:             "prjob-" + randHex(25),
		AgentID:           agent.ID, JobKind: "single",
		ExecutionRegionID: &row.ID, TotalSteps: 1,
		Status: model.ProbeJobQueued,
		PayloadTx: "", LeaseUntil: &deadline, DeadlineAt: &deadline,
	}
	payload := bridge.JobPayload{
		JobID: 0, Steps: []bridge.JobStepPayload{{
			StepID: 1, Protocol: task.Protocol, Target: task.Target, Options: options,
		}},
		DeadlineAt: deadline.Format(time.RFC3339), CreatedAt: time.Now().Format(time.RFC3339),
	}
	job.PayloadTx = marshalJSON(payload)
	if err := s.gorm.WithContext(ctx).Create(job).Error; err != nil {
		slog.Warn("远程派发失败:任务创建", "error", err)
		return false
	}
	payload.JobID = int(job.ID)
	job.PayloadTx = marshalJSON(payload)
	s.gorm.WithContext(ctx).Model(job).Update("payload_text", job.PayloadTx)
	step := model.ProbeJobStep{
		ProbeJobID: job.ID, StepIndex: 1, Protocol: task.Protocol,
		Target: task.Target, OptionsTx: marshalJSON(options), Status: model.RegionStatusPending,
	}
	s.gorm.WithContext(ctx).Create(&step)
	if s.remote == nil {
		return false
	}
	if err := s.remote.PublishJob(agent.AgentCode, payload); err != nil {
		slog.Warn("探针任务发布失败", "job", job.ID, "error", err)
		return false
	}
	now := time.Now()
	s.gorm.WithContext(ctx).Model(job).Updates(map[string]any{
		"status": model.ProbeJobPublished, "published_at": now,
	})
	return true
}

func boolToStr(b bool, t, f string) string {
	if b {
		return t
	}
	return f
}

// ApplyProbeJobResult 实现 bridge.Applier:结果回填 → 地区行/批量结果 → 汇总刷新。
func (s *Service) ApplyProbeJobResult(ctx context.Context, jobID uint64, agentCode string, result bridge.ResultPayload) error {
	var job model.ProbeJob
	if err := s.gorm.WithContext(ctx).First(&job, jobID).Error; err != nil {
		return err
	}
	if job.Status == model.ProbeJobCompleted || job.Status == model.ProbeJobCancelled {
		return nil // 幂等(QoS1 可能重复投递)
	}
	now := time.Now()
	s.gorm.WithContext(ctx).Model(&job).Updates(map[string]any{
		"status": model.ProbeJobCompleted, "finished_at": now,
		"summary_text": marshalJSON(map[string]any{
			"status": result.Status, "agentCode": result.AgentCode,
			"startedAt": result.StartedAt, "finishedAt": result.FinishedAt,
		}),
	})
	var steps []model.ProbeJobStep
	s.gorm.WithContext(ctx).Where("probe_job_id = ?", job.ID).Order("step_index ASC").Find(&steps)

	for i, stepResult := range result.Steps {
		detail := map[string]any{}
		for k, v := range stepResult.Detail {
			detail[k] = v
		}
		probeResult := prober.Result{
			Success: stepResult.Success,
			Status:  boolToStr(stepResult.Success, "success", "failed"),
			LatencyMs: stepResult.LatencyMs,
			ErrorCode: stepResult.ErrorCode, ErrorMessage: stepResult.ErrorMessage,
			Detail: detail, RawPayload: map[string]any{},
		}
		if i < len(steps) {
			s.gorm.WithContext(ctx).Model(&model.ProbeJobStep{}).Where("id = ?", steps[i].ID).Updates(map[string]any{
				"status": boolToStr(stepResult.Success, "success", "failed"),
				"resolved_target": strAny(detail["resolvedTarget"], ""),
				"latency_ms": stepResult.LatencyMs,
				"error_code": stepResult.ErrorCode, "error_message": stepResult.ErrorMessage,
				"detail_text": marshalJSON(detail),
			})
		}
		// 回填地区行(单任务)
		if job.ExecutionRegionID != nil && i == 0 {
			var row model.ExecutionRegion
			if err := s.gorm.WithContext(ctx).First(&row, *job.ExecutionRegionID).Error; err == nil {
				protocol := "dns"
			if i < len(steps) {
				protocol = steps[i].Protocol
			}
			s.persistRegionResult(ctx, &row, protocol, probeResult)
				if err := s.refreshExecutionStatus(ctx, row.ExecutionID); err != nil {
					slog.Warn("执行汇总刷新失败", "execution", row.ExecutionID, "error", err)
				}
			}
		}
		// 回填批量结果(batch job 的步骤与结果行一一对应)
		if job.BatchExecutionID != nil && i < len(steps) {
			s.gorm.WithContext(ctx).Exec(
				"UPDATE netprobe_batch_results SET status = ?, success = ?, resolved_target = ?, latency_ms = COALESCE(?, latency_ms), error_code = ?, error_message = ? WHERE batch_execution_id = ? AND target = ?",
				boolToStr(stepResult.Success, "success", "failed"), stepResult.Success,
				strAny(detail["resolvedTarget"], ""), stepResult.LatencyMs,
				stepResult.ErrorCode, stepResult.ErrorMessage,
				*job.BatchExecutionID, steps[i].Target,
			)
		}
	}
	return nil
}
