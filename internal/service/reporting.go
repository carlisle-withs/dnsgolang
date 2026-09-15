package service

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"gorm.io/gorm"

	"dnsss/internal/apitime"
	"dnsss/internal/model"
)

// ---------- meta ----------

type MetaPayload struct {
	Protocols []map[string]any  `json:"protocols"`
	Regions   []map[string]any  `json:"regions"`
	Nodes     []map[string]any  `json:"nodes"`
	Defaults  map[string]any    `json:"defaults"`
	Batch     map[string]any    `json:"batch"`
	ProbeControl map[string]any `json:"probeControl"`
}

var defaultProtocolOptions = map[string]map[string]any{
	"http":       {"method": "GET", "timeout": 10, "follow_redirects": true, "verify_tls": true},
	"ping":       {"count": 4, "timeout": 2},
	"dns":        {"resolver": "8.8.8.8", "record_type": "A", "timeout": 3, "transport": "udp", "server_mode": "resolver", "repeat_count": 1, "edns": true, "dnssec": false, "random_label": false, "compare_with_trust": false},
	"mtr":        {"max_hops": 20, "query_count": 3, "timeout": 2, "numeric": true},
	"traceroute": {"max_hops": 20, "query_count": 3, "timeout": 2, "numeric": true},
}

func (s *Service) BuildMeta(ctx context.Context) (*MetaPayload, error) {
	var regions []model.Region
	if err := s.gorm.WithContext(ctx).Where("is_active = ?", true).Order("display_order ASC, id ASC").Find(&regions).Error; err != nil {
		return nil, err
	}
	var nodes []model.Node
	if err := s.gorm.WithContext(ctx).Order("is_default DESC, code ASC").Find(&nodes).Error; err != nil {
		return nil, err
	}
	nodesByRegion := map[string][]model.Node{}
	for _, n := range nodes {
		nodesByRegion[n.RegionCode] = append(nodesByRegion[n.RegionCode], n)
	}

	regionPayloads := make([]map[string]any, 0, len(regions))
	for _, r := range regions {
		pool := schedulableOf(nodesByRegion[r.Code])
		online := 0
		onlineRemote := 0
		names := make([]string, 0, len(pool))
		for _, n := range pool {
			names = append(names, n.Name)
			if nodeOnline(n, nowRef()) {
				online++
				if n.Transport != model.NodeTransportLocal {
					onlineRemote++
				}
			}
		}
		poolStatus := "offline"
		if online > 0 {
			poolStatus = "online"
		} else if len(pool) > 0 {
			poolStatus = "idle"
		}
		summary := "无可调度探针"
		if len(pool) > 0 {
			summary = itoa(online) + "/" + itoa(len(pool)) + " 在线"
		}
		regionPayloads = append(regionPayloads, map[string]any{
			"code": r.Code, "name": r.Name,
			"mapLng": r.MapLng, "mapLat": r.MapLat,
			"probeCount": len(pool), "onlineProbeCount": online,
			"onlineRemoteProbeCount": onlineRemote,
			"poolStatus": poolStatus, "probeSummary": summary,
			"probeNames": names,
		})
	}

	nodePayloads := make([]map[string]any, 0, len(nodes))
	for _, n := range nodes {
		var capabilities []string
		_ = jsonUnmarshalDefault(n.CapabilitiesTx, &capabilities)
		if capabilities == nil {
			capabilities = []string{}
		}
		nodePayloads = append(nodePayloads, map[string]any{
			"code": n.Code, "name": n.Name, "regionCode": n.RegionCode,
			"status": n.Status, "isDefault": n.IsDefault, "transport": n.Transport,
			"isSchedulable": n.IsSchedulable, "queueName": n.QueueName,
			"agentRef": n.AgentRef, "brokerClientId": n.BrokerClientID,
			"lastHeartbeat": apitimeFromPtr(n.LastHeartbeat),
			"capabilities": capabilities,
		})
	}

	defaultRegions, _ := s.normalizeRegionCodes(ctx, nil, 1)
	defaults := map[string]any{
		"protocol": model.ProtocolHTTP,
		"regions": defaultRegions,
	}
	for proto, opts := range defaultProtocolOptions {
		copied := map[string]any{}
		for k, v := range opts {
			copied[k] = v
		}
		defaults[proto] = copied
	}
	return &MetaPayload{
		Protocols: []map[string]any{
			{"code": "http", "name": "HTTP", "enabled": true},
			{"code": "ping", "name": "PING", "enabled": true},
			{"code": "dns", "name": "DNS", "enabled": true},
			{"code": "mtr", "name": "MTR", "enabled": true},
			{"code": "traceroute", "name": "Traceroute", "enabled": true},
		},
		Regions:  regionPayloads,
		Nodes:    nodePayloads,
		Defaults: defaults,
		Batch: map[string]any{
			"enabled": true,
			"protocols": []string{"http", "ping", "dns", "mtr", "traceroute", "all"},
			"maxTargets": 10000, "maxFileSizeBytes": 2 * 1024 * 1024,
			"defaults": map[string]any{"regions": defaultRegions},
		},
		ProbeControl: map[string]any{
			"transportOptions": []map[string]string{
				{"code": "local", "name": "本地执行"},
				{"code": "mqtt", "name": "MQTT 探针"},
			},
			"agentStats": map[string]int{"total": 0, "online": 0},
		},
	}, nil
}

func schedulableOf(nodes []model.Node) []model.Node {
	out := make([]model.Node, 0, len(nodes))
	for _, n := range nodes {
		if n.IsSchedulable {
			out = append(out, n)
		}
	}
	return out
}

func apitimeFromPtr(t *time.Time) *apitime.Time {
	if t == nil {
		return nil
	}
	v := apitime.From(*t)
	return &v
}

func nowRef() time.Time { return time.Now() }

// ---------- task / execution ----------

func (s *Service) regionNames(ctx context.Context, codes []string) []string {
	if len(codes) == 0 {
		return []string{}
	}
	var regions []model.Region
	s.gorm.WithContext(ctx).Where("code IN ?", codes).Find(&regions)
	m := map[string]string{}
	for _, r := range regions {
		m[r.Code] = r.Name
	}
	out := make([]string, 0, len(codes))
	for _, code := range codes {
		if name, ok := m[code]; ok {
			out = append(out, name)
		} else {
			out = append(out, code)
		}
	}
	return out
}

// BuildTaskPayload 镜像原 build_task_payload 字段集。
func (s *Service) BuildTaskPayload(ctx context.Context, task *model.Task, latest *model.Execution) map[string]any {
	var regionCodes []string
	_ = jsonUnmarshalDefault(task.RegionCodesTx, &regionCodes)
	normalized, _ := s.normalizeRegionCodes(ctx, regionCodes, 0)
	if normalized == nil {
		normalized = []string{}
	}
	var options map[string]any
	_ = jsonUnmarshalDefault(task.OptionsTx, &options)
	if options == nil {
		options = map[string]any{}
	}
	return map[string]any{
		"id": task.ID,
		"taskNo": task.TaskNo,
		"mode": task.Mode,
		"protocol": task.Protocol,
		"target": task.Target,
		"targetDisplay": task.TargetDisplay,
		"regions": normalized,
		"regionNames": s.regionNames(ctx, normalized),
		"options": options,
		"schedule": task.ScheduleCron,
		"status": task.Status,
		"isEnabled": task.IsEnabled,
		"lastRunAt": apitimeFromPtr(task.LastRunAt),
		"nextRunAt": apitimeFromPtr(task.NextRunAt),
		"createdAt": apitime.From(task.CreateTime),
		"latestExecution": buildExecutionSummary(latest),
		"trend7d": []any{},
		"trend30d": []any{},
	}
}

func buildExecutionSummary(e *model.Execution) map[string]any {
	if e == nil {
		return nil
	}
	return map[string]any{
		"id": e.ID,
		"executionNo": e.ExecutionNo,
		"status": e.Status,
		"triggerType": e.TriggerType,
		"startedAt": apitimeFromPtr(e.StartedAt),
		"finishedAt": apitimeFromPtr(e.FinishedAt),
		"successRegionCount": e.SuccessRegionCount,
		"totalRegionCount": e.TotalRegionCount,
		"availabilityRatio": e.AvailabilityRatio,
		"summaryMessage": e.SummaryMessage,
	}
}

// BuildExecutionPayload 镜像原 build_execution_payload(overview/task/regions/maps/details)。
func (s *Service) BuildExecutionPayload(ctx context.Context, executionID uint64) (map[string]any, error) {
	var execution model.Execution
	if err := s.gorm.WithContext(ctx).First(&execution, executionID).Error; err != nil {
		return nil, gorm.ErrRecordNotFound
	}
	var task model.Task
	if err := s.gorm.WithContext(ctx).First(&task, execution.TaskID).Error; err != nil {
		return nil, err
	}
	var rows []model.ExecutionRegion
	if err := s.gorm.WithContext(ctx).Where("execution_id = ?", executionID).Order("id ASC").Find(&rows).Error; err != nil {
		return nil, err
	}

	regionResults := make([]map[string]any, 0, len(rows))
	protocolDetail := make([]map[string]any, 0, len(rows))
	mapPoints := make([]map[string]any, 0, len(rows))
	for i := range rows {
		detail := s.buildRegionDetail(ctx, &rows[i])
		regionResults = append(regionResults, detail)
		protocolDetail = append(protocolDetail, map[string]any{
			"regionCode": rows[i].RegionCode,
			"regionName": rows[i].RegionName,
			"success": rows[i].Success,
			"status": rows[i].Status,
			"detail": detail["detail"],
		})
		ripple := 0
		if rows[i].Success {
			ripple = 1
		}
		mapPoints = append(mapPoints, map[string]any{
			"name": rows[i].RegionName,
			"value": []float64{rows[i].MapLng, rows[i].MapLat, float64(ripple)},
			"status": rows[i].Status,
		})
	}
	return map[string]any{
		"overview": buildExecutionSummary(&execution),
		"task": map[string]any{
			"id": task.ID, "taskNo": task.TaskNo, "mode": task.Mode,
			"protocol": task.Protocol, "target": task.Target, "targetDisplay": task.TargetDisplay,
		},
		"regions": regionResults,
		"maps":  map[string]any{"points": mapPoints},
		"trends": map[string]any{"days7": []any{}, "days30": []any{}},
		"details": protocolDetail,
	}, nil
}

// buildRegionDetail 镜像原 build_region_detail:通用字段 + 协议 detail(从合并表反序列化)。
func (s *Service) buildRegionDetail(ctx context.Context, row *model.ExecutionRegion) map[string]any {
	var probe model.ProbeResult
	detail := map[string]any{}
	if err := s.gorm.WithContext(ctx).Where("execution_region_id = ?", row.ID).First(&probe).Error; err == nil {
		if strings.TrimSpace(probe.DetailTx) != "" {
			_ = json.Unmarshal([]byte(probe.DetailTx), &detail)
		}
	}
	if detail == nil {
		detail = map[string]any{}
	}
	var rawPayload map[string]any
	_ = jsonUnmarshalDefault(row.RawPayloadTx, &rawPayload)
	if rawPayload == nil {
		rawPayload = map[string]any{}
	}
	return map[string]any{
		"id": row.ID,
		"regionCode": row.RegionCode,
		"regionName": row.RegionName,
		"mapLng": row.MapLng,
		"mapLat": row.MapLat,
		"nodeCode": row.NodeCode,
		"nodeName": row.NodeName,
		"status": row.Status,
		"success": row.Success,
		"resolvedTarget": row.ResolvedTarget,
		"latencyMs": row.LatencyMs,
		"errorCode": row.ErrorCode,
		"errorMessage": row.ErrorMessage,
		"startedAt": apitimeFromPtr(row.StartedAt),
		"finishedAt": apitimeFromPtr(row.FinishedAt),
		"rawPayload": rawPayload,
		"detail": detail,
	}
}
