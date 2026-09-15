package service

import (
	"context"
	"fmt"
	"sort"
	"time"

	"dnsss/internal/model"
)

// BuildRiskBoardMeta 镜像 build_risk_board_meta。
func (s *Service) BuildRiskBoardMeta(ctx context.Context) (map[string]any, error) {
	meta, err := s.BuildMeta(ctx)
	if err != nil {
		return nil, err
	}
	regionPayloads := make([]map[string]any, 0, len(meta.Regions))
	for _, r := range meta.Regions {
		regionPayloads = append(regionPayloads, r)
	}
	nodePayloads := make([]map[string]any, 0, len(meta.Nodes))
	nodePayloads = append(nodePayloads, meta.Nodes...)
	return map[string]any{
		"filters": map[string]any{
			"windows": []map[string]string{
				{"code": "1h", "name": "1 小时"}, {"code": "24h", "name": "24 小时"},
				{"code": "7d", "name": "7 天"}, {"code": "30d", "name": "30 天"}, {"code": "90d", "name": "90 天"},
			},
			"protocols": []map[string]string{
				{"code": "all", "name": "全部"}, {"code": "dns", "name": "DNS"}, {"code": "http", "name": "HTTP"},
				{"code": "ping", "name": "PING"}, {"code": "mtr", "name": "MTR"}, {"code": "traceroute", "name": "Traceroute"},
			},
			"environments": []map[string]string{
				{"code": "prod", "name": "生产"}, {"code": "lab", "name": "靶场"},
			},
		},
		"defaults": map[string]any{"window": "30d", "protocol": "dns", "environment": "prod", "refreshSeconds": 30},
		"supports": map[string]any{"echartsGl": true, "globe": true},
		"regions":  regionPayloads,
		"nodes":    nodePayloads,
	}, nil
}

// BuildGlobeLayers 镜像 build_risk_board_globe_layers。
// DNS 风险事件依赖 P7 扫描器:当前 resultLayer 为空态,probeLayer 保留地区点。
func (s *Service) BuildGlobeLayers(ctx context.Context, windowCode, environment string) map[string]any {
	window := normalizeWindow(windowCode)
	cacheKey := fmt.Sprintf("globe-layers:%s:%s", window, environment)
	if cached := riskBoardCache.get(cacheKey); cached != nil {
		return cached
	}
	regions := s.regionMap(ctx)
	points := make([]map[string]any, 0, len(regions))
	for _, r := range regions {
		points = append(points, map[string]any{
			"name": r.Name, "regionCode": r.Code,
			"value":       []float64{r.Lng, r.Lat, 1},
			"riskCount":   0,
			"onlineNodeCount": r.nodeStatusMap[r.Code],
			"drilldownUrl": "/network-probe/agents",
		})
	}
	payload := map[string]any{
		"filters":    map[string]any{"window": window, "environment": environment},
		"probeLayer": map[string]any{"points": points},
		"resultLayer": map[string]any{
			"hotspots": []map[string]any{},
			"arcs":     []map[string]any{},
			"summary": map[string]any{
				"riskEventCount": 0, "hotspotCount": 0, "arcCount": 0, "lastDetectedAt": nil,
			},
		},
		"links": map[string]any{"agents": "/network-probe/agents", "dnsScans": "/network-probe/dns-trust/scans"},
	}
	riskBoardCache.set(cacheKey, payload)
	return payload
}

// BuildNodeDistribution 镜像 build_risk_board_node_distribution。
func (s *Service) BuildNodeDistribution(ctx context.Context, windowCode, protocolCode, environment string) map[string]any {
	window := normalizeWindow(windowCode)
	protocol := normalizeProtocol(protocolCode)
	cacheKey := fmt.Sprintf("node-distribution:%s:%s:%s", window, protocol, environment)
	if cached := riskBoardCache.get(cacheKey); cached != nil {
		return cached
	}
	since := time.Now().Add(-time.Duration(windowHours[window]) * time.Hour)
	events := s.buildRiskEvents(ctx, since, protocol, 0)

	regionRisk := map[string]int{}
	nodeRisk := map[string]int{}
	regionLast := map[string]string{}
	nodeLast := map[string]string{}
	for _, e := range events {
		regionCode := orDefault(e.SourceRegionCode, "global")
		regionRisk[regionCode]++
		if e.DetectedAt > regionLast[regionCode] {
			regionLast[regionCode] = e.DetectedAt
		}
		if e.NodeCode != "" {
			nodeRisk[e.NodeCode]++
			if e.DetectedAt > nodeLast[e.NodeCode] {
				nodeLast[e.NodeCode] = e.DetectedAt
			}
		}
	}

	var regions []model.Region
	s.gorm.WithContext(ctx).Where("is_active = ?", true).Order("display_order ASC, id ASC").Find(&regions)
	var nodes []model.Node
	s.gorm.WithContext(ctx).Order("code ASC").Find(&nodes)

	statusCounter := map[string]int{}
	regionRows := make([]map[string]any, 0, len(regions))
	for _, r := range regions {
		online, offline, maintenance := 0, 0, 0
		for _, n := range nodes {
			if n.RegionCode != r.Code {
				continue
			}
			switch n.Status {
			case "online":
				online++
			case "offline":
				offline++
			case "maintenance":
				maintenance++
			}
		}
		regionRows = append(regionRows, map[string]any{
			"regionCode": r.Code, "regionName": r.Name,
			"riskCount": regionRisk[r.Code],
			"onlineNodeCount": online, "offlineNodeCount": offline, "maintenanceNodeCount": maintenance,
			"lastDetectedAt": nullableStr(regionLast[r.Code]),
			"drilldownUrl":   "/network-probe/agents",
		})
	}
	nodeRows := make([]map[string]any, 0, len(nodes))
	regionName := map[string]string{}
	for _, r := range regions {
		regionName[r.Code] = r.Name
	}
	for _, n := range nodes {
		statusCounter[n.Status]++
		rn := regionName[n.RegionCode]
		if rn == "" {
			rn = "未分配"
		}
		nodeRows = append(nodeRows, map[string]any{
			"nodeCode": n.Code, "nodeName": n.Name,
			"regionCode": n.RegionCode, "regionName": rn,
			"status": n.Status, "transport": n.Transport, "isSchedulable": n.IsSchedulable,
			"riskCount": nodeRisk[n.Code], "lastDetectedAt": nullableStr(nodeLast[n.Code]),
			"drilldownUrl": "/network-probe/agents",
		})
	}
	sort.SliceStable(regionRows, func(i, j int) bool {
		return regionRows[i]["riskCount"].(int) > regionRows[j]["riskCount"].(int)
	})
	sort.SliceStable(nodeRows, func(i, j int) bool {
		return nodeRows[i]["riskCount"].(int) > nodeRows[j]["riskCount"].(int)
	})

	lastDetected := any(nil)
	if len(events) > 0 {
		lastDetected = events[0].DetectedAt
	}
	payload := map[string]any{
		"filters": map[string]any{"window": window, "protocol": protocol, "environment": environment},
		"summary": map[string]any{
			"totalRiskCount":  len(events),
			"activeNodeCount": s.activeNodeCount(ctx),
			"onlineNodeCount":     statusCounter["online"],
			"offlineNodeCount":    statusCounter["offline"],
			"maintenanceNodeCount": statusCounter["maintenance"],
			"impactedRegionCount": countPositive(regionRows, "riskCount"),
			"lastDetectedAt":      lastDetected,
		},
		"regions": regionRows,
		"nodes":   nodeRows,
		"charts": map[string]any{
			"nodeStatusDistribution": []map[string]any{
				{"name": "在线", "value": statusCounter["online"]},
				{"name": "离线", "value": statusCounter["offline"]},
				{"name": "维护", "value": statusCounter["maintenance"]},
			},
			"regionRiskDistribution": topRows(regionRows, "regionName", "riskCount", 8),
			"nodeRiskRanking":        topRowsWithCode(nodeRows, 10),
		},
		"links": map[string]any{"agents": "/network-probe/agents", "networkProbe": "/network-probe"},
	}
	riskBoardCache.set(cacheKey, payload)
	return payload
}

func nullableStr(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func countPositive(rows []map[string]any, key string) int {
	count := 0
	for _, row := range rows {
		if n, ok := row[key].(int); ok && n > 0 {
			count++
		}
	}
	return count
}

func topRows(rows []map[string]any, nameKey, valueKey string, limit int) []map[string]any {
	out := make([]map[string]any, 0, limit)
	for i, row := range rows {
		if i >= limit {
			break
		}
		out = append(out, map[string]any{
			"name": row[nameKey], "value": row[valueKey], "drilldownUrl": "/network-probe/agents",
		})
	}
	return out
}

func topRowsWithCode(rows []map[string]any, limit int) []map[string]any {
	out := make([]map[string]any, 0, limit)
	for i, row := range rows {
		if i >= limit {
			break
		}
		out = append(out, map[string]any{
			"name": row["nodeName"], "value": row["riskCount"], "nodeCode": row["nodeCode"],
			"drilldownUrl": "/network-probe/agents",
		})
	}
	return out
}

// BuildBatchRiskOverview 镜像 build_risk_board_batch_risk_overview(纯批量口径)。
func (s *Service) BuildBatchRiskOverview(ctx context.Context, windowCode, protocolCode, environment string) map[string]any {
	window := normalizeWindow(windowCode)
	protocol := normalizeProtocol(protocolCode)
	cacheKey := fmt.Sprintf("batch-risk:%s:%s:%s", window, protocol, environment)
	if cached := riskBoardCache.get(cacheKey); cached != nil {
		return cached
	}
	since := time.Now().Add(-time.Duration(windowHours[window]) * time.Hour)
	batchProtocols := nonDNSProtocols(protocol)
	payload := map[string]any{
		"filters": map[string]any{"window": window, "protocol": protocol, "environment": environment},
		"links": map[string]any{
			"batchTasks": "/network-probe/batch", "batchHistory": "/network-probe/batch-history",
		},
	}
	if len(batchProtocols) == 0 {
		payload["summary"] = map[string]any{
			"executionCount": 0, "successResultCount": 0, "failedResultCount": 0,
			"riskEventCount": 0, "avgLatencyMs": nil, "lastFinishedAt": nil,
		}
		payload["latestExecutions"] = []map[string]any{}
		payload["charts"] = map[string]any{
			"successFailure": []map[string]any{{"name": "成功", "value": 0}, {"name": "失败", "value": 0}},
			"resultCodeDistribution": []map[string]any{}, "protocolDistribution": []map[string]any{},
		}
		payload["rankings"] = map[string]any{"slowTargets": []map[string]any{}, "anomalyTargets": []map[string]any{}}
		payload["events"] = map[string]any{"stream": []map[string]any{}}
		riskBoardCache.set(cacheKey, payload)
		return payload
	}

	var results []model.BatchResult
	s.gorm.WithContext(ctx).Where("create_time >= ? AND protocol IN ?", since, batchProtocols).
		Order("id DESC").Limit(600).Find(&results)
	batchEvents := s.buildBatchEvents(ctx, since, protocol)

	successCount, failedCount := 0, 0
	var latencies []float64
	codeCounter := map[string]int{}
	protocolCounter := map[string]int{}
	anomalyTargets := map[string]int{}
	for _, r := range results {
		if r.Success {
			successCount++
		} else {
			failedCount++
			if r.Target != "" {
				anomalyTargets[r.Target]++
			}
		}
		if r.LatencyMs != nil {
			latencies = append(latencies, *r.LatencyMs)
		}
		if r.ResultCode != "" || r.ErrorCode != "" {
			codeCounter[orDefault(r.ResultCode, r.ErrorCode)]++
		}
		if r.Protocol != "" {
			protocolCounter[upper(r.Protocol)]++
		}
	}

	var executions []model.BatchExecution
	s.gorm.WithContext(ctx).
		Where("id IN (?)", s.gorm.Model(&model.BatchResult{}).
			Select("DISTINCT batch_execution_id").
			Where("create_time >= ? AND protocol IN ?", since, batchProtocols)).
		Order("id DESC").Limit(8).Find(&executions)
	latest := make([]map[string]any, 0, len(executions))
	var lastFinishedAt any
	for _, e := range executions {
		var avg any
		if e.AvgLatencyMs != nil {
			avg = *e.AvgLatencyMs
		}
		latest = append(latest, map[string]any{
			"executionId": e.ID, "executionNo": e.ExecutionNo,
			"taskId": e.BatchTaskID, "taskNo": "",
			"protocol": "all", "status": e.Status,
			"startedAt": apitimeFromPtr(e.StartedAt), "finishedAt": apitimeFromPtr(e.FinishedAt),
			"successCount": e.SuccessCount, "failedCount": e.FailedCount,
			"avgLatencyMs": avg, "summaryMessage": e.SummaryMessage,
			"drilldownUrl": fmt.Sprintf("/network-probe/batch-result/%d", e.ID),
		})
		if lastFinishedAt == nil && e.FinishedAt != nil {
			lastFinishedAt = apitimeFromPtr(e.FinishedAt)
		}
	}

	slow := make([]model.BatchResult, 0)
	for _, r := range results {
		if r.LatencyMs != nil {
			slow = append(slow, r)
		}
	}
	sort.SliceStable(slow, func(i, j int) bool {
		return derefF(slow[i].LatencyMs) > derefF(slow[j].LatencyMs)
	})
	if len(slow) > 10 {
		slow = slow[:10]
	}
	slowPayload := make([]map[string]any, 0, len(slow))
	for _, r := range slow {
		slowPayload = append(slowPayload, map[string]any{
			"id": r.ID, "executionId": r.BatchExecutionID, "target": r.Target,
			"protocol": r.Protocol, "latencyMs": r.LatencyMs,
			"resultCode": r.ResultCode, "status": r.Status,
			"drilldownUrl": fmt.Sprintf("/network-probe/batch-result/%d?resultId=%d&keyword=%s",
				r.BatchExecutionID, r.ID, r.Target),
		})
	}

	avgLatency := any(nil)
	if len(latencies) > 0 {
		sum := 0.0
		for _, v := range latencies {
			sum += v
		}
		avgLatence := float64(int(sum/float64(len(latencies))*100+0.5)) / 100
		avgLatency = avgLatence
	}
	stream := make([]map[string]any, 0, 20)
	for i, e := range batchEvents {
		if i >= 20 {
			break
		}
		stream = append(stream, eventToMap(e))
	}
	payload["summary"] = map[string]any{
		"executionCount":      len(executions),
		"successResultCount":  successCount,
		"failedResultCount":   failedCount,
		"riskEventCount":      len(batchEvents),
		"avgLatencyMs":        avgLatency,
		"lastFinishedAt":      lastFinishedAt,
	}
	payload["latestExecutions"] = latest
	payload["charts"] = map[string]any{
		"successFailure": []map[string]any{
			{"name": "成功", "value": successCount}, {"name": "失败", "value": failedCount},
		},
		"resultCodeDistribution": labelCounts(mostCommon(codeCounter, 10)),
		"protocolDistribution":   labelCounts(mostCommon(protocolCounter, 0)),
	}
	payload["rankings"] = map[string]any{
		"slowTargets": slowPayload,
		"anomalyTargets": withDrilldown(mostCommon(anomalyTargets, 10), "/network-probe/batch-history"),
	}
	payload["events"] = map[string]any{"stream": stream}
	riskBoardCache.set(cacheKey, payload)
	return payload
}

func labelCounts(rows []map[string]any) []map[string]any {
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, map[string]any{"label": row["name"], "count": row["value"]})
	}
	return out
}

func upper(v string) string {
	out := []rune(v)
	for i, r := range out {
		if r >= 'a' && r <= 'z' {
			out[i] = r - 32
		}
	}
	return string(out)
}
