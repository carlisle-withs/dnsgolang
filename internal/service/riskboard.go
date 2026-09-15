package service

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"

	"dnsss/internal/model"
)

// ---------- 风险大屏聚合(镜像 selectors/risk_board.py) ----------
// P5 范围:协议异常事件(单目标 + 批量)全量实现;DNS 风险事件依赖
// P7 扫描器(dns_trust_* 表),当前返回空——KPI 与库内数据保持自洽。

var windowHours = map[string]int{"1h": 1, "24h": 24, "7d": 24 * 7, "30d": 24 * 30, "90d": 24 * 90}

var supportedProtocols = map[string]bool{"all": true, "dns": true, "http": true, "ping": true, "mtr": true, "traceroute": true}

// 异常判定阈值(与原版一致)
const (
	httpLatencyThreshold    = 1500.0
	pingLatencyThreshold    = 300.0
	pingLossThreshold       = 20.0
	mtrLatencyThreshold     = 500.0
	mtrLossThreshold        = 20.0
	tracerouteLatencyThresh = 800.0
	tracerouteHopThreshold  = 20
)

func normalizeWindow(code string) string {
	if _, ok := windowHours[code]; ok {
		return code
	}
	return "24h"
}

func normalizeProtocol(code string) string {
	if supportedProtocols[code] {
		return code
	}
	return "all"
}

func nonDNSProtocols(protocolCode string) []string {
	if protocolCode == "dns" {
		return []string{}
	}
	all := []string{"http", "ping", "mtr", "traceroute"}
	if protocolCode != "all" {
		for _, p := range all {
			if p == protocolCode {
				return []string{p}
			}
		}
		return []string{}
	}
	return all
}

// riskEvent 大屏事件流条目(字段与原版逐一对应)。
type riskEvent struct {
	EventID          string   `json:"eventId"`
	Kind             string   `json:"kind"`
	Protocol         string   `json:"protocol"`
	Severity         string   `json:"severity"`
	ConfidenceTier   string   `json:"confidenceTier"`
	ConfidenceLabel  string   `json:"confidenceLabel"`
	Title            string   `json:"title"`
	Summary          string   `json:"summary"`
	RiskType         string   `json:"riskType"`
	TargetLabel      string   `json:"targetLabel"`
	DomainLabel      string   `json:"domainLabel"`
	TargetIP         string   `json:"targetIp"`
	TargetGeoLabel   string   `json:"targetGeoLabel"`
	TargetLng        *float64 `json:"targetLng"`
	TargetLat        *float64 `json:"targetLat"`
	SourceRegionCode string   `json:"sourceRegionCode"`
	SourceRegionName string   `json:"sourceRegionName"`
	SourceLng        float64  `json:"sourceLng"`
	SourceLat        float64  `json:"sourceLat"`
	NodeCode         string   `json:"nodeCode"`
	NodeName         string   `json:"nodeName"`
	ResultCode       string   `json:"resultCode"`
	DetectedAt       string   `json:"detectedAt"`
	DrilldownURL     string   `json:"drilldownUrl"`
}

type regionInfo struct {
	Code, Name    string
	Lng, Lat      float64
	nodeStatusMap map[string]int // regionCode -> 在线节点数
}

// protocolAnomaly 镜像 _protocol_anomaly 阈值分类。
func protocolAnomaly(protocol string, success bool, errorCode string, detail map[string]any, latencyMs *float64) (string, string) {
	switch protocol {
	case "http":
		httpStatus := int(toF(detail["httpStatus"]))
		totalMs := toF(detail["totalMs"])
		if totalMs == 0 {
			totalMs = derefF(latencyMs)
		}
		if !success || errorCode != "" {
			return "high", "HTTP 失败或超时"
		}
		if httpStatus >= 500 {
			return "high", "HTTP 5xx 异常"
		}
		if totalMs >= httpLatencyThreshold {
			return "medium", "HTTP 延迟偏高"
		}
	case "ping":
		lossPct := toF(detail["lossPct"])
		avgMs := toF(detail["avgMs"])
		if avgMs == 0 {
			avgMs = derefF(latencyMs)
		}
		if !success || errorCode != "" {
			return "high", "PING 失败或超时"
		}
		if lossPct >= pingLossThreshold {
			return "medium", "PING 丢包偏高"
		}
		if avgMs >= pingLatencyThreshold {
			return "medium", "PING 延迟偏高"
		}
	case "mtr":
		reached, hasReached := detail["destinationReached"].(bool)
		lossPct := toF(detail["packetLossPct"])
		avgMs := toF(detail["avgMs"])
		if avgMs == 0 {
			avgMs = derefF(latencyMs)
		}
		if !success || errorCode != "" || (hasReached && !reached) {
			return "high", "MTR 未达目标"
		}
		if lossPct >= mtrLossThreshold {
			return "medium", "MTR 丢包偏高"
		}
		if avgMs >= mtrLatencyThreshold {
			return "medium", "MTR 延迟偏高"
		}
	case "traceroute":
		reached, hasReached := detail["destinationReached"].(bool)
		hopCount := int(toF(detail["hopCount"]))
		avgMs := derefF(latencyMs)
		if !success || errorCode != "" || (hasReached && !reached) {
			return "high", "Traceroute 未达目标"
		}
		if hopCount >= tracerouteHopThreshold {
			return "medium", "Traceroute 跳数偏高"
		}
		if avgMs >= tracerouteLatencyThresh {
			return "medium", "Traceroute 延迟偏高"
		}
	}
	return "", ""
}

func toF(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	}
	return 0
}

func derefF(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
}

// buildRiskEvents 汇聚事件流(单目标 + 批量 + DNS 扫描(P7 前为空))。
func (s *Service) buildRiskEvents(ctx context.Context, since time.Time, protocolCode string, limit int) []riskEvent {
	events := append(s.buildExecutionEvents(ctx, since, protocolCode), s.buildBatchEvents(ctx, since, protocolCode)...)
	sort.SliceStable(events, func(i, j int) bool {
		return events[i].DetectedAt > events[j].DetectedAt
	})
	if limit > 0 && len(events) > limit {
		events = events[:limit]
	}
	return events
}

func (s *Service) regionMap(ctx context.Context) map[string]regionInfo {
	var regions []model.Region
	s.gorm.WithContext(ctx).Where("is_active = ?", true).Order("display_order ASC, id ASC").Find(&regions)
	var nodes []model.Node
	s.gorm.WithContext(ctx).Find(&nodes)
	onlineByRegion := map[string]int{}
	for _, n := range nodes {
		if n.Status == "online" {
			onlineByRegion[n.RegionCode]++
		}
	}
	out := map[string]regionInfo{}
	for _, r := range regions {
		out[r.Code] = regionInfo{Code: r.Code, Name: r.Name, Lng: r.MapLng, Lat: r.MapLat, nodeStatusMap: onlineByRegion}
	}
	return out
}

func (s *Service) buildSource(regions map[string]regionInfo, regionCode, nodeCode string) (code, name string, lng, lat float64) {
	info, ok := regions[regionCode]
	if !ok {
		info, ok = regions["global"]
	}
	if !ok {
		return "global", "全局", 105.0, 35.0
	}
	return info.Code, info.Name, info.Lng, info.Lat
}

func (s *Service) nodeNameOfCode(ctx context.Context, code string) string {
	if code == "" {
		return ""
	}
	var node model.Node
	if err := s.gorm.WithContext(ctx).Select("name").Where("code = ?", code).First(&node).Error; err != nil {
		return ""
	}
	return node.Name
}

// buildExecutionEvents 单目标协议异常事件(镜像 _build_execution_events)。
func (s *Service) buildExecutionEvents(ctx context.Context, since time.Time, protocolCode string) []riskEvent {
	protocols := nonDNSProtocols(protocolCode)
	if len(protocols) == 0 {
		return []riskEvent{}
	}
	var rows []struct {
		ID            uint64     `gorm:"column:id"`
		ExecutionID   uint64     `gorm:"column:execution_id"`
		RegionCode    string     `gorm:"column:region_code"`
		NodeCode      string     `gorm:"column:node_code"`
		Success       bool       `gorm:"column:success"`
		ErrorCode     string     `gorm:"column:error_code"`
		LatencyMs     *float64   `gorm:"column:latency_ms"`
		ResolvedTarget string    `gorm:"column:resolved_target"`
		CreateTime    time.Time  `gorm:"column:create_time"`
		Protocol      string     `gorm:"column:protocol"`
		Target        string     `gorm:"column:target"`
		TargetDisplay string     `gorm:"column:target_display"`
		DetailTx      *string    `gorm:"column:detail_text"`
	}
	s.gorm.WithContext(ctx).Raw(`
		SELECT er.id, er.execution_id, er.region_code, er.node_code, er.success, er.error_code,
		       er.latency_ms, er.resolved_target, er.create_time,
		       t.protocol, t.target, t.target_display, pr.detail_text
		FROM netprobe_execution_regions er
		JOIN netprobe_executions e ON e.id = er.execution_id
		JOIN netprobe_tasks t ON t.id = e.task_id
		LEFT JOIN netprobe_probe_results pr ON pr.execution_region_id = er.id
		WHERE er.create_time >= ? AND t.protocol IN ?
		ORDER BY er.create_time DESC, er.id DESC LIMIT 240`, since, protocols).Scan(&rows)

	regions := s.regionMap(ctx)
	events := []riskEvent{}
	nodeNames := map[string]string{}
	for _, row := range rows {
		detail := map[string]any{}
		if row.DetailTx != nil && strings.TrimSpace(*row.DetailTx) != "" {
			_ = json.Unmarshal([]byte(*row.DetailTx), &detail)
		}
		severity, summary := protocolAnomaly(row.Protocol, row.Success, row.ErrorCode, detail, row.LatencyMs)
		if severity == "" {
			continue
		}
		if _, ok := nodeNames[row.NodeCode]; !ok {
			nodeNames[row.NodeCode] = s.nodeNameOfCode(ctx, row.NodeCode)
		}
		code, name, lng, lat := s.buildSource(regions, row.RegionCode, row.NodeCode)
		targetLabel := row.TargetDisplay
		if targetLabel == "" {
			targetLabel = row.Target
		}
		events = append(events, riskEvent{
			EventID: fmt.Sprintf("%s-%d", row.Protocol, row.ID),
			Kind:    "protocol_anomaly", Protocol: row.Protocol,
			Severity: severity, ConfidenceTier: "protocol_anomaly", ConfidenceLabel: "协议异常",
			Title:   fmt.Sprintf("%s: %s", orDefault(targetLabel, strings.ToUpper(row.Protocol)), summary),
			Summary: summary, RiskType: "",
			TargetLabel: targetLabel, DomainLabel: targetLabel,
			TargetIP:       "",
			TargetGeoLabel: "",
			SourceRegionCode: code, SourceRegionName: name, SourceLng: lng, SourceLat: lat,
			NodeCode: row.NodeCode, NodeName: nodeNames[row.NodeCode],
			ResultCode: row.ErrorCode,
			DetectedAt: isoFormat(row.CreateTime),
			DrilldownURL: fmt.Sprintf("/network-probe/result/%d", row.ExecutionID),
		})
	}
	return events
}

// buildBatchEvents 批量协议异常事件(镜像 _build_batch_events)。
func (s *Service) buildBatchEvents(ctx context.Context, since time.Time, protocolCode string) []riskEvent {
	protocols := nonDNSProtocols(protocolCode)
	if len(protocols) == 0 {
		return []riskEvent{}
	}
	var rows []struct {
		ID              uint64    `gorm:"column:id"`
		BatchExecutionID uint64   `gorm:"column:batch_execution_id"`
		RegionCode      string    `gorm:"column:region_code"`
		NodeCode        string    `gorm:"column:node_code"`
		Protocol        string    `gorm:"column:protocol"`
		Success         bool      `gorm:"column:success"`
		ErrorCode       string    `gorm:"column:error_code"`
		ResultCode      string    `gorm:"column:result_code"`
		LatencyMs       *float64  `gorm:"column:latency_ms"`
		Target          string    `gorm:"column:target"`
		DetailTx        *string   `gorm:"column:detail_text"`
		CreateTime      time.Time `gorm:"column:create_time"`
	}
	s.gorm.WithContext(ctx).Raw(`
		SELECT r.id, r.batch_execution_id, r.region_code, r.node_code, r.protocol, r.success,
		       r.error_code, r.result_code, r.latency_ms, r.target, r.detail_text, r.create_time
		FROM netprobe_batch_results r
		WHERE r.create_time >= ? AND r.protocol IN ?
		ORDER BY r.create_time DESC, r.id DESC LIMIT 240`, since, protocols).Scan(&rows)

	regions := s.regionMap(ctx)
	events := []riskEvent{}
	nodeNames := map[string]string{}
	for _, row := range rows {
		detail := map[string]any{}
		if row.DetailTx != nil && strings.TrimSpace(*row.DetailTx) != "" {
			_ = json.Unmarshal([]byte(*row.DetailTx), &detail)
		}
		severity, summary := protocolAnomaly(row.Protocol, row.Success, row.ErrorCode, detail, row.LatencyMs)
		if severity == "" {
			continue
		}
		if _, ok := nodeNames[row.NodeCode]; !ok {
			nodeNames[row.NodeCode] = s.nodeNameOfCode(ctx, row.NodeCode)
		}
		code, name, lng, lat := s.buildSource(regions, row.RegionCode, row.NodeCode)
		events = append(events, riskEvent{
			EventID: fmt.Sprintf("%s-%d", row.Protocol, row.ID),
			Kind:    "protocol_anomaly", Protocol: row.Protocol,
			Severity: severity, ConfidenceTier: "protocol_anomaly", ConfidenceLabel: "协议异常",
			Title:   fmt.Sprintf("%s: %s", row.Target, summary),
			Summary: summary, RiskType: "",
			TargetLabel: row.Target, DomainLabel: row.Target,
			TargetIP:       "",
			TargetGeoLabel: "",
			SourceRegionCode: code, SourceRegionName: name, SourceLng: lng, SourceLat: lat,
			NodeCode: row.NodeCode, NodeName: nodeNames[row.NodeCode],
			ResultCode: orDefault(row.ResultCode, row.ErrorCode),
			DetectedAt: isoFormat(row.CreateTime),
			DrilldownURL: fmt.Sprintf("/network-probe/batch-result/%d?resultId=%d&keyword=%s",
				row.BatchExecutionID, row.ID, row.Target),
		})
	}
	return events
}

func isoFormat(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	// 与 Python isoformat 一致(微秒 6 位,无时区后缀)
	µs := t.Nanosecond() / 1000
	if µs == 0 {
		return t.Format("2006-01-02T15:04:05")
	}
	return t.Format("2006-01-02T15:04:05") + fmt.Sprintf(".%06d", µs)
}

// ---------- 30s 进程内缓存(未配 Redis 时的等价形态) ----------

type cacheEntry struct {
	payload  map[string]any
	expireAt time.Time
}

type ttlCache struct {
	mu      sync.Mutex
	entries map[string]cacheEntry
	ttl     time.Duration
}

var riskBoardCache = &ttlCache{entries: map[string]cacheEntry{}, ttl: 30 * time.Second}

func (c *ttlCache) get(key string) map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || time.Now().After(entry.expireAt) {
		return nil
	}
	return entry.payload
}

func (c *ttlCache) set(key string, payload map[string]any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = cacheEntry{payload: payload, expireAt: time.Now().Add(c.ttl)}
	if len(c.entries) > 64 {
		now := time.Now()
		for k, v := range c.entries {
			if now.After(v.expireAt) {
				delete(c.entries, k)
			}
		}
	}
}

// ---------- KPI 与榜单 ----------

func (s *Service) successRate24h(ctx context.Context) float64 {
	since := time.Now().Add(-24 * time.Hour)
	var singleTotal, singleSuccess, batchTotal, batchSuccess int64
	s.gorm.WithContext(ctx).Model(&model.ExecutionRegion{}).Where("create_time >= ?", since).Count(&singleTotal)
	s.gorm.WithContext(ctx).Model(&model.ExecutionRegion{}).Where("create_time >= ? AND success = 1", since).Count(&singleSuccess)
	s.gorm.WithContext(ctx).Model(&model.BatchResult{}).Where("create_time >= ?", since).Count(&batchTotal)
	s.gorm.WithContext(ctx).Model(&model.BatchResult{}).Where("create_time >= ? AND success = 1", since).Count(&batchSuccess)
	total := singleTotal + batchTotal
	if total == 0 {
		return 100.0
	}
	return float64(int(float64(singleSuccess+batchSuccess)/float64(total)*10000+0.5)) / 100
}

func (s *Service) activeNodeCount(ctx context.Context) int64 {
	var count int64
	s.gorm.WithContext(ctx).Model(&model.Node{}).Where("status = ? AND is_schedulable = ?", "online", true).Count(&count)
	return count
}

func (s *Service) recentRuns(ctx context.Context, since time.Time) []map[string]any {
	type runRow struct {
		Kind    string    `gorm:"column:kind"`
		Title   string    `gorm:"column:title"`
		Status  string    `gorm:"column:status"`
		Time    time.Time `gorm:"column:time"`
		Summary string    `gorm:"column:summary"`
	}
	var rows []runRow
	s.gorm.WithContext(ctx).Raw(`
		SELECT t.protocol AS kind, CONCAT(UPPER(t.protocol), ' 单次拨测 #', e.id) AS title,
		       e.status AS status, e.create_time AS time, e.summary_message AS summary
		FROM netprobe_executions e JOIN netprobe_tasks t ON t.id = e.task_id
		WHERE e.create_time >= ? ORDER BY e.id DESC LIMIT 5`, since).Scan(&rows)
	s.gorm.WithContext(ctx).Raw(`
		SELECT t.protocol AS kind, CONCAT(UPPER(t.protocol), ' 批量拨测 #', be.id) AS title,
		       be.status AS status, be.create_time AS time, be.summary_message AS summary
		FROM netprobe_batch_executions be JOIN netprobe_batch_tasks t ON t.id = be.batch_task_id
		WHERE be.create_time >= ? ORDER BY be.id DESC LIMIT 5`, since).Scan(&rows)
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Time.After(rows[j].Time) })
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		if len(out) >= 10 {
			break
		}
		out = append(out, map[string]any{
			"kind": r.Kind, "title": r.Title, "status": r.Status,
			"time": isoFormat(r.Time), "summary": r.Summary,
		})
	}
	return out
}

func distribution(counter map[string]int) []map[string]any {
	out := make([]map[string]any, 0, len(counter))
	for k, v := range counter {
		out = append(out, map[string]any{"name": k, "value": v})
	}
	return out
}

func mostCommon(counter map[string]int, limit int) []map[string]any {
	keys := make([]string, 0, len(counter))
	for k := range counter {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && counter[keys[j]] > counter[keys[j-1]]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	if limit > 0 && len(keys) > limit {
		keys = keys[:limit]
	}
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, map[string]any{"name": k, "value": counter[k]})
	}
	return out
}

func timelineKey(t time.Time, window string) string {
	if t.IsZero() {
		return ""
	}
	if window == "7d" || window == "30d" || window == "90d" {
		return t.Format("01-02")
	}
	return t.Format("01-02 15:00")
}

// ---------- overview ----------

// BuildRiskBoardOverview 镜像 build_risk_board_overview。
func (s *Service) BuildRiskBoardOverview(ctx context.Context, windowCode, protocolCode, environment string) map[string]any {
	window := normalizeWindow(windowCode)
	protocol := normalizeProtocol(protocolCode)
	cacheKey := fmt.Sprintf("overview:%s:%s:%s", window, protocol, environment)
	if cached := riskBoardCache.get(cacheKey); cached != nil {
		return cached
	}
	since := time.Now().Add(-time.Duration(windowHours[window]) * time.Hour)
	regions := s.regionMap(ctx)
	events := s.buildRiskEvents(ctx, since, protocol, 0)

	protocolCounter := map[string]int{}
	severityCounter := map[string]int{}
	confidenceCounter := map[string]int{}
	regionCounter := map[string]int{}
	domainCounter := map[string]int{}
	targetCounter := map[string]int{}
	timelineCounter := map[string]int{}
	regionCodesHit := map[string]bool{}
	var lastDetectedAt string
	for _, e := range events {
		protocolCounter[e.Protocol]++
		severityCounter[orDefault(e.Severity, "medium")]++
		confidenceCounter[orDefault(e.ConfidenceTier, "protocol_anomaly")]++
		regionCounter[e.SourceRegionName]++
		regionCodesHit[e.SourceRegionCode] = true
		if e.DomainLabel != "" {
			domainCounter[e.DomainLabel]++
		}
		if e.TargetLabel != "" {
			targetCounter[e.TargetLabel]++
		}
		if detected, err := time.ParseInLocation("2006-01-02T15:04:05.999999", e.DetectedAt, time.Local); err == nil {
			timelineCounter[timelineKey(detected, window)]++
		} else if e.DetectedAt != "" {
			if detected, err := time.ParseInLocation("2006-01-02T15:04:05", e.DetectedAt, time.Local); err == nil {
				timelineCounter[timelineKey(detected, window)]++
			}
		}
		if e.DetectedAt > lastDetectedAt {
			lastDetectedAt = e.DetectedAt
		}
	}

	// 地区点(所有活跃地区,风险计数叠加涟漪)
	points := make([]map[string]any, 0, len(regions))
	for _, r := range regions {
		related := regionCounter[r.Name]
		ripple := related
		if ripple < 1 {
			ripple = 1
		}
		points = append(points, map[string]any{
			"name": r.Name, "regionCode": r.Code,
			"value":  []float64{r.Lng, r.Lat, float64(ripple)},
			"riskCount": related, "onlineNodeCount": r.nodeStatusMap[r.Code],
			"drilldownUrl": "/network-probe/agents",
		})
	}

	dnsHighConfidence := 0
	protocolAnomalyCount := 0
	for _, e := range events {
		if e.Protocol == "dns" && e.ConfidenceTier == "high_confidence" {
			dnsHighConfidence++
		}
		if e.Protocol != "dns" {
			protocolAnomalyCount++
		}
	}

	// 时间线按 key 排序
	timelineKeys := make([]string, 0, len(timelineCounter))
	for k := range timelineCounter {
		if k != "" {
			timelineKeys = append(timelineKeys, k)
		}
	}
	sort.Strings(timelineKeys)
	timeline := make([]map[string]any, 0, len(timelineKeys))
	for _, k := range timelineKeys {
		timeline = append(timeline, map[string]any{"name": k, "value": timelineCounter[k]})
	}

	stream := make([]map[string]any, 0, len(events))
	for i, e := range events {
		if i >= 20 {
			break
		}
		stream = append(stream, eventToMap(e))
	}
	payload := map[string]any{
		"filters": map[string]any{"window": window, "protocol": protocol, "environment": environment},
		"kpis": map[string]any{
			"totalRiskCount":       len(events),
			"activeNodeCount":      s.activeNodeCount(ctx),
			"impactedRegionCount":  len(regionCodesHit),
			"successRate24h":       s.successRate24h(ctx),
			"dnsHighConfidenceCount": dnsHighConfidence,
			"protocolAnomalyCount": protocolAnomalyCount,
		},
		"globe": map[string]any{
			"points": points,
			"arcs": []map[string]any{},    // 目标地理坐标需 IP2Location BIN(P9 接入 geoip)
			"hotspots": []map[string]any{},
		},
		"charts": map[string]any{
			"protocolDistribution":  distribution(protocolCounter),
			"severityDistribution":  distribution(severityCounter),
			"confidenceDistribution": distribution(confidenceCounter),
			"timeline":              timeline,
		},
		"rankings": map[string]any{
			"topRiskDomains": withDrilldown(mostCommon(domainCounter, 8), "/network-probe/dns-trust?keyword=%s"),
			"topRiskRegions": withDrilldown(mostCommon(regionCounter, 8), "/network-probe/agents"),
			"topAnomalyTargets": mostCommon(targetCounter, 8),
		},
		"events": map[string]any{"stream": stream, "recentRuns": s.recentRuns(ctx, since)},
		"riskTypes": map[string]any{
			"summary":   map[string]any{"categoryCount": 0, "eventCount": 0, "highConfidenceCount": 0, "reviewRequiredCount": 0},
			"categories": []map[string]any{}, // DNS 风险分类依赖 P7 扫描器
		},
		"links": map[string]any{
			"dnsTrust": "/network-probe/dns-trust", "dnsScans": "/network-probe/dns-trust/scans",
			"agents": "/network-probe/agents", "networkProbe": "/network-probe",
		},
	}
	_ = lastDetectedAt
	riskBoardCache.set(cacheKey, payload)
	return payload
}

func withDrilldown(rows []map[string]any, pattern string) []map[string]any {
	for _, row := range rows {
		if name, ok := row["name"].(string); ok {
			row["drilldownUrl"] = fmt.Sprintf(pattern, name)
		}
	}
	return rows
}

func eventToMap(e riskEvent) map[string]any {
	data, _ := json.Marshal(e)
	out := map[string]any{}
	_ = json.Unmarshal(data, &out)
	return out
}

var _ = gorm.ErrRecordNotFound
