package service

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// ---------- 被动告警总览(Phase 5 骨架) ----------
// 原版依赖第二数据源(PASSIVE_ALERTS_DB_* 独立库);按方案 2.3 决策,
// Go 版一期返回 preset 演示数据 + 空骨架,表结构延后定义。

var passiveAlertTypeLabels = map[string]string{
	"gtld error":      "GTLD 解析异常",
	"abroad cn error": "境外解析 .cn 异常",
	"ip hijack":       "IP 劫持疑似",
	"ns hijack":       "NS 委派异常",
	"dga":             "DGA 域名活动",
	"nxDomain flood":  "NXDOMAIN 洪水",
}

type presetAlert struct {
	id          int
	alertType   string
	queryDomain string
	serverIP    string
	queryType   string
	rcode       string
	comments    string
}

// PUBLIC_PRESET_PASSIVE_ALERTS 与原演示数据一致。
var publicPresetAlerts = []presetAlert{
	{9001001, "gtld error", "critical-pay.demo.example", "198.51.100.53", "A", "SERVFAIL",
		"境外节点访问 GTLD 链路异常，建议进入案例1主动核实。"},
	{9001002, "abroad cn error", "cdn-edge.demo.example", "203.0.113.53", "A", "TIMEOUT",
		"跨区域解析失败，辅助案例1形成局部路径异常判断。"},
	{9002001, "ip hijack", "sso.demo.example", "192.0.2.53", "A", "NOERROR",
		"A 记录疑似导向非授权地址，建议进入案例2解析链核实。"},
	{9002002, "ns hijack", "finance.demo.example", "192.0.2.54", "NS", "NOERROR",
		"NS 委派疑似偏离基线，辅助案例2综合研判。"},
	{9003001, "dga", "x7f3a91c2e8.demo.example", "198.51.100.88", "A", "NOERROR",
		"算法生成域名特征命中，建议结合被动日志扩线分析。"},
	{9003002, "nxDomain flood", "miss-<random>.demo.example", "203.0.113.90", "A", "NXDOMAIN",
		"短时 NXDOMAIN 占比异常升高，疑似子域枚举探测。"},
}

// PassiveAlertsFilters 镜像原 PassiveAlertsQuerySerializer。
type PassiveAlertsFilters struct {
	Window    string
	Start     string
	End       string
	AlertType string
	Keyword   string
	Page      int
	Size      int
	Preset    string
}

func (f *PassiveAlertsFilters) normalize() {
	if f.Window != "1h" && f.Window != "24h" && f.Window != "7d" {
		f.Window = "24h"
	}
	if f.Page < 1 {
		f.Page = 1
	}
	if f.Size < 1 || f.Size > 100 {
		f.Size = 20
	}
}

var passiveWindowDeltas = map[string]time.Duration{"1h": time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour}

// BuildPassiveAlertsOverview preset=public 返回演示数据;否则返回空骨架。
func BuildPassiveAlertsOverview(filters PassiveAlertsFilters) map[string]any {
	filters.normalize()
	if filters.Preset == "public" {
		return publicPresetOverview(filters)
	}
	return emptyPassiveOverview(filters)
}

func passiveTypeLabel(code string) string {
	if label, ok := passiveAlertTypeLabels[code]; ok {
		return label
	}
	return code
}

func passiveFormat(t time.Time) string { return isoFormat(t) }

func publicPresetOverview(filters PassiveAlertsFilters) map[string]any {
	now := time.Now().Truncate(time.Second)
	rows := make([]map[string]any, 0, len(publicPresetAlerts))
	for index, item := range publicPresetAlerts {
		eventTime := now.Add(-time.Duration(index*7) * time.Minute)
		rawContent, _ := json.Marshal(map[string]any{
			"type": item.alertType,
			"time": isoFormat(eventTime),
			"data": map[string]any{
				"querydomain": item.queryDomain, "serverip": item.serverIP,
				"querytype": item.queryType, "rcode": item.rcode, "comments": item.comments,
			},
		})
		rows = append(rows, map[string]any{
			"id": item.id, "alertType": item.alertType,
			"alertTypeLabel": passiveTypeLabel(item.alertType),
			"createTime": isoFormat(eventTime), "eventTime": isoFormat(eventTime),
			"queryDomain": item.queryDomain, "serverIp": item.serverIP,
			"queryType": item.queryType, "rcode": item.rcode, "comments": item.comments,
			"rawValid": true, "rawContent": string(rawContent),
		})
	}
	if filters.AlertType != "" {
		filtered := rows[:0]
		for _, row := range rows {
			if row["alertType"] == filters.AlertType {
				filtered = append(filtered, row)
			}
		}
		rows = filtered
	}
	if filters.Keyword != "" {
		keyword := filters.Keyword
		filtered := rows[:0]
		for _, row := range rows {
			if containsFold(row["queryDomain"].(string), keyword) ||
				containsFold(row["serverIp"].(string), keyword) ||
				containsFold(row["alertType"].(string), keyword) {
				filtered = append(filtered, row)
			}
		}
		rows = filtered
	}
	total := len(rows)
	startIdx := (filters.Page - 1) * filters.Size
	if startIdx > total {
		startIdx = total
	}
	endIdx := startIdx + filters.Size
	if endIdx > total {
		endIdx = total
	}

	typeCounts := map[string]int{}
	rcodeCounts := map[string]int{}
	queryTypeCounts := map[string]int{}
	domainSet := map[string]bool{}
	serverSet := map[string]bool{}
	for _, row := range rows {
		typeCounts[row["alertType"].(string)]++
		rcodeCounts[row["rcode"].(string)]++
		queryTypeCounts[row["queryType"].(string)]++
		domainSet[row["queryDomain"].(string)] = true
		serverSet[row["serverIp"].(string)] = true
	}
	alertTypeOptions := make([]map[string]any, 0, len(typeCounts))
	for _, item := range publicPresetAlerts {
		if count, ok := typeCounts[item.alertType]; ok {
			alertTypeOptions = append(alertTypeOptions, map[string]any{
				"code": item.alertType, "name": passiveTypeLabel(item.alertType), "count": count,
			})
		}
	}

	// 时间线:7 分钟一档(与 preset 生成节奏一致)
	timeline := []map[string]any{}
	if total > 0 {
		for i := 0; i < 7; i++ {
			timeline = append(timeline, map[string]any{
				"name":  now.Add(-time.Duration(i*7) * time.Minute).Format("01-02 15:00"),
				"value": countInBucket(rows, now, i*7, (i+1)*7),
			})
		}
	}
	latest := any("")
	if len(rows) > 0 {
		latest = rows[0]["eventTime"]
	}
	return map[string]any{
		"filters": map[string]any{
			"window": filters.Window,
			"start":  passiveFormat(now.Add(-passiveWindowDeltas[filters.Window])),
			"end":    passiveFormat(now),
			"alertType": filters.AlertType, "keyword": filters.Keyword,
			"page": filters.Page, "size": filters.Size,
		},
		"summary": map[string]any{
			"totalAlerts": total, "alertTypeCount": len(typeCounts),
			"domainCount": len(domainSet), "serverIpCount": len(serverSet),
			"latestAlertTime": latest,
		},
		"options": map[string]any{
			"windows": []map[string]string{
				{"code": "1h", "name": "最近 1 小时"}, {"code": "24h", "name": "最近 24 小时"}, {"code": "7d", "name": "最近 7 天"},
			},
			"alertTypes": alertTypeOptions,
		},
		"charts": map[string]any{
			"timelineGranularity": "minute",
			"timeline":            timeline,
			"typeDistribution":    typeDistRows(typeCounts),
			"rcodeDistribution":   nameValueRows(rcodeCounts),
			"queryTypeDistribution": nameValueRows(queryTypeCounts),
		},
		"rankings": map[string]any{
			"topDomains":   topByCounter(domainCountFromRows(rows), 10),
			"topServerIps": topByCounter(serverCountFromRows(rows), 10),
		},
		"rows": rows[startIdx:endIdx],
		"pagination": map[string]any{
			"page": filters.Page, "size": filters.Size, "total": total,
			"totalPages": (total + filters.Size - 1) / filters.Size,
		},
		"performance": map[string]any{
			"timeIndexed": true, "topLimit": 10, "detailPaginated": true,
			"largeRange": passiveWindowDeltas[filters.Window] > 7*24*time.Hour,
		},
	}
}

func countInBucket(rows []map[string]any, now time.Time, fromMin, toMin int) int {
	count := 0
	for _, row := range rows {
		if eventTime, ok := row["eventTime"].(string); ok && eventTime != "" {
			if t, err := time.ParseInLocation("2006-01-02T15:04:05", eventTime, time.Local); err == nil {
				age := now.Sub(t).Minutes()
				if age >= float64(fromMin) && age < float64(toMin) {
					count++
				}
			}
		}
	}
	return count
}

func containsFold(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOfFold(s, sub) >= 0)
}

func indexOfFold(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if equalFold(s[i:i+len(sub)], sub) {
			return i
		}
	}
	return -1
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func typeDistRows(counter map[string]int) []map[string]any {
	out := make([]map[string]any, 0, len(counter))
	for code, count := range counter {
		out = append(out, map[string]any{"name": passiveTypeLabel(code), "code": code, "value": count})
	}
	return out
}

func nameValueRows(counter map[string]int) []map[string]any {
	rows := make([]map[string]any, 0, len(counter))
	for k, v := range counter {
		rows = append(rows, map[string]any{"name": k, "value": v})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i]["value"].(int) > rows[j]["value"].(int) })
	return rows
}

func domainCountFromRows(rows []map[string]any) map[string]int {
	out := map[string]int{}
	for _, row := range rows {
		out[row["queryDomain"].(string)]++
	}
	return out
}

func serverCountFromRows(rows []map[string]any) map[string]int {
	out := map[string]int{}
	for _, row := range rows {
		out[row["serverIp"].(string)]++
	}
	return out
}

func topByCounter(counter map[string]int, limit int) []map[string]any {
	rows := make([]map[string]any, 0, len(counter))
	for k, v := range counter {
		rows = append(rows, map[string]any{"name": k, "value": v})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i]["value"].(int) > rows[j]["value"].(int) })
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

func emptyPassiveOverview(filters PassiveAlertsFilters) map[string]any {
	now := time.Now()
	return map[string]any{
		"filters": map[string]any{
			"window": filters.Window,
			"start":  passiveFormat(now.Add(-passiveWindowDeltas[filters.Window])),
			"end":    passiveFormat(now),
			"alertType": filters.AlertType, "keyword": filters.Keyword,
			"page": filters.Page, "size": filters.Size,
		},
		"summary": map[string]any{
			"totalAlerts": 0, "alertTypeCount": 0, "domainCount": 0,
			"serverIpCount": 0, "latestAlertTime": nil,
		},
		"options": map[string]any{
			"windows": []map[string]string{
				{"code": "1h", "name": "最近 1 小时"}, {"code": "24h", "name": "最近 24 小时"}, {"code": "7d", "name": "最近 7 天"},
			},
			"alertTypes": []map[string]any{},
		},
		"charts": map[string]any{
			"timelineGranularity": "minute", "timeline": []map[string]any{},
			"typeDistribution": []map[string]any{}, "rcodeDistribution": []map[string]any{},
			"queryTypeDistribution": []map[string]any{},
		},
		"rankings": map[string]any{"topDomains": []map[string]any{}, "topServerIps": []map[string]any{}},
		"rows":     []map[string]any{},
		"pagination": map[string]any{
			"page": filters.Page, "size": filters.Size, "total": 0, "totalPages": 0,
		},
		"performance": map[string]any{
			"timeIndexed": true, "topLimit": 10, "detailPaginated": true,
			"largeRange": passiveWindowDeltas[filters.Window] > 7*24*time.Hour,
		},
		"note": fmt.Sprintf("被动告警数据源未接入(P9),preset=public 可查看演示数据"),
	}
}
