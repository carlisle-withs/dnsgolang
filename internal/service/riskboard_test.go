package service

import (
	"testing"
)

// 契约红线:异常判定阈值与原 risk_board.py 分类函数一致。
func TestProtocolAnomalyHTTP(t *testing.T) {
	cases := []struct {
		success   bool
		errorCode string
		detail    map[string]any
		severity  string
		summary   string
	}{
		{false, "http_timeout", nil, "high", "HTTP 失败或超时"},
		{true, "", map[string]any{"httpStatus": float64(502)}, "high", "HTTP 5xx 异常"},
		{true, "", map[string]any{"httpStatus": float64(200), "totalMs": 1600.0}, "medium", "HTTP 延迟偏高"},
		{true, "", map[string]any{"httpStatus": float64(200), "totalMs": 100.0}, "", ""},
	}
	for _, c := range cases {
		severity, summary := protocolAnomaly("http", c.success, c.errorCode, c.detail, nil)
		if severity != c.severity || (severity != "" && summary != c.summary) {
			t.Errorf("case %+v: got (%s,%s) want (%s,%s)", c, severity, summary, c.severity, c.summary)
		}
	}
}

func TestProtocolAnomalyPING(t *testing.T) {
	if s, _ := protocolAnomaly("ping", false, "ping_failed", nil, nil); s != "high" {
		t.Errorf("失败应 high, got %s", s)
	}
	if s, _ := protocolAnomaly("ping", true, "", map[string]any{"lossPct": 25.0}, nil); s != "medium" {
		t.Errorf("丢包≥20 应 medium, got %s", s)
	}
	avg := 400.0
	if s, _ := protocolAnomaly("ping", true, "", map[string]any{"avgMs": avg}, nil); s != "medium" {
		t.Errorf("延迟≥300 应 medium, got %s", s)
	}
	if s, _ := protocolAnomaly("ping", true, "", map[string]any{"avgMs": 50.0}, nil); s != "" {
		t.Errorf("正常应无异常, got %s", s)
	}
}

func TestProtocolAnomalyRoute(t *testing.T) {
	// mtr:未达目标 → high
	if s, _ := protocolAnomaly("mtr", true, "", map[string]any{"destinationReached": false}, nil); s != "high" {
		t.Errorf("MTR 未达目标应 high, got %s", s)
	}
	// traceroute:跳数超限 → medium
	if s, _ := protocolAnomaly("traceroute", true, "", map[string]any{"destinationReached": true, "hopCount": float64(25)}, nil); s != "medium" {
		t.Errorf("Traceroute 跳数偏高应 medium, got %s", s)
	}
}

func TestNormalizeWindowProtocol(t *testing.T) {
	if normalizeWindow("bogus") != "24h" || normalizeWindow("7d") != "7d" {
		t.Error("window 归一化错误")
	}
	if normalizeProtocol("bogus") != "all" || normalizeProtocol("mtr") != "mtr" {
		t.Error("protocol 归一化错误")
	}
}

func TestNonDNSProtocols(t *testing.T) {
	if len(nonDNSProtocols("dns")) != 0 {
		t.Error("dns 过滤应排除全部协议事件")
	}
	if len(nonDNSProtocols("http")) != 1 || nonDNSProtocols("http")[0] != "http" {
		t.Error("单协议过滤错误")
	}
	if len(nonDNSProtocols("all")) != 4 {
		t.Error("all 应含 http/ping/mtr/traceroute")
	}
}

func TestPassivePresetOverview(t *testing.T) {
	payload := BuildPassiveAlertsOverview(PassiveAlertsFilters{Preset: "public", Window: "24h"})
	summary := payload["summary"].(map[string]any)
	if summary["totalAlerts"].(int) != 6 {
		t.Errorf("preset 应有 6 条演示数据, got %v", summary["totalAlerts"])
	}
	filters := payload["filters"].(map[string]any)
	if filters["window"] != "24h" {
		t.Error("window 回显错误")
	}

	// 类型过滤
	filtered := BuildPassiveAlertsOverview(PassiveAlertsFilters{Preset: "public", AlertType: "ip hijack"})
	if filtered["summary"].(map[string]any)["totalAlerts"].(int) != 1 {
		t.Error("alert_type 过滤错误")
	}

	// 空骨架
	empty := BuildPassiveAlertsOverview(PassiveAlertsFilters{Window: "1h"})
	if empty["summary"].(map[string]any)["totalAlerts"].(int) != 0 {
		t.Error("非 preset 应返回空骨架")
	}
}
