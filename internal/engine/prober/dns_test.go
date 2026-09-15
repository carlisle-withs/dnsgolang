package prober

import (
	"testing"
)

// 契约红线:选项清洗与 clamp 规则必须与原 clean_dns_probe_options 一致。
func TestCleanDNSOptions(t *testing.T) {
	opts, err := CleanDNSOptions("www.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if opts.Resolver != "8.8.8.8" || opts.RecordType != "A" || opts.Timeout != 3 {
		t.Errorf("默认值错误: %+v", opts)
	}
	if !opts.EDNS || opts.DNSSEC || opts.RandomLabel {
		t.Errorf("布尔默认值错误: %+v", opts)
	}
	if len(opts.QueryPlan) != 1 || opts.QueryPlan[0].QueryName != "www.example.com" {
		t.Errorf("查询计划错误: %+v", opts.QueryPlan)
	}
	if opts.ZoneDomain != "example.com" {
		t.Errorf("zone_domain=%s want example.com", opts.ZoneDomain)
	}
}

func TestCleanDNSOptionsClamps(t *testing.T) {
	opts, err := CleanDNSOptions("www.example.com", map[string]any{
		"timeout": 99, "repeat_count": 99, "trace_max_hops": 99,
		"trace_max_ns_per_hop": 0, "latency_sample_count": 0, "route_max_hops": 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Timeout != 20 || opts.RepeatCount != 5 || opts.TraceMaxHops != 8 {
		t.Errorf("上限 clamp 失败: %+v", opts)
	}
	if opts.TraceMaxNSPerHop != 3 || opts.LatencySampleCount != 5 || opts.RouteMaxHops != 3 {
		t.Errorf("下限 clamp 失败: %+v", opts)
	}
}

func TestCleanDNSOptionsRejects(t *testing.T) {
	if _, err := CleanDNSOptions("a.com", map[string]any{"record_type": "ZZZ"}); err == nil {
		t.Error("非法 record_type 应报错")
	}
	if _, err := CleanDNSOptions("a.com", map[string]any{"transport": "icmp"}); err == nil {
		t.Error("非法 transport 应报错")
	}
	if _, err := CleanDNSOptions("a.com", map[string]any{"server_mode": "middle"}); err == nil {
		t.Error("非法 server_mode 应报错")
	}
}

func TestCleanDNSOptionsAXFRForcesTCP(t *testing.T) {
	opts, err := CleanDNSOptions("example.com", map[string]any{"record_type": "AXFR", "transport": "udp"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.QueryPlan[0].Transport != "tcp" {
		t.Errorf("AXFR 必须强制 tcp, got %s", opts.QueryPlan[0].Transport)
	}
}

func TestCleanDNSOptionsDerivedDefaults(t *testing.T) {
	opts, err := CleanDNSOptions("a.com", map[string]any{"compare_with_trust": true})
	if err != nil {
		t.Fatal(err)
	}
	if !opts.TraceResolutionPath || !opts.AuthorityMethodAnalysis {
		t.Errorf("compare_with_trust=true 应派生开启 trace 与 authority 分析: %+v", opts)
	}
}

func TestNormalizeQueryStepRandomLabel(t *testing.T) {
	step, err := normalizeQueryStep(map[string]any{
		"query_name": "example.com.", "record_type": "a", "random_label": true,
	}, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if step.RecordType != "A" || step.QueryName != "example.com" || !step.RandomLabel {
		t.Errorf("step 规范化错误: %+v", step)
	}
}
