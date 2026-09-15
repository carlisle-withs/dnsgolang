package service

import (
	"strings"
	"testing"

	"dnsss/internal/model"
)

// 契约红线:manifest 解析(auto/json/yaml)与归一化行为对齐原版。
func TestParseManifestJSON(t *testing.T) {
	text := `[{"domain":"example.com","owner":"ops","key_hosts":[{"fqdn":"www.example.com","notes":"web"}]}]`
	items, format, err := parseManifest(text, "auto")
	if err != nil {
		t.Fatal(err)
	}
	if format != "json" || len(items) != 1 {
		t.Fatalf("format=%s items=%d", format, len(items))
	}
	normalized, env, err := normalizeManifest(items)
	if err != nil {
		t.Fatal(err)
	}
	if env != "prod" {
		t.Errorf("environment=%s want prod", env)
	}
	// apex 主机应被自动补齐
	if len(normalized[0].KeyHosts) != 2 || normalized[0].KeyHosts[0].FQDN != "example.com" {
		t.Errorf("apex 主机补齐失败: %+v", normalized[0].KeyHosts)
	}
	if normalized[0].KeyHosts[1].FQDN != "www.example.com" {
		t.Errorf("key_hosts 顺序错误")
	}
}

func TestParseManifestYAMLSubset(t *testing.T) {
	text := `- domain: example.com
  owner: ops
  importance: critical
  key_hosts:
  - fqdn: www.example.com
    notes: web
  - fqdn: mail.example.com
`
	items, format, err := parseManifest(text, "auto")
	if err != nil {
		t.Fatal(err)
	}
	if format != "yaml" || len(items) != 1 {
		t.Fatalf("format=%s items=%d err=%v", format, len(items), err)
	}
	normalized, _, err := normalizeManifest(items)
	if err != nil {
		t.Fatal(err)
	}
	// apex + www + mail = 3
	if len(normalized[0].KeyHosts) != 3 {
		t.Errorf("主机数=%d want 3(含 apex)", len(normalized[0].KeyHosts))
	}
	if normalized[0].Importance != "critical" || normalized[0].Owner != "ops" {
		t.Errorf("字段解析错误: %+v", normalized[0])
	}
}

func TestParseManifestBareDomainList(t *testing.T) {
	text := "- example.com\n- foo.org\n"
	items, _, err := parseManifest(text, "yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].Domain != "example.com" {
		t.Errorf("裸域名列表解析错误: %+v", items)
	}
}

func TestParseManifestEnvConflict(t *testing.T) {
	text := `[{"domain":"a.com","environment":"prod"},{"domain":"b.com","environment":"lab"}]`
	items, _, err := parseManifest(text, "json")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := normalizeManifest(items); err == nil {
		t.Error("混合环境应报错")
	}
}

func TestParseManifestEmpty(t *testing.T) {
	if _, _, err := parseManifest("  ", "auto"); err == nil {
		t.Error("空清单应报错")
	}
}

// parseRRLine:与原 parse_rr_line 一致的 dig 行解析。
func TestParseRRLine(t *testing.T) {
	row := parseRRLine("www.example.test. 300 IN CNAME example.test.", "answer")
	if row == nil {
		t.Fatal("解析失败")
	}
	if row.RRName != "www.example.test" || row.RRType != "CNAME" || row.RRValue != "example.test." {
		t.Errorf("字段错误: %+v", row)
	}
	if row.TTL == nil || *row.TTL != 300 {
		t.Errorf("TTL 解析错误: %v", row.TTL)
	}
	if parseRRLine("too short", "answer") != nil {
		t.Error("非法行应返回 nil")
	}
	// 与原版一致:恰好 4 段(缺 value)返回空 value 行,不足 4 段返回 nil
	if row := parseRRLine("example.test. 300 IN A", "answer"); row == nil || row.RRValue != "" {
		t.Errorf("缺 value 的行应返回空 value 行: %+v", row)
	}
}

func TestBuildHostDiscoveryPlan(t *testing.T) {
	apex := fakeTrustHost("example.com", "")
	if plan := buildHostDiscoveryPlan(apex, "example.com"); len(plan) != 6 {
		t.Errorf("apex 计划应 6 步(A/AAAA/NS/SOA/random/AXFR), got %d", len(plan))
	}
	nsHost := fakeTrustHost("ns1.example.com", "role=ns_host; auto discovered")
	if plan := buildHostDiscoveryPlan(nsHost, "example.com"); len(plan) != 2 {
		t.Errorf("NS 主机计划应 2 步, got %d", len(plan))
	}
	sub := fakeTrustHost("www.example.com", "")
	if plan := buildHostDiscoveryPlan(sub, "example.com"); len(plan) != 3 {
		t.Errorf("子域计划应 3 步(A/AAAA/CNAME), got %d", len(plan))
	}
}

func fakeTrustHost(fqdn, notes string) (h model.TrustHost) {
	h.FQDN = fqdn
	h.Notes = notes
	return h
}

func TestRRExactAndGroupKeys(t *testing.T) {
	a := rrExactKey("answer", "WWW.Example.COM.", "a", " 1.2.3.4 ")
	b := rrExactKey("answer", "www.example.com", "A", "1.2.3.4")
	if a != b {
		t.Errorf("归一化键不一致:\n%s\n%s", a, b)
	}
	if rrGroupKey("answer", "www.example.com", "A") == rrGroupKey("answer", "www.example.com", "CNAME") {
		t.Error("不同类型不应同组")
	}
}

func TestBuildChunkManifest(t *testing.T) {
	manifest := buildChunkManifest([]string{"example.com", "foo.org"})
	if !strings.Contains(manifest, `"domain":"example.com"`) {
		t.Errorf("清单生成错误: %s", manifest)
	}
}
