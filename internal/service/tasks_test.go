package service

import (
	"strings"
	"testing"
	"time"

	"github.com/robfig/cron/v3"
)

func TestValidateCron(t *testing.T) {
	if err := validateCron("*/5 * * * *"); err != nil {
		t.Errorf("合法 cron 被拒绝: %v", err)
	}
	if err := validateCron("* * * *"); err == nil {
		t.Error("4 段 cron 应被拒绝")
	}
}

func TestNextCronRun(t *testing.T) {
	base := time.Date(2026, 9, 15, 10, 0, 0, 0, time.Local)
	next, err := nextCronRun("*/5 * * * *", base)
	if err != nil {
		t.Fatal(err)
	}
	if next.Sub(base) != 5*time.Minute {
		t.Errorf("next=%v want +5min", next)
	}
}

func TestDomainRegexMatchesOriginal(t *testing.T) {
	// 与原版 DOMAIN_RE 行为对齐(RE2 等价改写)
	valid := []string{"example.com", "a-b.example.co.uk", "xn--fiqs8s.example"}
	invalid := []string{"http://example.com", "-bad.example.com", "example.1a", "example"}
	for _, v := range valid {
		if !isDomain(v) {
			t.Errorf("%s 应为合法域名", v)
		}
	}
	for _, v := range invalid {
		if isDomain(v) {
			t.Errorf("%s 应为非法域名", v)
		}
	}
}

func TestIPv4Regex(t *testing.T) {
	if !ipv4Re.MatchString("211.68.69.240") {
		t.Error("合法 IPv4 被拒绝")
	}
	if ipv4Re.MatchString("999.1.1.1") || ipv4Re.MatchString("a.b.c.d") {
		t.Error("非法 IPv4 未被拒绝")
	}
}

func TestMarshalJSONString(t *testing.T) {
	if got := marshalJSON([]string{"a", "b"}); !strings.Contains(got, `"a"`) {
		t.Errorf("序列化错误: %s", got)
	}
	_ = cron.ParseStandard // 确认依赖可用
}
