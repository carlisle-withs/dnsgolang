package service

import (
	"testing"
)

// 契约红线:批量输入规范化(2.5.2)与原 parse_batch_input 行为一致。
func TestParseBatchInputText(t *testing.T) {
	parsed, err := ParseBatchInput("text", "example.com\n# 注释\nbad_域名\nEXAMPLE.com.\nexample2.com", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Stats.ValidTargetCount != 2 {
		t.Errorf("有效数=%d want 2(example.com 重复算 duplicate)", parsed.Stats.ValidTargetCount)
	}
	if parsed.Stats.DuplicateCount != 1 {
		t.Errorf("重复数=%d want 1(大小写/尾点归一后重复)", parsed.Stats.DuplicateCount)
	}
	if parsed.Stats.InvalidTargetCount != 1 {
		t.Errorf("无效数=%d want 1", parsed.Stats.InvalidTargetCount)
	}
	if parsed.Stats.TotalInputCount != 4 {
		t.Errorf("总数=%d want 4(注释行不计)", parsed.Stats.TotalInputCount)
	}
}

func TestParseBatchInputEmpty(t *testing.T) {
	if _, err := ParseBatchInput("text", "\n\n# 只有注释\n", "", nil); err == nil {
		t.Error("空输入应报错")
	}
}

func TestParseBatchInputCSVHeader(t *testing.T) {
	csv := "domain,note\nexample.com,x\nbad!,y\n"
	parsed, err := ParseBatchInput("file", "", "list.csv", []byte(csv))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Stats.ValidTargetCount != 1 || parsed.Stats.InvalidTargetCount != 1 {
		t.Errorf("CSV 解析错误: %+v", parsed.Stats)
	}
}

func TestBatchDomainValidation(t *testing.T) {
	valid := []string{"example.com", "a-b.example.co.uk", "xn--fiqs8s.example"}
	invalid := []string{"https://example.com", "-bad.com", "example", "example.1", ""}
	for _, v := range valid {
		if !IsValidBatchDomain(NormalizeBatchDomain(v)) {
			t.Errorf("%s 应为合法批量域名", v)
		}
	}
	for _, v := range invalid {
		if IsValidBatchDomain(NormalizeBatchDomain(v)) {
			t.Errorf("%s 应为非法批量域名", v)
		}
	}
}

func TestExpandBatchProtocols(t *testing.T) {
	if len(expandBatchProtocols("all")) != 5 {
		t.Error("all 应展开为五协议")
	}
	if expandBatchProtocols("dns")[0] != "dns" {
		t.Error("单协议应保持不变")
	}
}

func TestBuildBatchResultCode(t *testing.T) {
	cases := []struct {
		protocol string
		success  bool
		rcode    string
		errorCode string
		want     string
	}{
		{"dns", false, "NXDOMAIN", "", "NXDOMAIN"},
		{"dns", false, "", "timeout", "timeout"},
		{"ping", true, "", "", "PING_OK"},
		{"ping", false, "", "", "PING_FAILED"},
		{"mtr", false, "", "mtr_incomplete", "mtr_incomplete"},
	}
	for _, c := range cases {
		got := buildBatchResultCode(c.protocol, probeResultFor(c.success, c.rcode, c.errorCode))
		if got != c.want {
			t.Errorf("resultCode(%s)=%s want %s", c.protocol, got, c.want)
		}
	}
}
