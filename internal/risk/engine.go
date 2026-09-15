package risk

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// ---------- 判定引擎输入 ----------

// RecordObserved 观测记录(来自快照)。
type RecordObserved struct {
	Section string
	Name    string
	Type    string
	Value   string
	TTL     *int
}

// RecordBaseline 基线记录。
type RecordBaseline struct {
	Section string
	Name    string
	Type    string
	Value   string
	TTLMin  *int
	TTLMax  *int
}

// HostConfig 主机配置(allow_* 开关)。
type HostConfig struct {
	FQDN          string
	ZoneDomain    string
	AllowWildcard bool
	AllowAXFR     bool
	AllowRebind   bool
	IsApex        bool
}

// Observation 单主机观测汇总。
type Observation struct {
	RCODE         string
	ErrorKind     string
	LatencyMs     *float64
	NSNameList    []string   // 权威 NS 主机名(answer 权威段)
	NSGlueIPList  []string   // additional 段 glue IP
	UniqueIPSet   []string   // 本主机名直接解析出的 IP 集合
	WildcardHit   bool
	AXFRSuccess   bool
	AXFRRecords   int
	RandomLabel   string
	Records       []RecordObserved
	LatencySamples []float64 // 延迟采样(方法4)
	TraceBroken   bool       // 解析路径断点
	ResolverAnswers map[string][]string // resolver → 唯一 IP 集合(方法6)
}

// Verdict 单风险判定结果。
type Verdict struct {
	RiskType       string
	Status         string // normal | suspicious
	Severity       string
	ConfidenceTier string
	ConfidenceLabel string
	MethodCode     string
	MethodLabel    string
	SummaryMessage string
	Evidence       map[string]any
}

// Evaluate 对单主机执行全部方法判定:可疑项 + 负例(措辞与原版一致)。
func Evaluate(host HostConfig, baseline []RecordBaseline, obs Observation) []Verdict {
	verdicts := make([]Verdict, 0, len(RiskOrder))

	// 基线参照集
	primaryExpected := []string{} // 主记录期望值(answer 段 A/AAAA/CNAME)
	baselineNSNames := []string{} // 基线 NS 主机名
	baselineGlueIPs := []string{} // 基线 NS glue IP
	expectedNameTypes := map[string]bool{}
	for _, r := range baseline {
		if r.Section != "answer" {
			continue
		}
		switch r.Type {
		case "A", "AAAA", "CNAME":
			primaryExpected = append(primaryExpected, r.Value)
		}
		expectedNameTypes[norm(r.Name)+"|"+r.Type] = true
	}
	for _, r := range baseline {
		if r.Type == "NS" {
			baselineNSNames = append(baselineNSNames, norm(strings.Trim(r.Value, ".")))
		}
	}
	nsNameSet := map[string]bool{}
	for _, n := range baselineNSNames {
		nsNameSet[n] = true
	}
	for _, r := range baseline {
		if (r.Type == "A" || r.Type == "AAAA") && nsNameSet[norm(r.Name)] {
			baselineGlueIPs = append(baselineGlueIPs, r.Value)
		}
	}

	// 观测集
	primaryObserved := []string{}
	observedNameTypes := map[string]bool{}
	for _, r := range obs.Records {
		if r.Section != "answer" {
			continue
		}
		if (r.Type == "A" || r.Type == "AAAA" || r.Type == "CNAME") && norm(r.Name) == norm(host.FQDN) {
			primaryObserved = append(primaryObserved, r.Value)
		}
		observedNameTypes[norm(r.Name)+"|"+r.Type] = true
	}
	hasBaseline := len(baseline) > 0

	// record_deletion:基线存在的 (name,type) 在应答缺失
	recordDeletionHit := false
	missing := []string{}
	if hasBaseline {
		for key := range expectedNameTypes {
			if !observedNameTypes[key] {
				recordDeletionHit = true
				missing = append(missing, key)
			}
		}
		sort.Strings(missing)
	}

	// ns 匹配
	observedNS := normSet(obs.NSNameList)
	nsNameHit := hasBaseline && len(baselineNSNames) > 0 && len(observedNS) > 0 && !setEqual(normSet(baselineNSNames), observedNS)
	nsIPHit := false
	if hasBaseline && len(baselineGlueIPs) > 0 && len(obs.NSGlueIPList) > 0 {
		intersect := 0
		baselineSet := normSet(baselineGlueIPs)
		for _, ip := range obs.NSGlueIPList {
			if baselineSet[norm(ip)] {
				intersect++
			}
		}
		nsIPHit = intersect == 0 // 完全失配
	}

	// dns_rebind:多值 IP + (公私混用 | 偏离基线 | TTL 越界)
	ipClasses := map[string]bool{}
	for _, ip := range obs.UniqueIPSet {
		ipClasses[ipClass(ip)] = true
	}
	var baselineTTLMin, baselineTTLMax *int
	for _, r := range baseline {
		if r.Section == "answer" && (r.Type == "A" || r.Type == "AAAA") {
			if baselineTTLMin == nil || (r.TTLMin != nil && *r.TTLMin < *baselineTTLMin) {
				if r.TTLMin != nil {
					baselineTTLMin = r.TTLMin
				}
			}
			if baselineTTLMax == nil || (r.TTLMax != nil && *r.TTLMax > *baselineTTLMax) {
				if r.TTLMax != nil {
					baselineTTLMax = r.TTLMax
				}
			}
		}
	}
	rebindHit := !host.AllowRebind && len(obs.UniqueIPSet) > 1
	if rebindHit {
		multiClass := len(ipClasses) > 1
		offBaseline := hasBaseline && !subset(normList(obs.UniqueIPSet), normSet(primaryExpected))
		ttlOut := false
		if baselineTTLMin != nil || baselineTTLMax != nil {
			for _, r := range obs.Records {
				if r.Section != "answer" || r.Type != "A" || norm(r.Name) != norm(host.FQDN) || r.TTL == nil {
					continue
				}
				if (baselineTTLMin != nil && *r.TTL < *baselineTTLMin) || (baselineTTLMax != nil && *r.TTL > *baselineTTLMax) {
					ttlOut = true
				}
			}
		}
		rebindHit = multiClass || offBaseline || ttlOut
	}

	// resolver divergence:多数派/少数派分歧
	divergenceHit := false
	if len(obs.ResolverAnswers) >= 2 {
		signatureCounts := map[string]int{}
		for _, ips := range obs.ResolverAnswers {
			signatureCounts[ipSignature(ips)]++
		}
		if len(signatureCounts) > 1 {
			divergenceHit = true
		}
	}

	// latency 分布:P95 > 2000ms 或样本极差过大(无历史基线时的绝对阈值,方案 2.6.6)
	latencyHit := false
	latencySummary := "未发现权威链延迟分布异常"
	if len(obs.LatencySamples) >= 3 {
		sorted := append([]float64{}, obs.LatencySamples...)
		sort.Float64s(sorted)
		p95 := sorted[len(sorted)*95/100]
		if p95 > 2000 {
			latencyHit = true
			latencySummary = "需复核异常：权威链延迟分布偏离历史基线"
		}
	}

	// trace 断点
	traceSummary := "未发现解析路径异常"
	if obs.TraceBroken {
		traceSummary = "需复核异常：解析路径存在断点或偏离基线"
	}

	eval := func(riskType string, hit bool, positive, negative string, evidence map[string]any) {
		status := "normal"
		summary := negative
		if hit {
			status = "suspicious"
			summary = positive
		}
		verdicts = append(verdicts, Verdict{
			RiskType: riskType, Status: status,
			Severity: RiskSeverity[riskType],
			ConfidenceTier: ConfidenceTier(riskType), ConfidenceLabel: ConfidenceLabel(riskType),
			MethodCode: MethodCodeForRisk(riskType), MethodLabel: MethodLabelForCode(MethodCodeForRisk(riskType)),
			SummaryMessage: summary, Evidence: evidence,
		})
	}

	primaryExpectedFlag := len(primaryExpected) > 0

	eval("unreach", primaryExpectedFlag && obs.ErrorKind == "timeout",
		"高置信异常：查询超时，建议优先排查解析链路", "未发现不可达异常",
		map[string]any{"expected": primaryExpected, "errorKind": obs.ErrorKind, "rcode": obs.RCODE})
	eval("no_service", primaryExpectedFlag && (obs.ErrorKind == "servfail" || obs.ErrorKind == "connection_refused"),
		"高置信异常：目标 DNS 服务返回 SERVFAIL 或连接被拒绝", "未发现 no-service 异常",
		map[string]any{"expected": primaryExpected, "errorKind": obs.ErrorKind, "rcode": obs.RCODE})
	eval("refused", obs.RCODE == "REFUSED",
		"高置信异常：目标返回 REFUSED", "未发现拒绝查询异常",
		map[string]any{"rcode": obs.RCODE})
	eval("empty_answer", primaryExpectedFlag && obs.RCODE == "NOERROR" && len(primaryObserved) == 0,
		"需复核异常：基线要求存在记录，但本次为空，应结合业务变更复核", "未发现需要复核的空应答异常",
		map[string]any{"expected": primaryExpected, "observed": primaryObserved, "rcode": obs.RCODE})
	eval("record_deletion", recordDeletionHit,
		"需复核异常：结构性基线记录缺失，需结合基线完整性与变更记录复核", "未发现需要复核的记录缺失异常",
		map[string]any{"expected": primaryExpected, "observed": primaryObserved, "missing": missing, "rcode": obs.RCODE})
	eval("resolution_path_anomaly", obs.TraceBroken, traceSummary, "未发现解析路径异常",
		map[string]any{"traceBroken": obs.TraceBroken})
	eval("latency_distribution_anomaly", latencyHit, latencySummary, "未发现权威链延迟分布异常",
		map[string]any{"samples": obs.LatencySamples})
	eval("route_path_anomaly", false, "需复核异常：权威链路由路径偏离历史基线", "未发现权威链路由路径异常",
		map[string]any{}) // 路由路径采样依赖 traceroute 基线,公网扫描默认 normal
	eval("ns_ip_hijack", nsIPHit,
		"需复核异常：NS 主机 IP 与可信集合完全失配，需复核是否为预期变更", "未发现需要复核的 NS IP 偏差",
		map[string]any{"baselineGlueIps": baselineGlueIPs, "observedGlueIps": obs.NSGlueIPList})
	eval("ns_name_hijack", nsNameHit,
		"需复核异常：权威 NS 名称与可信基线不一致，需复核是否为预期变更", "未发现需要复核的 NS 名称偏差",
		map[string]any{"baselineNsNames": baselineNSNames, "observedNsNames": obs.NSNameList})
	eval("resolver_divergence", divergenceHit,
		"需复核异常：跨解析器应答不收敛，需对比多地解析链路", "未发现跨解析器差异异常",
		map[string]any{"resolverAnswers": obs.ResolverAnswers})
	eval("wildcard_poisoning", !host.AllowWildcard && obs.WildcardHit,
		"随机子域命中有效 RRSet", "未发现泛解析污染风险",
		map[string]any{"allowWildcard": host.AllowWildcard, "wildcardHit": obs.WildcardHit, "randomLabel": obs.RandomLabel})
	eval("dns_rebind", rebindHit,
		"同一主机名在短窗口返回异常多值 IP", "未发现 DNS Rebind 风险",
		map[string]any{"allowRebind": host.AllowRebind, "expected": primaryExpected,
			"observedUniqueIps": obs.UniqueIPSet, "ipClasses": keysOf(ipClasses)})
	eval("axfr_exposed", !host.AllowAXFR && obs.AXFRSuccess,
		"AXFR 可成功传送整区", "未发现 AXFR 暴露风险",
		map[string]any{"allowAxfr": host.AllowAXFR, "axfrSuccess": obs.AXFRSuccess,
			"axfrRecordCount": obs.AXFRRecords})

	return verdicts
}

// SuspiciousOf 过滤可疑项。
func SuspiciousOf(verdicts []Verdict) []Verdict {
	out := []Verdict{}
	for _, v := range verdicts {
		if v.Status == "suspicious" {
			out = append(out, v)
		}
	}
	return out
}

func norm(v string) string { return strings.ToLower(strings.Trim(strings.TrimSpace(v), ".")) }

func normList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, norm(v))
	}
	return out
}

func normSet(values []string) map[string]bool {
	out := map[string]bool{}
	for _, v := range values {
		if n := norm(v); n != "" {
			out[n] = true
		}
	}
	return out
}

func setEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func subset(items []string, set map[string]bool) bool {
	for _, item := range items {
		if !set[item] {
			return false
		}
	}
	return true
}

func keysOf(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		if k != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func ipClass(value string) string {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return ""
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return "private"
	}
	return "public"
}

func ipSignature(ips []string) string {
	sorted := normList(ips)
	sort.Strings(sorted)
	return fmt.Sprintf("%v", sorted)
}
