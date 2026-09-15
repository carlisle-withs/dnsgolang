// Package risk 承载 14 类风险目录、6 类检测方法与判定引擎(Phase 7 核心,
// 规则逐条对齐原 dnsrisk/services.py 的 verdict 生成块)。
package risk

// RiskOrder 风险判定顺序(与原 RISK_ORDER 一致)。
var RiskOrder = []string{
	"unreach", "no_service", "refused", "empty_answer", "record_deletion",
	"resolution_path_anomaly", "latency_distribution_anomaly", "route_path_anomaly",
	"ns_ip_hijack", "ns_name_hijack", "resolver_divergence",
	"wildcard_poisoning", "dns_rebind", "axfr_exposed",
}

// RiskSeverity 与原 RISK_SEVERITY 一致。
var RiskSeverity = map[string]string{
	"unreach": "high", "no_service": "high", "refused": "high",
	"empty_answer": "medium", "record_deletion": "medium",
	"resolution_path_anomaly": "high", "latency_distribution_anomaly": "medium",
	"route_path_anomaly": "medium", "ns_ip_hijack": "medium", "ns_name_hijack": "medium",
	"resolver_divergence": "medium", "wildcard_poisoning": "high",
	"dns_rebind": "critical", "axfr_exposed": "high",
}

var highConfidenceRisks = map[string]bool{
	"unreach": true, "no_service": true, "refused": true,
}

var reviewRequiredRisks = map[string]bool{
	"empty_answer": true, "record_deletion": true, "resolution_path_anomaly": true,
	"latency_distribution_anomaly": true, "route_path_anomaly": true,
	"ns_ip_hijack": true, "ns_name_hijack": true, "resolver_divergence": true,
}

// RiskLabels 中文标签(set-analysis 契约)。
var RiskLabels = map[string]string{
	"unreach": "DNS 服务不可达", "no_service": "DNS 服务异常", "refused": "DNS 查询被拒绝",
	"empty_answer": "DNS 空应答", "record_deletion": "关键记录缺失",
	"resolution_path_anomaly": "解析路径异常", "latency_distribution_anomaly": "延迟分布异常",
	"route_path_anomaly": "路由路径异常", "ns_ip_hijack": "NS IP 异常",
	"ns_name_hijack": "NS 名称异常", "resolver_divergence": "跨解析器结果差异",
	"wildcard_poisoning": "泛解析异常", "dns_rebind": "DNS Rebind", "axfr_exposed": "AXFR 暴露",
}

// Method 检测方法目录(原 OWNERSHIP_METHOD_CATALOG)。
type Method struct {
	Code      string   `json:"code"`
	Label     string   `json:"label"`
	Desc      string   `json:"description"`
	RiskTypes []string `json:"riskTypes"`
}

var MethodCatalog = []Method{
	{"availability_baseline_validation", "服务可达性与记录基线校验",
		"通过可达性、RCODE 和主记录基线比对发现停服、拒绝服务、空应答与记录缺失。",
		[]string{"unreach", "no_service", "refused", "empty_answer", "record_deletion"}},
	{"authority_chain_integrity", "权威链完整性校验",
		"通过 NS / SOA / Glue / AXFR / 泛解析 等链路特征识别所有权相关权威链异常。",
		[]string{"ns_ip_hijack", "ns_name_hijack", "wildcard_poisoning", "dns_rebind", "axfr_exposed"}},
	{"resolution_path_analysis", "解析路径分析",
		"从 Root/TLD/Auth 逐跳追踪解析路径，识别关键路径失败、终端 NS 偏离和 Glue/Auth IP 完全失配。",
		[]string{"resolution_path_anomaly"}},
	{"latency_distribution_analysis", "延迟分布分析",
		"对终端权威 NS/Auth IP 进行多次 DNS 查询采样，基于历史正常基线识别延迟分布异常。",
		[]string{"latency_distribution_anomaly"}},
	{"route_path_analysis", "路由路径分析",
		"对终端权威 NS/Auth IP 执行 MTR/Traceroute，基于历史正常基线识别路径不可达、跳数和路径指纹异常。",
		[]string{"route_path_anomaly"}},
	{"cross_resolver_consensus", "跨解析器差异对比",
		"使用多家公共解析器交叉复核同一域名的应答是否收敛，用于识别运营实体间的异常解析差异。",
		[]string{"resolver_divergence"}},
}

// ConfidenceTier 风险置信分层。
func ConfidenceTier(riskType string) string {
	if highConfidenceRisks[riskType] {
		return "high_confidence"
	}
	if reviewRequiredRisks[riskType] {
		return "review_required"
	}
	return ""
}

// ConfidenceLabel 中文置信标签。
func ConfidenceLabel(riskType string) string {
	switch ConfidenceTier(riskType) {
	case "high_confidence":
		return "高置信异常"
	case "review_required":
		return "需复核异常"
	}
	return ""
}

// HighestConfidenceTier 多风险取最高置信。
func HighestConfidenceTier(riskTypes []string) string {
	highest := ""
	for _, item := range riskTypes {
		tier := ConfidenceTier(item)
		switch tier {
		case "high_confidence":
			return "high_confidence"
		case "review_required":
			highest = "review_required"
		}
	}
	return highest
}

// HighestSeverity 多风险取最高严重度。
func HighestSeverity(riskTypes []string) string {
	rank := map[string]int{"": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	highest := ""
	for _, item := range riskTypes {
		if rank[RiskSeverity[item]] > rank[highest] {
			highest = RiskSeverity[item]
		}
	}
	return highest
}

// MethodCodeForRisk 风险 → 方法编码。
func MethodCodeForRisk(riskType string) string {
	for _, m := range MethodCatalog {
		for _, r := range m.RiskTypes {
			if r == riskType {
				return m.Code
			}
		}
	}
	return ""
}

// MethodLabelForCode 方法编码 → 中文名。
func MethodLabelForCode(code string) string {
	for _, m := range MethodCatalog {
		if m.Code == code {
			return m.Label
		}
	}
	return ""
}

// SeverityRank 严重度排序权重。
func SeverityRank(severity string) int {
	switch severity {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}
