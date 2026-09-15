package prober

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"dnsss/internal/engine/dnsclient"
)

var validRecordTypes = map[string]bool{
	"A": true, "AAAA": true, "CNAME": true, "MX": true, "NS": true,
	"TXT": true, "SOA": true, "PTR": true, "AXFR": true,
}

// QueryStep 查询计划单步(对应原 normalize_dns_query_step)。
type QueryStep struct {
	QueryName    string `json:"query_name"`
	RecordType   string `json:"record_type"`
	Transport    string `json:"transport"`
	ServerMode   string `json:"server_mode"`
	RepeatCount  int    `json:"repeat_count"`
	EDNS         bool   `json:"edns"`
	DNSSEC       bool   `json:"dnssec"`
	RandomLabel  bool   `json:"random_label,omitempty"`
}

// DNSOptions 清洗后的 DNS 拨测选项(对应原 clean_dns_probe_options)。
type DNSOptions struct {
	Resolver                 string     `json:"resolver"`
	RecordType               string     `json:"record_type"`
	Timeout                  float64    `json:"timeout"`
	Transport                string     `json:"transport"`
	ServerMode               string     `json:"server_mode"`
	RepeatCount              int        `json:"repeat_count"`
	EDNS                     bool       `json:"edns"`
	DNSSEC                   bool       `json:"dnssec"`
	RandomLabel              bool       `json:"random_label"`
	CompareWithTrust         bool       `json:"compare_with_trust"`
	TraceResolutionPath      bool       `json:"trace_resolution_path"`
	TraceRootServers         []string   `json:"trace_root_servers"`
	TraceMaxHops             int        `json:"trace_max_hops"`
	TraceMaxNSPerHop         int        `json:"trace_max_ns_per_hop"`
	AuthorityMethodAnalysis  bool       `json:"authority_method_analysis"`
	LatencySampleCount       int        `json:"latency_sample_count"`
	RouteMaxHops             int        `json:"route_max_hops"`
	QueryPlan                []QueryStep `json:"query_plan"`
	ZoneDomain               string     `json:"zone_domain"`
}

func clampInt(v, min, max, fallback int) int {
	if v == 0 {
		v = fallback
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func toFloat(v any, fallback float64) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case string:
		var f float64
		if _, err := fmt.Sscanf(n, "%g", &f); err == nil {
			return f
		}
	}
	return fallback
}

func toInt(v any, fallback int) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case bool:
		return fallback
	case string:
		var i int
		if _, err := fmt.Sscanf(n, "%d", &i); err == nil {
			return i
		}
	}
	return fallback
}

func toBool(v any, fallback bool) bool {
	switch b := v.(type) {
	case bool:
		return b
	case string:
		switch strings.ToLower(b) {
		case "true", "1", "yes":
			return true
		case "false", "0", "no", "":
			return false
		}
	}
	return fallback
}

// CleanDNSOptions 校验并补全 DNS 拨测选项;非法值返回错误(与原 ValueError 对应)。
func CleanDNSOptions(target string, options map[string]any) (*DNSOptions, error) {
	if options == nil {
		options = map[string]any{}
	}
	recordType := strings.ToUpper(str(options["record_type"], "A"))
	if !validRecordTypes[recordType] {
		return nil, fmt.Errorf("unsupported dns record type: %s", recordType)
	}
	transport := strings.ToLower(str(options["transport"], "udp"))
	if transport != "udp" && transport != "tcp" {
		return nil, fmt.Errorf("unsupported dns transport: %s", transport)
	}
	serverMode := strings.ToLower(str(options["server_mode"], "resolver"))
	if serverMode != "resolver" && serverMode != "authoritative" {
		return nil, fmt.Errorf("unsupported dns server mode: %s", serverMode)
	}
	compareWithTrust := toBool(options["compare_with_trust"], false)
	cleaned := &DNSOptions{
		Resolver:                firstNonEmpty(strings.TrimSpace(str(options["resolver"], "8.8.8.8")), "8.8.8.8"),
		RecordType:              recordType,
		Timeout:                 clampFloat(toFloat(options["timeout"], 3), 1, 20, 3),
		Transport:               transport,
		ServerMode:              serverMode,
		RepeatCount:             clampInt(toInt(options["repeat_count"], 1), 1, 5, 1),
		EDNS:                    toBool(options["edns"], true),
		DNSSEC:                  toBool(options["dnssec"], false),
		RandomLabel:             toBool(options["random_label"], false),
		CompareWithTrust:        compareWithTrust,
		TraceResolutionPath:     toBool(options["trace_resolution_path"], compareWithTrust),
		TraceRootServers:        normalizeRootServers(options["trace_root_servers"]),
		TraceMaxHops:            clampInt(toInt(options["trace_max_hops"], 8), 1, 8, 8),
		TraceMaxNSPerHop:        clampInt(toInt(options["trace_max_ns_per_hop"], 3), 1, 3, 3),
		AuthorityMethodAnalysis: toBool(options["authority_method_analysis"], compareWithTrust),
		LatencySampleCount:      clampInt(toInt(options["latency_sample_count"], 5), 1, 5, 5),
		RouteMaxHops:            clampInt(toInt(options["route_max_hops"], 16), 3, 30, 16),
	}
	if rawPlan, ok := options["query_plan"].([]any); ok && len(rawPlan) > 0 {
		cleaned.QueryPlan = make([]QueryStep, 0, len(rawPlan))
		for _, rawStep := range rawPlan {
			stepMap, _ := rawStep.(map[string]any)
			step, err := normalizeQueryStep(stepMap, target)
			if err != nil {
				return nil, err
			}
			cleaned.QueryPlan = append(cleaned.QueryPlan, step)
		}
		cleaned.ZoneDomain = dnsclient.InferZoneDomain(target)
	} else {
		cleaned.QueryPlan, cleaned.ZoneDomain = buildQueryPlan(target, cleaned)
	}
	return cleaned, nil
}

func clampFloat(v, min, max, fallback float64) float64 {
	if v == 0 {
		v = fallback
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func str(v any, fallback string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	if v == nil {
		return fallback
	}
	if s := fmt.Sprintf("%v", v); s != "" && s != "<nil>" {
		return s
	}
	return fallback
}

func firstNonEmpty(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func normalizeRootServers(v any) []string {
	var candidates []string
	switch value := v.(type) {
	case string:
		candidates = strings.FieldsFunc(value, func(r rune) bool { return r == ' ' || r == ',' || r == ';' })
	case []any:
		for _, item := range value {
			candidates = append(candidates, fmt.Sprintf("%v", item))
		}
	}
	seen := map[string]bool{}
	out := []string{}
	for _, item := range candidates {
		current := strings.TrimSpace(item)
		if current == "" || seen[current] {
			continue
		}
		seen[current] = true
		out = append(out, current)
		if len(out) >= 8 {
			break
		}
	}
	return out
}

func normalizeQueryStep(step map[string]any, target string) (QueryStep, error) {
	recordType := strings.ToUpper(str(step["record_type"], str(step["query_type"], "A")))
	if !validRecordTypes[recordType] {
		return QueryStep{}, fmt.Errorf("unsupported dns record type: %s", recordType)
	}
	transport := strings.ToLower(str(step["transport"], "udp"))
	if transport != "udp" && transport != "tcp" {
		return QueryStep{}, fmt.Errorf("unsupported dns transport: %s", transport)
	}
	if recordType == "AXFR" {
		transport = "tcp"
	}
	serverMode := strings.ToLower(str(step["server_mode"], "resolver"))
	if serverMode != "resolver" && serverMode != "authoritative" {
		return QueryStep{}, fmt.Errorf("unsupported dns server mode: %s", serverMode)
	}
	queryName := strings.Trim(strings.TrimSpace(str(step["query_name"], target)), ".")
	return QueryStep{
		QueryName:   queryName,
		RecordType:  recordType,
		Transport:   transport,
		ServerMode:  serverMode,
		RepeatCount: clampInt(toInt(step["repeat_count"], 1), 1, 5, 1),
		EDNS:        toBool(step["edns"], true),
		DNSSEC:      toBool(step["dnssec"], false),
		RandomLabel: toBool(step["random_label"], false),
	}, nil
}

// buildQueryPlan 构建默认查询计划。
// 原版在开启 compare_with_trust 时附加权威/NS/SOA/AXFR/泛解析步骤(依赖
// dnsrisk 可信库,Phase 6 接入);当前无可信库场景仅保留主查询步骤。
func buildQueryPlan(target string, opts *DNSOptions) ([]QueryStep, string) {
	step := QueryStep{
		QueryName:   strings.Trim(target, "."),
		RecordType:  opts.RecordType,
		Transport:   opts.Transport,
		ServerMode:  opts.ServerMode,
		RepeatCount: opts.RepeatCount,
		EDNS:        opts.EDNS,
		DNSSEC:      opts.DNSSEC,
	}
	if opts.RecordType == "AXFR" {
		step.Transport = "tcp"
	}
	return []QueryStep{step}, dnsclient.InferZoneDomain(target)
}

// ExecuteDNS 执行完整 DNS 拨测(对应原 execute_dns_probe)。
func ExecuteDNS(ctx context.Context, target string, options map[string]any) Result {
	hostTarget := strings.Trim(target, ".")
	cleaned, err := CleanDNSOptions(hostTarget, options)
	if err != nil {
		return failedResult("invalid_options", err.Error(), map[string]any{})
	}
	resolverIP := cleaned.Resolver
	rawPayload := map[string]any{
		"resolver_ip": resolverIP,
		"record_type": cleaned.RecordType,
		"query_plan":  cleaned.QueryPlan,
	}
	startedAt := time.Now()

	var primary *dnsclient.Result
	rawOutputParts := []string{}
	stepOutcomes := []map[string]any{}
	uniqueIPSet := map[string]bool{}
	nsNameList := map[string]bool{}
	nsGlueIPList := map[string]bool{}
	soaMname, soaSerial := "", ""
	wildcardHit := false
	randomLabelValue := ""
	axfrSuccess := false
	axfrRecordCount := 0
	axfrZoneHash := ""

	for stepIndex, step := range cleaned.QueryPlan {
		for repeatIndex := 1; repeatIndex <= step.RepeatCount; repeatIndex++ {
			queryName := step.QueryName
			if step.RandomLabel {
				randomLabelValue = fmt.Sprintf("np-%d", time.Now().UnixMilli())
				queryName = randomLabelValue + "." + queryName
			}
			stepResult := dnsclient.RunQuery(ctx, dnsclient.Spec{
				QueryName: queryName, RecordType: step.RecordType, ResolverIP: resolverIP,
				Timeout: cleaned.Timeout, Transport: step.Transport, ServerMode: step.ServerMode,
				EDNS: step.EDNS, DNSSEC: step.DNSSEC, RecursionDesired: true,
			})
			rawOutputParts = append(rawOutputParts, stepResult.RawOutput)
			if primary == nil {
				primary = &stepResult
			}
			stepOutcomes = append(stepOutcomes, map[string]any{
				"step_index": stepIndex + 1, "repeat_index": repeatIndex,
				"query_name": queryName, "record_type": step.RecordType,
				"transport": step.Transport, "server_mode": step.ServerMode,
				"rcode": stepResult.Rcode, "success": stepResult.Success,
				"error_kind": stepResult.ErrorKind, "error_message": stepResult.ErrorMessage,
			})
			for _, line := range stepResult.Answer {
				fields := strings.Fields(line)
				if len(fields) < 5 {
					continue
				}
				name, rrtype, value := fields[0], fields[3], fields[len(fields)-1]
				zone := dnsclient.InferZoneDomain(queryName)
				if (rrtype == "A" || rrtype == "AAAA") &&
					dnsclient.NormalizeName(name) == dnsclient.NormalizeName(queryName) {
					uniqueIPSet[value] = true
				}
				if rrtype == "NS" && dnsclient.NormalizeName(name) == dnsclient.NormalizeName(zone) {
					nsNameList[value] = true
				}
				if rrtype == "SOA" {
					values := strings.Fields(value)
					if len(values) > 0 {
						soaMname = strings.Trim(values[0], ".")
					}
					if len(values) > 2 {
						soaSerial = values[2]
					}
				}
			}
			for _, line := range stepResult.Additional {
				fields := strings.Fields(line)
				if len(fields) >= 5 && (fields[3] == "A" || fields[3] == "AAAA") {
					nsGlueIPList[fields[len(fields)-1]] = true
				}
			}
			if step.RandomLabel && len(stepResult.Answer) > 0 {
				wildcardHit = true
			}
			if step.RecordType == "AXFR" {
				axfrSuccess = stepResult.Rcode == "NOERROR" && len(stepResult.Answer) > 0
				axfrRecordCount = len(stepResult.Answer)
				if len(stepResult.Answer) > 0 {
					axfrZoneHash = dnsclient.ZoneHash(stepResult.Answer)
				}
			}
		}
	}

	var resolutionTrace *dnsclient.TraceResult
	if cleaned.TraceResolutionPath {
		traceType := cleaned.RecordType
		if traceType == "AXFR" {
			traceType = "A"
		}
		resolutionTrace = dnsclient.TraceResolutionPath(ctx, hostTarget, traceType,
			cleaned.Timeout, cleaned.TraceRootServers, resolverIP,
			cleaned.TraceMaxHops, cleaned.TraceMaxNSPerHop)
		if resolutionTrace.RawSummary != "" {
			rawOutputParts = append(rawOutputParts, ";; RESOLUTION TRACE\n"+resolutionTrace.RawSummary)
		}
	}
	finishedAt := time.Now()

	if primary == nil {
		primary = &dnsclient.Result{
			Rcode: "DNSERROR", ErrorKind: "dns_error",
			ErrorMessage: "未获取到 DNS 结果",
			Answer: []string{}, Authority: []string{}, Additional: []string{},
			ResolvedIPs: []string{}, CnameChain: []string{},
		}
	}
	rawPayload["resolution_trace"] = resolutionTrace
	success := len(primary.Answer) > 0 && primary.Rcode == "NOERROR"
	flags := map[string]any{}
	for k, v := range primary.Flags {
		flags[k] = v
	}
	if resolutionTrace != nil {
		flags["resolutionTrace"] = resolutionTrace
	}

	observation := map[string]any{
		"fqdn":              hostTarget,
		"zone_domain":       cleaned.ZoneDomain,
		"resolver_ip":       resolverIP,
		"server_mode":       primary.ServerMode,
		"compare_with_trust": cleaned.CompareWithTrust,
		"status":            boolToStr(success, "success", "failed"),
		"started_at":        startedAt,
		"finished_at":       finishedAt,
		"latency_ms":        primary.LatencyMs,
		"rcode":             primary.Rcode,
		"error_code":        boolToStr(success, "", "dns_failed"),
		"error_kind":        primary.ErrorKind,
		"query_plan":        cleaned.QueryPlan,
		"raw_output":        strings.TrimSpace(strings.Join(nonEmptyStr(rawOutputParts), "\n\n")),
		"flags":             flags,
		"ns_name_list":      sortedKeys(nsNameList),
		"ns_glue_ip_list":   sortedKeys(nsGlueIPList),
		"unique_ip_set":     sortedKeys(uniqueIPSet),
		"soa_mname":         soaMname,
		"soa_serial":        soaSerial,
		"random_label":      randomLabelValue,
		"wildcard_hit":      wildcardHit,
		"axfr_success":      axfrSuccess,
		"axfr_record_count": axfrRecordCount,
		"axfr_zone_hash":    axfrZoneHash,
		"step_outcomes":     stepOutcomes,
	}

	resolvedTarget := hostTarget
	if len(primary.ResolvedIPs) > 0 {
		resolvedTarget = strings.Join(primary.ResolvedIPs, ",")
	}
	errCode, errMsg := "", ""
	if !success {
		errCode = "dns_failed"
		errMsg = primary.ErrorMessage
		if errMsg == "" {
			errMsg = "DNS 无有效答案"
		}
	}
	return Result{
		Success:        success,
		Status:         boolToStr(success, "success", "failed"),
		ResolvedTarget: resolvedTarget,
		LatencyMs:      primary.LatencyMs,
		ErrorCode:      errCode,
		ErrorMessage:   errMsg,
		RawPayload:     rawPayload,
		Detail: map[string]any{
			"resolver_ip": resolverIP,
			"record_type": cleaned.RecordType,
			"rcode":       primary.Rcode,
			"query_ms":    primary.LatencyMs,
			"answers":     nonEmptyStr(primary.Answer),
			"authority":   nonEmptyStr(primary.Authority),
			"additional":  nonEmptyStr(primary.Additional),
			"resolved_ips": nonEmptyStr(primary.ResolvedIPs),
			"cname_chain": nonEmptyStr(primary.CnameChain),
			"observation": observation,
		},
	}
}

func boolToStr(b bool, t, f string) string {
	if b {
		return t
	}
	return f
}

func nonEmptyStr(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// MarshalDetail 序列化 detail 为 JSON 文本(落库用)。
func MarshalDetail(detail map[string]any) string {
	data, err := json.Marshal(detail)
	if err != nil {
		return "{}"
	}
	return string(data)
}
