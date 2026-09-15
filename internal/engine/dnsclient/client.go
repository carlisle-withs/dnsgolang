// Package dnsclient 封装 miekg/dns,复刻原 dnspython 执行器的可观测行为:
// dig 风格应答行("name. TTL IN TYPE VALUE")、flags 字典、HEADER 原始输出、
// error_kind 分类、权威模式解析、AXFR、随机子域泛解析探测与解析链路追踪。
package dnsclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

var (
	recordTypes    = map[string]bool{"A": true, "AAAA": true, "CNAME": true, "MX": true, "NS": true, "TXT": true, "SOA": true, "PTR": true, "AXFR": true}
	serverModes    = map[string]bool{"resolver": true, "authoritative": true}
	publicRootHint = []string{
		"198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13", "192.203.230.10",
		"192.5.5.241", "192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30",
		"193.0.14.129", "199.7.83.42", "202.12.27.33",
	}
)

// Spec 单次 DNS 查询参数(对应原 run_single_dns_query)。
type Spec struct {
	QueryName   string
	RecordType  string
	ResolverIP  string
	Timeout     float64
	Transport   string // udp | tcp(AXFR 强制 tcp)
	ServerMode  string // resolver | authoritative
	EDNS        bool
	DNSSEC      bool
	RecursionDesired bool
}

// Result 单次查询结果,字段语义与原实现逐一对应。
type Result struct {
	Rcode        string
	LatencyMs    *float64
	Answer       []string
	Authority    []string
	Additional   []string
	ResolvedIPs  []string
	CnameChain   []string
	ErrorKind    string
	ErrorMessage string
	Flags        map[string]any
	RawOutput    string
	Success      bool
	ServerMode   string
}

func roundMs(d time.Duration) *float64 {
	v := float64(d.Microseconds()) / 1000.0
	v = float64(int(v*100+0.5)) / 100 // 保留 2 位小数,与 round(...,2) 一致
	return &v
}

// NormalizeName 规范化域名:去空白、去尾部点、转小写。
func NormalizeName(v string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(v), "."))
}

// SplitServer 拆分 "host" / "host:port" / "[v6]:port"。
func SplitServer(v string, defaultPort int) (string, int) {
	s := strings.TrimSpace(v)
	if s == "" {
		return "", defaultPort
	}
	if strings.HasPrefix(s, "[") {
		if end := strings.Index(s, "]"); end > 0 {
			host := s[1:end]
			tail := s[end+1:]
			if strings.HasPrefix(tail, ":") {
				if p, err := strconv.Atoi(tail[1:]); err == nil {
					return host, p
				}
			}
			return host, defaultPort
		}
	}
	if strings.Count(s, ":") == 1 {
		if host, port, ok := strings.Cut(s, ":"); ok {
			if p, err := strconv.Atoi(port); err == nil {
				return host, p
			}
		}
	}
	return s, defaultPort
}

// InferZoneDomain 推断注册域(tldextract 语义:publicsuffix,失败取最后两段)。
func InferZoneDomain(fqdn string) string {
	value := NormalizeName(fqdn)
	if value == "" {
		return ""
	}
	if host, err := publicsuffix.EffectiveTLDPlusOne(value); err == nil {
		return host
	}
	labels := strings.Split(value, ".")
	if len(labels) <= 2 {
		return value
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

// DetectErrorKind 与原 detect_dns_error_kind 一致的错误分类。
func DetectErrorKind(message, rcode string) string {
	m := strings.ToLower(message)
	if strings.Contains(m, "connection refused") || strings.Contains(m, "actively refused") {
		return "connection_refused"
	}
	if rcode == "SERVFAIL" {
		return "servfail"
	}
	if strings.Contains(m, "timed out") || strings.Contains(m, "timeout") || strings.Contains(m, "i/o timeout") {
		return "timeout"
	}
	if rcode == "REFUSED" {
		return "refused"
	}
	return "dns_error"
}

// rrLines 将 RR 集合渲染为 dig 风格行:"name. TTL IN TYPE VALUE"(空格分隔,
// 与 dnspython "%s %s IN %s %s" 对齐;miekg RR.String() 为制表符分隔)。
func rrLines(rrsets []dns.RR) []string {
	rows := make([]string, 0, len(rrsets))
	for _, rr := range rrsets {
		rows = append(rows, strings.ReplaceAll(rr.String(), "\t", " "))
	}
	return rows
}

func responseFlags(msg *dns.Msg) map[string]any {
	return map[string]any{
		"aa":   msg.Authoritative,
		"ra":   msg.RecursionAvailable,
		"ad":   msg.AuthenticatedData,
		"cd":   msg.CheckingDisabled,
		"rd":   msg.RecursionDesired,
		"edns": msg.IsEdns0() != nil,
	}
}

// FormatRawOutput 渲染 dig 风格 HEADER 摘要。
func FormatRawOutput(rcode string, answer, authority, additional []string, latencyMs *float64) string {
	var b strings.Builder
	fmt.Fprintf(&b, ";; ->>HEADER<<- status: %s", rcode)
	if len(answer) > 0 {
		b.WriteString("\n;; ANSWER SECTION:")
		for _, line := range answer {
			b.WriteString("\n" + line)
		}
		b.WriteString("\n")
	}
	if len(authority) > 0 {
		b.WriteString("\n;; AUTHORITY SECTION:")
		for _, line := range authority {
			b.WriteString("\n" + line)
		}
		b.WriteString("\n")
	}
	if len(additional) > 0 {
		b.WriteString("\n;; ADDITIONAL SECTION:")
		for _, line := range additional {
			b.WriteString("\n" + line)
		}
		b.WriteString("\n")
	}
	if latencyMs != nil {
		fmt.Fprintf(&b, "\n;; Query time: %d msec", int(*latencyMs))
	}
	return strings.TrimSpace(b.String())
}

func isIPStr(v string) bool { return net.ParseIP(v) != nil }

func failedResult(rcode, errorKind, errMsg string, serverMode string) Result {
	kind := errorKind
	if kind == "" {
		kind = DetectErrorKind(errMsg, rcode)
	}
	return Result{
		Rcode: rcode, LatencyMs: nil, Flags: map[string]any{},
		Answer: []string{}, Authority: []string{}, Additional: []string{},
		ResolvedIPs: []string{}, CnameChain: []string{},
		ErrorKind: kind, ErrorMessage: errMsg, RawOutput: errMsg,
		Success: false, ServerMode: serverMode,
	}
}

// ResolveAuthoritativeServer 先查 zone NS,再解析首个 NS 的 A/AAAA,返回权威 IP。
func ResolveAuthoritativeServer(ctx context.Context, queryName, resolverIP string, timeout float64) (string, error) {
	zone := InferZoneDomain(queryName)
	if zone == "" {
		zone = queryName
	}
	nsResult := RunQuery(ctx, Spec{
		QueryName: zone, RecordType: "NS", ResolverIP: resolverIP,
		Timeout: timeout, Transport: "udp", ServerMode: "resolver",
		EDNS: true, RecursionDesired: true,
	})
	var nsTarget string
	for _, line := range nsResult.Answer {
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[3] == "NS" {
			nsTarget = strings.Trim(fields[len(fields)-1], ".")
			break
		}
	}
	if nsTarget == "" {
		return "", fmt.Errorf("unable to resolve authoritative NS for %s", zone)
	}
	for _, qtype := range []string{"A", "AAAA"} {
		ipResult := RunQuery(ctx, Spec{
			QueryName: nsTarget, RecordType: qtype, ResolverIP: resolverIP,
			Timeout: timeout, Transport: "udp", ServerMode: "resolver",
			EDNS: true, RecursionDesired: true,
		})
		for _, line := range ipResult.Answer {
			fields := strings.Fields(line)
			if len(fields) >= 5 && isIPStr(fields[len(fields)-1]) {
				return fields[len(fields)-1], nil
			}
		}
	}
	return "", fmt.Errorf("unable to resolve authoritative server address")
}

// RunQuery 执行单次 DNS 查询(对应原 run_single_dns_query,含 AXFR 分支)。
func RunQuery(ctx context.Context, spec Spec) Result {
	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = 3
	}
	serverMode := spec.ServerMode
	if !serverModes[serverMode] {
		serverMode = "resolver"
	}
	if spec.RecordType == "AXFR" {
		return runAXFR(ctx, spec, timeout, serverMode)
	}

	server := spec.ResolverIP
	if serverMode == "authoritative" {
		auth, err := ResolveAuthoritativeServer(ctx, spec.QueryName, spec.ResolverIP, timeout)
		if err != nil {
			return failedResult("DNSERROR", "", err.Error(), serverMode)
		}
		server = auth
	}
	host, port := SplitServer(server, 53)

	qtype, ok := dns.StringToType[spec.RecordType]
	if !ok {
		return failedResult("DNSERROR", "", "unsupported dns record type: "+spec.RecordType, serverMode)
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(spec.QueryName), qtype)
	if spec.EDNS || spec.DNSSEC {
		msg.SetEdns0(4096, spec.DNSSEC)
	}
	msg.RecursionDesired = spec.RecursionDesired

	deadline := time.Now().Add(time.Duration(timeout * float64(time.Second)))
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	network := "udp"
	if spec.Transport == "tcp" {
		network = "tcp"
	}
	client := &dns.Client{Net: network, Timeout: time.Duration(timeout * float64(time.Second))}

	started := time.Now()
	resp, _, err := client.ExchangeContext(ctx, msg, net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		if isTimeout(err) || ctx.Err() != nil {
			return failedResult("TIMEOUT", "timeout", err.Error(), serverMode)
		}
		return failedResult("DNSERROR", "", err.Error(), serverMode)
	}
	latency := roundMs(time.Since(started))

	answer := rrLines(resp.Answer)
	authority := rrLines(resp.Ns)
	additional := rrLines(resp.Extra)
	resolvedIPs := make([]string, 0, len(answer))
	cnameChain := make([]string, 0)
	for _, line := range answer {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		tail := fields[len(fields)-1]
		if isIPStr(tail) && (fields[3] == "A" || fields[3] == "AAAA") {
			resolvedIPs = append(resolvedIPs, tail)
		}
		if fields[3] == "CNAME" {
			cnameChain = append(cnameChain, strings.Trim(tail, "."))
		}
	}
	rcode := dns.RcodeToString[resp.Rcode]
	success := rcode == "NOERROR" && len(answer) > 0
	errKind, errMsg := "", ""
	if !success {
		if rcode != "NOERROR" {
			errKind, errMsg = DetectErrorKind("", rcode), rcode
		} else {
			errKind, errMsg = DetectErrorKind("", ""), ""
		}
	}
	return Result{
		Rcode: rcode, LatencyMs: latency,
		Answer: answer, Authority: authority, Additional: additional,
		ResolvedIPs: resolvedIPs, CnameChain: cnameChain,
		ErrorKind: errKind, ErrorMessage: errMsg,
		Flags:    responseFlags(resp),
		RawOutput: FormatRawOutput(rcode, answer, authority, additional, latency),
		Success:  success, ServerMode: serverMode,
	}
}

func runAXFR(ctx context.Context, spec Spec, timeout float64, serverMode string) Result {
	server := spec.ResolverIP
	if serverMode == "authoritative" {
		auth, err := ResolveAuthoritativeServer(ctx, spec.QueryName, spec.ResolverIP, timeout)
		if err != nil {
			return failedResult("AXFRERROR", "", err.Error(), serverMode)
		}
		server = auth
	}
	host, port := SplitServer(server, 53)

	transfer := &dns.Transfer{
		DialTimeout:  time.Duration(timeout * float64(time.Second)),
		ReadTimeout:  time.Duration(timeout * float64(time.Second)),
		WriteTimeout: time.Duration(timeout * float64(time.Second)),
	}
	started := time.Now()
	req := new(dns.Msg)
	req.SetAxfr(dns.Fqdn(spec.QueryName))
	channel, err := transfer.In(req, net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return failedResult("AXFRERROR", "", err.Error(), serverMode)
	}
	answerLines := make([]string, 0, 64)
	for rrset := range channel {
		if rrset.Error != nil {
			return failedResult("AXFRERROR", "", rrset.Error.Error(), serverMode)
		}
		for _, rr := range rrset.RR {
			answerLines = append(answerLines, strings.ReplaceAll(rr.String(), "\t", " "))
		}
	}
	latency := roundMs(time.Since(started))
	resolvedIPs := make([]string, 0)
	for _, line := range answerLines {
		fields := strings.Fields(line)
		if len(fields) >= 5 && (fields[3] == "A" || fields[3] == "AAAA") && isIPStr(fields[len(fields)-1]) {
			resolvedIPs = append(resolvedIPs, fields[len(fields)-1])
		}
	}
	return Result{
		Rcode: "NOERROR", LatencyMs: latency,
		Answer: answerLines, Authority: []string{}, Additional: []string{},
		ResolvedIPs: resolvedIPs, CnameChain: []string{},
		ErrorKind: "", ErrorMessage: "",
		Flags: map[string]any{"aa": true, "ra": false, "ad": false, "cd": false, "rd": false, "edns": spec.EDNS},
		RawOutput: strings.Join(answerLines, "\n"),
		Success:  true, ServerMode: serverMode,
	}
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timeout") || strings.Contains(msg, "i/o timeout")
}

// ZoneHash 计算 AXFR 应答集合哈希(泛解析/AXFR 证据用)。
func ZoneHash(lines []string) string {
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}

// TraceHop 解析链路单跳。
type TraceHop struct {
	Server  string   `json:"server"`
	Query   string   `json:"query"`
	Rcode   string   `json:"rcode"`
	NS      []string `json:"ns"`
	Glue    []string `json:"glue"`
}

// TraceResult 解析路径追踪结果(root→TLD→权威)。
type TraceResult struct {
	Hops      []TraceHop `json:"hops"`
	BrokenAt  string     `json:"brokenAt"`
	ExtraAuth []string   `json:"extraAuth"`
	RawSummary string    `json:"rawSummary"`
}

// TraceResolutionPath 自 root hints(或指定起点)逐层向权威逼近。
func TraceResolutionPath(ctx context.Context, queryName, recordType string, timeout float64, rootServers []string, resolverIP string, maxHops, maxNSPerHop int) *TraceResult {
	if maxHops <= 0 {
		maxHops = 8
	}
	if maxNSPerHop <= 0 {
		maxNSPerHop = 3
	}
	roots := rootServers
	if len(roots) == 0 {
		roots = publicRootHint
	}
	labels := strings.Split(NormalizeName(queryName), ".")
	result := &TraceResult{Hops: []TraceHop{}}
	var raw strings.Builder

	servers := roots
	depth := 0
	for depth < maxHops && depth <= len(labels) {
		name := strings.Join(labels[depth:], ".")
		if name == "" {
			break
		}
		hop := TraceHop{Server: servers[0], Query: name, NS: []string{}, Glue: []string{}}
		resp := RunQuery(ctx, Spec{
			QueryName: name, RecordType: "NS", ResolverIP: servers[0],
			Timeout: timeout, Transport: "udp", ServerMode: "resolver",
			EDNS: false, RecursionDesired: false,
		})
		hop.Rcode = resp.Rcode
		for _, line := range resp.Answer {
			fields := strings.Fields(line)
			if len(fields) >= 5 && fields[3] == "NS" {
				hop.NS = append(hop.NS, strings.Trim(fields[len(fields)-1], "."))
			}
		}
		if len(hop.NS) == 0 {
			for _, line := range resp.Authority {
				fields := strings.Fields(line)
				if len(fields) >= 5 && fields[3] == "NS" {
					hop.NS = append(hop.NS, strings.Trim(fields[len(fields)-1], "."))
				}
			}
		}
		for _, line := range resp.Additional {
			fields := strings.Fields(line)
			if len(fields) >= 5 && isIPStr(fields[len(fields)-1]) {
				hop.Glue = append(hop.Glue, fields[len(fields)-1])
			}
		}
		fmt.Fprintf(&raw, ";; HOP %d server=%s query=%s rcode=%s ns=%v glue=%v\n",
			depth+1, hop.Server, hop.Query, hop.Rcode, hop.NS, hop.Glue)
		result.Hops = append(result.Hops, hop)
		if len(hop.NS) == 0 {
			result.BrokenAt = hop.Query
			break
		}
		next := make([]string, 0, len(hop.Glue))
		next = append(next, hop.Glue...)
		if len(next) == 0 {
			for i, ns := range hop.NS {
				if i >= maxNSPerHop {
					break
				}
				if isIPStr(ns) {
					next = append(next, ns)
					continue
				}
				ipRes := RunQuery(ctx, Spec{
					QueryName: ns, RecordType: "A", ResolverIP: pickResolver(resolverIP, servers),
					Timeout: timeout, Transport: "udp", ServerMode: "resolver",
					EDNS: false, RecursionDesired: true,
				})
				for _, line := range ipRes.Answer {
					fields := strings.Fields(line)
					if len(fields) >= 5 && isIPStr(fields[len(fields)-1]) {
						next = append(next, fields[len(fields)-1])
					}
				}
			}
		}
		if len(next) == 0 {
			result.BrokenAt = hop.Query
			break
		}
		if len(next) > maxNSPerHop {
			next = next[:maxNSPerHop]
		}
		servers = next
		depth++
		if depth == len(labels) {
			break
		}
	}
	result.RawSummary = strings.TrimSpace(raw.String())
	sort.Strings(result.ExtraAuth)
	return result
}

func pickResolver(configured string, servers []string) string {
	if configured != "" {
		return configured
	}
	if len(servers) > 0 {
		return servers[0]
	}
	return "8.8.8.8"
}

// LatencySamples 采样 n 次查询延迟(延迟分布分析证据)。
func LatencySamples(ctx context.Context, queryName, recordType, resolverIP string, timeout float64, n int) []float64 {
	if n <= 0 {
		n = 5
	}
	samples := make([]float64, 0, n)
	for i := 0; i < n; i++ {
		res := RunQuery(ctx, Spec{
			QueryName: queryName, RecordType: recordType, ResolverIP: resolverIP,
			Timeout: timeout, Transport: "udp", ServerMode: "resolver",
			EDNS: false, RecursionDesired: true,
		})
		if res.LatencyMs != nil {
			samples = append(samples, *res.LatencyMs)
		}
	}
	return samples
}
