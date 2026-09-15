package prober

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ---------- MTR(exec mtr --report --json,与原实现一致) ----------

// ExecuteMTR 执行 MTR 拨测:exec 系统 mtr 命令并解析 JSON 报告。
func ExecuteMTR(ctx context.Context, target string, options map[string]any) Result {
	if options == nil {
		options = map[string]any{}
	}
	hostTarget := stripSchemeHost(target)
	maxHops := clampInt(toInt(options["max_hops"], 10), 1, 30, 10)
	queryCount := clampInt(toInt(options["query_count"], 1), 1, 10, 1)
	timeout := clampFloat(toFloat(options["timeout"], 1), 0.1, 10, 1)
	numeric := toBool(options["numeric"], true)
	completeOnUnreached := toBool(options["complete_on_unreached"], false)

	args := []string{"--report", "--json", "-c", strconv.Itoa(queryCount), "-m", strconv.Itoa(maxHops)}
	if numeric {
		args = append(args, "-n")
	}
	args = append(args, hostTarget)
	timeoutSeconds := maxInt(20, queryCount*maxInt(int(timeout), 1)+15)

	rawPayload := map[string]any{"command": append([]string{"mtr"}, args...), "target": hostTarget}
	started := time.Now()

	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
	defer cancel()
	out, err := runCommand(ctx, "mtr", args)
	rawOutput := strings.TrimSpace(out)
	if err != nil {
		if isMissingBinary(err) {
			return failedResult("mtr_missing", "当前环境缺少 mtr/pathping 命令", rawPayload)
		}
		if ctx.Err() != nil || isTimeoutErr(err) {
			return failedResult("mtr_timeout", err.Error(), rawPayload)
		}
		return failedResult("mtr_error", err.Error(), rawPayload)
	}

	parsed := parseMtrJSON(rawOutput, hostTarget, maxHops, queryCount)
	return buildRouteResult("mtr", parsed, hostTarget, maxHops, queryCount, completeOnUnreached, rawOutput, rawPayload, started)
}

// ---------- Traceroute(exec traceroute,文本解析) ----------

// ExecuteTraceroute 执行 Traceroute 拨测:exec 系统 traceroute 命令。
func ExecuteTraceroute(ctx context.Context, target string, options map[string]any) Result {
	if options == nil {
		options = map[string]any{}
	}
	hostTarget := stripSchemeHost(target)
	maxHops := clampInt(toInt(options["max_hops"], 12), 1, 30, 12)
	queryCount := clampInt(toInt(options["query_count"], 3), 1, 10, 3)
	timeout := clampFloat(toFloat(options["timeout"], 1), 0.1, 10, 1)
	numeric := toBool(options["numeric"], true)
	completeOnUnreached := toBool(options["complete_on_unreached"], false)

	args := []string{"-m", strconv.Itoa(maxHops), "-w", strconv.Itoa(maxInt(int(timeout), 1)), "-q", strconv.Itoa(queryCount)}
	if numeric {
		args = append(args, "-n")
	}
	args = append(args, hostTarget)
	timeoutSeconds := maxInt(15, maxHops*queryCount*maxInt(int(timeout), 1)+10)

	rawPayload := map[string]any{"command": append([]string{"traceroute"}, args...), "target": hostTarget}
	started := time.Now()

	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
	defer cancel()
	out, err := runCommand(ctx, "traceroute", args)
	rawOutput := strings.TrimSpace(out)
	if err != nil {
		if isMissingBinary(err) {
			return failedResult("traceroute_missing", "当前环境缺少 traceroute/tracert 命令", rawPayload)
		}
		if ctx.Err() != nil || isTimeoutErr(err) {
			return failedResult("traceroute_timeout", err.Error(), rawPayload)
		}
		return failedResult("traceroute_error", err.Error(), rawPayload)
	}

	parsed := parseTracerouteText(rawOutput, hostTarget, maxHops, queryCount)
	return buildRouteResult("traceroute", parsed, hostTarget, maxHops, queryCount, completeOnUnreached, rawOutput, rawPayload, started)
}

// ---------- 解析结果结构 ----------

type routeHop struct {
	Hop      int      `json:"hop"`
	Address  string   `json:"address"`
	Host     string   `json:"host"`
	Probes   []*float64 `json:"probes,omitempty"`
	LossPct  *float64 `json:"lossPct,omitempty"`
	LastMs   *float64 `json:"lastMs"`
	AvgMs    *float64 `json:"avgMs"`
	BestMs   *float64 `json:"bestMs,omitempty"`
	WorstMs  *float64 `json:"worstMs,omitempty"`
	JitterMs *float64 `json:"jitterMs,omitempty"`
}

type routeParse struct {
	hopCount          int
	destinationReached bool
	resolvedIP        string
	lastAddress       string
	finalLatencyMs    *float64
	avgLatencyMs      *float64
	bestMs, worstMs   *float64
	packetLossPct     *float64
	jitterMs          *float64
	hops              []routeHop
}

var ipv4FindRe = regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}`)
var msTokenRe = regexp.MustCompile(`(\d+(?:\.\d+)?)\s*ms`)
var tracerouteLineRe = regexp.MustCompile(`^\s*(\d+)\s+(.*)$`)

func parseMtrJSON(rawOutput, target string, maxHops, queryCount int) *routeParse {
	var payload struct {
		Report struct {
			Hubs []struct {
				Count int     `json:"count"`
				Host  string  `json:"host"`
				Loss  float64 `json:"Loss%"`
				Last  *float64 `json:"Last"`
				Avg   *float64 `json:"Avg"`
				Best  *float64 `json:"Best"`
				Wrst  *float64 `json:"Wrst"`
				StDev *float64 `json:"StDev"`
			} `json:"hubs"`
		} `json:"report"`
	}
	if err := json.Unmarshal([]byte(rawOutput), &payload); err != nil {
		return emptyRouteParse()
	}
	targetIPs := resolveTargetIPs(target)
	hops := make([]routeHop, 0, len(payload.Report.Hubs))
	for i, hub := range payload.Report.Hubs {
		hop := routeHop{
			Hop: hub.Count, Address: hub.Host, Host: hub.Host,
			LossPct: f64p(round2(hub.Loss)),
			LastMs:  hub.Last, AvgMs: hub.Avg, BestMs: hub.Best, WorstMs: hub.Wrst, JitterMs: hub.StDev,
		}
		if hop.Hop == 0 {
			hop.Hop = i + 1
		}
		hops = append(hops, hop)
	}
	return buildRouteParse(hops, targetIPs, maxHops)
}

func parseTracerouteText(rawOutput, target string, maxHops, queryCount int) *routeParse {
	targetIPs := resolveTargetIPs(target)
	hops := []routeHop{}
	for _, line := range strings.Split(rawOutput, "\n") {
		m := tracerouteLineRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		hopNumber, _ := strconv.Atoi(m[1])
		remainder := strings.TrimSpace(m[2])
		address := extractLastAddress(remainder)
		probes := []*float64{}
		for _, token := range msTokenRe.FindAllStringSubmatch(remainder, -1) {
			v, _ := strconv.ParseFloat(token[1], 64)
			probes = append(probes, &v)
		}
		if len(probes) == 0 && strings.Contains(remainder, "*") {
			for i := 0; i < maxInt(queryCount, strings.Count(remainder, "*")); i++ {
				probes = append(probes, nil)
			}
		}
		hops = append(hops, routeHop{Hop: hopNumber, Address: address, Host: address, Probes: probes})
	}
	return buildRouteParse(hops, targetIPs, maxHops)
}

func buildRouteParse(hops []routeHop, targetIPs []string, maxHops int) *routeParse {
	parse := &routeParse{hops: hops, hopCount: len(hops)}
	reached := false
	for i := range hops {
		if matchesDestination(hops[i].Address, targetIPs) {
			parse.destinationReached = true
			parse.resolvedIP = hops[i].Address
			parse.finalLatencyMs = hops[i].AvgMs
			if parse.finalLatencyMs == nil && len(hops[i].Probes) > 0 {
				for j := len(hops[i].Probes) - 1; j >= 0; j-- {
					if hops[i].Probes[j] != nil {
						parse.finalLatencyMs = hops[i].Probes[j]
						break
					}
				}
			}
			reached = true
			break
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		if hops[i].Address != "" {
			parse.lastAddress = hops[i].Address
			break
		}
	}
	// traceroute 补全每跳统计
	for i := range hops {
		if hops[i].Probes == nil {
			continue
		}
		numeric := []*float64{}
		timeouts := 0
		for _, p := range hops[i].Probes {
			if p != nil {
				numeric = append(numeric, p)
			} else {
				timeouts++
			}
		}
		if len(numeric) > 0 {
			sum := 0.0
			minV, maxV := *numeric[0], *numeric[0]
			for _, v := range numeric {
				sum += *v
				if *v < minV {
					minV = *v
				}
				if *v > maxV {
					maxV = *v
				}
			}
			hops[i].AvgMs = f64p(round2(sum / float64(len(numeric))))
			hops[i].BestMs = f64p(minV)
			hops[i].WorstMs = f64p(maxV)
			hops[i].LastMs = numeric[len(numeric)-1]
		}
		if len(hops[i].Probes) > 0 {
			hops[i].LossPct = f64p(round2(float64(timeouts) / float64(len(hops[i].Probes)) * 100))
		}
	}
	if !reached {
		for i := len(hops) - 1; i >= 0; i-- {
			if hops[i].AvgMs != nil {
				parse.finalLatencyMs = hops[i].AvgMs
				break
			}
		}
	}
	if len(hops) > maxHops {
		parse.hops = hops[:maxHops]
	}
	return parse
}

func emptyRouteParse() *routeParse { return &routeParse{hops: []routeHop{}} }

func buildRouteResult(kind string, parsed *routeParse, hostTarget string, maxHops, queryCountForDetail int, completeOnUnreached bool, rawOutput string, rawPayload map[string]any, started time.Time) Result {
	destinationReached := parsed.destinationReached
	success := destinationReached || completeOnUnreached
	latency := parsed.finalLatencyMs
	if kind == "mtr" && latency == nil {
		latency = parsed.avgLatencyMs
	}
	if latency == nil {
		v := round2(float64(time.Since(started).Microseconds()) / 1000.0)
		latency = &v
	}
	resolvedTarget := parsed.resolvedIP
	if resolvedTarget == "" {
		resolvedTarget = parsed.lastAddress
	}
	if resolvedTarget == "" {
		resolvedTarget = hostTarget
	}
	var errCode, errMsg string
	if !success {
		prefix := "mtr"
		if kind == "traceroute" {
			prefix = "traceroute"
		}
		errCode = prefix + "_incomplete"
		switch {
		case parsed.lastAddress != "":
			if completeOnUnreached {
				errMsg = fmt.Sprintf("未在 %d 跳内到达目标，最后响应节点 %s，已返回部分路径结果", maxHops, parsed.lastAddress)
			} else {
				errMsg = fmt.Sprintf("未在 %d 跳内到达目标，最后响应节点 %s", maxHops, parsed.lastAddress)
			}
		case completeOnUnreached:
			errMsg = fmt.Sprintf("未在 %d 跳内到达目标，已返回部分路径结果", maxHops)
		default:
			errMsg = fmt.Sprintf("未在 %d 跳内到达目标", maxHops)
		}
	}
	detail := map[string]any{
		"max_hops":            maxHops,
		"hop_count":           parsed.hopCount,
		"destination_reached": destinationReached,
		"hops":                parsed.hops,
		"raw_output_text":     rawOutput,
	}
	if kind == "mtr" {
		detail["probe_count"] = queryCountForDetail
		detail["packet_loss_pct"] = parsed.packetLossPct
		detail["best_latency_ms"] = parsed.bestMs
		detail["avg_latency_ms"] = parsed.avgLatencyMs
		detail["worst_latency_ms"] = parsed.worstMs
		detail["jitter_ms"] = parsed.jitterMs
	} else {
		detail["query_count"] = queryCountForDetail
		detail["resolved_ip"] = parsed.resolvedIP
	}
	return Result{
		Success:        success,
		Status:         boolToStr(success, "success", "failed"),
		ResolvedTarget: resolvedTarget,
		LatencyMs:      latency,
		ErrorCode:      errCode,
		ErrorMessage:   errMsg,
		RawPayload:     rawPayload,
		Detail:         detail,
	}
}

// ---------- 工具 ----------

func runCommand(ctx context.Context, name string, args []string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func isMissingBinary(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "executable file not found") ||
		strings.Contains(msg, "no such file or directory") ||
		strings.Contains(msg, "not found")
}

func extractLastAddress(text string) string {
	if text == "" {
		return ""
	}
	lower := strings.ToLower(text)
	if strings.Contains(lower, "request timed out") || strings.Contains(text, "请求超时") {
		return ""
	}
	if matches := ipv4FindRe.FindAllString(text, -1); len(matches) > 0 {
		return matches[len(matches)-1]
	}
	fields := strings.Fields(strings.TrimSpace(text))
	if len(fields) == 0 {
		return ""
	}
	last := strings.Trim(fields[len(fields)-1], "[]()")
	if strings.Contains(last, "*") || strings.Contains(lower, "timed") {
		return ""
	}
	return last
}

func matchesDestination(address string, targetIPs []string) bool {
	if address == "" {
		return false
	}
	for _, ip := range targetIPs {
		if address == ip {
			return true
		}
	}
	return false
}

func resolveTargetIPs(host string) []string {
	if net.ParseIP(host) != nil {
		return []string{host}
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, v4.String())
		} else {
			out = append(out, ip.String())
		}
	}
	return out
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
