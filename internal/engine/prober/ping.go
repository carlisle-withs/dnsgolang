package prober

import (
	"context"
	"fmt"
	"strings"
	"time"

	probing "github.com/prometheus-community/pro-bing"
)

// ExecutePing 执行 PING 拨测(原生 ICMP,pro-bing)。
// 原版 exec 系统 ping + pingparsing;按技术方案 4 章选型改用原生库:
// 先尝试特权 raw ICMP,权限不足(容器非 root)时降级非特权 UDP ICMP。
func ExecutePING(ctx context.Context, target string, options map[string]any) Result {
	if options == nil {
		options = map[string]any{}
	}
	hostTarget := stripSchemeHost(target)
	count := clampInt(toInt(options["count"], 4), 1, 10, 4)
	timeout := clampInt(toInt(options["timeout"], 2), 1, 10, 2)

	budget := time.Duration((time.Duration(count)*time.Duration(timeout) + 5) * time.Second)
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	rawPayload := map[string]any{"target": hostTarget, "count": count, "timeout": timeout}
	started := time.Now()

	stats, err := runPing(ctx, hostTarget, count, timeout)
	if err != nil {
		if isTimeoutErr(err) {
			return failedResult("ping_timeout", err.Error(), rawPayload)
		}
		return failedResult("ping_error", err.Error(), rawPayload)
	}

	avgMs := stats.avg
	var latency *float64
	if stats.recv > 0 && avgMs != nil {
		latency = avgMs
	} else {
		v := round2(float64(time.Since(started).Microseconds()) / 1000.0)
		latency = &v
	}
	success := stats.recv > 0
	rawOutput := synthesizePingOutput(hostTarget, count, stats)
	errCode, errMsg := "", ""
	if !success {
		errCode, errMsg = "ping_failed", "PING 执行失败"
	}
	return Result{
		Success:        success,
		Status:         boolToStr(success, "success", "failed"),
		ResolvedTarget: hostTarget,
		LatencyMs:      latency,
		ErrorCode:      errCode,
		ErrorMessage:   errMsg,
		RawPayload:     rawPayload,
		Detail: map[string]any{
			"sent_count":      count,
			"recv_count":      stats.recv,
			"loss_pct":        stats.lossPct,
			"min_ms":          stats.min,
			"avg_ms":          stats.avg,
			"max_ms":          stats.max,
			"mdev_ms":         stats.mdev,
			"ttl":             stats.ttl,
			"raw_output_text": rawOutput,
		},
	}
}

type pingStats struct {
	recv     int
	lossPct  float64
	min, avg, max, mdev, ttl *float64
}

func runPing(ctx context.Context, host string, count, timeoutSec int) (*pingStats, error) {
	stats, err := pingOnce(ctx, host, count, timeoutSec, true)
	if err == nil {
		return stats, nil
	}
	// 特权 raw ICMP 失败(常见:非 root 无 CAP_NET_RAW)→ 降级非特权 UDP
	stats2, err2 := pingOnce(ctx, host, count, timeoutSec, false)
	if err2 == nil {
		return stats2, nil
	}
	return nil, err2
}

func pingOnce(ctx context.Context, host string, count, timeoutSec int, privileged bool) (*pingStats, error) {
	pinger := probing.New(host)
	pinger.SetPrivileged(privileged)
	pinger.Count = count
	pinger.Timeout = time.Duration(timeoutSec) * time.Duration(count) * time.Second
	if pinger.Timeout < 2*time.Second {
		pinger.Timeout = 2 * time.Second
	}
	pinger.OnRecv = func(pkt *probing.Packet) {} // 每包回调(保留扩展点)
	if err := pinger.RunWithContext(ctx); err != nil {
		return nil, err
	}
	stats := &pingStats{recv: pinger.PacketsRecv, lossPct: round2(pinger.Statistics().PacketLoss)}
	s := pinger.Statistics()
	if stats.recv > 0 {
		stats.min = f64p(round2(float64(s.MinRtt.Microseconds()) / 1000.0))
		stats.avg = f64p(round2(float64(s.AvgRtt.Microseconds()) / 1000.0))
		stats.max = f64p(round2(float64(s.MaxRtt.Microseconds()) / 1000.0))
		stats.mdev = f64p(round2(float64(s.StdDevRtt.Microseconds()) / 1000.0))
	}
	return stats, nil
}

func f64p(v float64) *float64 { return &v }

// synthesizePingOutput 生成与 iputils ping 文本风格一致的摘要
//(pro-bing 无原始输出,前端 rawOutput 展示用)。
func synthesizePingOutput(host string, count int, s *pingStats) string {
	var b strings.Builder
	fmt.Fprintf(&b, "PING %s: %d data bytes\n", host, 56)
	if s.recv > 0 {
		fmt.Fprintf(&b, "\n--- %s ping statistics ---\n", host)
		fmt.Fprintf(&b, "%d packets transmitted, %d packets received, %.1f%% packet loss\n", count, s.recv, s.lossPct)
		fmt.Fprintf(&b, "rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n", *s.min, *s.avg, *s.max, *s.mdev)
	} else {
		fmt.Fprintf(&b, "\n--- %s ping statistics ---\n", host)
		fmt.Fprintf(&b, "%d packets transmitted, 0 packets received, 100.0%% packet loss\n", count)
	}
	return b.String()
}

func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline")
}

func stripSchemeHost(target string) string {
	if i := strings.Index(target, "://"); i > 0 {
		rest := target[i+3:]
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			rest = rest[:j]
		}
		if k := strings.LastIndex(rest, "@"); k >= 0 {
			rest = rest[k+1:]
		}
		if h, _, err := splitHostPort(rest); err == nil {
			return h
		}
		return rest
	}
	return target
}

func splitHostPort(hostport string) (string, string, error) {
	if i := strings.LastIndex(hostport, ":"); i > 0 {
		return hostport[:i], hostport[i+1:], nil
	}
	return hostport, "", fmt.Errorf("no port")
}
