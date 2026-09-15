package prober

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"time"
)

// ExecuteHTTP 执行 HTTP 拨测。原版(httpx)未做分段计时;Go 版用 httptrace
// 补齐 DNS/连接/TTFB 四段计时(增强,超集字段,前端已展示该结构)。
func ExecuteHTTP(ctx context.Context, target string, options map[string]any) Result {
	if options == nil {
		options = map[string]any{}
	}
	method := strings.ToUpper(str(options["method"], "GET"))
	timeout := clampFloat(toFloat(options["timeout"], 10), 0.1, 120, 10)
	followRedirects := toBool(options["follow_redirects"], true)
	verifyTLS := toBool(options["verify_tls"], true)

	rawPayload := map[string]any{
		"method":  method,
		"timeout": timeout,
	}

	var dnsStart, dnsDone, connectStart, connectDone, ttfbStart, ttfbDone time.Time
	remoteIP := ""
	traceCtx := httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone:  func(httptrace.DNSDoneInfo) { dnsDone = time.Now() },
		ConnectStart: func(network, addr string) {
			if connectStart.IsZero() {
				connectStart = time.Now()
			}
		},
		ConnectDone: func(network, addr string, err error) {
			if err == nil && connectDone.IsZero() {
				connectDone = time.Now()
				remoteIP = hostPortHost(addr)
			}
		},
		WroteRequest: func(httptrace.WroteRequestInfo) { ttfbStart = time.Now() },
		GotFirstResponseByte: func() {
			if ttfbDone.IsZero() {
				ttfbDone = time.Now()
			}
		},
	})

	transport := &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{Timeout: time.Duration(timeout * float64(time.Second))}).DialContext,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: !verifyTLS, ServerName: hostOf(target)},
		TLSHandshakeTimeout: time.Duration(timeout * float64(time.Second)),
	}
	client := &http.Client{
		Timeout:   time.Duration(timeout * float64(time.Second)),
		Transport: transport,
	}
	redirects := 0
	if !followRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			redirects++
			if redirects >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			return nil
		}
	}

	started := time.Now()
	req, err := http.NewRequestWithContext(traceCtx, method, target, nil)
	if err != nil {
		return failedResult("http_error", err.Error(), rawPayload)
	}
	resp, err := client.Do(req)
	if err != nil {
		if isHTTPTimeout(err) {
			return failedResult("http_timeout", err.Error(), rawPayload)
		}
		return failedResult("http_error", err.Error(), rawPayload)
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 2<<10)) // 2KB 预览
	total := time.Since(started)
	totalMs := round2(float64(total.Microseconds()) / 1000.0)
	_ = readErr

	headers := map[string]any{}
	for k := range resp.Header {
		headers[k] = resp.Header.Get(k)
	}
	tlsInfo := map[string]any{"scheme": "https", "is_https": strings.HasPrefix(target, "https://")}
	if resp.TLS != nil {
		tlsInfo["http_version"] = tlsVersionName(resp.TLS.Version)
		if len(resp.TLS.PeerCertificates) > 0 {
			cert := resp.TLS.PeerCertificates[0]
			tlsInfo["version"] = tlsVersionName(resp.TLS.Version)
			tlsInfo["issuer"] = cert.Issuer.CommonName
			tlsInfo["subject"] = cert.Subject.CommonName
			tlsInfo["expire_at"] = cert.NotAfter
		}
	} else {
		tlsInfo["scheme"] = "http"
		tlsInfo["is_https"] = false
	}

	finalURL := resp.Request.URL.String()
	rawPayload["final_url"] = finalURL
	rawPayload["headers"] = headers

	success := resp.StatusCode >= 200 && resp.StatusCode < 300
	errCode, errMsg := "", ""
	if !success {
		errCode, errMsg = "http_status_error", "HTTP 返回状态异常"
	}
	return Result{
		Success:        success,
		Status:         boolToStr(success, "success", "failed"),
		ResolvedTarget: finalURL,
		LatencyMs:      &totalMs,
		ErrorCode:      errCode,
		ErrorMessage:   errMsg,
		RawPayload:     rawPayload,
		Detail: map[string]any{
			"url":              finalURL,
			"method":           method,
			"http_status":      resp.StatusCode,
			"dns_ms":           elapsedMs(dnsStart, dnsDone),
			"connect_ms":       elapsedMs(connectStart, connectDone),
			"ttfb_ms":          elapsedMs(ttfbStart, ttfbDone),
			"total_ms":         totalMs,
			"redirect_count":   redirects,
			"body_size":        len(body),
			"response_headers": headers,
			"tls_info":         tlsInfo,
			"remote_ip":        remoteIP,
			"body_preview":     string(body),
		},
	}
}

func hostOf(target string) string {
	if u, err := url.Parse(target); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return ""
}

func hostPortHost(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

func elapsedMs(start, end time.Time) *float64 {
	if start.IsZero() || end.IsZero() || end.Before(start) {
		return nil
	}
	v := round2(float64(end.Sub(start).Microseconds()) / 1000.0)
	return &v
}

func round2(v float64) float64 {
	return float64(int(v*100+0.5)) / 100
}

func isHTTPTimeout(err error) bool {
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timeout") || strings.Contains(msg, "context deadline exceeded")
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLSv1.0"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	}
	return fmt.Sprintf("0x%04x", version)
}
