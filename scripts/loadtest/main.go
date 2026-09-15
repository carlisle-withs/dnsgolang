// loadtest:批量拨测压测工具(对齐原系统 2.10 口径)。
// 生成 lt-000001.test … lt-NNNNNN.test 目标(.test 保留 TLD,本地 resolver 秒回 NXDOMAIN,
// 不打公网),分档测量创建耗时 / 执行耗时 / 吞吐。
//
// 用法:go run ./scripts/loadtest -server http://localhost:8000 -user admin -pass xxx \
//
//	-resolver 127.0.0.1:8053 -sizes 100,1000,10000
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type result struct {
	size        int
	createMs    float64
	execMs      float64
	throughput  float64
	totalChecks int
	successN    int
	status      string
}

func main() {
	server := flag.String("server", "http://localhost:8000", "服务地址")
	username := flag.String("user", "admin", "用户名")
	password := flag.String("pass", "", "密码")
	resolver := flag.String("resolver", "127.0.0.1:8053", "本地测试 resolver")
	sizes := flag.String("sizes", "100,1000,10000", "分档目标数,逗号分隔")
	flag.Parse()
	if *password == "" {
		fmt.Println("缺少 -pass 参数")
		os.Exit(1)
	}
	token := login(*server, *username, *password)
	fmt.Printf("登录成功,目标服务 %s,resolver %s\n\n", *server, *resolver)

	for _, sizeStr := range strings.Split(*sizes, ",") {
		size, _ := strconv.Atoi(strings.TrimSpace(sizeStr))
		if size <= 0 {
			continue
		}
		r := runBatch(*server, token, *resolver, size)
		fmt.Printf("%6d 目标 | 创建 %8.0fms | 执行 %8.2fs | 吞吐 %8.0f/s | 检查 %6d | 状态 %s\n",
			r.size, r.createMs, r.execMs/1000, r.throughput, r.totalChecks, r.status)
	}
	fmt.Println("\n红线对照:10k 档吞吐 ≥1000/s,创建 ≤1s")
}

func runBatch(server, token, resolver string, size int) result {
	var sb strings.Builder
	for i := 1; i <= size; i++ {
		if i > 1 {
			sb.WriteString("\n")
		}
		sb.WriteString(fmt.Sprintf("lt-%06d.test", i))
	}
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	_ = writer.WriteField("protocol", "dns")
	_ = writer.WriteField("input_mode", "text")
	_ = writer.WriteField("targets_text", sb.String())
	_ = writer.WriteField("regions", "global")
	_ = writer.WriteField("mode", "once")
	_ = writer.WriteField("options", fmt.Sprintf(`{"resolver":"%s","record_type":"A"}`, resolver))
	_ = writer.Close()

	createStart := time.Now()
	respBody, err := httpPost(server+"/api/netprobe/batch/tasks", token, body.Bytes(), writer.FormDataContentType())
	if err != nil {
		fmt.Println("创建失败:", err)
		os.Exit(1)
	}
	createMs := float64(time.Since(createStart).Microseconds()) / 1000.0
	executionID := intJSON(respBody, "data", "executionId")
	if executionID == 0 {
		fmt.Println("创建响应异常:", string(respBody))
		os.Exit(1)
	}

	execStart := time.Now()
	var lastStatus string
	for {
		time.Sleep(200 * time.Millisecond)
		detail := apiGet(server+fmt.Sprintf("/api/netprobe/batch/executions/%d", executionID), token)
		lastStatus = jsonStr(detail, "data", "overview", "status")
		if lastStatus != "pending" && lastStatus != "running" {
			break
		}
		if time.Since(execStart) > 10*time.Minute {
			fmt.Println("执行超时")
			os.Exit(1)
		}
	}
	execMs := float64(time.Since(execStart).Microseconds()) / 1000.0
	final := apiGet(server+fmt.Sprintf("/api/netprobe/batch/executions/%d", executionID), token)
	total := intJSON(final, "data", "overview", "expectedCheckCount")
	if total == 0 {
		total = size
	}
	return result{
		size: size, createMs: createMs, execMs: execMs,
		throughput:  float64(total) / (execMs / 1000.0),
		totalChecks: total,
		successN:    intJSON(final, "data", "overview", "successCount"),
		status:      lastStatus,
	}
}

func login(server, user, pass string) string {
	resp, err := http.Post(server+"/api/oauth/login/", "application/json",
		strings.NewReader(fmt.Sprintf(`{"username":%q,"password":%q}`, user, pass)))
	if err != nil {
		fmt.Println("登录失败:", err)
		os.Exit(1)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	token := jsonStr(body, "data", "token")
	if token == "" {
		fmt.Println("登录失败:", string(body))
		os.Exit(1)
	}
	return token
}

func httpPost(rawURL, token string, body []byte, contentType string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", contentType)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func apiGet(rawURL, token string) []byte {
	req, _ := http.NewRequest(http.MethodGet, rawURL, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return []byte("{}")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return body
}

func walk(v any, keys ...string) any {
	current := v
	for _, key := range keys {
		m, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = m[key]
	}
	return current
}

func intJSON(data []byte, keys ...string) int {
	var parsed any
	if json.Unmarshal(data, &parsed) != nil {
		return 0
	}
	if f, ok := walk(parsed, keys...).(float64); ok {
		return int(f)
	}
	return 0
}

func jsonStr(data []byte, keys ...string) string {
	var parsed any
	if json.Unmarshal(data, &parsed) != nil {
		return ""
	}
	if s, ok := walk(parsed, keys...).(string); ok {
		return s
	}
	return ""
}
