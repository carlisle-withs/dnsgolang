// dnsss-agent:远程探针运行时(方案 5.6)。
// 启动 → HTTP 注册(X-Probe-Token)→ MQTT 连接(LWT offline,retain)
// → 订阅 jobs/control → 本地执行步骤(复用 engine/prober)→ 发布结果 → 30s 心跳。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	pahomqtt "github.com/eclipse/paho.mqtt.golang"

	"dnsss/internal/engine/prober"
)

type registerResponse struct {
	Code int `json:"code"`
	Data struct {
		AgentID   uint64 `json:"agentId"`
		AgentCode string `json:"agentCode"`
		Broker    struct {
			Host     string `json:"host"`
			Port     int    `json:"port"`
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"broker"`
		Topics struct {
			Jobs    string `json:"jobs"`
			Control string `json:"control"`
			Status  string `json:"status"`
			Results string `json:"results"`
			Events  string `json:"events"`
		} `json:"topics"`
	} `json:"data"`
}

type jobPayload struct {
	JobID      int `json:"jobId"`
	Steps      []struct {
		StepID   int            `json:"stepId"`
		Protocol string         `json:"protocol"`
		Target   string         `json:"target"`
		Options  map[string]any `json:"options"`
	} `json:"steps"`
	DeadlineAt string `json:"deadlineAt"`
}

func main() {
	server := flag.String("server", "http://localhost:8000", "服务端地址")
	agentCode := flag.String("code", "probe-local-01", "探针编码")
	regionCode := flag.String("region", "north", "所属地区")
	token := flag.String("token", os.Getenv("DNSSS_PROBE_TOKEN"), "注册共享 token")
	version := flag.String("version", "go-1.0", "探针版本")
	brokerOverride := flag.String("broker", os.Getenv("DNSSS_MQTT_BROKER"), "MQTT broker(默认用注册响应)")
	flag.Parse()
	if *token == "" {
		log.Fatal("缺少 -token 或 DNSSS_PROBE_TOKEN")
	}

	// 1. 注册
	regBody, _ := json.Marshal(map[string]any{
		"agent_code": *agentCode, "region_code": *regionCode,
		"capabilities": []string{"http", "ping", "dns", "mtr", "traceroute"},
		"version": *version,
	})
	req, _ := http.NewRequest(http.MethodPost, *server+"/api/probe-agents/register", bytes.NewReader(regBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Probe-Token", *token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal("注册失败: ", err)
	}
	var reg registerResponse
	_ = json.NewDecoder(resp.Body).Decode(&reg)
	resp.Body.Close()
	if reg.Code != 200 || reg.Data.AgentCode == "" {
		log.Fatalf("注册失败: %s", mustReplay(regBody, resp.StatusCode))
	}
	broker := *brokerOverride
	if broker == "" && reg.Data.Broker.Host != "" {
		broker = fmt.Sprintf("tcp://%s:%d", reg.Data.Broker.Host, reg.Data.Broker.Port)
	}
	if broker == "" {
		log.Fatal("未获得 broker 连接信息")
	}
	log.Printf("注册成功 agent=%s, broker=%s", reg.Data.AgentCode, broker)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	statusTopic := "probe/status/" + reg.Data.AgentCode
	client := connect(reg, broker, statusTopic)
	defer client.Disconnect(250)

	// 2. 心跳(30s retain)
	go heartbeat(ctx, client, statusTopic, *agentCode, *version)

	// 3. 订阅任务
	seenJobs := sync.Map{}
	tokenSub := client.Subscribe("probe/jobs/"+reg.Data.AgentCode, 1, func(_ pahomqtt.Client, m pahomqtt.Message) {
		var job jobPayload
		if err := json.Unmarshal(m.Payload(), &job); err != nil {
			log.Printf("任务解析失败: %v", err)
			return
		}
		if _, loaded := seenJobs.LoadOrStore(job.JobID, true); loaded {
			return // QoS1 去重
		}
		go executeJob(client, reg.Data.AgentCode, job)
	})
	tokenSub.WaitTimeout(5 * time.Second)
	log.Printf("agent 就绪,订阅 %s", "probe/jobs/"+reg.Data.AgentCode)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("agent 退出(由 LWT 广播 offline)")
}

func mustReplay(body []byte, status int) string {
	return fmt.Sprintf("HTTP %d: %s", status, string(body))
}

func connect(reg registerResponse, broker, statusTopic string) pahomqtt.Client {
	publishOffline := func(c pahomqtt.Client) {
		payload, _ := json.Marshal(map[string]any{
			"agentCode": reg.Data.AgentCode, "state": "offline", "ts": time.Now().Format(time.RFC3339),
		})
		c.Publish(statusTopic, 1, true, payload) // retain LWT 语义兜底
	}
	opts := pahomqtt.NewClientOptions().
		AddBroker(broker).
		SetClientID("dnsss-agent-" + reg.Data.AgentCode).
		SetUsername(reg.Data.Broker.Username).
		SetPassword(reg.Data.Broker.Password).
		SetAutoReconnect(true).
		SetConnectRetryInterval(3 * time.Second).
		SetWill(statusTopic, string(mustJSON(map[string]any{
			"agentCode": reg.Data.AgentCode, "state": "offline",
			"ts": time.Now().Format(time.RFC3339),
		})), 1, true) // LWT:掉线时 broker 自动发布 offline(retain)
	opts.OnConnectionLost = func(c pahomqtt.Client, err error) {
		log.Printf("连接断开: %v(自动重连)", err)
	}
	client := pahomqtt.NewClient(opts)
	if t := client.Connect(); t.WaitTimeout(15*time.Second) && t.Error() != nil {
		_ = publishOffline
		log.Fatal("MQTT 连接失败: ", t.Error())
	}
	return client
}

func heartbeat(ctx context.Context, client pahomqtt.Client, statusTopic, agentCode, version string) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			payload, _ := json.Marshal(map[string]any{
				"agentCode": agentCode, "state": "online",
				"activeJobs": 0, "version": version, "ts": time.Now().Format(time.RFC3339),
			})
			client.Publish(statusTopic, 1, true, payload)
		}
	}
}

func executeJob(client pahomqtt.Client, agentCode string, job jobPayload) {
	started := time.Now()
	steps := make([]map[string]any, 0, len(job.Steps))
	status := "success"
	for _, step := range job.Steps {
		result := runStep(step.Protocol, step.Target, step.Options)
		if !result.Success {
			status = "failed"
		}
		detail := map[string]any{}
		for k, v := range result.Detail {
			detail[k] = v
		}
		steps = append(steps, map[string]any{
			"stepId": step.StepID, "success": result.Success,
			"detail": detail, "latencyMs": result.LatencyMs,
			"errorCode": result.ErrorCode, "errorMessage": result.ErrorMessage,
			"resolvedTarget": result.ResolvedTarget,
		})
	}
	payload, _ := json.Marshal(map[string]any{
		"jobId": job.JobID, "agentCode": agentCode, "status": status,
		"startedAt": started.Format(time.RFC3339),
		"finishedAt": time.Now().Format(time.RFC3339),
		"steps": steps,
	})
	topic := fmt.Sprintf("probe/results/%s/%d", agentCode, job.JobID)
	client.Publish(topic, 1, false, payload)
	log.Printf("job #%d 完成(%s,%d 步)", job.JobID, status, len(job.Steps))
}

func runStep(protocol, target string, options map[string]any) prober.Result {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if options == nil {
		options = map[string]any{}
	}
	switch strings.ToLower(protocol) {
	case "dns":
		return prober.ExecuteDNS(ctx, target, options)
	case "http":
		return prober.ExecuteHTTP(ctx, target, options)
	case "ping":
		return prober.ExecutePING(ctx, target, options)
	case "mtr":
		return prober.ExecuteMTR(ctx, target, options)
	case "traceroute":
		return prober.ExecuteTraceroute(ctx, target, options)
	}
	return prober.Result{Success: false, Status: "failed",
		ErrorCode: "unsupported_protocol", ErrorMessage: "unsupported protocol: " + protocol}
}

func mustJSON(v any) []byte {
	data, _ := json.Marshal(v)
	return data
}
