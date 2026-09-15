// Package queue 封装 Asynq 任务队列(队列划分对照方案 2.8:
// default=单次拨测调度、netprobe=批量执行、dnsrisk=扫描/构建)。
package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/hibiken/asynq"
)

const (
	QueueDefault  = "default"
	QueueNetprobe = "netprobe"

	TypeDispatchExecution      = "netprobe:dispatch_execution"
	TypeDispatchBatchExecution = "netprobe:dispatch_batch_execution"
	TypeAggregateDailyMetrics  = "netprobe:aggregate_daily_metrics"
)

// Client 生产端。
type Client struct {
	client *asynq.Client
}

func NewClient(redisAddr, redisPassword string) (*Client, error) {
	if redisAddr == "" {
		return nil, fmt.Errorf("DNSSS_REDIS_ADDR 未配置")
	}
	redis := asynq.RedisClientOpt{Addr: redisAddr, Password: redisPassword}
	return &Client{client: asynq.NewClient(redis)}, nil
}

func (c *Client) Close() { _ = c.client.Close() }

func (c *Client) enqueue(queueName, typeName string, payload []byte, opts ...asynq.Option) (string, error) {
	task := asynq.NewTask(typeName, payload)
	opts = append([]asynq.Option{asynq.Queue(queueName), asynq.MaxRetry(2)}, opts...)
	info, err := c.client.Enqueue(task, opts...)
	if err != nil {
		return "", err
	}
	return info.ID, nil
}

// EnqueueDispatchExecution 单次拨测执行(default 队列)。
func (c *Client) EnqueueDispatchExecution(executionID uint64, triggerType string) (string, error) {
	payload := marshalPayload(map[string]any{"execution_id": executionID, "trigger_type": triggerType})
	return c.enqueue(QueueDefault, TypeDispatchExecution, payload)
}

// EnqueueDispatchBatchExecution 批量拨测执行(netprobe 队列)。
func (c *Client) EnqueueDispatchBatchExecution(executionID uint64, triggerType string) (string, error) {
	payload := marshalPayload(map[string]any{"execution_id": executionID, "trigger_type": triggerType})
	return c.enqueue(QueueNetprobe, TypeDispatchBatchExecution, payload)
}

// EnqueueAggregateDailyMetrics 日聚合任务。
func (c *Client) EnqueueAggregateDailyMetrics(date string) (string, error) {
	return c.enqueue(QueueDefault, TypeAggregateDailyMetrics, marshalPayload(map[string]any{"date": date}))
}

func marshalPayload(v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return data
}

// Handler 消费端注册(worker 二进制使用)。
type Handler struct {
	server *asynq.Server
	mux    *asynq.ServeMux
}

// NewWorker 创建 Asynq 消费者。concurrency 为全局并发上限。
func NewWorker(redisAddr, redisPassword string, concurrency int) *Handler {
	redis := asynq.RedisClientOpt{Addr: redisAddr, Password: redisPassword}
	server := asynq.NewServer(redis, asynq.Config{
		Concurrency: concurrency,
		Queues: map[string]int{
			QueueDefault:  6,
			QueueNetprobe: 3, // 批量任务单协程编排,内部自带 goroutine 池
		},
		RetryDelayFunc: func(n int, e error, t *asynq.Task) time.Duration {
			return time.Duration(n+1) * 10 * time.Second
		},
	})
	return &Handler{server: server, mux: asynq.NewServeMux()}
}

func (h *Handler) Register(typeName string, handler func(context.Context, []byte) error) {
	h.mux.HandleFunc(typeName, func(ctx context.Context, t *asynq.Task) error {
		return handler(ctx, t.Payload())
	})
}

func (h *Handler) Run() error {
	slog.Info("worker 启动,消费队列 default/netprobe")
	if err := h.server.Run(h.mux); err != nil {
		return err
	}
	return nil
}
