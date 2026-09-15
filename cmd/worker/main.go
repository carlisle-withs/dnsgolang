// dnsss-worker:Asynq 队列消费者(方案 3.1 的 worker 角色)。
// 消费 default(单次拨测)与 netprobe(批量执行)队列;
// 内置周期任务:每日 00:10 日聚合(replace Celery beat)。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/robfig/cron/v3"

	"dnsss/internal/bridge"
	"dnsss/internal/config"
	"dnsss/internal/database"
	"dnsss/internal/queue"
	"dnsss/internal/service"
)

type taskPayload struct {
	ExecutionID uint64 `json:"execution_id"`
	TriggerType string `json:"trigger_type"`
	Date        string `json:"date"`
}

func main() {
	concurrency := flag.Int("concurrency", 8, "Asynq 全局并发上限")
	flag.Parse()

	cfg, err := config.Load()
	if err != nil {
		slog.Error("配置加载失败", "error", err)
		os.Exit(1)
	}
	if cfg.RedisAddr == "" {
		slog.Error("worker 需要 DNSSS_REDIS_ADDR")
		os.Exit(1)
	}
	db, err := database.Open(cfg.DBDSN)
	if err != nil {
		slog.Error("数据库连接失败", "error", err)
		os.Exit(1)
	}
	svc := service.New(db, cfg)

	worker := queue.NewWorker(cfg.RedisAddr, cfg.RedisPass, *concurrency)

	worker.Register(queue.TypeDispatchExecution, func(ctx context.Context, payload []byte) error {
		var p taskPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return err
		}
		if p.ExecutionID == 0 {
			return nil
		}
		if err := svc.RunSingleExecution(ctx, p.ExecutionID); err != nil {
			slog.Error("单次拨测执行失败", "execution_id", p.ExecutionID, "error", err)
		}
		return nil // 业务失败不重试(结果已落库)
	})

	worker.Register(queue.TypeDispatchBatchExecution, func(ctx context.Context, payload []byte) error {
		var p taskPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return err
		}
		if p.ExecutionID == 0 {
			return nil
		}
		if err := svc.RunBatchExecution(ctx, p.ExecutionID, p.TriggerType); err != nil {
			slog.Error("批量执行失败", "execution_id", p.ExecutionID, "error", err)
			return err
		}
		return nil
	})

	worker.Register(queue.TypeAggregateDailyMetrics, func(ctx context.Context, payload []byte) error {
		var p taskPayload
		_ = json.Unmarshal(payload, &p)
		return svc.AggregateDailyMetrics(ctx, p.Date)
	})

	// 周期调度(Celery beat 等价):每日 00:10 日聚合;每 5 分钟心跳本地节点
	cronSchedule := cron.New()
	// MQTT bridge:批量/单次远程派发的发布与结果回填
	if cfg.MQTTBroker != "" {
		b := bridge.New(cfg, db, svc)
		if err := b.Start(context.Background()); err != nil {
			slog.Error("MQTT bridge 启动失败", "error", err)
		} else {
			svc.SetRemotePublisher(b)
		}
	}
	if _, err := cronSchedule.AddFunc("10 0 * * *", func() {
		if err := svc.AggregateDailyMetrics(context.Background(), time.Now().AddDate(0, 0, -1).Format("2006-01-02")); err != nil {
			slog.Warn("日聚合失败", "error", err)
		}
	}); err != nil {
		slog.Error("注册日聚合调度失败", "error", err)
	}
	if _, err := cronSchedule.AddFunc("*/5 * * * *", func() {
		_ = svc.HeartbeatLocalNode(context.Background())
	}); err != nil {
		slog.Error("注册心跳调度失败", "error", err)
	}
	cronSchedule.Start()
	defer cronSchedule.Stop()

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		slog.Info("worker 收到停机信号")
		cronSchedule.Stop()
		svc.Close()
		os.Exit(0)
	}()

	if err := worker.Run(); err != nil {
		slog.Error("worker 退出", "error", err)
		os.Exit(1)
	}
}
