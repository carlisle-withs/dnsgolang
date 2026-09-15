// dnsss-server:HTTP API + 内嵌执行器与调度循环(开发期单进程形态;
// Phase 4 拆分独立 worker 二进制并接入 Asynq)。
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/golang-migrate/migrate/v4"
	migratemysql "github.com/golang-migrate/migrate/v4/database/mysql"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"gorm.io/gorm"

	"dnsss/internal/auth"
	"dnsss/internal/config"
	"dnsss/internal/database"
	"dnsss/internal/httpapi"
	"dnsss/internal/queue"
	"dnsss/internal/seed"
	"dnsss/internal/service"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("配置加载失败", "error", err)
		os.Exit(1)
	}
	db, err := database.Open(cfg.DBDSN)
	if err != nil {
		slog.Error("数据库连接失败", "error", err)
		os.Exit(1)
	}

	migrateOnly := flag.Bool("migrate", false, "执行迁移后退出")
	seedOnly := flag.Bool("seed", false, "执行种子后退出")
	flag.Parse()

	if *migrateOnly {
		if err := runMigrations(cfg.DBDSN, db); err != nil {
			slog.Error("迁移失败", "error", err)
			os.Exit(1)
		}
		slog.Info("迁移完成")
		return
	}
	if *seedOnly {
		if err := seed.Run(context.Background(), db, cfg.AdminInitPassword); err != nil {
			slog.Error("种子失败", "error", err)
			os.Exit(1)
		}
		slog.Info("种子完成")
		return
	}

	jwtMgr := auth.NewManager(cfg.JWTSecret, cfg.JWTHours, cfg.RefreshDay)
	svc := service.New(db, cfg)

	// 配置了 Redis 时批量/单次执行经 Asynq 派发给独立 worker;未配置则进程内执行
	var queueClient *queue.Client
	if cfg.RedisAddr != "" {
		queueClient, err = queue.NewClient(cfg.RedisAddr, cfg.RedisPass)
		if err != nil {
			slog.Error("Asynq 客户端初始化失败", "error", err)
			os.Exit(1)
		}
		defer queueClient.Close()
		slog.Info("Asynq 队列已启用", "redis", cfg.RedisAddr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go svc.ScheduleLoop(ctx)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           httpapi.New(cfg, db, jwtMgr, svc, queueClient).Router(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		slog.Info("dnsss-server 启动", "listen", cfg.Listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP 服务异常退出", "error", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	slog.Info("收到停机信号,优雅退出")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)
	cancel()
	svc.Close()
}

func runMigrations(dsn string, db *gorm.DB) error {
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	// golang-migrate 逐迁移文件整段执行,需要多语句模式
	multi, err := database.Open(dsn + "&multiStatements=true")
	if err != nil {
		return err
	}
	multiDB, _ := multi.DB()
	defer multiDB.Close()
	driver, err := migratemysql.WithInstance(multiDB, &migratemysql.Config{})
	if err != nil {
		return fmt.Errorf("初始化迁移驱动失败: %w", err)
	}
	m, err := migrate.NewWithDatabaseInstance("file://migrations", "mysql", driver)
	if err != nil {
		return fmt.Errorf("打开迁移目录失败: %w", err)
	}
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return err
	}
	return sqlDB.Ping()
}
