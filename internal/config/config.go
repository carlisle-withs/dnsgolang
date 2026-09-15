// Package config 环境变量驱动的配置加载(DNSSS_ 前缀,零硬编码凭据)。
// 必填项缺失时启动即失败,与原版"SECRET_KEY/DB 密码硬编码在源码里"的做法相反。
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Listen     string
	DBDSN      string
	RedisAddr  string
	RedisPass  string
	JWTSecret  string
	JWTHours   int
	RefreshDay int

	AdminInitPassword string

	BatchLocalConcurrency int
	BatchFlushSize        int
	SingleExecutionMode   string // auto | local | remote

	StaticDir string
	CORSOrigins []string

	MQTTBroker    string
	MQTTUsername  string
	MQTTPassword  string
	ProbeToken    string
	ProbeLeaseSeconds int
}

func getenv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func Load() (*Config, error) {
	cfg := &Config{
		Listen:                getenv("DNSSS_LISTEN", ":8000"),
		DBDSN:                 os.Getenv("DNSSS_DB_DSN"),
		RedisAddr:             getenv("DNSSS_REDIS_ADDR", ""),
		RedisPass:             getenv("DNSSS_REDIS_PASSWORD", ""),
		JWTSecret:             os.Getenv("DNSSS_JWT_SECRET"),
		JWTHours:              getenvInt("DNSSS_JWT_TTL_HOURS", 24),
		RefreshDay:            getenvInt("DNSSS_JWT_REFRESH_DAYS", 7),
		AdminInitPassword:     os.Getenv("DNSSS_ADMIN_PASSWORD"),
		BatchLocalConcurrency: getenvInt("DNSSS_BATCH_CONCURRENCY", 256),
		BatchFlushSize:        getenvInt("DNSSS_BATCH_FLUSH_SIZE", 200),
		SingleExecutionMode:   getenv("DNSSS_SINGLE_EXECUTION_MODE", "auto"),
		StaticDir:             os.Getenv("DNSSS_STATIC_DIR"),
		CORSOrigins:           splitList(getenv("DNSSS_CORS_ORIGINS", "http://localhost:5173")),
		MQTTBroker:            getenv("DNSSS_MQTT_BROKER", ""),
		MQTTUsername:          getenv("DNSSS_MQTT_USERNAME", ""),
		MQTTPassword:          getenv("DNSSS_MQTT_PASSWORD", ""),
		ProbeToken:            getenv("DNSSS_PROBE_TOKEN", ""),
		ProbeLeaseSeconds:     getenvInt("DNSSS_PROBE_LEASE_SECONDS", 180),
	}
	if cfg.DBDSN == "" {
		return nil, fmt.Errorf("缺少必填环境变量 DNSSS_DB_DSN")
	}
	if len(cfg.JWTSecret) < 32 {
		return nil, fmt.Errorf("DNSSS_JWT_SECRET 必填且长度至少 32 字符")
	}
	switch cfg.SingleExecutionMode {
	case "auto", "local", "remote":
	default:
		cfg.SingleExecutionMode = "auto"
	}
	return cfg, nil
}

func splitList(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
