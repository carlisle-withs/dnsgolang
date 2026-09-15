// Package middleware 提供 recover / 请求日志 / CORS / JWT 鉴权中间件。
package middleware

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"dnsss/internal/auth"
	"dnsss/internal/dto"
)

const (
	ContextUserIDKey    = "user_id"
	ContextUsernameKey  = "username"
	ContextAuthenticated = "authenticated"
)

func Recover() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("panic recovered", "error", r, "path", c.Request.URL.Path)
				dto.Fail(c, http.StatusInternalServerError, "服务器内部错误")
			}
		}()
		c.Next()
	}
}

func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		slog.Info("request",
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", c.Writer.Status(),
			"duration_ms", float64(time.Since(start).Microseconds())/1000.0,
			"client_ip", c.ClientIP(),
		)
	}
}

func CORS(allowedOrigins []string) gin.HandlerFunc {
	allowed := map[string]bool{}
	for _, o := range allowedOrigins {
		allowed[strings.TrimSpace(o)] = true
	}
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin != "" && (allowed[origin] || allowed["*"]) {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Probe-Token")
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		}
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

// JWT 鉴权中间件。豁免清单与原系统对齐:登录/刷新、匿名单次拨测、健康检查;
// 其余接口一律要求 Bearer token,失败返回 403 + errors:"请先登录"。
// 豁免路径仍尽力解析 token(DRF 行为):匿名创建的 once 任务一旦携带
// token 即归属该用户。
func JWT(mgr *auth.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		claims, parseErr := parseBearer(mgr, header)
		if parseErr == nil && claims != nil {
			c.Set(ContextUserIDKey, claims.UserID)
			c.Set(ContextUsernameKey, claims.Username)
			c.Set(ContextAuthenticated, true)
		}
		if isWhitelisted(c) {
			c.Next()
			return
		}
		if parseErr != nil {
			dto.Fail(c, http.StatusForbidden, dto.ErrLoginRequired.Error())
			return
		}
		c.Next()
	}
}

func parseBearer(mgr *auth.Manager, header string) (*auth.Claims, error) {
	if !strings.HasPrefix(header, "Bearer ") {
		return nil, auth.ErrInvalidToken
	}
	return mgr.Parse(strings.TrimSpace(strings.TrimPrefix(header, "Bearer ")))
}

func isWhitelisted(c *gin.Context) bool {
	path := c.Request.URL.Path
	if path == "/healthz" || path == "/metrics" {
		return true
	}
	if path == "/api/oauth/login/" && c.Request.Method == http.MethodPost {
		return true
	}
	if path == "/api/oauth/refresh/" && c.Request.Method == http.MethodPost {
		return true
	}
	// 匿名单次拨测:schedule 模式仍要求登录(由 handler 内部校验)
	if path == "/api/netprobe/tasks" && c.Request.Method == http.MethodPost {
		return true
	}
	return false
}

// UserID 从上下文取当前用户;未登录返回 (0, false)。
func UserID(c *gin.Context) (uint64, bool) {
	v, ok := c.Get(ContextUserIDKey)
	if !ok {
		return 0, false
	}
	id, ok := v.(uint64)
	return id, ok
}

func IsAuthenticated(c *gin.Context) bool {
	v, ok := c.Get(ContextAuthenticated)
	if !ok {
		return false
	}
	b, _ := v.(bool)
	return b
}
