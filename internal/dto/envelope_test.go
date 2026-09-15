package dto

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// 契约红线:envelope 结构是前端 axios 拦截器的解包依据。
func TestEnvelopeSuccess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	OK(c, map[string]any{"k": 1})

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["msg"] != "成功" || body["code"].(float64) != 200 {
		t.Errorf("成功包裹错误: %v", body)
	}
	if body["errors"] != "" {
		t.Errorf("成功时 errors 应为空字符串: %v", body)
	}
	data := body["data"].(map[string]any)
	if data["k"].(float64) != 1 {
		t.Errorf("data 错误: %v", data)
	}
}

func TestEnvelopeFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	Fail(c, http.StatusForbidden, "请先登录")

	if w.Code != http.StatusForbidden {
		t.Errorf("status=%d want 403", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["msg"] != "请求失败" || body["code"].(float64) != 1 || body["errors"] != "请先登录" {
		t.Errorf("失败包裹错误: %v", body)
	}
	if _, ok := body["data"].(map[string]any); !ok {
		t.Errorf("失败时 data 应为空对象: %v", body["data"])
	}
}

func TestAPIErrorFieldJoin(t *testing.T) {
	err := NewFieldError("target", "目标必须是域名或 IPv4")
	if err.Error() != "目标必须是域名或 IPv4" {
		t.Errorf("字段错误消息错误: %s", err.Error())
	}
}
