// Package dto 实现原系统的统一响应包裹(ResponseMiddleware 契约):
//
//	成功: HTTP 200/201, {"msg":"成功","errors":"","code":200,"data":<业务数据>}
//	失败: HTTP 4xx/5xx, {"msg":"请求失败","errors":"<描述>","code":1,"data":{}}
//
// 前端 axios 拦截器依赖此结构解包,任何接口不得裸返 JSON。
package dto

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	MsgSuccess = "成功"
	MsgFailure = "请求失败"

	CodeSuccess = 200
	CodeFailure = 1
)

// ErrLoginRequired 鉴权失败(403 + errors:"请先登录",前端据此跳转登录页)。
var ErrLoginRequired = errors.New("请先登录")

type envelope struct {
	Msg    string `json:"msg"`
	Errors any    `json:"errors"`
	Code   int    `json:"code"`
	Data   any    `json:"data"`
}

func OK(c *gin.Context, data any) {
	if data == nil {
		data = gin.H{}
	}
	c.AbortWithStatusJSON(http.StatusOK, envelope{MsgSuccess, "", CodeSuccess, data})
}

func Created(c *gin.Context, data any) {
	if data == nil {
		data = gin.H{}
	}
	c.AbortWithStatusJSON(http.StatusCreated, envelope{MsgSuccess, "", CodeSuccess, data})
}

func NoContent(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

// Fail 输出失败包裹。message 为空时输出 null(与原版 errors:null 行为一致)。
func Fail(c *gin.Context, status int, message string) {
	var errs any
	if message != "" {
		errs = message
	}
	c.AbortWithStatusJSON(status, envelope{MsgFailure, errs, CodeFailure, gin.H{}})
}

// APIError 携带 HTTP 状态与可选的字段级校验错误。字段错误被拼接为
// 一条人类可读描述,与原版 DRF ValidationError 的字段信息对齐。
type APIError struct {
	Status int
	Msg    string
	Fields map[string][]string
}

func (e *APIError) Error() string {
	if len(e.Fields) == 0 {
		return e.Msg
	}
	parts := make([]string, 0, len(e.Fields))
	for _, msgs := range e.Fields {
		parts = append(parts, msgs...)
	}
	if e.Msg != "" {
		parts = append(parts, e.Msg)
	}
	return strings.Join(parts, "; ")
}

func NewAPIError(status int, msg string) *APIError {
	return &APIError{Status: status, Msg: msg}
}

func NewFieldError(field, msg string) *APIError {
	return &APIError{Status: http.StatusBadRequest, Fields: map[string][]string{field: {msg}}}
}

// Abort 以 APIError 中止请求;未知错误一律 500 且不泄漏内部细节。
func Abort(c *gin.Context, err error) {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		Fail(c, apiErr.Status, apiErr.Error())
		return
	}
	Fail(c, http.StatusInternalServerError, "服务器内部错误")
}
