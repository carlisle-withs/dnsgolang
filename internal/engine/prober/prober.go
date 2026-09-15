// Package prober 定义五协议拨测执行器统一接口。
// detail 为协议专属明细(map 键与原版序列化字段一致),由调用方落库/序列化。
package prober

// Result 拨测结果(对应原 execute_*_probe 的返回结构)。
type Result struct {
	Success       bool
	Status        string // success | failed
	ResolvedTarget string
	LatencyMs     *float64
	ErrorCode     string
	ErrorMessage  string
	RawPayload    map[string]any
	Detail        map[string]any
}

func failedResult(errorCode, errorMessage string, raw map[string]any) Result {
	if raw == nil {
		raw = map[string]any{}
	}
	return Result{
		Success: false, Status: "failed",
		ErrorCode: errorCode, ErrorMessage: errorMessage,
		RawPayload: raw, Detail: map[string]any{},
	}
}
