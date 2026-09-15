// Package apitime 复刻原 Django 接口的时间序列化行为:
// USE_TZ=False + TIME_ZONE=Asia/Shanghai,DRF 输出 datetime.isoformat()——
// 本地时区、"2006-01-02T15:04:05" 且仅当微秒非零时追加 ".ffffff"(6 位,无时区后缀)。
package apitime

import (
	"fmt"
	"strings"
	"time"
)

const baseLayout = "2006-01-02T15:04:05"

// MarshalISO 按 Python isoformat 语义渲染 time。
func MarshalISO(t time.Time) string {
	if t.Nanosecond()/1000 == 0 {
		return t.Format(baseLayout)
	}
	return t.Format(baseLayout) + fmt.Sprintf(".%06d", t.Nanosecond()/1000)
}

// Time 是对外 JSON 序列化使用的包装类型;零值输出 null 需使用 *Time。
type Time struct{ time.Time }

func From(t time.Time) Time { return Time{t} }

func Now() Time { return Time{time.Now()} }

func (t Time) MarshalJSON() ([]byte, error) {
	if t.IsZero() {
		return []byte("null"), nil
	}
	return []byte(`"` + MarshalISO(t.Time) + `"`), nil
}

func (t *Time) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	if s == "" || s == "null" {
		t.Time = time.Time{}
		return nil
	}
	for _, layout := range []string{baseLayout + ".000000", baseLayout + ".000", baseLayout, time.RFC3339Nano, time.RFC3339} {
		if parsed, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			t.Time = parsed
			return nil
		}
	}
	return fmt.Errorf("apitime: 无法解析时间 %q", s)
}
