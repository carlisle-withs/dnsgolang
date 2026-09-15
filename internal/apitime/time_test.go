package apitime

import (
	"encoding/json"
	"testing"
	"time"
)

// 契约红线:时间格式必须与原 Django 输出一致(本地时区 + 微秒 6 位,无时区后缀;
// 微秒为 0 时 Python isoformat 不输出小数部分)。
func TestMarshalISO(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	cases := []struct {
		in   time.Time
		want string
	}{
		{time.Date(2026, 9, 15, 16, 17, 47, 82865*1000, loc), `"2026-09-15T16:17:47.082865"`},
		{time.Date(2026, 9, 15, 16, 17, 47, 0, loc), `"2026-09-15T16:17:47"`},
	}
	for _, c := range cases {
		data, err := json.Marshal(From(c.in))
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != c.want {
			t.Errorf("got %s want %s", data, c.want)
		}
	}
}

func TestNullTime(t *testing.T) {
	var v *Time
	data, _ := json.Marshal(v)
	if string(data) != "null" {
		t.Errorf("nil 时间应输出 null,got %s", data)
	}
}

func TestRoundTrip(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	original := From(time.Date(2026, 9, 15, 16, 17, 47, 82865*1000, loc))
	data, _ := json.Marshal(original)
	var parsed Time
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if got := MarshalISO(parsed.Time); got != "2026-09-15T16:17:47.082865" {
		t.Errorf("round trip 格式变化: %s", got)
	}
}
