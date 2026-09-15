package dnsclient

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// 契约红线:应答行必须与 dnspython 的 "%s %s IN %s %s" 输出一致(dig 格式)。
func TestRRLinesDigFormat(t *testing.T) {
	rr, err := dns.NewRR("www.bupt.edu.cn. 422 IN CNAME vn46.bupt.edu.cn.")
	if err != nil {
		t.Fatal(err)
	}
	lines := rrLines([]dns.RR{rr})
	want := "www.bupt.edu.cn. 422 IN CNAME vn46.bupt.edu.cn."
	if lines[0] != want {
		t.Errorf("got %q want %q", lines[0], want)
	}

	aRR, _ := dns.NewRR("example.com. 300 IN A 93.184.216.34")
	lines = rrLines([]dns.RR{aRR})
	if lines[0] != "example.com. 300 IN A 93.184.216.34" {
		t.Errorf("A 记录格式错误: %q", lines[0])
	}
}

func TestDetectErrorKind(t *testing.T) {
	cases := []struct {
		msg, rcode, want string
	}{
		{"connection refused", "DNSERROR", "connection_refused"},
		{"", "SERVFAIL", "servfail"},
		{"read udp: i/o timeout", "DNSERROR", "timeout"},
		{"", "REFUSED", "refused"},
		{"something odd", "DNSERROR", "dns_error"},
	}
	for _, c := range cases {
		if got := DetectErrorKind(c.msg, c.rcode); got != c.want {
			t.Errorf("DetectErrorKind(%q,%q)=%s want %s", c.msg, c.rcode, got, c.want)
		}
	}
}

func TestSplitServer(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port int
	}{
		{"8.8.8.8", "8.8.8.8", 53},
		{"223.5.5.5:5353", "223.5.5.5", 5353},
		{"[2001:db8::1]:53", "2001:db8::1", 53},
		{"[2001:db8::1]", "2001:db8::1", 53},
	}
	for _, c := range cases {
		host, port := SplitServer(c.in, 53)
		if host != c.host || port != c.port {
			t.Errorf("SplitServer(%q)=(%s,%d) want (%s,%d)", c.in, host, port, c.host, c.port)
		}
	}
}

func TestInferZoneDomain(t *testing.T) {
	cases := map[string]string{
		"www.bupt.edu.cn.": "bupt.edu.cn",
		"example.com":      "example.com",
		"a.b.example.co.uk": "example.co.uk",
		"":                 "",
	}
	for in, want := range cases {
		if got := InferZoneDomain(in); got != want {
			t.Errorf("InferZoneDomain(%q)=%s want %s", in, got, want)
		}
	}
}

func TestFormatRawOutput(t *testing.T) {
	latency := 25.19
	out := FormatRawOutput("NOERROR", []string{"example.com. 300 IN A 1.2.3.4"}, nil, nil, &latency)
	want := ";; ->>HEADER<<- status: NOERROR\n;; ANSWER SECTION:\nexample.com. 300 IN A 1.2.3.4\n\n;; Query time: 25 msec"
	if out != want {
		t.Errorf("raw output 格式错误:\ngot  %s\nwant %s", out, want)
	}
}

func TestNormalizeName(t *testing.T) {
	if got := NormalizeName(" WWW.Example.COM. "); got != "www.example.com" {
		t.Errorf("NormalizeName=%s", got)
	}
}

func TestRoundMsKeepsTwoDecimals(t *testing.T) {
	v := roundMs(25190 * time.Microsecond)
	if *v != 25.19 {
		t.Errorf("roundMs=%v want 25.19", *v)
	}
}
