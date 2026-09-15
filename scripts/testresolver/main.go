// testresolver:本地测试用 DNS 服务器(替代 docker unbound,兼作压测 resolver)。
// 行为:example.test 及其子域返回固定记录(含 CNAME/NS/SOA),其余 NXDOMAIN 秒回。
// 用法:go run ./scripts/testresolver [-addr 127.0.0.1:8053]
package main

import (
	"flag"
	"log"
	"strings"

	"github.com/miekg/dns"
)

var records = map[string]map[uint16][]string{
	"example.test.": {
		dns.TypeA:    {"203.0.113.10"},
		dns.TypeAAAA: {"2001:db8::10"},
		dns.TypeNS:   {"ns1.example.test."},
		dns.TypeSOA:  {"ns1.example.test. admin.example.test. 2026091501 7200 3600 1209600 300"},
	},
	"www.example.test.": {
		dns.TypeCNAME: {"example.test."},
	},
	"ns1.example.test.": {
		dns.TypeA: {"203.0.113.53"},
	},
}

func handle(w dns.ResponseWriter, req *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.RecursionAvailable = true

	q := req.Question[0]
	log.Printf("query %s %s from %s", q.Name, dns.TypeToString[q.Qtype], w.RemoteAddr())
	rrs, ok := records[strings.ToLower(q.Name)]
	if !ok {
		resp.Rcode = dns.RcodeNameError
		// SOA in authority for NXDOMAIN
		soa, _ := dns.NewRR("test. 3600 IN SOA ns1.test. admin.test. 1 7200 3600 1209600 300")
		if soa != nil {
			resp.Ns = []dns.RR{soa}
		}
	} else if values, ok := rrs[q.Qtype]; ok {
		for _, v := range values {
			rr, err := dns.NewRR(dns.Fqdn(q.Name) + " 300 IN " + dns.TypeToString[q.Qtype] + " " + v)
			if err == nil {
				resp.Answer = append(resp.Answer, rr)
			}
		}
	} else if cnames, ok := rrs[dns.TypeCNAME]; ok && q.Qtype != dns.TypeCNAME {
		// 真实解析器行为:A 查询 CNAME-only 名称时返回 CNAME 并续接目标记录
		for _, v := range cnames {
			rr, err := dns.NewRR(dns.Fqdn(q.Name) + " 300 IN CNAME " + v)
			if err == nil {
				resp.Answer = append(resp.Answer, rr)
			}
			target := strings.ToLower(strings.Trim(v, ".") + ".")
			if targetRRs, ok := records[target]; ok {
				for _, tv := range targetRRs[q.Qtype] {
					trr, err := dns.NewRR(v + " 300 IN " + dns.TypeToString[q.Qtype] + " " + tv)
					if err == nil {
						resp.Answer = append(resp.Answer, trr)
					}
				}
			}
		}
	}
	_ = w.WriteMsg(resp)
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8053", "监听地址")
	flag.Parse()
	for _, network := range []string{"udp", "tcp"} {
		go func(net string) {
			server := &dns.Server{Addr: *addr, Net: net, Handler: dns.HandlerFunc(handle)}
			if err := server.ListenAndServe(); err != nil {
				log.Fatalf("%s 监听失败: %v", net, err)
			}
		}(network)
	}
	log.Printf("测试 DNS 服务器已启动 %s (example.test 本地域,其余 NXDOMAIN)", *addr)
	select {}
}
