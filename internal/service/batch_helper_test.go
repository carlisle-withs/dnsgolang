package service

import "dnsss/internal/engine/prober"

func probeResultFor(success bool, rcode, errorCode string) prober.Result {
	detail := map[string]any{}
	if rcode != "" {
		detail["rcode"] = rcode
	}
	return prober.Result{Success: success, ErrorCode: errorCode, Detail: detail}
}
