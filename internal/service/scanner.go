package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"dnsss/internal/dto"
	"dnsss/internal/engine/dnsclient"
	"dnsss/internal/engine/prober"
	"dnsss/internal/model"
	"dnsss/internal/risk"
)

// ---------- 扫描任务创建 ----------

// CreateScanJob 校验圈定主机集并异步执行(方案 2.6.3 流水线)。
func (s *Service) CreateScanJob(ctx context.Context, body map[string]any, requestedBy *uint64) (*model.ScanJob, error) {
	environment := orDefault(strAny(body["environment"], ""), model.TrustEnvProd)
	resolver := orDefault(strAny(body["resolver"], ""), "223.5.5.5")
	timeout := toFloatDefault(body["timeout"], 3)
	concurrency := int(toF(body["concurrency"]))
	if concurrency <= 0 {
		concurrency = 8
	}
	limit := int(toF(body["limit"]))
	keyword := strAny(body["keyword"], "")

	var domainIDs, hostIDs []uint64
	for _, v := range anySlice(body["domain_ids"]) {
		if id := toUint64(v); id > 0 {
			domainIDs = append(domainIDs, id)
		}
	}
	for _, v := range anySlice(body["host_ids"]) {
		if id := toUint64(v); id > 0 {
			hostIDs = append(hostIDs, id)
		}
	}
	var resolverPool []string
	for _, v := range anySlice(body["resolver_pool"]) {
		if r := strAny(v, ""); r != "" {
			resolverPool = append(resolverPool, r)
		}
	}

	// 圈定主机集
	query := s.gorm.WithContext(ctx).Model(&model.TrustHost{}).
		Joins("JOIN dns_trust_domains d ON d.id = dns_trust_hosts.domain_id").
		Where("dns_trust_hosts.enabled = 1 AND d.enabled = 1 AND d.environment = ?", environment)
	if len(domainIDs) > 0 {
		query = query.Where("dns_trust_hosts.domain_id IN ?", domainIDs)
	}
	if len(hostIDs) > 0 {
		query = query.Where("dns_trust_hosts.id IN ?", hostIDs)
	}
	if keyword != "" {
		query = query.Where("dns_trust_hosts.fqdn LIKE ?", "%"+strings.ToLower(keyword)+"%")
	}
	if limit > 0 && limit <= 5000 {
		query = query.Limit(limit)
	}
	var hosts []model.TrustHost
	if err := query.Order("dns_trust_hosts.id ASC").Find(&hosts).Error; err != nil {
		return nil, err
	}
	if len(hosts) == 0 {
		return nil, dto.NewFieldError("host_ids", "没有符合条件的可信主机")
	}
	domainIDSet := map[uint64]bool{}
	for _, h := range hosts {
		domainIDSet[h.DomainID] = true
	}

	job := &model.ScanJob{
		Environment: environment, Status: model.ScanStatusPending,
		RequestedByID: requestedBy, ResolverIP: resolver,
		TimeoutSeconds: timeout, Concurrency: concurrency,
		Keyword: keyword, ResolverPoolTx: marshalJSON(resolverPool),
		DomainIDsTx: marshalJSON(domainIDs), HostIDsTx: marshalJSON(hostIDs),
		TotalDomains: len(domainIDSet), TotalHosts: len(hosts),
		SummaryMessage: fmt.Sprintf("共 %d 个主机待扫描", len(hosts)),
	}
	if limit > 0 {
		job.LimitCount = &limit
	}
	job.FiltersTx = marshalJSON(map[string]any{
		"environment": environment, "domain_ids": domainIDs, "host_ids": hostIDs,
		"keyword": keyword, "limit": limit, "resolver": resolver,
	})
	if err := s.gorm.WithContext(ctx).Create(job).Error; err != nil {
		return nil, err
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.pool <- struct{}{}
		defer func() { <-s.pool }()
		if err := s.RunScanJob(context.Background(), job.ID); err != nil {
			slog.Error("扫描执行失败", "job_id", job.ID, "error", err)
		}
	}()
	return job, nil
}

func anySlice(v any) []any {
	if s, ok := v.([]any); ok {
		return s
	}
	return nil
}

func toFloatDefault(v any, fallback float64) float64 {
	if f := toF(v); f > 0 {
		return f
	}
	return fallback
}

// ---------- 扫描执行 ----------

// RunScanJob 扫描流水线:逐主机 生成计划 → 并发查询 → 快照 → 方法分析 → 判定落库。
func (s *Service) RunScanJob(ctx context.Context, jobID uint64) error {
	var job model.ScanJob
	if err := s.gorm.WithContext(ctx).First(&job, jobID).Error; err != nil {
		return err
	}
	now := time.Now()
	s.gorm.WithContext(ctx).Model(&job).Updates(map[string]any{
		"status": model.ScanStatusRunning, "started_at": now,
	})

	var domainIDs, hostIDs []uint64
	_ = json.Unmarshal([]byte(job.DomainIDsTx), &domainIDs)
	_ = json.Unmarshal([]byte(job.HostIDsTx), &hostIDs)
	query := s.gorm.WithContext(ctx).Model(&model.TrustHost{}).
		Joins("JOIN dns_trust_domains d ON d.id = dns_trust_hosts.domain_id").
		Where("dns_trust_hosts.enabled = 1 AND d.enabled = 1 AND d.environment = ?", job.Environment)
	if len(domainIDs) > 0 {
		query = query.Where("dns_trust_hosts.domain_id IN ?", domainIDs)
	}
	if len(hostIDs) > 0 {
		query = query.Where("dns_trust_hosts.id IN ?", hostIDs)
	}
	if job.Keyword != "" {
		query = query.Where("dns_trust_hosts.fqdn LIKE ?", "%"+job.Keyword+"%")
	}
	if job.LimitCount != nil && *job.LimitCount > 0 {
		query = query.Limit(*job.LimitCount)
	}
	var hosts []model.TrustHost
	if err := query.Order("dns_trust_hosts.id ASC").Find(&hosts).Error; err != nil {
		return err
	}
	var domains []model.TrustDomain
	s.gorm.WithContext(ctx).Find(&domains)
	domainMap := map[uint64]model.TrustDomain{}
	for _, d := range domains {
		domainMap[d.ID] = d
	}

	var resolverPool []string
	_ = json.Unmarshal([]byte(job.ResolverPoolTx), &resolverPool)

	var (
		mu          sync.Mutex
		processed   int
		successN    int
		suspiciousN int
		errorN      int
		latencySum  float64
		latencyCnt  int
		riskTypeCounts   = map[string]int{}
		severityCounts   = map[string]int{}
		confidenceCounts = map[string]int{}
		methodCounts     = map[string]int{}
		domainRiskCount  = map[uint64]int{}
	)

	sem := make(chan struct{}, job.Concurrency)
	var wg sync.WaitGroup
	for i := range hosts {
		host := hosts[i]
		domain := domainMap[host.DomainID]
		wg.Add(1)
		sem <- struct{}{}
		go func(host model.TrustHost, domain model.TrustDomain) {
			defer wg.Done()
			defer func() { <-sem }()
			hostCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
			defer cancel()
			result := s.scanHost(hostCtx, &job, host, domain, resolverPool)
			mu.Lock()
			defer mu.Unlock()
			processed++
			switch result.Status {
			case model.ResultStatusNormal:
				successN++
			case model.ResultStatusSuspicious:
				successN++
				suspiciousN++
			case model.ResultStatusError:
				errorN++
			}
			if result.LatencyMs != nil {
				latencySum += *result.LatencyMs
				latencyCnt++
			}
			var riskTypes []string
			_ = json.Unmarshal([]byte(result.RiskTypesTx), &riskTypes)
			for _, rt := range riskTypes {
				riskTypeCounts[rt]++
				if code := risk.MethodCodeForRisk(rt); code != "" {
					methodCounts[code]++
				}
			}
			if result.Severity != "" && len(riskTypes) > 0 {
				severityCounts[result.Severity]++
			}
			if result.ConfidenceTier != "" && len(riskTypes) > 0 {
				confidenceCounts[result.ConfidenceTier]++
			}
			if result.DomainID != nil && len(riskTypes) > 0 {
				domainRiskCount[*result.DomainID]++
			}
			// 进度回写(每 20 主机或收尾)
			if processed%20 == 0 || processed == len(hosts) {
				s.gorm.WithContext(ctx).Model(&model.ScanJob{}).Where("id = ?", job.ID).
					Updates(map[string]any{
						"processed_hosts": processed, "success_hosts": successN,
						"suspicious_hosts": suspiciousN, "error_hosts": errorN,
						"summary_message": fmt.Sprintf("已扫描 %d/%d 个主机", processed, len(hosts)),
					})
			}
		}(host, domain)
	}
	wg.Wait()

	// 汇总 summary(方案 2.6.4 实测结构)
	topRiskDomains := []map[string]any{}
	type domainRow struct {
		ID    uint64
		Domain string
		Count int
	}
	rows := []domainRow{}
	for id, count := range domainRiskCount {
		if d, ok := domainMap[id]; ok {
			rows = append(rows, domainRow{ID: id, Domain: d.Domain, Count: count})
		}
	}
	for i := 1; i < len(rows); i++ {
		for j := i; j > 0 && rows[j].Count > rows[j-1].Count; j-- {
			rows[j], rows[j-1] = rows[j-1], rows[j]
		}
	}
	for i, r := range rows {
		if i >= 5 {
			break
		}
		topRiskDomains = append(topRiskDomains, map[string]any{"domain": r.Domain, "riskCount": r.Count})
	}
	var avgLatency any
	if latencyCnt > 0 {
		v := float64(int(latencySum/float64(latencyCnt)*100+0.5)) / 100
		avgLatency = v
	}
	progressPercent := 100.0
	summary := map[string]any{
		"processedHosts": processed, "totalHosts": len(hosts),
		"successHosts": successN, "suspiciousHosts": suspiciousN, "errorHosts": errorN,
		"riskTypeCounts": riskTypeCounts, "severityCounts": severityCounts,
		"confidenceCounts": confidenceCounts, "methodCounts": methodCounts,
		"methodCount": len(methodCounts), "avgLatencyMs": avgLatency,
		"topRiskDomains": topRiskDomains, "progressPercent": progressPercent,
	}
	finished := time.Now()
	updates := map[string]any{
		"status": model.ScanStatusCompleted, "finished_at": finished,
		"processed_hosts": processed, "success_hosts": successN,
		"suspicious_hosts": suspiciousN, "error_hosts": errorN,
		"summary_text": marshalJSON(summary),
		"summary_message": fmt.Sprintf("扫描完成: %d 主机 / %d 可疑", processed, suspiciousN),
	}
	if avgLatency != nil {
		updates["avg_latency_ms"] = avgLatency
	}
	s.gorm.WithContext(ctx).Model(&model.ScanJob{}).Where("id = ?", job.ID).Updates(updates)
	return nil
}

// scanHost 执行单主机扫描:观测 → 判定 → 结果/快照/verdicts 落库。
func (s *Service) scanHost(ctx context.Context, job *model.ScanJob, host model.TrustHost, domain model.TrustDomain, resolverPool []string) *model.ScanResult {
	zoneDomain := domain.Domain
	// 查询计划(镜像 build_batch_scan_query_plan)
	plan := []prober.QueryStep{}
	udp := func(name, rtype string) prober.QueryStep {
		return prober.QueryStep{QueryName: name, RecordType: rtype, Transport: "udp", ServerMode: "resolver", RepeatCount: 1, EDNS: true}
	}
	if normalizeFQDN(host.FQDN) == normalizeFQDN(zoneDomain) {
		plan = []prober.QueryStep{udp(zoneDomain, "A"), udp(zoneDomain, "AAAA"), udp(zoneDomain, "NS"), udp(zoneDomain, "SOA")}
	} else if strings.Contains(strings.ToLower(host.Notes), "role=ns_host") || strings.HasPrefix(host.FQDN, "ns") {
		plan = []prober.QueryStep{udp(host.FQDN, "A"), udp(host.FQDN, "AAAA")}
	} else {
		plan = []prober.QueryStep{udp(host.FQDN, "A"), udp(host.FQDN, "AAAA"), udp(host.FQDN, "CNAME")}
	}

	observedAt := time.Now()
	var records []model.ObservationRecord
	snapshot := &model.ObservationSnapshot{
		HostID: host.ID, ScanJobID: &job.ID, ResolverIP: job.ResolverIP,
		QueryPlanTx: marshalJSON(plan), ObservedAt: &observedAt,
	}
	riskObs := risk.Observation{ResolverAnswers: map[string][]string{}}
	var primaryLatency *float64
	rawOutputs := []string{}
	traceBroken := false

	for _, step := range plan {
		res := dnsclient.RunQuery(ctx, dnsclient.Spec{
			QueryName: step.QueryName, RecordType: step.RecordType, ResolverIP: job.ResolverIP,
			Timeout: job.TimeoutSeconds, Transport: step.Transport, ServerMode: step.ServerMode,
			EDNS: step.EDNS, RecursionDesired: true,
		})
		rawOutputs = append(rawOutputs, res.RawOutput)
		if primaryLatency == nil && res.LatencyMs != nil {
			primaryLatency = res.LatencyMs
			snapshot.LatencyMs = res.LatencyMs
		}
		if res.Rcode != "NOERROR" && res.ErrorKind != "" && snapshot.RCODE == "" {
			snapshot.RCODE = res.Rcode
			snapshot.ErrorKind = res.ErrorKind
		}
		if snapshot.RCODE == "" || snapshot.RCODE == "NOERROR" {
			snapshot.RCODE = res.Rcode
			if res.Rcode == "NOERROR" {
				snapshot.ErrorKind = ""
			}
		}
		for section, lines := range map[string][]string{"answer": res.Answer, "authority": res.Authority, "additional": res.Additional} {
			for _, line := range lines {
				rr := parseRRLine(line, section)
				if rr == nil {
					continue
				}
				records = append(records, model.ObservationRecord{
					SnapshotID: 0, Section: rr.Section, RRName: rr.RRName,
					RRType: rr.RRType, RRValue: rr.RRValue, TTL: rr.TTL,
				})
				switch {
				case rr.RRType == "NS" && normalizeFQDN(rr.RRName) == normalizeFQDN(zoneDomain):
					riskObs.NSNameList = appendUnique(riskObs.NSNameList, strings.Trim(rr.RRValue, "."))
				case (rr.RRType == "A" || rr.RRType == "AAAA") && rr.Section == "answer" && normalizeFQDN(rr.RRName) == normalizeFQDN(host.FQDN):
					riskObs.UniqueIPSet = appendUnique(riskObs.UniqueIPSet, rr.RRValue)
				case (rr.RRType == "A" || rr.RRType == "AAAA") && rr.Section == "additional":
					riskObs.NSGlueIPList = appendUnique(riskObs.NSGlueIPList, rr.RRValue)
				case rr.RRType == "SOA":
					values := strings.Fields(rr.RRValue)
					if len(values) > 0 {
						snapshot.SOAMname = strings.Trim(values[0], ".")
					}
					if len(values) > 2 {
						snapshot.SOASerial = values[2]
					}
				}
			}
		}
	}

	// resolver_pool 交叉复核(方法6)
	for _, resolver := range resolverPool {
		res := dnsclient.RunQuery(ctx, dnsclient.Spec{
			QueryName: host.FQDN, RecordType: "A", ResolverIP: resolver,
			Timeout: job.TimeoutSeconds, Transport: "udp", ServerMode: "resolver",
			EDNS: true, RecursionDesired: true,
		})
		riskObs.ResolverAnswers[resolver] = append([]string{}, res.ResolvedIPs...)
	}

	snapshot.NSNameListTx = marshalJSON(riskObs.NSNameList)
	snapshot.NSGlueIPListTx = marshalJSON(riskObs.NSGlueIPList)
	snapshot.UniqueIPSetTx = marshalJSON(riskObs.UniqueIPSet)
	snapshot.RawOutputTx = strings.Join(rawOutputs, "\n\n")

	// 泛解析探测(apex 主机)
	if normalizeFQDN(host.FQDN) == normalizeFQDN(zoneDomain) {
		randomLabel := fmt.Sprintf("np-%d", time.Now().UnixMilli())
		probeName := randomLabel + "." + zoneDomain
		res := dnsclient.RunQuery(ctx, dnsclient.Spec{
			QueryName: probeName, RecordType: "A", ResolverIP: job.ResolverIP,
			Timeout: job.TimeoutSeconds, Transport: "udp", ServerMode: "resolver",
			EDNS: true, RecursionDesired: true,
		})
		if len(res.Answer) > 0 {
			riskObs.WildcardHit = true
			snapshot.WildcardHit = true
		}
		snapshot.RandomLabel = randomLabel
	}

	// 基线
	var baselines []model.TrustRecordBaseline
	s.gorm.WithContext(ctx).Where("host_id = ?", host.ID).Find(&baselines)
	// zone apex 主机配置(泛解析/AXFR 开关看 zone)
	zoneHost := host
	if normalizeFQDN(host.FQDN) != normalizeFQDN(zoneDomain) {
		var apex model.TrustHost
		if err := s.gorm.WithContext(ctx).Where("domain_id = ? AND fqdn = ?", host.DomainID, zoneDomain).First(&apex).Error; err == nil {
			zoneHost = apex
		}
	}

	hostConfig := risk.HostConfig{
		FQDN: host.FQDN, ZoneDomain: zoneDomain,
		AllowWildcard: zoneHost.AllowWildcard, AllowAXFR: zoneHost.AllowAXFR,
		AllowRebind: host.AllowRebind,
		IsApex: normalizeFQDN(host.FQDN) == normalizeFQDN(zoneDomain),
	}
	riskRecords := make([]risk.RecordObserved, 0, len(records))
	for _, r := range records {
		riskRecords = append(riskRecords, risk.RecordObserved{Section: r.Section, Name: r.RRName, Type: r.RRType, Value: r.RRValue, TTL: r.TTL})
	}
	riskBaseline := make([]risk.RecordBaseline, 0, len(baselines))
	for _, b := range baselines {
		riskBaseline = append(riskBaseline, risk.RecordBaseline{Section: b.Section, Name: b.RRName, Type: b.RRType, Value: b.RRValue, TTLMin: b.TTLMin, TTLMax: b.TTLMax})
	}
	riskObs.Records = riskRecords
	riskObs.RCODE = snapshot.RCODE
	riskObs.ErrorKind = snapshot.ErrorKind
	riskObs.TraceBroken = traceBroken
	riskObs.AXFRSuccess = snapshot.AXFRSuccess
	riskObs.AXFRRecords = snapshot.AXFRRecordCount
	riskObs.RandomLabel = snapshot.RandomLabel
	riskObs.LatencyMs = snapshot.LatencyMs
	verdicts := risk.Evaluate(hostConfig, riskBaseline, riskObs)
	suspicious := risk.SuspiciousOf(verdicts)

	// 快照 + 观测记录落库
	if err := s.gorm.WithContext(ctx).Create(snapshot).Error; err == nil {
		for i := range records {
			records[i].SnapshotID = snapshot.ID
		}
		if len(records) > 0 {
			s.gorm.WithContext(ctx).CreateInBatches(records, 200)
		}
		methodFindings := map[string]any{}
		for _, v := range verdicts {
			if v.Status == "suspicious" {
				methodFindings[v.MethodCode] = appendFindings(methodFindings[v.MethodCode], v)
			}
		}
		for code, findings := range methodFindings {
			s.gorm.WithContext(ctx).Create(&model.ObservationMethodEvidence{
				SnapshotID: snapshot.ID, MethodCode: code, FindingsTx: marshalJSON(findings),
			})
		}
	}

	// verdicts upsert(host × risk_type 唯一)
	detectedAt := observedAt
	for _, v := range verdicts {
		record := model.RiskVerdictLatest{
			HostID: host.ID, RiskType: v.RiskType, Status: v.Status,
			Severity: v.Severity, ConfidenceTier: v.ConfidenceTier,
			MethodCode: v.MethodCode, SummaryMessage: v.SummaryMessage,
			EvidenceTx: marshalJSON(v.Evidence), DetectedAt: &detectedAt,
		}
		s.gorm.WithContext(ctx).
			Where(model.RiskVerdictLatest{HostID: host.ID, RiskType: v.RiskType}).
			Assign(record).FirstOrCreate(&model.RiskVerdictLatest{})
	}

	// 扫描结果
	riskTypes := make([]string, 0, len(suspicious))
	confidenceLabels := map[string]bool{}
	for _, v := range suspicious {
		riskTypes = append(riskTypes, v.RiskType)
		if v.ConfidenceLabel != "" {
			confidenceLabels[v.ConfidenceLabel] = true
		}
	}
	status := model.ResultStatusNormal
	summaryMessage := "未发现风险异常"
	if snapshot.ErrorKind != "" && snapshot.RCODE != "NOERROR" && snapshot.RCODE != "NXDOMAIN" {
		status = model.ResultStatusNormal
	}
	if len(riskTypes) > 0 {
		status = model.ResultStatusSuspicious
		summaryMessage = fmt.Sprintf("发现 %d 类需复核 DNS 异常：%s", len(riskTypes), strings.Join(riskTypes, ", "))
		if tier := risk.HighestConfidenceTier(riskTypes); tier == "high_confidence" {
			summaryMessage = fmt.Sprintf("发现 %d 类 DNS 异常（含高置信）：%s", len(riskTypes), strings.Join(riskTypes, ", "))
		}
	}
	labels := make([]string, 0, len(confidenceLabels))
	for label := range confidenceLabels {
		labels = append(labels, label)
	}
	sortStrings(labels)
	domainID := host.DomainID
	snapshotID := snapshot.ID
	result := &model.ScanResult{
		ScanJobID: job.ID, DomainID: &domainID, HostID: host.ID,
		SnapshotID: &snapshotID, Status: status,
		Severity: risk.HighestSeverity(riskTypes),
		ConfidenceTier: risk.HighestConfidenceTier(riskTypes),
		ConfidenceLabelsTx: marshalJSON(labels),
		SuspiciousCount: len(riskTypes), SummaryMessage: summaryMessage,
		RCODE: snapshot.RCODE, ErrorKind: snapshot.ErrorKind,
		LatencyMs: snapshot.LatencyMs,
		RiskTypesTx: marshalJSON(riskTypes),
		EvidenceTx: marshalJSON(map[string]any{
			"jobId": job.ID, "fqdn": host.FQDN, "resolver": job.ResolverIP,
			"queryPlan": plan,
			"observations": map[string]any{
				"rcode": snapshot.RCODE, "nsNames": riskObs.NSNameList,
				"glueIps": riskObs.NSGlueIPList, "uniqueIps": riskObs.UniqueIPSet,
				"wildcardHit": riskObs.WildcardHit,
			},
			"methodResults": suspiciousEvidence(suspicious),
			"verdicts": verdictEvidence(verdicts),
		}),
		DetectedAt: &detectedAt,
	}
	if err := s.gorm.WithContext(ctx).Create(result).Error; err != nil {
		slog.Error("扫描结果落库失败", "host", host.ID, "error", err)
	}
	return result
}

func appendUnique(list []string, v string) []string {
	for _, item := range list {
		if item == v {
			return list
		}
	}
	return append(list, v)
}

func appendFindings(existing any, v risk.Verdict) []map[string]any {
	var list []map[string]any
	switch e := existing.(type) {
	case []map[string]any:
		list = e
	case []any:
		list = make([]map[string]any, 0, len(e))
		for _, item := range e {
			if m, ok := item.(map[string]any); ok {
				list = append(list, m)
			}
		}
	}
	return append(list, map[string]any{
		"riskType": v.RiskType, "severity": v.Severity,
		"confidenceTier": v.ConfidenceTier, "summary": v.SummaryMessage,
		"evidence": v.Evidence,
	})
}

func suspiciousEvidence(suspicious []risk.Verdict) []map[string]any {
	out := make([]map[string]any, 0, len(suspicious))
	for _, v := range suspicious {
		out = append(out, map[string]any{
			"riskType": v.RiskType, "methodCode": v.MethodCode, "methodLabel": v.MethodLabel,
			"severity": v.Severity, "confidenceTier": v.ConfidenceTier,
			"summary": v.SummaryMessage, "evidence": v.Evidence,
		})
	}
	return out
}

func verdictEvidence(verdicts []risk.Verdict) []map[string]any {
	out := make([]map[string]any, 0, len(verdicts))
	for _, v := range verdicts {
		out = append(out, map[string]any{
			"riskType": v.RiskType, "status": v.Status, "severity": v.Severity,
			"confidenceTier": v.ConfidenceTier, "summary": v.SummaryMessage,
		})
	}
	return out
}

// RequestScanStop 停止扫描(协作式:执行循环按 processed 检查,终态幂等)。
func (s *Service) RequestScanStop(ctx context.Context, jobID uint64) error {
	var job model.ScanJob
	if err := s.gorm.WithContext(ctx).First(&job, jobID).Error; err != nil {
		return dto.NewAPIError(400, "扫描任务不存在")
	}
	if job.Status != model.ScanStatusPending && job.Status != model.ScanStatusRunning {
		return nil
	}
	return s.gorm.WithContext(ctx).Model(&job).Updates(map[string]any{
		"status": model.ScanStatusFailed, "last_error": "manual_stop",
		"summary_message": "扫描已手动停止", "finished_at": time.Now(),
	}).Error
}

// ---------- 监测 profile 调度(每分钟) ----------

// RunDueMonitorProfiles 触发到期 profile(方案 2.8 run_due_monitor_profiles)。
func (s *Service) RunDueMonitorProfiles(ctx context.Context) error {
	var profiles []model.ScanMonitorProfile
	now := time.Now()
	s.gorm.WithContext(ctx).
		Where("enabled = 1 AND (last_run_at IS NULL OR last_run_at <= ?)", now.Add(-time.Duration(1)*time.Second)).
		Find(&profiles)
	for i := range profiles {
		profile := &profiles[i]
		if profile.LastRunAt != nil && now.Sub(*profile.LastRunAt) < time.Duration(profile.IntervalSeconds)*time.Second {
			continue
		}
		job, err := s.CreateScanJob(ctx, map[string]any{
			"environment":  profile.Environment,
			"resolver":     profile.ResolverIP,
			"resolver_pool": jsonAny(profile.ResolverPoolTx),
			"timeout":      profile.TimeoutSeconds,
			"concurrency":  profile.Concurrency,
			"keyword":      profile.Keyword,
			"domain_ids":   jsonAny(profile.DomainIDsTx),
			"host_ids":     jsonAny(profile.HostIDsTx),
		}, profile.CreatedByID)
		if err != nil {
			slog.Warn("监测 profile 触发失败", "profile", profile.ID, "error", err)
			s.gorm.WithContext(ctx).Model(profile).Updates(map[string]any{"last_status": "failed", "last_run_at": now})
			continue
		}
		s.gorm.WithContext(ctx).Model(profile).Updates(map[string]any{
			"last_status": "running", "last_run_at": now,
		})
		_ = job
	}
	return nil
}

func jsonAny(s string) any {
	var v any
	if strings.TrimSpace(s) != "" {
		_ = json.Unmarshal([]byte(s), &v)
	}
	return v
}
