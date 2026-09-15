package service

import (
	"context"
	"strconv"
	"strings"

	"dnsss/internal/apitime"
	"dnsss/internal/dto"
	"dnsss/internal/model"
)

// ---------- dns-trust DTO(镜像 DnsTrust*Serializer) ----------

func ptrInt64(v int64) *int64 { return &v }

// trustDomainPayload 镜像 DnsTrustDomainSerializer。
func (s *Service) trustDomainPayload(ctx context.Context, d model.TrustDomain, hostCount *int64) map[string]any {
	if hostCount == nil {
		var count int64
		s.gorm.WithContext(ctx).Model(&model.TrustHost{}).Where("domain_id = ?", d.ID).Count(&count)
		hostCount = &count
	}
	return map[string]any{
		"id": d.ID, "domain": d.Domain, "owner": d.Owner, "importance": d.Importance,
		"enabled": d.Enabled, "environment": d.Environment, "notes": d.Notes,
		"create_time": apitime.From(d.CreateTime), "update_time": apitime.From(d.UpdateTime),
		"hostCount": *hostCount,
	}
}

// ListTrustDomains 镜像 DomainListCreateAPIView.get。
func (s *Service) ListTrustDomains(ctx context.Context, environment, keyword, domainID string, page, pageSize int) (map[string]any, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 5000 {
		pageSize = 20
	}
	query := s.gorm.WithContext(ctx).Model(&model.TrustDomain{})
	if domainID != "" {
		query = query.Where("id = ?", domainID)
	}
	if environment != "" {
		query = query.Where("environment = ?", environment)
	}
	if keyword != "" {
		query = query.Where("domain LIKE ?", "%"+keyword+"%")
	}
	var total int64
	query.Count(&total)
	var domains []model.TrustDomain
	query.Order("environment ASC, domain ASC").Offset((page - 1) * pageSize).Limit(pageSize).Find(&domains)
	hostCounts := map[uint64]int64{}
	if len(domains) > 0 {
		ids := make([]uint64, 0, len(domains))
		for _, d := range domains {
			ids = append(ids, d.ID)
		}
		type countRow struct {
			DomainID uint64
			Count    int64
		}
		var rows []countRow
		s.gorm.WithContext(ctx).Model(&model.TrustHost{}).Select("domain_id, COUNT(*) AS count").
			Where("domain_id IN ?", ids).Group("domain_id").Scan(&rows)
		for _, r := range rows {
			hostCounts[r.DomainID] = r.Count
		}
	}
	results := make([]map[string]any, 0, len(domains))
	for _, d := range domains {
		count := hostCounts[d.ID]
		results = append(results, s.trustDomainPayload(ctx, d, &count))
	}
	return map[string]any{
		"results": results, "total": total, "page": page,
		"pageSize": pageSize, "totalPages": totalPagesOf(int(total), pageSize),
	}, nil
}

func totalPagesOf(total, pageSize int) int {
	if total == 0 || pageSize == 0 {
		return 0
	}
	return (total + pageSize - 1) / pageSize
}

// CreateTrustDomain 镜像 POST /domains。
func (s *Service) CreateTrustDomain(ctx context.Context, body map[string]any) (map[string]any, error) {
	domain := normalizeFQDN(strAny(body["domain"], ""))
	if domain == "" {
		return nil, dto.NewFieldError("domain", "该字段是必填项。")
	}
	environment := orDefault(strAny(body["environment"], ""), model.TrustEnvProd)
	if environment != model.TrustEnvProd && environment != model.TrustEnvLab {
		return nil, dto.NewFieldError("environment", "必须是其中一个候选值: prod, lab。")
	}
	importance := orDefault(strAny(body["importance"], ""), model.TrustImportanceHigh)
	switch importance {
	case model.TrustImportanceCritical, model.TrustImportanceHigh, model.TrustImportanceMedium:
	default:
		return nil, dto.NewFieldError("importance", "必须是其中一个候选值: critical, high, medium。")
	}
	var existing model.TrustDomain
	if err := s.gorm.WithContext(ctx).Where(model.TrustDomain{Domain: domain, Environment: environment}).First(&existing).Error; err == nil {
		return nil, dto.NewFieldError("domain", "主域已存在")
	}
	record := model.TrustDomain{
		Domain: domain, Owner: strAny(body["owner"], ""),
		Importance: importance, Enabled: true, Environment: environment,
		Notes: strAny(body["notes"], ""),
	}
	if v, ok := body["enabled"].(bool); ok {
		record.Enabled = v
	}
	if err := s.gorm.WithContext(ctx).Create(&record).Error; err != nil {
		return nil, err
	}
	return s.trustDomainPayload(ctx, record, ptrInt64(0)), nil
}

// trustHostPayload 镜像 DnsTrustHostSerializer。
func (s *Service) trustHostPayload(ctx context.Context, h model.TrustHost, domain model.TrustDomain, baselineCount, pendingCount *int64) map[string]any {
	if baselineCount == nil {
		var count int64
		s.gorm.WithContext(ctx).Model(&model.TrustRecordBaseline{}).Where("host_id = ?", h.ID).Count(&count)
		baselineCount = &count
	}
	if pendingCount == nil {
		var count int64
		s.gorm.WithContext(ctx).Model(&model.TrustCandidateRecord{}).
			Where("host_id = ? AND status = ?", h.ID, model.CandidateStatusDraft).Count(&count)
		pendingCount = &count
	}
	return map[string]any{
		"id": h.ID, "domainId": h.DomainID, "domainName": domain.Domain,
		"environment": domain.Environment, "fqdn": h.FQDN,
		"baseline_source": h.BaselineSource, "baseline_status": h.BaselineStatus,
		"allow_wildcard": h.AllowWildcard, "allow_axfr": h.AllowAXFR,
		"allow_rebind": h.AllowRebind, "dnssec_expected": h.DNSSECExpected,
		"enabled": h.Enabled, "notes": h.Notes,
		"create_time": apitime.From(h.CreateTime), "update_time": apitime.From(h.UpdateTime),
		"baselineCount": *baselineCount, "pendingCandidateCount": *pendingCount,
	}
}

// ListTrustHosts 镜像 HostListCreateAPIView.get(ids_only/无分页/分页三种形态)。
func (s *Service) ListTrustHosts(ctx context.Context, domainID, environment, keyword, idsOnly string, withPageSize bool, page, pageSize int) (map[string]any, error) {
	query := s.gorm.WithContext(ctx).Model(&model.TrustHost{})
	if domainID != "" {
		query = query.Where("domain_id = ?", domainID)
	}
	if environment != "" {
		query = query.Where("domain_id IN (?)", s.gorm.Model(&model.TrustDomain{}).Select("id").Where("environment = ?", environment))
	}
	if keyword != "" {
		query = query.Where("fqdn LIKE ?", "%"+keyword+"%")
	}
	if idsOnly == "1" || idsOnly == "true" || idsOnly == "yes" {
		var ids []uint64
		query.Order("id ASC").Pluck("id", &ids)
		results := make([]map[string]any, 0, len(ids))
		for _, id := range ids {
			results = append(results, map[string]any{"id": id})
		}
		return map[string]any{"results": results, "total": len(ids)}, nil
	}
	var total int64
	query.Count(&total)
	if !withPageSize {
		var hosts []model.TrustHost
		query.Order("domain_id ASC, fqdn ASC").Find(&hosts)
		return map[string]any{"results": s.trustHostListPayloads(ctx, hosts), "total": total}, nil
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 500 {
		pageSize = 20
	}
	var hosts []model.TrustHost
	query.Order("domain_id ASC, fqdn ASC").Offset((page - 1) * pageSize).Limit(pageSize).Find(&hosts)
	return map[string]any{
		"results": s.trustHostListPayloads(ctx, hosts), "total": total,
		"page": page, "pageSize": pageSize, "totalPages": totalPagesOf(int(total), pageSize),
	}, nil
}

func (s *Service) trustHostListPayloads(ctx context.Context, hosts []model.TrustHost) []map[string]any {
	if len(hosts) == 0 {
		return []map[string]any{}
	}
	hostIDs := make([]uint64, 0, len(hosts))
	domainIDs := map[uint64]bool{}
	for _, h := range hosts {
		hostIDs = append(hostIDs, h.ID)
		domainIDs[h.DomainID] = true
	}
	ids := make([]uint64, 0, len(domainIDs))
	for id := range domainIDs {
		ids = append(ids, id)
	}
	var domains []model.TrustDomain
	s.gorm.WithContext(ctx).Where("id IN ?", ids).Find(&domains)
	domainMap := map[uint64]model.TrustDomain{}
	for _, d := range domains {
		domainMap[d.ID] = d
	}
	baselineCounts := map[uint64]int64{}
	pendingCounts := map[uint64]int64{}
	type countRow struct {
		HostID uint64
		Count  int64
	}
	var baselineRows []countRow
	s.gorm.WithContext(ctx).Model(&model.TrustRecordBaseline{}).
		Select("host_id, COUNT(*) AS count").Where("host_id IN ?", hostIDs).Group("host_id").Scan(&baselineRows)
	for _, r := range baselineRows {
		baselineCounts[r.HostID] = r.Count
	}
	var pendingRows []countRow
	s.gorm.WithContext(ctx).Model(&model.TrustCandidateRecord{}).
		Select("host_id, COUNT(*) AS count").
		Where("host_id IN ? AND status = ?", hostIDs, model.CandidateStatusDraft).
		Group("host_id").Scan(&pendingRows)
	for _, r := range pendingRows {
		pendingCounts[r.HostID] = r.Count
	}
	results := make([]map[string]any, 0, len(hosts))
	for _, h := range hosts {
		domain := domainMap[h.DomainID]
		bc, pc := baselineCounts[h.ID], pendingCounts[h.ID]
		results = append(results, s.trustHostPayload(ctx, h, domain, &bc, &pc))
	}
	return results
}

// CreateTrustHost 镜像 POST /hosts。
func (s *Service) CreateTrustHost(ctx context.Context, body map[string]any) (map[string]any, error) {
	domainID := toUint64(body["domain_id"])
	if domainID == 0 {
		return nil, dto.NewFieldError("domain_id", "该字段是必填项。")
	}
	var domain model.TrustDomain
	if err := s.gorm.WithContext(ctx).First(&domain, domainID).Error; err != nil {
		return nil, dto.NewFieldError("domain_id", "主域不存在")
	}
	fqdn := normalizeFQDN(strAny(body["fqdn"], ""))
	if fqdn == "" {
		return nil, dto.NewFieldError("fqdn", "主机名不能为空")
	}
	host := model.TrustHost{
		DomainID: domainID, FQDN: fqdn,
		BaselineSource: orDefault(strAny(body["baseline_source"], ""), model.TrustSourceManual),
		BaselineStatus: orDefault(strAny(body["baseline_status"], ""), model.TrustStatusTrusted),
		AllowWildcard:  toBoolBody(body["allow_wildcard"], false),
		AllowAXFR:      toBoolBody(body["allow_axfr"], false),
		AllowRebind:    toBoolBody(body["allow_rebind"], false),
		DNSSECExpected: toBoolBody(body["dnssec_expected"], false),
		Enabled:        toBoolBody(body["enabled"], true),
		Notes:          strAny(body["notes"], ""),
	}
	if err := s.gorm.WithContext(ctx).Create(&host).Error; err != nil {
		return nil, err
	}
	return s.trustHostPayload(ctx, host, domain, ptrInt64(0), ptrInt64(0)), nil
}

func toUint64(v any) uint64 {
	switch n := v.(type) {
	case float64:
		return uint64(n)
	case uint64:
		return n
	case int:
		return uint64(n)
	case string:
		parsed, _ := strconv.ParseUint(n, 10, 64)
		return parsed
	}
	return 0
}

func toBoolBody(v any, fallback bool) bool {
	switch b := v.(type) {
	case bool:
		return b
	case string:
		return b == "true" || b == "1"
	}
	return fallback
}

// GetTrustHost 取主机(含所属域)。
func (s *Service) GetTrustHost(ctx context.Context, hostID uint64) (*model.TrustHost, *model.TrustDomain, error) {
	var host model.TrustHost
	if err := s.gorm.WithContext(ctx).First(&host, hostID).Error; err != nil {
		return nil, nil, dto.NewAPIError(400, "可信主机不存在")
	}
	var domain model.TrustDomain
	if err := s.gorm.WithContext(ctx).First(&domain, host.DomainID).Error; err != nil {
		return nil, nil, dto.NewAPIError(400, "主域不存在")
	}
	return &host, &domain, nil
}

// BuildHostBaseline 镜像 HostBaselineAPIView。
func (s *Service) BuildHostBaseline(ctx context.Context, hostID uint64) (map[string]any, error) {
	host, domain, err := s.GetTrustHost(ctx, hostID)
	if err != nil {
		return nil, err
	}
	var records []model.TrustRecordBaseline
	s.gorm.WithContext(ctx).Where("host_id = ?", host.ID).
		Order("section ASC, rrname ASC, rrtype ASC, rrvalue ASC").Find(&records)
	recordPayloads := make([]map[string]any, 0, len(records))
	for _, r := range records {
		recordPayloads = append(recordPayloads, map[string]any{
			"id": r.ID, "section": r.Section, "rrname": r.RRName, "rrtype": r.RRType,
			"rrvalue": r.RRValue, "ttl_min": r.TTLMin, "ttl_max": r.TTLMax, "is_required": r.IsRequired,
		})
	}
	return map[string]any{
		"host":    s.trustHostPayload(ctx, *host, *domain, nil, nil),
		"records": recordPayloads,
	}, nil
}

// BuildHostCandidates 镜像 get_host_candidate_payload(batches + diffStatus + removedRecords)。
func (s *Service) BuildHostCandidates(ctx context.Context, hostID uint64) (map[string]any, error) {
	host, domain, err := s.GetTrustHost(ctx, hostID)
	if err != nil {
		return nil, err
	}
	var baselines []model.TrustRecordBaseline
	s.gorm.WithContext(ctx).Where("host_id = ?", host.ID).
		Order("section ASC, rrname ASC, rrtype ASC, rrvalue ASC").Find(&baselines)
	baselineExact := map[string]model.TrustRecordBaseline{}
	baselineGroup := map[string]bool{}
	for _, r := range baselines {
		exactKey := rrExactKey(r.Section, r.RRName, r.RRType, r.RRValue)
		baselineExact[exactKey] = r
		baselineGroup[rrGroupKey(r.Section, r.RRName, r.RRType)] = true
	}
	var candidates []model.TrustCandidateRecord
	s.gorm.WithContext(ctx).Where("host_id = ?", host.ID).
		Order("batch_id DESC, section ASC, rrname ASC, rrtype ASC, rrvalue ASC").Find(&candidates)
	var batches []model.TrustCandidateBatch
	s.gorm.WithContext(ctx).Find(&batches)
	batchMap := map[uint64]model.TrustCandidateBatch{}
	for _, b := range batches {
		batchMap[b.ID] = b
	}

	type batchPayload struct {
		batch         map[string]any
		records       []map[string]any
		candidateKeys map[string]bool
	}
	grouped := []*batchPayload{}
	groupIndex := map[uint64]*batchPayload{}
	for _, r := range candidates {
		entry, ok := groupIndex[r.BatchID]
		if !ok {
			b := batchMap[r.BatchID]
			entry = &batchPayload{
				batch: map[string]any{
					"id": b.ID, "source_type": b.SourceType, "source_label": b.SourceLabel,
					"environment": b.Environment, "status": b.Status,
					"requestedBy": s.userNameOf(ctx, b.RequestedByID),
					"approvedBy":  s.userNameOf(ctx, b.ApprovedByID),
					"approved_at": apitimeFromPtr(b.ApprovedAt),
					"summary_message": b.SummaryMessage,
					"create_time":    apitime.From(b.CreateTime),
					"candidateCount": 0,
				},
				records:       []map[string]any{},
				candidateKeys: map[string]bool{},
			}
			groupIndex[r.BatchID] = entry
			grouped = append(grouped, entry)
		}
		exactKey := rrExactKey(r.Section, r.RRName, r.RRType, r.RRValue)
		entry.candidateKeys[exactKey] = true
		diffStatus := "added"
		if _, ok := baselineExact[exactKey]; ok {
			diffStatus = "unchanged"
		} else if baselineGroup[rrGroupKey(r.Section, r.RRName, r.RRType)] {
			diffStatus = "changed"
		}
		entry.records = append(entry.records, map[string]any{
			"id": r.ID, "status": r.Status, "section": r.Section,
			"rrname": r.RRName, "rrtype": r.RRType, "rrvalue": r.RRValue,
			"ttl_min": r.TTLMin, "ttl_max": r.TTLMax, "is_required": r.IsRequired,
			"reviewedBy": s.userNameOf(ctx, r.ReviewedBy), "reviewed_at": apitimeFromPtr(r.ReviewedAt),
			"review_note": r.ReviewNote, "diffStatus": diffStatus,
		})
		entry.batch["candidateCount"] = len(entry.records)
	}
	batchesPayload := make([]map[string]any, 0, len(grouped))
	for _, entry := range grouped {
		removed := []map[string]any{}
		for key, record := range baselineExact {
			if entry.candidateKeys[key] {
				continue
			}
			removed = append(removed, map[string]any{
				"id": record.ID, "status": "baseline", "section": record.Section,
				"rrname": record.RRName, "rrtype": record.RRType, "rrvalue": record.RRValue,
				"ttl_min": record.TTLMin, "ttl_max": record.TTLMax, "is_required": record.IsRequired,
				"reviewedBy": "", "reviewed_at": nil, "review_note": "", "diffStatus": "removed",
			})
		}
		batchesPayload = append(batchesPayload, map[string]any{
			"batch": entry.batch, "records": entry.records, "removedRecords": removed,
		})
	}
	return map[string]any{
		"host":    s.trustHostPayload(ctx, *host, *domain, nil, nil),
		"batches": batchesPayload,
	}, nil
}

func rrExactKey(section, name, rrtype, value string) string {
	return section + "|" + normalizeFQDN(name) + "|" + stringsUpper(rrtype) + "|" + strings.TrimSpace(value)
}

func rrGroupKey(section, name, rrtype string) string {
	return section + "|" + normalizeFQDN(name) + "|" + stringsUpper(rrtype)
}

func stringsUpper(v string) string {
	out := []rune(v)
	for i, r := range out {
		if r >= 'a' && r <= 'z' {
			out[i] = r - 32
		}
	}
	return string(out)
}

func (s *Service) userNameOf(ctx context.Context, id *uint64) string {
	if id == nil {
		return ""
	}
	var user struct{ Username string }
	if err := s.gorm.WithContext(ctx).Table("users").Select("username").Where("id = ?", *id).Scan(&user).Error; err != nil || user.Username == "" {
		return ""
	}
	return user.Username
}

// BuildHostSnapshots 镜像 HostSnapshotsAPIView(观测快照表 P7 落地,当前空态)。
func (s *Service) BuildHostSnapshots(ctx context.Context, hostID uint64) (map[string]any, error) {
	if _, _, err := s.GetTrustHost(ctx, hostID); err != nil {
		return nil, err
	}
	return map[string]any{"hostId": hostID, "results": []map[string]any{}}, nil
}

// trustBuildJobPayload 镜像 DnsTrustBuildJobSerializer。
func (s *Service) TrustBuildJobPayload(job model.TrustBuildJob) map[string]any {
	progress := 0.0
	if job.TotalChunks > 0 {
		progress = float64(int(float64(job.ProcessedChunks)/float64(job.TotalChunks)*10000+0.5)) / 100
	}
	var retryOfID any = nil
	if job.RetryOfID != nil {
		retryOfID = *job.RetryOfID
	}
	return map[string]any{
		"id": job.ID, "environment": job.Environment, "status": job.Status,
		"requestedBy": s.userNameOf(context.Background(), job.RequestedByID), "retryOfId": retryOfID,
		"input_path": job.InputPath, "source_label": job.SourceLabel,
		"resolver_ip": job.ResolverIP, "timeout_seconds": job.TimeoutSeconds,
		"chunk_size": job.ChunkSize, "max_hosts_per_domain": job.MaxHostsPerDomain,
		"limit":      job.LimitCount, "import_only": job.ImportOnly, "auto_approve": job.AutoApprove,
		"total_input_hosts": job.TotalInputHosts, "total_domains": job.TotalDomains,
		"total_chunks": job.TotalChunks, "processed_chunks": job.ProcessedChunks,
		"imported_domains": job.ImportedDomains, "imported_hosts": job.ImportedHosts,
		"discovered_hosts": job.DiscoveredHosts, "candidate_records": job.CandidateRecords,
		"approved_hosts": job.ApprovedHosts, "trusted_hosts": job.TrustedHosts, "draft_hosts": job.DraftHosts,
		"current_chunk": job.CurrentChunk,
		"started_at":    apitimeFromPtr(job.StartedAt), "finished_at": apitimeFromPtr(job.FinishedAt),
		"summary_message": job.SummaryMessage, "last_error": job.LastError,
		"celery_task_id": job.WorkerTaskID, "progressPercent": progress,
		"create_time": apitime.From(job.CreateTime), "update_time": apitime.From(job.UpdateTime),
	}
}

// ListTrustBuildJobs 镜像 TrustBuildJobListCreateAPIView.get。
func (s *Service) ListTrustBuildJobs(ctx context.Context, environment, status string, page, pageSize int) (map[string]any, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 200 {
		pageSize = 20
	}
	query := s.gorm.WithContext(ctx).Model(&model.TrustBuildJob{})
	if environment != "" {
		query = query.Where("environment = ?", environment)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}
	var total int64
	query.Count(&total)
	var jobs []model.TrustBuildJob
	query.Order("id DESC").Offset((page - 1) * pageSize).Limit(pageSize).Find(&jobs)
	results := make([]map[string]any, 0, len(jobs))
	for _, job := range jobs {
		results = append(results, s.TrustBuildJobPayload(job))
	}
	return map[string]any{
		"results": results, "total": total, "page": page,
		"pageSize": pageSize, "totalPages": totalPagesOf(int(total), pageSize),
	}, nil
}

