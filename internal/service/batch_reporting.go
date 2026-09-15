package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"gorm.io/gorm"

	"dnsss/internal/apitime"
	"dnsss/internal/dto"
	"dnsss/internal/model"
)

func dtoNewNotFound(msg string) error { return dto.NewAPIError(400, msg) }

// ---------- 批量 DTO(镜像 selectors/batch_reporting.py) ----------

func expectedCheckCount(task *model.BatchTask, regionCodes []string) int {
	regionCount := len(regionCodes)
	if regionCount == 0 {
		regionCount = 1
	}
	return task.ValidTargetCount * regionCount * len(expandBatchProtocols(task.Protocol))
}

// BuildBatchExecutionSummary 镜像 build_batch_execution_summary。
func (s *Service) BuildBatchExecutionSummary(ctx context.Context, e *model.BatchExecution, task *model.BatchTask) map[string]any {
	if e == nil {
		return nil
	}
	if task == nil {
		task = &model.BatchTask{}
		s.gorm.WithContext(ctx).Where("id = ?", e.BatchTaskID).First(task)
	}
	var regionCodes []string
	_ = json.Unmarshal([]byte(task.RegionCodesTx), &regionCodes)
	expected := expectedCheckCount(task, regionCodes)
	completed := e.SuccessCount + e.FailedCount
	progress := 0.0
	if expected > 0 {
		progress = float64(int(float64(completed)/float64(expected)*10000+0.5)) / 100
	}
	canStop := e.Status == model.BatchStatusPending || e.Status == model.BatchStatusRunning
	return map[string]any{
		"id": e.ID, "executionNo": e.ExecutionNo, "triggerType": e.TriggerType,
		"status": e.Status, "startedAt": apitimeFromPtr(e.StartedAt), "finishedAt": apitimeFromPtr(e.FinishedAt),
		"successCount": e.SuccessCount, "failedCount": e.FailedCount,
		"totalCheckCount": completed, "expectedCheckCount": expected, "completedCheckCount": completed,
		"progressPercent": progress, "availabilityRatio": e.AvailabilityRatio,
		"avgLatencyMs": e.AvgLatencyMs, "summaryMessage": e.SummaryMessage,
		"workerTaskId": e.WorkerTaskID,
		"stopRequestedAt": apitimeFromPtr(e.StopRequestedAt), "cancelledAt": apitimeFromPtr(e.CancelledAt),
		"canStop": canStop,
	}
}

// BuildBatchTaskPayload 镜像 build_batch_task_payload。
func (s *Service) BuildBatchTaskPayload(ctx context.Context, task *model.BatchTask) map[string]any {
	var regionCodes []string
	_ = json.Unmarshal([]byte(task.RegionCodesTx), &regionCodes)
	normalized, _ := s.normalizeRegionCodes(ctx, regionCodes, 0)
	if normalized == nil {
		normalized = []string{}
	}
	names := s.regionNames(ctx, normalized)
	var options map[string]any
	_ = json.Unmarshal([]byte(task.OptionsTx), &options)
	if options == nil {
		options = map[string]any{}
	}
	createdBy := ""
	if task.CreatedByID != nil {
		var user model.User
		if err := s.gorm.WithContext(ctx).Select("username").First(&user, *task.CreatedByID).Error; err == nil {
			createdBy = user.Username
		}
	}
	latest := s.latestBatchExecution(ctx, task.ID)
	return map[string]any{
		"id": task.ID, "taskNo": task.TaskNo, "mode": task.Mode, "protocol": task.Protocol,
		"expandedProtocols": expandBatchProtocols(task.Protocol),
		"inputMode": task.InputMode, "sourceFileName": task.SourceFileName,
		"targetDisplay": fmt.Sprintf("%d 个域名", task.ValidTargetCount),
		"regions": normalized, "regionNames": names,
		"regionSummary": regionSummary(names), "schedule": task.ScheduleCron,
		"isEnabled": task.IsEnabled, "status": task.Status, "options": options,
		"totalInputCount": task.TotalInputCount, "validTargetCount": task.ValidTargetCount,
		"invalidTargetCount": task.InvalidTargetCount, "duplicateCount": task.DuplicateCount,
		"startedAt": apitimeFromPtr(task.StartedAt), "finishedAt": apitimeFromPtr(task.FinishedAt),
		"lastRunAt": apitimeFromPtr(task.LastRunAt), "nextRunAt": apitimeFromPtr(task.NextRunAt),
		"createdAt": apitime.From(task.CreateTime), "createdBy": createdBy,
		"latestExecution": s.BuildBatchExecutionSummary(ctx, latest, task),
		"trend7d": []any{}, "trend30d": []any{},
	}
}

func regionSummary(names []string) string {
	if len(names) == 0 {
		return "--"
	}
	out := names[0]
	for _, n := range names[1:] {
		out += " / " + n
	}
	return out
}

func (s *Service) latestBatchExecution(ctx context.Context, taskID uint64) *model.BatchExecution {
	var e model.BatchExecution
	if err := s.gorm.WithContext(ctx).Where("batch_task_id = ?", taskID).Order("id DESC").First(&e).Error; err != nil {
		return nil
	}
	return &e
}

// BuildBatchTaskDetailPayload 详情 = 列表字段 + targetsText。
func (s *Service) BuildBatchTaskDetailPayload(ctx context.Context, task *model.BatchTask) map[string]any {
	payload := s.BuildBatchTaskPayload(ctx, task)
	var targets []model.BatchTarget
	s.gorm.WithContext(ctx).Where("batch_task_id = ?", task.ID).Order("line_no ASC, id ASC").
		Find(&targets)
	rows := make([]string, 0, len(targets))
	for _, t := range targets {
		rows = append(rows, t.RawTarget)
	}
	payload["targetsText"] = joinLines(rows)
	return payload
}

func joinLines(rows []string) string {
	out := ""
	for i, r := range rows {
		if i > 0 {
			out += "\n"
		}
		out += r
	}
	return out
}

// BuildBatchExecutionPayload 镜像 build_batch_execution_payload(overview+charts)。
func (s *Service) BuildBatchExecutionPayload(ctx context.Context, executionID uint64) (map[string]any, error) {
	var execution model.BatchExecution
	if err := s.gorm.WithContext(ctx).First(&execution, executionID).Error; err != nil {
		return nil, gorm.ErrRecordNotFound
	}
	var task model.BatchTask
	if err := s.gorm.WithContext(ctx).First(&task, execution.BatchTaskID).Error; err != nil {
		return nil, err
	}
	// 全部走 SQL 聚合:轮询接口绝不全量加载结果行(含 MEDIUMTEXT 明细)
	type codeCountRow struct {
		Label string
		Count int
	}
	var codeDistRows, protoDistRows []codeCountRow
	s.gorm.WithContext(ctx).Model(&model.BatchResult{}).
		Where("batch_execution_id = ? AND result_code <> ''", executionID).
		Select("result_code AS label, COUNT(*) AS count").
		Group("result_code").Order("count DESC, label ASC").Limit(10).Scan(&codeDistRows)
	s.gorm.WithContext(ctx).Model(&model.BatchResult{}).
		Where("batch_execution_id = ?", executionID).
		Select("protocol AS label, COUNT(*) AS count").
		Group("protocol").Order("count DESC, label ASC").Scan(&protoDistRows)

	var slow []slowRow
	s.gorm.WithContext(ctx).Model(&model.BatchResult{}).
		Where("batch_execution_id = ? AND latency_ms IS NOT NULL", executionID).
		Select("id, target, protocol, latency_ms, result_code, status").
		Order("latency_ms DESC, id ASC").Limit(20).Scan(&slow)

	slowPayload := make([]map[string]any, 0, len(slow))
	for _, sr := range slow {
		slowPayload = append(slowPayload, map[string]any{
			"id": sr.ID, "target": sr.Target, "protocol": sr.Protocol,
			"latencyMs": sr.LatencyMs, "resultCode": sr.ResultCode, "status": sr.Status,
		})
	}
	codeDist := make([]map[string]any, 0, len(codeDistRows))
	for _, r := range codeDistRows {
		codeDist = append(codeDist, map[string]any{"label": r.Label, "count": r.Count})
	}
	protoDist := make([]map[string]any, 0, len(protoDistRows))
	for _, r := range protoDistRows {
		protoDist = append(protoDist, map[string]any{"label": r.Label, "count": r.Count})
	}

	taskPayload := s.BuildBatchTaskPayload(ctx, &task)
	var regionCodes []string
	s.gorm.WithContext(ctx).Model(&model.BatchResult{}).
		Where("batch_execution_id = ? AND region_code <> ''", executionID).
		Distinct().Pluck("region_code", &regionCodes)
	names := make([]string, 0, len(regionCodes))
	for _, code := range regionCodes {
		if name := s.regionNameOf(ctx, code); name != "" {
			names = append(names, name)
		}
	}
	sortStrings(names)
	regionSummaryStr := regionSummary(names)
	if regionSummaryStr == "--" {
		if rn, ok := taskPayload["regionNames"].([]string); ok {
			regionSummaryStr = regionSummary(rn)
		}
	}
	return map[string]any{
		"overview": s.BuildBatchExecutionSummary(ctx, &execution, &task),
		"task":     taskPayload,
		"inputStats": map[string]any{
			"totalInputCount": task.TotalInputCount, "validTargetCount": task.ValidTargetCount,
			"invalidTargetCount": task.InvalidTargetCount, "duplicateCount": task.DuplicateCount,
		},
		"regionSummary": regionSummaryStr,
		"nodeSummary":   "默认拨测节点",
		"charts": map[string]any{
			"successFailure": []map[string]any{
				{"name": "成功", "value": execution.SuccessCount},
				{"name": "失败", "value": execution.FailedCount},
			},
			"resultCodeDistribution": codeDist,
			"protocolDistribution":   protoDist,
			"slowTargets":            slowPayload,
		},
		"invalidTargets":   s.batchTargetPreview(ctx, task.ID, model.BatchInputInvalid),
		"duplicateTargets": s.batchTargetPreview(ctx, task.ID, model.BatchInputDuplicate),
	}, nil
}

func (s *Service) regionNameOf(ctx context.Context, code string) string {
	var region model.Region
	if err := s.gorm.WithContext(ctx).Select("name").Where("code = ?", code).First(&region).Error; err != nil {
		return ""
	}
	return region.Name
}

func (s *Service) batchTargetPreview(ctx context.Context, taskID uint64, status string) []map[string]any {
	var targets []model.BatchTarget
	s.gorm.WithContext(ctx).Where("batch_task_id = ? AND input_status = ?", taskID, status).
		Order("line_no ASC, id ASC").Limit(50).Find(&targets)
	out := make([]map[string]any, 0, len(targets))
	for _, t := range targets {
		out = append(out, map[string]any{
			"id": t.ID, "lineNo": t.LineNo, "rawTarget": t.RawTarget,
			"normalizedTarget": t.NormalizedTarget, "status": t.InputStatus, "skipReason": t.SkipReason,
		})
	}
	return out
}

func topCounts(counts map[string]int, limit int) []map[string]any {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	// 按 count 降序、key 升序(与原 order_by("-count","result_code") 一致)
	sortStrings(keys)
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && counts[keys[j]] > counts[keys[j-1]]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	if limit > 0 && len(keys) > limit {
		keys = keys[:limit]
	}
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, map[string]any{"label": k, "count": counts[k]})
	}
	return out
}

func sortStrings(v []string) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j] < v[j-1]; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}

type slowRow struct {
	ID         uint64  `gorm:"column:id"`
	Target     string  `gorm:"column:target"`
	Protocol   string  `gorm:"column:protocol"`
	LatencyMs  *float64 `gorm:"column:latency_ms"`
	ResultCode string  `gorm:"column:result_code"`
	Status     string  `gorm:"column:status"`
}

// BatchResultsQuery 结果明细分页过滤(2.5.4 契约)。
type BatchResultsQuery struct {
	Page       int
	Size       int
	Status     string
	Protocol   string
	ResultCode string
	Keyword    string
	Sort       string // latest | latency_desc | latency_asc
}

// BuildBatchResultsPayload 镜像 build_batch_results_payload。
func (s *Service) BuildBatchResultsPayload(ctx context.Context, executionID uint64, q BatchResultsQuery) (map[string]any, error) {
	var execution model.BatchExecution
	if err := s.gorm.WithContext(ctx).First(&execution, executionID).Error; err != nil {
		return nil, dtoNewNotFound("批量执行不存在")
	}
	if q.Page < 1 {
		q.Page = 1
	}
	if q.Size < 1 || q.Size > 100 {
		q.Size = 20
	}
	query := s.gorm.WithContext(ctx).Model(&model.BatchResult{}).Where("batch_execution_id = ?", executionID)
	if q.Status != "" {
		query = query.Where("status = ?", q.Status)
	}
	if q.Protocol != "" {
		query = query.Where("protocol = ?", q.Protocol)
	}
	if q.ResultCode != "" {
		query = query.Where("result_code = ?", q.ResultCode)
	}
	if q.Keyword != "" {
		like := "%" + q.Keyword + "%"
		query = query.Where("target LIKE ? OR resolved_target LIKE ? OR error_message LIKE ?", like, like, like)
	}
	switch q.Sort {
	case "latency_desc":
		query = query.Order("latency_ms DESC, id ASC")
	case "latency_asc":
		query = query.Order("latency_ms ASC, id ASC")
	default:
		query = query.Order("id DESC")
	}
	var total int64
	query.Count(&total)
	var rows []model.BatchResult
	query.Offset((q.Page - 1) * q.Size).Limit(q.Size).Find(&rows)

	results := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		results = append(results, map[string]any{
			"id": r.ID, "target": r.Target, "protocol": r.Protocol, "status": r.Status,
			"success": r.Success, "resolvedTarget": r.ResolvedTarget, "latencyMs": r.LatencyMs,
			"resultCode": r.ResultCode, "errorCode": r.ErrorCode, "errorMessage": r.ErrorMessage,
			"regionName": s.regionNameOf(ctx, r.RegionCode), "nodeName": s.nodeNameOf(ctx, r.NodeCode),
		})
	}
	return map[string]any{
		"page": q.Page, "size": q.Size, "total": total, "results": results,
	}, nil
}

func (s *Service) nodeNameOf(ctx context.Context, code string) string {
	if code == "" {
		return ""
	}
	var node model.Node
	if err := s.gorm.WithContext(ctx).Select("name").Where("code = ?", code).First(&node).Error; err != nil {
		return ""
	}
	return node.Name
}

// BuildBatchResultDetail 镜像 build_batch_result_detail_payload。
func (s *Service) BuildBatchResultDetail(ctx context.Context, resultID uint64) (map[string]any, error) {
	var r model.BatchResult
	if err := s.gorm.WithContext(ctx).First(&r, resultID).Error; err != nil {
		return nil, dtoNewNotFound("批量结果不存在")
	}
	detail := map[string]any{}
	if strings.TrimSpace(r.DetailTx) != "" {
		_ = json.Unmarshal([]byte(r.DetailTx), &detail)
	}
	rawPayload := map[string]any{}
	if strings.TrimSpace(r.RawPayloadTx) != "" {
		_ = json.Unmarshal([]byte(r.RawPayloadTx), &rawPayload)
	}
	return map[string]any{
		"id": r.ID, "target": r.Target, "protocol": r.Protocol, "status": r.Status,
		"success": r.Success, "resolvedTarget": r.ResolvedTarget, "latencyMs": r.LatencyMs,
		"resultCode": r.ResultCode, "errorCode": r.ErrorCode, "errorMessage": r.ErrorMessage,
		"regionName": s.regionNameOf(ctx, r.RegionCode), "nodeName": s.nodeNameOf(ctx, r.NodeCode),
		"detail": detail, "rawPayload": rawPayload,
	}, nil
}
