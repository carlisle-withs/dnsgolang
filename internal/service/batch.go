package service

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gorm.io/gorm"

	"dnsss/internal/dto"
	"dnsss/internal/engine/prober"
	"dnsss/internal/model"
)

// ---------- 批量输入规范化(镜像原 parse_batch_input / iter_batch_rows) ----------

// batchDomainRe 原批量 DOMAIN_RE 的 RE2 等价改写。
var batchDomainRe = regexp.MustCompile(`^(?:[a-zA-Z0-9][a-zA-Z0-9-]{0,62}\.)+(?:[a-zA-Z]{2,63}|xn--[a-zA-Z0-9-]{2,59})$`)

const (
	batchMaxFileSize    = 2 * 1024 * 1024 // 2MB
	batchMaxValidTarget = 10000           // Go 版收紧上限(方案 2.5.1)
)

type BatchInputRecord struct {
	LineNo           int
	RawTarget        string
	NormalizedTarget string
	InputStatus      string
	SkipReason       string
}

type ParsedBatchInput struct {
	Records []BatchInputRecord
	Stats   struct {
		TotalInputCount   int `json:"totalInputCount"`
		ValidTargetCount  int `json:"validTargetCount"`
		InvalidTargetCount int `json:"invalidTargetCount"`
		DuplicateCount    int `json:"duplicateCount"`
	}
}

// NormalizeBatchDomain 与原 normalize_domain 一致:strip + 小写 + 去尾点。
func NormalizeBatchDomain(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	return strings.TrimSuffix(value, ".")
}

func IsValidBatchDomain(value string) bool {
	return !strings.HasPrefix(value, "://") && batchDomainRe.MatchString(value)
}

// ParseBatchInput 解析 text/file 输入并统计有效/无效/重复(2.5.2 契约)。
func ParseBatchInput(inputMode, targetsText string, fileName string, fileContent []byte) (*ParsedBatchInput, error) {
	rows, err := iterBatchRows(inputMode, targetsText, fileName, fileContent)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, dto.NewFieldError("targets_text", "未检测到有效输入内容")
	}
	parsed := &ParsedBatchInput{}
	seen := map[string]bool{}
	for _, row := range rows {
		lineNo, _ := strconv.Atoi(row[0])
		rawTarget := row[1]
		normalized := NormalizeBatchDomain(rawTarget)
		if normalized == "" {
			continue
		}
		record := BatchInputRecord{LineNo: lineNo, RawTarget: strings.TrimSpace(rawTarget), NormalizedTarget: normalized}
		switch {
		case !IsValidBatchDomain(normalized):
			record.InputStatus, record.SkipReason = model.BatchInputInvalid, "域名格式非法"
			parsed.Stats.InvalidTargetCount++
		case seen[normalized]:
			record.InputStatus, record.SkipReason = model.BatchInputDuplicate, "重复域名"
			parsed.Stats.DuplicateCount++
		default:
			seen[normalized] = true
			record.InputStatus = model.BatchInputValid
			parsed.Stats.ValidTargetCount++
		}
		parsed.Records = append(parsed.Records, record)
	}
	if parsed.Stats.ValidTargetCount == 0 {
		return nil, dto.NewFieldError("targets_text", "未检测到有效域名")
	}
	if parsed.Stats.ValidTargetCount > batchMaxValidTarget {
		return nil, dto.NewFieldError("targets_text", fmt.Sprintf("单次批量任务最多允许 %d 个有效域名", batchMaxValidTarget))
	}
	parsed.Stats.TotalInputCount = len(parsed.Records)
	return parsed, nil
}

func iterBatchRows(inputMode, targetsText, fileName string, fileContent []byte) ([][2]string, error) {
	rows := [][2]string{}
	if inputMode == "text" {
		for i, line := range strings.Split(targetsText, "\n") {
			value := strings.TrimSpace(line)
			if value == "" || strings.HasPrefix(value, "#") {
				continue
			}
			rows = append(rows, [2]string{fmt.Sprint(i + 1), value})
		}
		return rows, nil
	}
	if len(fileContent) == 0 {
		return nil, dto.NewFieldError("file", "请上传 txt/csv 文件")
	}
	if len(fileContent) > batchMaxFileSize {
		return nil, dto.NewFieldError("file", "上传文件不能超过 2 MB")
	}
	ext := ""
	if parts := strings.Split(strings.ToLower(fileName), "."); len(parts) > 1 {
		ext = parts[len(parts)-1]
	}
	if ext != "txt" && ext != "csv" {
		return nil, dto.NewFieldError("file", "仅支持 txt/csv 文件")
	}
	content := strings.TrimPrefix(string(fileContent), "\ufeff") // utf-8-sig
	if ext == "txt" {
		for i, line := range strings.Split(content, "\n") {
			value := strings.TrimSpace(line)
			if value == "" || strings.HasPrefix(value, "#") {
				continue
			}
			rows = append(rows, [2]string{fmt.Sprint(i + 1), value})
		}
		return rows, nil
	}
	records, err := csv.NewReader(strings.NewReader(content)).ReadAll()
	if err != nil || len(records) == 0 {
		return rows, nil
	}
	headerIndex := csvTargetColumn(records[0])
	start, valueIndex := 0, 0
	if headerIndex != nil {
		start, valueIndex = 1, *headerIndex
	}
	for i := start; i < len(records); i++ {
		row := records[i]
		if len(row) <= valueIndex {
			continue
		}
		value := strings.TrimSpace(row[valueIndex])
		if value == "" || strings.HasPrefix(value, "#") {
			continue
		}
		rows = append(rows, [2]string{fmt.Sprint(i + 1), value})
	}
	return rows, nil
}

func csvTargetColumn(header []string) *int {
	for i, cell := range header {
		switch strings.ToLower(strings.TrimSpace(cell)) {
		case "domain", "target":
			return &i
		}
	}
	return nil
}

// ---------- 批量选项清洗(镜像 clean_batch_options 的 clamp 规则) ----------

func CleanBatchOptions(protocol string, options map[string]any) (map[string]any, error) {
	if options == nil {
		options = map[string]any{}
	}
	if protocol == model.ProtocolAll {
		out := map[string]any{}
		for _, p := range []string{"http", "ping", "dns", "mtr", "traceroute"} {
			sub, _ := options[p].(map[string]any)
			cleaned, err := cleanSingleBatchOptions(p, sub)
			if err != nil {
				return nil, err
			}
			out[p] = cleaned
		}
		return out, nil
	}
	return cleanSingleBatchOptions(protocol, options)
}

func cleanSingleBatchOptions(protocol string, options map[string]any) (map[string]any, error) {
	switch protocol {
	case model.ProtocolDNS:
		cleaned, err := prober.CleanDNSOptions("example.com", options)
		if err != nil {
			return nil, dto.NewFieldError("options", err.Error())
		}
		return structToMap(cleaned), nil
	case model.ProtocolHTTP:
		cleaned := map[string]any{"method": "GET", "timeout": 10, "follow_redirects": true, "verify_tls": true}
		method := strings.ToUpper(strAny(options["method"], "GET"))
		if method != "GET" && method != "HEAD" {
			return nil, dto.NewFieldError("options", "HTTP 仅支持 GET/HEAD")
		}
		cleaned["method"] = method
		cleaned["timeout"] = clampInt(toIntAny(options["timeout"], 10), 1, 30, 10)
		cleaned["follow_redirects"] = toBoolAny(options["follow_redirects"], true)
		cleaned["verify_tls"] = toBoolAny(options["verify_tls"], true)
		return cleaned, nil
	case model.ProtocolPing:
		return map[string]any{
			"count":   clampInt(toIntAny(options["count"], 4), 1, 10, 4),
			"timeout": clampInt(toIntAny(options["timeout"], 2), 1, 10, 2),
		}, nil
	case model.ProtocolMTR, model.ProtocolTraceroute:
		return map[string]any{
			"max_hops":    clampInt(toIntAny(options["max_hops"], 20), 1, 30, 20),
			"query_count": clampInt(toIntAny(options["query_count"], 3), 1, 10, 3),
			"timeout":     clampInt(toIntAny(options["timeout"], 2), 1, 10, 2),
			"numeric":     toBoolAny(options["numeric"], true),
		}, nil
	}
	return map[string]any{}, nil
}

func structToMap(v any) map[string]any {
	data, _ := json.Marshal(v)
	out := map[string]any{}
	_ = json.Unmarshal(data, &out)
	return out
}

// ---------- 批量任务创建 ----------

type CreateBatchInput struct {
	Protocol       string
	InputMode      string // text | file
	TargetsText    string
	FileName       string
	FileContent    []byte
	Regions        []string
	Options        map[string]any
	Mode           string
	Schedule       string
}

// CreateBatchTask 校验并创建批量任务 + 初始执行(once)。
func (s *Service) CreateBatchTask(ctx context.Context, in CreateBatchInput, userID uint64, clientIP string) (*model.BatchTask, *model.BatchExecution, error) {
	switch in.Protocol {
	case model.ProtocolHTTP, model.ProtocolPing, model.ProtocolDNS, model.ProtocolMTR, model.ProtocolTraceroute, model.ProtocolAll:
	default:
		return nil, nil, dto.NewFieldError("protocol", "必须是其中一个候选值: http, ping, dns, mtr, traceroute, all。")
	}
	if in.InputMode != "text" && in.InputMode != "file" {
		return nil, nil, dto.NewFieldError("input_mode", "必须是其中一个候选值: text, file。")
	}
	if in.Mode == "" {
		in.Mode = model.TaskModeOnce
	}
	if in.Mode != model.TaskModeOnce && in.Mode != model.TaskModeSchedule {
		return nil, nil, dto.NewFieldError("mode", "必须是其中一个候选值: once, schedule。")
	}
	if in.Mode == model.TaskModeSchedule {
		if err := validateCron(in.Schedule); err != nil {
			return nil, nil, dto.NewFieldError("schedule", err.Error())
		}
	} else {
		in.Schedule = ""
	}
	regionCodes, err := s.normalizeRegionCodes(ctx, in.Regions, 0)
	if err != nil {
		return nil, nil, err
	}
	if len(regionCodes) == 0 {
		return nil, nil, dto.NewFieldError("regions", "至少选择一个地区")
	}
	options, err := CleanBatchOptions(in.Protocol, in.Options)
	if err != nil {
		return nil, nil, err
	}
	parsed, err := ParseBatchInput(in.InputMode, in.TargetsText, in.FileName, in.FileContent)
	if err != nil {
		return nil, nil, err
	}

	task := &model.BatchTask{
		TaskNo:             "npbatch-" + randHex(23),
		Mode:               in.Mode,
		Protocol:           in.Protocol,
		InputMode:          in.InputMode,
		SourceFileName:     in.FileName,
		RegionCodesTx:      marshalJSON(regionCodes),
		OptionsTx:          marshalJSON(options),
		ScheduleCron:       in.Schedule,
		Status:             model.BatchStatusPending,
		IsEnabled:          true,
		CreatedByID:        &userID,
		ClientIP:           clientIP,
		TotalInputCount:    parsed.Stats.TotalInputCount,
		ValidTargetCount:   parsed.Stats.ValidTargetCount,
		InvalidTargetCount: parsed.Stats.InvalidTargetCount,
		DuplicateCount:     parsed.Stats.DuplicateCount,
	}
	err = s.gorm.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(task).Error; err != nil {
			return err
		}
		targets := make([]model.BatchTarget, 0, len(parsed.Records))
		for _, r := range parsed.Records {
			targets = append(targets, model.BatchTarget{
				BatchTaskID: task.ID, LineNo: r.LineNo, RawTarget: r.RawTarget,
				NormalizedTarget: r.NormalizedTarget, InputStatus: r.InputStatus, SkipReason: r.SkipReason,
			})
		}
		if err := tx.CreateInBatches(targets, 200).Error; err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if in.Mode == model.TaskModeSchedule {
		next, _ := nextCronRun(in.Schedule, time.Now())
		if !next.IsZero() {
			s.gorm.WithContext(ctx).Model(task).Update("next_run_at", next)
		}
		return task, nil, nil
	}
	execution := &model.BatchExecution{
		ExecutionNo: "npbexec-" + randHex(23),
		BatchTaskID: task.ID,
		TriggerType: model.TriggerManual,
		Status:      model.BatchStatusPending,
	}
	if err := s.gorm.WithContext(ctx).Create(execution).Error; err != nil {
		return nil, nil, err
	}
	return task, execution, nil
}

// ---------- 批量执行引擎(goroutine 池 + 缓冲落库 + stop) ----------

// DispatchBatchInProcess 进程内异步执行批量任务(未配置 Redis 时的兜底)。
func (s *Service) DispatchBatchInProcess(executionID uint64, triggerType string) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.pool <- struct{}{}
		defer func() { <-s.pool }()
		if err := s.RunBatchExecution(context.Background(), executionID, triggerType); err != nil {
			slog.Error("批量执行失败", "execution_id", executionID, "error", err)
		}
	}()
}

// RunBatchExecution 执行批量拨测(方案 5.3.4)。
func (s *Service) RunBatchExecution(ctx context.Context, executionID uint64, triggerType string) error {
	var execution model.BatchExecution
	if err := s.gorm.WithContext(ctx).First(&execution, executionID).Error; err != nil {
		return err
	}
	var task model.BatchTask
	if err := s.gorm.WithContext(ctx).First(&task, execution.BatchTaskID).Error; err != nil {
		return err
	}
	now := time.Now()
	if execution.StopRequestedAt != nil || execution.CancelledAt != nil {
		s.markBatchCancelled(ctx, &execution, &task)
		return nil
	}

	var regionCodes []string
	_ = json.Unmarshal([]byte(task.RegionCodesTx), &regionCodes)
	regionCodes, err := s.normalizeRegionCodes(ctx, regionCodes, 0)
	if err != nil {
		return err
	}
	s.gorm.WithContext(ctx).Model(&model.BatchTask{}).Where("id = ?", task.ID).
		Updates(map[string]any{"status": model.BatchStatusRunning, "started_at": now, "update_time": now})
	s.gorm.WithContext(ctx).Model(&model.BatchExecution{}).Where("id = ?", executionID).
		Updates(map[string]any{"status": model.BatchStatusRunning, "started_at": now, "trigger_type": coalesce(triggerType, execution.TriggerType), "update_time": now})

	var targets []model.BatchTarget
	if err := s.gorm.WithContext(ctx).Where("batch_task_id = ? AND input_status = ?", task.ID, model.BatchInputValid).
		Order("line_no ASC, id ASC").Find(&targets).Error; err != nil {
		return err
	}
	protocols := expandBatchProtocols(task.Protocol)
	if len(regionCodes) == 0 {
		return s.finishBatchWithError(ctx, &execution, &task, "没有可用地区可执行批量拨测")
	}
	if len(targets) == 0 {
		return s.finishBatchWithError(ctx, &execution, &task, "没有可执行的有效域名")
	}

	var options map[string]any
	_ = json.Unmarshal([]byte(task.OptionsTx), &options)

	type workItem struct {
		target   model.BatchTarget
		protocol string
		opts     map[string]any
		region   string
	}
	workItems := make([]workItem, 0, len(targets)*len(protocols)*len(regionCodes))
	for _, regionCode := range regionCodes {
		for _, t := range targets {
			for _, protocol := range protocols {
				opts := options
				if task.Protocol == model.ProtocolAll {
					if sub, ok := options[protocol].(map[string]any); ok {
						opts = sub
					} else {
						opts = map[string]any{}
					}
				}
				workItems = append(workItems, workItem{target: t, protocol: protocol, opts: opts, region: regionCode})
			}
		}
	}

	var (
		successCount int64
		doneCount    int64
		latencySumUs int64
		latencyCount int64
	)
	nodeCode := s.defaultNodeCode(ctx)
	resultCh := make(chan *model.BatchResult, s.cfg.BatchFlushSize*2)
	writerDone := make(chan struct{})
	var writeErr atomic.Value
	go func() {
		defer close(writerDone)
		buffer := make([]model.BatchResult, 0, s.cfg.BatchFlushSize)
		flush := func() {
			if len(buffer) == 0 {
				return
			}
			if err := s.gorm.WithContext(ctx).CreateInBatches(buffer, s.cfg.BatchFlushSize).Error; err != nil {
				writeErr.Store(err)
				slog.Error("批量结果落库失败", "error", err)
			}
			buffer = buffer[:0]
		}
		flushTicker := time.NewTicker(500 * time.Millisecond)
		defer flushTicker.Stop()
		for {
			select {
			case r, ok := <-resultCh:
				if !ok {
					flush()
					return
				}
				buffer = append(buffer, *r)
				if len(buffer) >= s.cfg.BatchFlushSize {
					flush()
					// 进度回写(与落库同频,避免轮询打爆 DB)
					success := int(atomic.LoadInt64(&successCount))
					done := int(atomic.LoadInt64(&doneCount))
					s.gorm.WithContext(ctx).Model(&model.BatchExecution{}).Where("id = ?", executionID).
						Updates(map[string]any{
							"success_count": success,
							"failed_count":  done - success,
						})
				}
			case <-flushTicker.C:
				flush()
			}
		}
	}()

	stopCheck := func() bool {
		var ex model.BatchExecution
		if err := s.gorm.WithContext(ctx).Select("stop_requested_at").First(&ex, executionID).Error; err == nil {
			return ex.StopRequestedAt != nil
		}
		return false
	}

	sem := make(chan struct{}, s.cfg.BatchLocalConcurrency)
	var wg sync.WaitGroup
	stopped := false
	for i := range workItems {
		if i%s.cfg.BatchLocalConcurrency == 0 && stopCheck() {
			stopped = true
			break
		}
		item := workItems[i]
		wg.Add(1)
		sem <- struct{}{}
		go func(item workItem) {
			defer wg.Done()
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			result := runBatchTargetProbe(ctx, item.protocol, item.target.NormalizedTarget, item.opts)
			atomic.AddInt64(&doneCount, 1)
			if result.Success {
				atomic.AddInt64(&successCount, 1)
			}
			if result.LatencyMs != nil {
				atomic.AddInt64(&latencySumUs, int64(*result.LatencyMs*1000))
				atomic.AddInt64(&latencyCount, 1)
			}
			resultCh <- buildBatchResultRow(executionID, item, result, nodeCode)
		}(item)
	}
	wg.Wait()
	close(resultCh)
	<-writerDone

	if stopped || stopCheck() {
		s.markBatchCancelled(ctx, &execution, &task)
		return nil
	}
	if err, ok := writeErr.Load().(error); ok && err != nil {
		return err
	}

	totalCount := len(workItems)
	failedCount := totalCount - int(successCount)
	finished := time.Now()
	updates := map[string]any{
		"status": "", "finished_at": finished,
		"success_count": int(successCount), "failed_count": failedCount,
		"update_time": finished,
	}
	ratio := float64(successCount) / float64(maxInt(totalCount, 1)) * 100
	updates["availability_ratio"] = float64(int(ratio*100+0.5)) / 100
	if latencyCount > 0 {
		avg := float64(int(float64(latencySumUs)/float64(latencyCount)/10+0.5)) / 100
		updates["avg_latency_ms"] = avg
	}
	taskStatus := model.BatchStatusFailed
	switch {
	case int(successCount) == totalCount:
		updates["status"] = model.BatchStatusSuccess
		updates["summary_message"] = fmt.Sprintf("全部 %d 项拨测成功", totalCount)
		taskStatus = model.BatchStatusSuccess
	case successCount > 0:
		updates["status"] = model.BatchStatusPartial
		updates["summary_message"] = fmt.Sprintf("共 %d 项拨测，成功 %d 项", totalCount, int(successCount))
		taskStatus = model.BatchStatusPartial
	default:
		updates["status"] = model.BatchStatusFailed
		updates["summary_message"] = fmt.Sprintf("全部 %d 项拨测失败", totalCount)
	}
	s.gorm.WithContext(ctx).Model(&model.BatchExecution{}).Where("id = ?", executionID).Updates(updates)
	taskUpdates := map[string]any{"status": taskStatus, "finished_at": finished, "last_run_at": finished, "update_time": finished}
	if task.Mode == model.TaskModeSchedule {
		if next, err := nextCronRun(task.ScheduleCron, finished); err == nil {
			taskUpdates["next_run_at"] = next
		}
	}
	s.gorm.WithContext(ctx).Model(&model.BatchTask{}).Where("id = ?", task.ID).Updates(taskUpdates)
	return nil
}

func coalesce(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func expandBatchProtocols(protocol string) []string {
	if protocol == model.ProtocolAll {
		return []string{model.ProtocolHTTP, model.ProtocolPing, model.ProtocolDNS, model.ProtocolMTR, model.ProtocolTraceroute}
	}
	return []string{protocol}
}

func (s *Service) defaultNodeCode(ctx context.Context) string {
	node, err := s.getDefaultNode(ctx, "")
	if err != nil || node == nil {
		return "default-node"
	}
	return node.Code
}

func (s *Service) finishBatchWithError(ctx context.Context, execution *model.BatchExecution, task *model.BatchTask, message string) error {
	now := time.Now()
	s.gorm.WithContext(ctx).Model(execution).Updates(map[string]any{
		"status": model.BatchStatusFailed, "finished_at": now, "failed_count": 0, "summary_message": message,
	})
	s.gorm.WithContext(ctx).Model(task).Updates(map[string]any{
		"status": model.BatchStatusFailed, "finished_at": now, "update_time": now,
	})
	return nil
}

// markBatchCancelled 停止语义(镜像原 BatchExecutionStopAPIView)。
func (s *Service) markBatchCancelled(ctx context.Context, execution *model.BatchExecution, task *model.BatchTask) {
	var success, failed int64
	s.gorm.WithContext(ctx).Model(&model.BatchResult{}).Where("batch_execution_id = ?", execution.ID).
		Select("COALESCE(SUM(success=1),0) AS success, COALESCE(SUM(success=0),0) AS failed").Row().Scan(&success, &failed)
	now := time.Now()
	total := int(success + failed)
	ratio := 0.0
	if total > 0 {
		ratio = float64(int(float64(success)/float64(total)*10000+0.5)) / 100
	}
	stopAt := now
	if execution.StopRequestedAt != nil {
		stopAt = *execution.StopRequestedAt
	}
	cancelledAt := now
	if execution.CancelledAt != nil {
		cancelledAt = *execution.CancelledAt
	}
	s.gorm.WithContext(ctx).Model(execution).Updates(map[string]any{
		"stop_requested_at": stopAt, "cancelled_at": cancelledAt,
		"status": model.BatchStatusCancelled, "finished_at": now,
		"success_count": int(success), "failed_count": int(failed),
		"availability_ratio": ratio,
		"summary_message":    fmt.Sprintf("执行已停止，已完成 %d 项检测", total),
	})
	taskUpdates := map[string]any{"status": model.BatchStatusCancelled, "finished_at": now, "last_run_at": now, "update_time": now}
	if task.Mode == model.TaskModeSchedule {
		if next, err := nextCronRun(task.ScheduleCron, now); err == nil {
			taskUpdates["next_run_at"] = next
		}
	}
	s.gorm.WithContext(ctx).Model(task).Updates(taskUpdates)
}

// RequestBatchStop 处理停止请求(镜像原视图语义)。
func (s *Service) RequestBatchStop(ctx context.Context, executionID uint64) error {
	var execution model.BatchExecution
	if err := s.gorm.WithContext(ctx).First(&execution, executionID).Error; err != nil {
		return dto.NewAPIError(400, "批量执行不存在")
	}
	if execution.Status != model.BatchStatusPending && execution.Status != model.BatchStatusRunning {
		return nil // 已终态:幂等返回
	}
	now := time.Now()
	return s.gorm.WithContext(ctx).Model(&execution).Updates(map[string]any{
		"stop_requested_at": now, "cancelled_at": now,
		"status": model.BatchStatusCancelled, "finished_at": now, "update_time": now,
	}).Error
}

// ---------- 批量探测分发 ----------

func runBatchTargetProbe(ctx context.Context, protocol, normalizedTarget string, options map[string]any) prober.Result {
	probeTarget := normalizedTarget
	if protocol == model.ProtocolHTTP {
		probeTarget = "https://" + normalizedTarget
	}
	switch protocol {
	case model.ProtocolHTTP:
		return prober.ExecuteHTTP(ctx, probeTarget, options)
	case model.ProtocolPing:
		return prober.ExecutePING(ctx, probeTarget, options)
	case model.ProtocolDNS:
		return prober.ExecuteDNS(ctx, probeTarget, options)
	case model.ProtocolMTR:
		return prober.ExecuteMTR(ctx, probeTarget, options)
	case model.ProtocolTraceroute:
		return prober.ExecuteTraceroute(ctx, probeTarget, options)
	}
	return prober.Result{Success: false, Status: "failed", ErrorCode: "unsupported_protocol",
		ErrorMessage: "unsupported batch protocol: " + protocol, Detail: map[string]any{}, RawPayload: map[string]any{}}
}

func buildBatchResultRow(executionID uint64, item struct {
	target   model.BatchTarget
	protocol string
	opts     map[string]any
	region   string
}, result prober.Result, nodeCode string) *model.BatchResult {
	status := model.BatchStatusFailed
	if result.Success {
		status = model.BatchStatusSuccess
	}
	resolved := result.ResolvedTarget
	if len(resolved) > 1024 {
		resolved = resolved[:1024]
	}
	errMsg := result.ErrorMessage
	if len(errMsg) > 255 {
		errMsg = errMsg[:255]
	}
	detail := batchDetailForAPI(item.protocol, result)
	return &model.BatchResult{
		BatchExecutionID: executionID,
		RegionCode:       item.region,
		NodeCode:         nodeCode,
		Target:           item.target.NormalizedTarget,
		Protocol:         item.protocol,
		Status:           status,
		Success:          result.Success,
		ResolvedTarget:   resolved,
		LatencyMs:        result.LatencyMs,
		ResultCode:       buildBatchResultCode(item.protocol, result),
		ErrorCode:        result.ErrorCode,
		ErrorMessage:     errMsg,
		DetailTx:         marshalJSON(detail),
		RawPayloadTx:     marshalJSON(result.RawPayload),
	}
}

// batchDetailForAPI 批量明细(镜像 normalize_batch_detail,DNS 不含 observation)。
func batchDetailForAPI(protocol string, result prober.Result) map[string]any {
	detail := protocolDetailForAPI(protocol, result)
	delete(detail, "observation")
	return detail
}

// buildBatchResultCode 镜像原 build_batch_result_code。
func buildBatchResultCode(protocol string, result prober.Result) string {
	switch protocol {
	case model.ProtocolHTTP:
		if httpStatus, ok := result.Detail["http_status"]; ok && httpStatus != nil {
			return fmt.Sprintf("%v", httpStatus)
		}
		return result.ErrorCode
	case model.ProtocolDNS:
		if rcode, ok := result.Detail["rcode"].(string); ok && rcode != "" {
			return rcode
		}
		return result.ErrorCode
	case model.ProtocolPing:
		if result.Success {
			return "PING_OK"
		}
		return orDefault(result.ErrorCode, "PING_FAILED")
	case model.ProtocolMTR:
		if result.Success {
			return "MTR_OK"
		}
		return orDefault(result.ErrorCode, "MTR_FAILED")
	case model.ProtocolTraceroute:
		if result.Success {
			return "TRACE_OK"
		}
		return orDefault(result.ErrorCode, "TRACEROUTE_FAILED")
	}
	return result.ErrorCode
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func clampInt(v, min, max, fallback int) int {
	if v == 0 {
		v = fallback
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func strAny(v any, fallback string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return fallback
}

func toIntAny(v any, fallback int) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	}
	return fallback
}

func toBoolAny(v any, fallback bool) bool {
	switch b := v.(type) {
	case bool:
		return b
	}
	return fallback
}

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// ---------- 日聚合(aggregate_daily_metrics,每日 00:10) ----------

type metricGroupRow struct {
	RegionCode string `gorm:"column:region_code"`
	Protocol   string `gorm:"column:protocol"`
	Total      int    `gorm:"column:total"`
	Success    int    `gorm:"column:success"`
}

// AggregateDailyMetrics 按地区×协议聚合昨日可用率与延迟分位。
// 计数走 GROUP BY;分位数逐组有序拉取延迟列(GROUP_CONCAT 受
// group_concat_max_len=1024 截断,不可用于万级行)。
func (s *Service) AggregateDailyMetrics(ctx context.Context, date string) error {
	if date == "" {
		date = time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	}
	groups := []metricGroupRow{}
	// 单目标:execution_regions 按任务协议聚合
	s.gorm.WithContext(ctx).Raw(`
		SELECT er.region_code AS region_code, t.protocol AS protocol, COUNT(*) AS total, SUM(er.success) AS success
		FROM netprobe_execution_regions er
		JOIN netprobe_executions e ON e.id = er.execution_id
		JOIN netprobe_tasks t ON t.id = e.task_id
		WHERE DATE(er.create_time) = ?
		GROUP BY er.region_code, t.protocol`, date).Scan(&groups)
	// 批量:batch_results 自带协议
	s.gorm.WithContext(ctx).Raw(`
		SELECT region_code AS region_code, protocol AS protocol, COUNT(*) AS total, SUM(success) AS success
		FROM netprobe_batch_results
		WHERE DATE(create_time) = ?
		GROUP BY region_code, protocol`, date).Scan(&groups)

	merged := map[string]*model.DailyMetric{}
	for _, g := range groups {
		if g.RegionCode == "" && g.Protocol == "" {
			continue
		}
		key := g.RegionCode + "/" + g.Protocol
		m, ok := merged[key]
		if !ok {
			m = &model.DailyMetric{StatDate: date, RegionCode: g.RegionCode, Protocol: g.Protocol}
			merged[key] = m
		}
		m.TotalCount += g.Total
		m.SuccessCount += g.Success
	}
	for _, m := range merged {
		if m.TotalCount > 0 {
			m.AvailabilityRatio = float64(int(float64(m.SuccessCount)/float64(m.TotalCount)*10000+0.5)) / 100
		}
		latencies := s.dayLatencies(ctx, date, m.RegionCode, m.Protocol)
		if len(latencies) > 0 {
			p50, p95 := percentile(latencies, 50), percentile(latencies, 95)
			m.LatencyP50Ms, m.LatencyP95Ms = &p50, &p95
		}
		if err := s.gorm.WithContext(ctx).Where(model.DailyMetric{
			StatDate: m.StatDate, RegionCode: m.RegionCode, Protocol: m.Protocol,
		}).Assign(*m).FirstOrCreate(&model.DailyMetric{}).Error; err != nil {
			slog.Warn("日指标写入失败", "key", m.RegionCode+"/"+m.Protocol, "error", err)
		}
	}
	slog.Info("日聚合完成", "date", date, "rows", len(merged))
	return nil
}

// dayLatencies 有序拉取单组的延迟样本(单目标 + 批量两源合并后排序)。
func (s *Service) dayLatencies(ctx context.Context, date, regionCode, protocol string) []float64 {
	var fromSingle, fromBatch []float64
	s.gorm.WithContext(ctx).Raw(`
		SELECT er.latency_ms FROM netprobe_execution_regions er
		JOIN netprobe_executions e ON e.id = er.execution_id
		JOIN netprobe_tasks t ON t.id = e.task_id
		WHERE DATE(er.create_time) = ? AND er.region_code = ? AND t.protocol = ? AND er.latency_ms IS NOT NULL
		ORDER BY er.latency_ms`, date, regionCode, protocol).Scan(&fromSingle)
	s.gorm.WithContext(ctx).Raw(`
		SELECT latency_ms FROM netprobe_batch_results
		WHERE DATE(create_time) = ? AND region_code = ? AND protocol = ? AND latency_ms IS NOT NULL
		ORDER BY latency_ms`, date, regionCode, protocol).Scan(&fromBatch)
	merged := append(fromSingle, fromBatch...)
	sortFloats(merged)
	return merged
}

func sortFloats(v []float64) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j] < v[j-1]; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}

func percentile(sorted []float64, p int) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := (len(sorted)-1)*p/100 + 1
	if idx > len(sorted) {
		idx = len(sorted)
	}
	return float64(int(sorted[idx-1]*100+0.5)) / 100
}

// ---------- 重跑 ----------

// RerunBatchTask 重建执行并入队。
func (s *Service) RerunBatchTask(ctx context.Context, taskID uint64) (*model.BatchTask, *model.BatchExecution, error) {
	var task model.BatchTask
	if err := s.gorm.WithContext(ctx).First(&task, taskID).Error; err != nil {
		return nil, nil, dto.NewAPIError(400, "批量任务不存在")
	}
	execution := &model.BatchExecution{
		ExecutionNo: "npbexec-" + randHex(23),
		BatchTaskID: task.ID,
		TriggerType: model.TriggerRetry,
		Status:      model.BatchStatusPending,
	}
	if err := s.gorm.WithContext(ctx).Create(execution).Error; err != nil {
		return nil, nil, err
	}
	s.gorm.WithContext(ctx).Model(&task).Updates(map[string]any{"status": model.BatchStatusPending, "finished_at": nil})
	return &task, execution, nil
}
