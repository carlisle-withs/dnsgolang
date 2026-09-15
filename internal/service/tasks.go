package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/robfig/cron/v3"
	"gorm.io/gorm"

	"dnsss/internal/config"
	"dnsss/internal/dto"
	"dnsss/internal/engine/prober"
	"dnsss/internal/model"
)

var (
	ipv4Re = regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$`)
	// 原版 DOMAIN_RE 的 RE2 等价改写(去负向前瞻):
	// 标签 1-63 且不以 "-" 开头,TLD 为 2-63 字母或 punycode;scheme 前缀在代码里拒绝
	domainRe = regexp.MustCompile(`^(?:[a-zA-Z0-9][a-zA-Z0-9-]{0,62}\.)+(?:[a-zA-Z]{2,63}|xn--[a-zA-Z0-9-]{2,59})$`)
)

func isDomain(s string) bool {
	return !strings.HasPrefix(s, "://") && domainRe.MatchString(s)
}

func randHex(n int) string {
	buf := make([]byte, n/2+1)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)[:n]
}

func itoa(n int) string { return strconv.Itoa(n) }

func jsonUnmarshalDefault(s string, v any) error {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return json.Unmarshal([]byte(s), v)
}

// Service 任务编排服务。
type Service struct {
	gorm  *gorm.DB
	cfg   *config.Config
	pool  chan struct{}
	wg    sync.WaitGroup
}

func New(db *gorm.DB, cfg *config.Config) *Service {
	concurrency := cfg.BatchLocalConcurrency
	if concurrency <= 0 {
		concurrency = 64
	}
	return &Service{gorm: db, cfg: cfg, pool: make(chan struct{}, concurrency)}
}

// Close 等待在跑任务结束(优雅停机)。
func (s *Service) Close() {
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		slog.Warn("等待在跑任务超时,强制退出")
	}
}

// ---------- 创建任务(镜像 TaskCreateSerializer + TaskListCreateAPIView.post) ----------

type CreateTaskInput struct {
	Mode          string
	Protocol      string
	Target        string
	TargetDisplay string
	Regions       []string
	Options       map[string]any
	Schedule      string
}

func (s *Service) CreateTask(ctx context.Context, in CreateTaskInput, userID uint64, authenticated bool, clientIP string) (*model.Task, *model.Execution, error) {
	switch in.Mode {
	case model.TaskModeOnce, model.TaskModeSchedule:
	default:
		return nil, nil, dto.NewFieldError("mode", "必须是其中一个候选值: once, schedule。")
	}
	switch in.Protocol {
	case model.ProtocolHTTP, model.ProtocolPing, model.ProtocolDNS, model.ProtocolMTR, model.ProtocolTraceroute:
	default:
		return nil, nil, dto.NewFieldError("protocol", "必须是其中一个候选值: http, ping, dns, mtr, traceroute。")
	}
	target := strings.TrimSpace(in.Target)
	if target == "" {
		return nil, nil, dto.NewFieldError("target", "该字段是必填项。")
	}
	targetDisplay := in.TargetDisplay
	if targetDisplay == "" {
		targetDisplay = target
	}

	if in.Mode == model.TaskModeSchedule {
		if !authenticated {
			return nil, nil, dto.NewAPIError(403, "定时监控任务需要登录后创建")
		}
		schedule := strings.TrimSpace(in.Schedule)
		if schedule == "" {
			return nil, nil, dto.NewFieldError("schedule", "定时任务必须提供 cron")
		}
		if err := validateCron(schedule); err != nil {
			return nil, nil, dto.NewFieldError("schedule", err.Error())
		}
		in.Schedule = schedule
	} else {
		in.Schedule = ""
	}

	// 地区校验
	var activeRegions []model.Region
	if err := s.gorm.WithContext(ctx).Where("is_active = ?", true).Find(&activeRegions).Error; err != nil {
		return nil, nil, err
	}
	activeCodes := map[string]bool{}
	for _, r := range activeRegions {
		activeCodes[r.Code] = true
	}
	if len(in.Regions) > 0 {
		var invalid []string
		for _, code := range in.Regions {
			if !activeCodes[code] {
				invalid = append(invalid, code)
			}
		}
		if len(invalid) > 0 {
			return nil, nil, dto.NewFieldError("regions", "无效地区: "+strings.Join(invalid, ","))
		}
	}

	// 目标规范化
	options := in.Options
	if options == nil {
		options = map[string]any{}
	}
	parsed, _ := url.Parse(target)
	if in.Protocol != model.ProtocolHTTP && parsed.Scheme != "" && parsed.Hostname() != "" {
		target = parsed.Hostname()
	}
	if in.Protocol == model.ProtocolHTTP {
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			target = "https://" + target
		}
	} else if in.Protocol == model.ProtocolPing || in.Protocol == model.ProtocolMTR || in.Protocol == model.ProtocolTraceroute {
		if !(ipv4Re.MatchString(target) || isDomain(strings.Trim(target, "."))) {
			return nil, nil, dto.NewFieldError("target", "目标必须是域名或 IPv4")
		}
	} else if in.Protocol == model.ProtocolDNS {
		if !isDomain(strings.Trim(target, ".")) {
			return nil, nil, dto.NewFieldError("target", "DNS 目标必须是合法域名")
		}
		if _, err := prober.CleanDNSOptions(target, options); err != nil {
			return nil, nil, dto.NewFieldError("options", err.Error())
		}
	}
	if in.Mode == model.TaskModeOnce && (in.Protocol == model.ProtocolMTR || in.Protocol == model.ProtocolTraceroute) {
		if _, ok := options["complete_on_unreached"]; !ok {
			options["complete_on_unreached"] = true
		}
	}

	if len(in.Regions) == 0 {
		defaults, err := s.normalizeRegionCodes(ctx, nil, 1)
		if err != nil {
			return nil, nil, err
		}
		if len(defaults) == 0 {
			defaults = firstActiveRegion(activeRegions)
		}
		if len(defaults) == 0 {
			return nil, nil, dto.NewFieldError("regions", "当前没有可用地区")
		}
		in.Regions = defaults
	}

	source := "public"
	createdBy := (*uint64)(nil)
	if authenticated {
		source = "user"
		createdBy = &userID
	}
	task := &model.Task{
		TaskNo:        "nptask-" + randHex(24),
		Mode:          in.Mode,
		Protocol:      in.Protocol,
		Target:        target,
		TargetDisplay: targetDisplay,
		RegionCodesTx: marshalJSON(in.Regions),
		OptionsTx:     marshalJSON(options),
		ScheduleCron:  in.Schedule,
		Status:        model.TaskStatusPending,
		IsEnabled:     true,
		CreatedByID:   createdBy,
		ClientIP:      clientIP,
		Source:        source,
	}
	if err := s.gorm.WithContext(ctx).Create(task).Error; err != nil {
		return nil, nil, err
	}

	if task.Mode == model.TaskModeSchedule {
		next, err := nextCronRun(task.ScheduleCron, time.Now())
		if err == nil {
			s.gorm.WithContext(ctx).Model(task).Update("next_run_at", next)
			task.NextRunAt = &next
		}
		return task, nil, nil
	}

	execution, err := s.buildExecution(ctx, task, model.TriggerManual)
	if err != nil {
		return nil, nil, err
	}
	s.DispatchExecution(execution.ID, model.TriggerManual)
	return task, execution, nil
}

func firstActiveRegion(regions []model.Region) []string {
	if len(regions) == 0 {
		return nil
	}
	return []string{regions[0].Code}
}

func marshalJSON(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return "null"
	}
	return string(data)
}

func validateCron(expr string) error {
	parts := strings.Fields(expr)
	if len(parts) != 5 {
		return fmt.Errorf("cron 表达式必须包含 5 段")
	}
	for _, part := range parts {
		if part == "" {
			return fmt.Errorf("cron 表达式不能为空")
		}
	}
	if _, err := nextCronRun(expr, time.Now()); err != nil {
		return fmt.Errorf("cron 表达式非法: %v", err)
	}
	return nil
}

// ---------- 执行调度 ----------

// DispatchExecution 异步执行一次拨测(进程内 goroutine 池,对应 Celery
// dispatch_probe_execution;Phase 4 替换为 Asynq 队列)。
func (s *Service) DispatchExecution(executionID uint64, triggerType string) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.pool <- struct{}{}
		defer func() { <-s.pool }()
		if err := s.RunSingleExecution(context.Background(), executionID); err != nil {
			slog.Error("执行拨测失败", "execution_id", executionID, "error", err)
		}
	}()
}

// RunSingleExecution 执行单目标拨测:逐地区选节点 → 本地执行/远程探针 → 汇总。
func (s *Service) RunSingleExecution(ctx context.Context, executionID uint64) error {
	var execution model.Execution
	if err := s.gorm.WithContext(ctx).First(&execution, executionID).Error; err != nil {
		return err
	}
	var task model.Task
	if err := s.gorm.WithContext(ctx).First(&task, execution.TaskID).Error; err != nil {
		return err
	}
	now := time.Now()
	s.gorm.WithContext(ctx).Model(&model.Execution{}).Where("id = ?", executionID).
		Updates(map[string]any{"status": model.ExecStatusRunning, "started_at": now, "update_time": now})
	s.gorm.WithContext(ctx).Model(&model.Task{}).Where("id = ?", task.ID).
		Update("status", model.TaskStatusRunning)

	var regionRows []model.ExecutionRegion
	if err := s.gorm.WithContext(ctx).Where("execution_id = ?", executionID).Order("id ASC").Find(&regionRows).Error; err != nil {
		return err
	}
	for i := range regionRows {
		row := &regionRows[i]
		if row.Status == model.RegionStatusSuccess {
			continue
		}
		desired, err := s.getSingleExecutionNode(ctx, row.RegionCode, s.cfg.SingleExecutionMode)
		if err != nil {
			slog.Warn("节点选择失败", "region", row.RegionCode, "error", err)
		}
		started := time.Now()
		updates := map[string]any{"status": model.RegionStatusRunning, "started_at": started, "update_time": started}
		if desired != nil && desired.Code != row.NodeCode {
			updates["node_code"], updates["node_name"], updates["node_transport"] = desired.Code, desired.Name, desired.Transport
			row.NodeCode, row.NodeName, row.NodeTransport = desired.Code, desired.Name, desired.Transport
		}
		s.gorm.WithContext(ctx).Model(&model.ExecutionRegion{}).Where("id = ?", row.ID).Updates(updates)

		var result prober.Result
		if row.NodeTransport == model.NodeTransportMQTT {
			// 远程探针:Phase 8 接入 MQTT bridge 前统一落 agent_unavailable
			result = prober.Result{
				Success: false, Status: "failed",
				ErrorCode: "agent_unavailable", ErrorMessage: "远程探针不可用",
				Detail: map[string]any{}, RawPayload: map[string]any{},
			}
		} else {
			result = s.executeProtocol(ctx, &task, row)
		}
		s.persistRegionResult(ctx, row, task.Protocol, result)
	}
	return s.refreshExecutionStatus(ctx, executionID)
}

func (s *Service) executeProtocol(ctx context.Context, task *model.Task, row *model.ExecutionRegion) prober.Result {
	var options map[string]any
	_ = jsonUnmarshalDefault(task.OptionsTx, &options)
	// 探测预算:options.timeout + 1s 余量(与方案 7.1 约定一致)
	budget := 11 * time.Second
	if t, ok := options["timeout"].(float64); ok && t > 0 {
		budget = time.Duration((t + 1) * float64(time.Second))
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	switch task.Protocol {
	case model.ProtocolDNS:
		return prober.ExecuteDNS(ctx, task.Target, options)
	case model.ProtocolHTTP:
		return prober.ExecuteHTTP(ctx, task.Target, options)
	case model.ProtocolPing:
		return prober.ExecutePING(ctx, task.Target, options)
	case model.ProtocolMTR:
		return prober.ExecuteMTR(ctx, task.Target, options)
	case model.ProtocolTraceroute:
		return prober.ExecuteTraceroute(ctx, task.Target, options)
	}
	return prober.Result{
		Success: false, Status: "failed",
		ErrorCode: "unsupported_protocol", ErrorMessage: "unsupported protocol: " + task.Protocol,
		Detail: map[string]any{}, RawPayload: map[string]any{},
	}
}

func (s *Service) persistRegionResult(ctx context.Context, row *model.ExecutionRegion, protocol string, result prober.Result) {
	finished := time.Now()
	updates := map[string]any{
		"status":          result.Status,
		"success":         result.Success,
		"resolved_target": result.ResolvedTarget,
		"error_code":      result.ErrorCode,
		"error_message":   result.ErrorMessage,
		"finished_at":     finished,
		"raw_payload_text": marshalJSON(result.RawPayload),
		"update_time":     finished,
	}
	if result.LatencyMs != nil {
		updates["latency_ms"] = *result.LatencyMs
	}
	if err := s.gorm.WithContext(ctx).Model(&model.ExecutionRegion{}).Where("id = ?", row.ID).Updates(updates).Error; err != nil {
		slog.Error("落库地区结果失败", "region_row", row.ID, "error", err)
		return
	}
	detail := protocolDetailForAPI(protocol, result)
	var existing model.ProbeResult
	if err := s.gorm.WithContext(ctx).Where("execution_region_id = ?", row.ID).First(&existing).Error; err == nil {
		s.gorm.WithContext(ctx).Model(&existing).Updates(map[string]any{
			"protocol": protocol, "detail_text": marshalJSON(detail), "update_time": finished,
		})
		return
	}
	s.gorm.WithContext(ctx).Create(&model.ProbeResult{
		ExecutionRegionID: row.ID, Protocol: protocol, DetailTx: marshalJSON(detail),
	})
}

// protocolDetailForAPI 将执行器明细重映射为前端消费的 camelCase 契约字段。
func protocolDetailForAPI(protocol string, result prober.Result) map[string]any {
	detail := map[string]any{}
	switch protocol {
	case model.ProtocolDNS:
		rename := map[string]string{
			"resolver_ip": "resolverIp", "record_type": "recordType", "query_ms": "queryMs",
			"resolved_ips": "resolvedIps", "cname_chain": "cnameChain",
		}
		for k, v := range result.Detail {
			if nk, ok := rename[k]; ok {
				detail[nk] = v
			} else {
				detail[k] = v
			}
		}
	case model.ProtocolHTTP:
		rename := map[string]string{
			"http_status": "httpStatus", "dns_ms": "dnsMs", "connect_ms": "connectMs",
			"ttfb_ms": "ttfbMs", "total_ms": "totalMs", "redirect_count": "redirectCount",
			"body_size": "bodySize", "response_headers": "responseHeaders",
			"tls_info": "tlsInfo", "remote_ip": "remoteIp", "body_preview": "bodyPreview",
		}
		for k, v := range result.Detail {
			if nk, ok := rename[k]; ok {
				detail[nk] = v
			} else {
				detail[k] = v
			}
		}
	case model.ProtocolPing:
		rename := map[string]string{
			"sent_count": "sentCount", "recv_count": "recvCount", "loss_pct": "lossPct",
			"min_ms": "minMs", "avg_ms": "avgMs", "max_ms": "maxMs", "mdev_ms": "mdevMs",
			"raw_output_text": "rawOutput",
		}
		for k, v := range result.Detail {
			if nk, ok := rename[k]; ok {
				detail[nk] = v
			} else {
				detail[k] = v
			}
		}
	case model.ProtocolMTR:
		rename := map[string]string{
			"max_hops": "maxHops", "probe_count": "probeCount", "hop_count": "hopCount",
			"destination_reached": "destinationReached", "packet_loss_pct": "packetLossPct",
			"best_latency_ms": "bestLatencyMs", "avg_latency_ms": "avgLatencyMs",
			"worst_latency_ms": "worstLatencyMs", "jitter_ms": "jitterMs",
			"raw_output_text": "rawOutput",
		}
		for k, v := range result.Detail {
			if nk, ok := rename[k]; ok {
				detail[nk] = v
			} else {
				detail[k] = v
			}
		}
	case model.ProtocolTraceroute:
		rename := map[string]string{
			"max_hops": "maxHops", "query_count": "queryCount", "hop_count": "hopCount",
			"destination_reached": "destinationReached", "resolved_ip": "resolvedIp",
			"raw_output_text": "rawOutput",
		}
		for k, v := range result.Detail {
			if nk, ok := rename[k]; ok {
				detail[nk] = v
			} else {
				detail[k] = v
			}
		}
	default:
		for k, v := range result.Detail {
			detail[k] = v
		}
	}
	return detail
}

// ---------- 定时调度 ----------

// RunDueSchedules 触发到期 schedule 任务(每分钟由调度协程调用)。
func (s *Service) RunDueSchedules(ctx context.Context) error {
	var tasks []model.Task
	now := time.Now()
	if err := s.gorm.WithContext(ctx).
		Where("mode = ? AND is_enabled = ? AND next_run_at IS NOT NULL AND next_run_at <= ?",
			model.TaskModeSchedule, true, now).
		Find(&tasks).Error; err != nil {
		return err
	}
	for i := range tasks {
		task := &tasks[i]
		execution, err := s.buildExecution(ctx, task, model.TriggerSchedule)
		if err != nil {
			slog.Error("创建定时执行失败", "task", task.ID, "error", err)
			continue
		}
		s.DispatchExecution(execution.ID, model.TriggerSchedule)
		next, err := nextCronRun(task.ScheduleCron, now)
		if err == nil {
			s.gorm.WithContext(ctx).Model(task).Updates(map[string]any{"next_run_at": next, "update_time": now})
		}
	}
	return nil
}

// HeartbeatLocalNode 刷新本地默认节点心跳(在线判定依据)。
func (s *Service) HeartbeatLocalNode(ctx context.Context) error {
	now := time.Now()
	return s.gorm.WithContext(ctx).Model(&model.Node{}).
		Where("transport = ? AND is_default = ?", model.NodeTransportLocal, true).
		Updates(map[string]any{"status": "online", "last_heartbeat": now, "update_time": now}).Error
}

// ScheduleLoop 后台调度循环:每 5 分钟心跳、每分钟扫描到期任务。
func (s *Service) ScheduleLoop(ctx context.Context) {
	_ = s.HeartbeatLocalNode(ctx)
	heartbeat := time.NewTicker(5 * time.Minute)
	scan := time.NewTicker(time.Minute)
	defer heartbeat.Stop()
	defer scan.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeat.C:
			if err := s.HeartbeatLocalNode(ctx); err != nil {
				slog.Warn("心跳刷新失败", "error", err)
			}
		case <-scan.C:
			if err := s.RunDueSchedules(ctx); err != nil {
				slog.Warn("定时任务扫描失败", "error", err)
			}
		}
	}
}

// ---------- 工具 ----------

func nextCronRun(expr string, base time.Time) (time.Time, error) {
	sched, err := cron.ParseStandard(expr)
	if err != nil {
		return time.Time{}, err
	}
	return sched.Next(base), nil
}
