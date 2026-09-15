// Package service 承载业务编排:任务创建校验、执行调度、节点选择与状态汇总。
package service

import (
	"context"
	"log/slog"
	"sort"
	"time"

	"dnsss/internal/model"
)

const localHeartbeatGrace = 900 // 秒,与原 NETPROBE_LOCAL_NODE_HEARTBEAT_GRACE_SECONDS 默认一致

func heartbeatFresh(node model.Node, ref time.Time) bool {
	if node.LastHeartbeat == nil {
		return false
	}
	grace := localHeartbeatGrace
	if node.Transport != model.NodeTransportLocal {
		grace = 90
	}
	return !node.LastHeartbeat.Before(ref.Add(-time.Duration(grace) * time.Second))
}

func nodeOnline(node model.Node, ref time.Time) bool {
	return node.Status == "online" && heartbeatFresh(node, ref)
}

// rankSingleNode 与原 _rank_single_node 一致:在线 > 状态在线 > 远程 > 默认 > id。
func rankSingleNode(node model.Node, ref time.Time) rankTuple {
	return rankTuple{
		boolToInt(!nodeOnline(node, ref)),
		boolToInt(node.Status != "online"),
		boolToInt(node.Transport == model.NodeTransportLocal),
		boolToInt(!node.IsDefault),
		node.ID,
	}
}

type rankTuple struct {
	a, b, c, d int
	id         uint64
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (db *Service) schedulableNodes(ctx context.Context) ([]model.Node, error) {
	var nodes []model.Node
	if err := db.gorm.WithContext(ctx).Where("is_schedulable = ?", true).Find(&nodes).Error; err != nil {
		return nil, err
	}
	return nodes, nil
}

// getSingleExecutionNode 与原 get_single_execution_node 语义一致。
func (db *Service) getSingleExecutionNode(ctx context.Context, regionCode, mode string) (*model.Node, error) {
	nodes, err := db.schedulableNodes(ctx)
	if err != nil {
		return nil, err
	}
	ref := time.Now()
	pool := nodes
	if regionCode != "" {
		filtered := make([]model.Node, 0, len(nodes))
		for _, n := range nodes {
			if n.RegionCode == regionCode {
				filtered = append(filtered, n)
			}
		}
		pool = filtered
	}
	switch mode {
	case "local":
		locals := make([]model.Node, 0, len(pool))
		for _, n := range pool {
			if n.Transport == model.NodeTransportLocal {
				locals = append(locals, n)
			}
		}
		if len(locals) > 0 {
			pool = locals
		}
	case "remote":
		remotes := make([]model.Node, 0, len(pool))
		for _, n := range pool {
			if n.Transport != model.NodeTransportLocal {
				remotes = append(remotes, n)
			}
		}
		if len(remotes) > 0 {
			pool = remotes
		}
	}
	if len(pool) == 0 {
		return db.getDefaultNode(ctx, regionCode)
	}
	online := make([]model.Node, 0, len(pool))
	for _, n := range pool {
		if nodeOnline(n, ref) {
			online = append(online, n)
		}
	}
	if len(online) == 0 {
		online = pool
	}
	sort.Slice(online, func(i, j int) bool {
		return rankTupleLess(rankSingleNode(online[i], ref), rankSingleNode(online[j], ref))
	})
	return &online[0], nil
}

func rankTupleLess(x, y rankTuple) bool {
	if x.a != y.a {
		return x.a < y.a
	}
	if x.b != y.b {
		return x.b < y.b
	}
	if x.c != y.c {
		return x.c < y.c
	}
	if x.d != y.d {
		return x.d < y.d
	}
	return x.id < y.id
}

func (db *Service) getDefaultNode(ctx context.Context, regionCode string) (*model.Node, error) {
	nodes, err := db.schedulableNodes(ctx)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		var node model.Node
		if err := db.gorm.WithContext(ctx).Order("is_default DESC, id ASC").First(&node).Error; err != nil {
			return nil, err
		}
		return &node, nil
	}
	pool := nodes
	if regionCode != "" {
		filtered := make([]model.Node, 0, len(nodes))
		for _, n := range nodes {
			if n.RegionCode == regionCode {
				filtered = append(filtered, n)
			}
		}
		if len(filtered) > 0 {
			pool = filtered
		}
	}
	ref := time.Now()
	sort.Slice(pool, func(i, j int) bool {
		return rankTupleLess(rankSingleNode(pool[i], ref), rankSingleNode(pool[j], ref))
	})
	return &pool[0], nil
}

// NormalizeRegionCodes 导出给 HTTP 层的地区校验入口。
func (db *Service) NormalizeRegionCodes(ctx context.Context, codes []string) ([]string, error) {
	return db.normalizeRegionCodes(ctx, codes, 0)
}

// normalizeRegionCodes 校验并去重地区;为空时回退默认地区(与原语义一致:
// 有在线远程探针的地区优先,其次有节点的地区,global 兜底)。
func (db *Service) normalizeRegionCodes(ctx context.Context, codes []string, limit int) ([]string, error) {
	var regions []model.Region
	if err := db.gorm.WithContext(ctx).Where("is_active = ?", true).Order("display_order ASC, id ASC").Find(&regions).Error; err != nil {
		return nil, err
	}
	active := map[string]bool{}
	for _, r := range regions {
		active[r.Code] = true
	}
	normalized := make([]string, 0, len(codes))
	seen := map[string]bool{}
	for _, code := range codes {
		if active[code] && !seen[code] {
			seen[code] = true
			normalized = append(normalized, code)
		}
	}
	if len(normalized) > 0 {
		if limit > 0 && len(normalized) > limit {
			normalized = normalized[:limit]
		}
		return normalized, nil
	}
	defaults := db.defaultRegionCodes(regions, limit)
	if limit > 0 && len(defaults) > limit {
		defaults = defaults[:limit]
	}
	return defaults, nil
}

func (db *Service) defaultRegionCodes(regions []model.Region, limit int) []string {
	type regionRank struct {
		region model.Region
		onlineRemote, online, hasNodes int
		isGlobal                       int
	}
	nodes, err := db.schedulableNodes(context.Background())
	if err != nil {
		slog.Warn("加载节点失败", "error", err)
		nodes = nil
	}
	ref := time.Now()
	nodesByRegion := map[string][]model.Node{}
	for _, n := range nodes {
		nodesByRegion[n.RegionCode] = append(nodesByRegion[n.RegionCode], n)
	}
	ranks := make([]regionRank, 0, len(regions))
	for _, r := range regions {
		rn := regionRank{region: r}
		for _, n := range nodesByRegion[r.Code] {
			rn.hasNodes = 1
			if nodeOnline(n, ref) {
				rn.online = 1
				if n.Transport != model.NodeTransportLocal {
					rn.onlineRemote = 1
				}
			}
		}
		if r.Code == "global" {
			rn.isGlobal = 1
		}
		ranks = append(ranks, rn)
	}
	sort.Slice(ranks, func(i, j int) bool {
		a, b := ranks[i], ranks[j]
		if a.onlineRemote != b.onlineRemote {
			return a.onlineRemote > b.onlineRemote
		}
		if a.online != b.online {
			return a.online > b.online
		}
		if a.hasNodes != b.hasNodes {
			return a.hasNodes > b.hasNodes
		}
		if a.isGlobal != b.isGlobal {
			return a.isGlobal < b.isGlobal
		}
		if a.region.DisplayOrder != b.region.DisplayOrder {
			return a.region.DisplayOrder < b.region.DisplayOrder
		}
		return a.region.ID < b.region.ID
	})
	if limit <= 0 {
		limit = 1
	}
	out := make([]string, 0, limit)
	for _, r := range ranks {
		if len(out) >= limit {
			break
		}
		out = append(out, r.region.Code)
	}
	return out
}

// buildExecution 创建执行与地区结果行(region/node 信息快照冗余存储)。
func (db *Service) buildExecution(ctx context.Context, task *model.Task, triggerType string) (*model.Execution, error) {
	var codes []string
	if err := jsonUnmarshalDefault(task.RegionCodesTx, &codes); err != nil {
		return nil, err
	}
	regionCodes, err := db.normalizeRegionCodes(ctx, codes, 0)
	if err != nil {
		return nil, err
	}
	var regions []model.Region
	if err := db.gorm.WithContext(ctx).Where("code IN ?", regionCodes).Find(&regions).Error; err != nil {
		return nil, err
	}
	regionMap := map[string]model.Region{}
	for _, r := range regions {
		regionMap[r.Code] = r
	}
	execution := &model.Execution{
		ExecutionNo:     "npexec-" + randHex(24),
		TaskID:          task.ID,
		TriggerType:     triggerType,
		Status:          model.ExecStatusPending,
		TotalRegionCount: len(regionCodes),
	}
	if err := db.gorm.WithContext(ctx).Create(execution).Error; err != nil {
		return nil, err
	}
	rows := make([]model.ExecutionRegion, 0, len(regionCodes))
	for _, code := range regionCodes {
		region, ok := regionMap[code]
		if !ok {
			continue
		}
		node, err := db.getDefaultNode(ctx, code)
		if err != nil {
			slog.Warn("节点选择失败", "region", code, "error", err)
		}
		row := model.ExecutionRegion{
			ExecutionID: execution.ID,
			RegionCode:  region.Code,
			RegionName:  region.Name,
			MapLng:      region.MapLng,
			MapLat:      region.MapLat,
			Status:      model.RegionStatusPending,
		}
		if node != nil {
			row.NodeCode, row.NodeName, row.NodeTransport = node.Code, node.Name, node.Transport
		}
		rows = append(rows, row)
	}
	if len(rows) > 0 {
		if err := db.gorm.WithContext(ctx).CreateInBatches(rows, 100).Error; err != nil {
			return nil, err
		}
	}
	execution.TotalRegionCount = len(rows)
	if err := db.gorm.WithContext(ctx).Model(execution).Update("total_region_count", len(rows)).Error; err != nil {
		return nil, err
	}
	return execution, nil
}

// refreshExecutionStatus 汇总地区结果,更新执行与任务状态(与原语义一致:
// 全部成功/部分成功/全部失败;运行中输出"等待远程探针回传 (n/m)")。
func (db *Service) refreshExecutionStatus(ctx context.Context, executionID uint64) error {
	var execution model.Execution
	if err := db.gorm.WithContext(ctx).First(&execution, executionID).Error; err != nil {
		return err
	}
	var results []model.ExecutionRegion
	if err := db.gorm.WithContext(ctx).Where("execution_id = ?", executionID).Order("id ASC").Find(&results).Error; err != nil {
		return err
	}
	total := len(results)
	success := 0
	running := 0
	for _, r := range results {
		if r.Success {
			success++
		}
		if r.Status == model.RegionStatusPending || r.Status == model.RegionStatusRunning {
			running++
		}
	}
	ratio := 0.0
	if total > 0 {
		ratio = float64(success) / float64(total) * 100
	}
	ratio = float64(int(ratio*100+0.5)) / 100

	updates := map[string]any{
		"success_region_count": success,
		"total_region_count":   total,
		"availability_ratio":   ratio,
		"update_time":          time.Now(),
	}
	taskUpdates := map[string]any{"update_time": time.Now()}
	if running > 0 {
		updates["status"] = model.ExecStatusRunning
		updates["summary_message"] = "等待远程探针回传 (" + itoa(total-running) + "/" + itoa(total) + ")"
		taskUpdates["status"] = model.TaskStatusRunning
	} else {
		now := time.Now()
		updates["finished_at"] = now
		taskUpdates["last_run_at"] = now
		switch {
		case total > 0 && success == total:
			updates["status"] = model.ExecStatusSuccess
			updates["summary_message"] = "全部地区拨测成功"
			taskUpdates["status"] = model.TaskStatusSuccess
		case success > 0:
			updates["status"] = model.ExecStatusPartial
			updates["summary_message"] = "部分地区拨测成功"
			taskUpdates["status"] = model.TaskStatusPartial
		default:
			updates["status"] = model.ExecStatusFailed
			updates["summary_message"] = "全部地区拨测失败"
			taskUpdates["status"] = model.TaskStatusFailed
		}
	}
	if err := db.gorm.WithContext(ctx).Model(&model.Execution{}).Where("id = ?", executionID).Updates(updates).Error; err != nil {
		return err
	}
	return db.gorm.WithContext(ctx).Model(&model.Task{}).Where("id = ?", execution.TaskID).Updates(taskUpdates).Error
}
