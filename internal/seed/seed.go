// Package seed 初始化基础数据:8 个固定地区、本地默认节点、admin 用户。
// admin 密码来自 DNSSS_ADMIN_PASSWORD(无默认值,与原系统硬编码密码相反)。
package seed

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"gorm.io/gorm"

	"dnsss/internal/auth"
	"dnsss/internal/model"
)

type RegionSeed struct {
	Code         string
	Name         string
	DisplayOrder int
	Lng, Lat     float64
}

// 与原 0002_seed_defaults 迁移完全一致的 8 地区。
var Regions = []RegionSeed{
	{"global", "全局", 0, 105.0, 35.0},
	{"north", "华北", 10, 116.40, 39.90},
	{"east", "华东", 20, 121.47, 31.23},
	{"south", "华南", 30, 113.27, 23.13},
	{"central", "华中", 40, 114.31, 30.52},
	{"southwest", "西南", 50, 104.07, 30.67},
	{"northwest", "西北", 60, 103.84, 36.06},
	{"northeast", "东北", 70, 123.43, 41.80},
}

func Run(ctx context.Context, db *gorm.DB, adminPassword string) error {
	for _, r := range Regions {
		region := model.Region{
			Code: r.Code, Name: r.Name, DisplayOrder: r.DisplayOrder,
			IsActive: true, MapLng: r.Lng, MapLat: r.Lat,
		}
		if err := db.WithContext(ctx).
			Where(model.Region{Code: r.Code}).Assign(region).FirstOrCreate(&region).Error; err != nil {
			return fmt.Errorf("种子地区 %s 失败: %w", r.Code, err)
		}
	}

	node := model.Node{
		Code: "default-node", Name: "默认拨测节点", RegionCode: "global",
		QueueName: "netprobe_default", Transport: model.NodeTransportLocal,
		Host: "default-worker", Status: "online", CapabilitiesTx: `["http","ping","dns"]`,
		IsDefault: true, IsSchedulable: true, LastHeartbeat: ptrTime(time.Now()),
	}
	if err := db.WithContext(ctx).
		Where(model.Node{Code: node.Code}).Assign(node).FirstOrCreate(&node).Error; err != nil {
		return fmt.Errorf("种子默认节点失败: %w", err)
	}

	if adminPassword == "" {
		return errors.New("种子 admin 需要 DNSSS_ADMIN_PASSWORD 环境变量")
	}
	var count int64
	db.WithContext(ctx).Model(&model.User{}).Count(&count)
	if count == 0 {
		hash, err := auth.HashPassword(adminPassword)
		if err != nil {
			return err
		}
		admin := model.User{
			Username: "admin", PasswordHash: hash, Name: "管理员",
			IsSuperuser: true, IsActive: true, Avatar: "avatar/default.png",
		}
		if err := db.WithContext(ctx).Create(&admin).Error; err != nil {
			return fmt.Errorf("种子 admin 失败: %w", err)
		}
		slog.Info("已创建初始 admin 账号", "username", "admin")
	}
	return nil
}

func ptrTime(t time.Time) *time.Time { return &t }
