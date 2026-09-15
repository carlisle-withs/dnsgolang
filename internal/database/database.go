// Package database 管理 MySQL(GORM)连接。
// 约定:迁移由 golang-migrate SQL 文件负责,运行时不做 AutoMigrate。
package database

import (
	"fmt"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func Open(dsn string) (*gorm.DB, error) {
	if !containsParam(dsn, "parseTime") {
		dsn = appendParam(dsn, "parseTime=true")
	}
	if !containsParam(dsn, "loc=") {
		dsn = appendParam(dsn, "loc=Local")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		return nil, fmt.Errorf("连接 MySQL 失败: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(64)
	sqlDB.SetMaxIdleConns(16)
	sqlDB.SetConnMaxLifetime(time.Hour)
	return db, nil
}

func containsParam(dsn, key string) bool {
	for i := 0; i < len(dsn); i++ {
		if dsn[i] == '?' || dsn[i] == '&' {
			rest := dsn[i+1:]
			if len(rest) >= len(key) && rest[:len(key)] == key {
				next := rest[len(key):]
				if next == "" || next[0] == '=' || next[0] == '&' {
					return true
				}
			}
		}
	}
	return false
}

func appendParam(dsn, param string) string {
	if !contains(dsn, '?') {
		return dsn + "?" + param
	}
	return dsn + "&" + param
}

func contains(s string, ch byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == ch {
			return true
		}
	}
	return false
}
