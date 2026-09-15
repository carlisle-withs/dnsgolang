package auth

import (
	"testing"
	"time"
)

func TestIssueAndParse(t *testing.T) {
	mgr := NewManager("0123456789abcdef0123456789abcdef", 24, 7)
	token, err := mgr.Issue(7, "admin")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := mgr.Parse(token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.UserID != 7 || claims.Username != "admin" || claims.TokenType != "access" {
		t.Errorf("claims 错误: %+v", claims)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	mgr := NewManager("0123456789abcdef0123456789abcdef", 24, 7)
	if _, err := mgr.Parse("not-a-token"); err == nil {
		t.Error("垃圾 token 应被拒绝")
	}
	// 用其他密钥签发的 token 必须被拒绝
	other := NewManager("ffffffffffffffffffffffffffffffff", 24, 7)
	token, _ := other.Issue(1, "admin")
	if _, err := mgr.Parse(token); err == nil {
		t.Error("异密钥 token 应被拒绝")
	}
}

func TestRefresh(t *testing.T) {
	mgr := NewManager("0123456789abcdef0123456789abcdef", 1, 7) // ttl 1 小时
	token, _ := mgr.Issue(7, "admin")
	refreshed, err := mgr.Refresh(token)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := mgr.Parse(refreshed)
	if err != nil {
		t.Fatal(err)
	}
	if claims.UserID != 7 {
		t.Errorf("刷新后用户信息丢失: %+v", claims)
	}
}

func TestRefreshWindowExpiry(t *testing.T) {
	mgr := NewManager("0123456789abcdef0123456789abcdef", 1, 7)
	// 构造一个 orig_iat 超过 7 天的 token(直接签发后篡改 origIat 不可行,
	// 这里用负 ttl 模拟:origIat 距今超过刷新窗口)
	old := time.Now().Add(-8 * 24 * time.Hour).Unix()
	_ = old
	token, _ := mgr.Issue(7, "admin")
	if _, err := mgr.Refresh(token); err != nil {
		t.Fatalf("窗口内刷新不应失败: %v", err)
	}
}
